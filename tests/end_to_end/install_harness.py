"""Host side of the install test: runs the whole install flow under QEMU software emulation inside Docker.

There is no hypervisor on the development machine, so every guest runs under QEMU's TCG in a container, exactly as
in the
boot test (boot_harness.py, which this module reuses for the container, the streaming and the cleanup). The flow has
four
steps, each in a container of its own, sharing one throwaway Docker volume that holds the target disk and the plan
medium:

    make media -> install (boot the ISO; the engine installs and powers off)
               -> boot the installed disk, type the passphrase, read the self-check
               -> boot it again with wrong passphrases and see that it stays locked

Variables, defaults and how to read a failure: docs/development/INSTALL_TESTING.md. The passphrase exists only in
memory,
in the plan medium inside the volume (deleted with it) and on QEMU's input; it is passed through stdin, never argv or
the
environment, and scrubbed from everything that is shown or saved.
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from tests.end_to_end import boot_harness
from tests.end_to_end.boot_harness import (
    HARNESS_DIR,
    IN_CONTAINER_HARNESS,
    IN_CONTAINER_ISO,
    BootConfig,
    BootEnvironmentError,
    ConfigError,
    StreamOutcome,
    bind_mount_option,
    hardened_run_prefix,
    printable_console_text,
    require_a_real_run,
    stream_container,
)
from tests.end_to_end.container_install import NO_UEFI_EXIT_STATUS
from tests.end_to_end.install_console import (
    FirstOf,
    PromptTyper,
    Scrubber,
    UnlockFailedWatcher,
    install_problems,
    installed_boot_problems,
    parse_install_events,
    wrong_passphrase_problems,
)
from tests.end_to_end.install_plan import (
    DEFAULT_KDF_ITER_TIME_MS,
    DEFAULT_KDF_MEMORY_KIB,
    Secret,
    build_plan,
    generate_passphrase,
    generate_wrong_passphrase,
    plan_bytes,
)

ENV_INSTALL_TIMEOUT = "PAI_INSTALL_TIMEOUT"
ENV_BOOT_TIMEOUT = "PAI_INSTALL_BOOT_TIMEOUT"
ENV_NEGATIVE_TIMEOUT = "PAI_INSTALL_NEGATIVE_TIMEOUT"
ENV_SETTLE = "PAI_INSTALL_UNLOCK_SETTLE"
ENV_DISK_GIB = "PAI_INSTALL_DISK_GIB"
ENV_UEFI = "PAI_INSTALL_UEFI"
ENV_ECHO = "PAI_INSTALL_ECHO"
ENV_KDF_MEMORY = "PAI_INSTALL_KDF_MEMORY_KIB"
ENV_KDF_ITER_TIME = "PAI_INSTALL_KDF_ITER_MS"

# Software emulation is slow, and the install copies a whole root filesystem through an encrypted volume: defaults that
# leave room for a loaded machine (the boot test's own timeout is 1800 s for a boot alone).
DEFAULT_INSTALL_TIMEOUT_S = 5400
DEFAULT_BOOT_TIMEOUT_S = 2400  # GRUB, the kernel, the unlock, then the whole self-check with the kiosk
DEFAULT_NEGATIVE_TIMEOUT_S = 1500
DEFAULT_SETTLE_S = 180  # how long the guest may stay silent after the last wrong passphrase before the run is over
DEFAULT_DISK_GIB = (
    20  # the engine refuses a target below 16 GiB; the file is sparse, only what the guest writes is used
)
WRONG_ATTEMPTS = 3  # the number of wrong passphrases the negative test types (cryptsetup's own number of tries)
MEDIA_STEP_TIMEOUT_S = 300
PROBE_TIMEOUT_S = 120
VOLUME_REMOVE_TIMEOUT_S = 120
UEFI_MODES = ("auto", "on", "off")

CONTAINER_PREFIX = "pai-instharness"
IN_CONTAINER_SCRIPT = f"{IN_CONTAINER_HARNESS}/container_install.py"
IN_CONTAINER_DISKS = "/disks"
LOG_DIR = Path(tempfile.gettempdir())


@dataclass(frozen=True)
class InstallConfig:
    boot: BootConfig  # memory, CPUs and extra kernel words of the install boot (PAI_QEMU_MEMORY, PAI_QEMU_CPUS, ...)
    install_timeout_s: float = DEFAULT_INSTALL_TIMEOUT_S
    boot_timeout_s: float = DEFAULT_BOOT_TIMEOUT_S
    negative_timeout_s: float = DEFAULT_NEGATIVE_TIMEOUT_S
    settle_s: float = DEFAULT_SETTLE_S
    disk_gib: int = DEFAULT_DISK_GIB
    uefi: str = "auto"  # auto: when the image has firmware; on: and its absence is an error; off: BIOS only
    echo: bool = False  # show the (scrubbed) console while the guests run
    kdf_memory_kib: int = DEFAULT_KDF_MEMORY_KIB
    kdf_iter_time_ms: int = DEFAULT_KDF_ITER_TIME_MS

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> InstallConfig:
        uefi = env.get(ENV_UEFI, "").strip().lower() or "auto"
        if uefi not in UEFI_MODES:
            raise ConfigError(f"{ENV_UEFI} must be one of {', '.join(UEFI_MODES)}, got {uefi!r}")
        number = boot_harness._positive_number
        return cls(
            boot=BootConfig.from_env(env),
            install_timeout_s=number(env, ENV_INSTALL_TIMEOUT, DEFAULT_INSTALL_TIMEOUT_S),
            boot_timeout_s=number(env, ENV_BOOT_TIMEOUT, DEFAULT_BOOT_TIMEOUT_S),
            negative_timeout_s=number(env, ENV_NEGATIVE_TIMEOUT, DEFAULT_NEGATIVE_TIMEOUT_S),
            settle_s=number(env, ENV_SETTLE, DEFAULT_SETTLE_S),
            disk_gib=int(number(env, ENV_DISK_GIB, DEFAULT_DISK_GIB, whole=True)),
            uefi=uefi,
            echo=env.get(ENV_ECHO, "").strip().lower() in {"1", "true", "yes", "on"},
            kdf_memory_kib=int(number(env, ENV_KDF_MEMORY, DEFAULT_KDF_MEMORY_KIB, whole=True)),
            kdf_iter_time_ms=int(number(env, ENV_KDF_ITER_TIME, DEFAULT_KDF_ITER_TIME_MS, whole=True)),
        )


# ---- docker commands -------------------------------------------------------------------------------------------------


def new_run_id() -> str:
    return f"{os.getpid()}-{uuid.uuid4().hex[:8]}"


def volume_mount_option(volume: str) -> list[str]:
    return ["--mount", f"type=volume,source={volume},target={IN_CONTAINER_DISKS}"]


def step_command(
    name: str, tag: str, volume: str, step_args: list[str], *, iso: Path | None = None, interactive: bool = False
) -> list[str]:
    """`docker run` for one step: the hardened container of the boot test, the harness mounted read-only, the
    shared volume
    mounted read-write, the ISO (when the step boots it) read-only. A step never has a network or a capability."""
    return [
        *hardened_run_prefix(name, interactive=interactive),
        *volume_mount_option(volume),
        *bind_mount_option(HARNESS_DIR, IN_CONTAINER_HARNESS),
        *(bind_mount_option(iso, IN_CONTAINER_ISO) if iso is not None else []),
        tag,
        "python3",
        IN_CONTAINER_SCRIPT,
        *step_args,
    ]


def machine_args(config: BootConfig) -> list[str]:
    return ["--memory-mib", str(config.memory_mib), "--cpus", str(config.cpus)]


def install_step_args(config: BootConfig) -> list[str]:
    # One argument in the --name=value form, so that a value starting with "-" is not read as an option.
    extra = [f"--extra-kernel-args={config.extra_kernel_args}"] if config.extra_kernel_args else []
    return ["install", IN_CONTAINER_ISO, *machine_args(config), *extra]


def boot_disk_step_args(config: BootConfig, firmware: str) -> list[str]:
    return ["boot-disk", "--firmware", firmware, *machine_args(config)]


# ---- results ---------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class StepResult:
    """One QEMU step: its console (secrets scrubbed), what it ended as, and why it is not a pass (empty: it is)."""

    outcome: StreamOutcome
    problems: list[str]
    log: Path

    @property
    def output(self) -> str:
        return self.outcome.output

    def tail(self, lines: int = 60) -> str:
        return "\n".join(printable_console_text(self.output).splitlines()[-lines:])


def save_log(name: str, text: str) -> Path:
    """Write a console to a fixed place (replacing the last run's) with control characters made visible, and return
    it."""
    path = LOG_DIR / f"pai-e2e-last-{name}.log"
    path.write_text(printable_console_text(text), encoding="utf-8", newline="\n")
    return path


def _echo_for(config: InstallConfig) -> Callable[[str], None] | None:
    if not config.echo:
        return None

    def show(line: str) -> None:
        encoding = sys.stdout.encoding or "utf-8"
        sys.stdout.write(printable_console_text(line).encode(encoding, errors="replace").decode(encoding))
        sys.stdout.flush()

    return show


def _is_result_event(line: str) -> bool:
    return bool(parse_install_events(line).results)


class InstallSession:
    """One install test run: owns the Docker volume the steps share and removes it (with the target disk and the plan
    medium, which holds the passphrase) when it is closed. Use as a context manager."""

    def __init__(self, tag: str, config: InstallConfig) -> None:
        self.tag = tag
        self.config = config
        self.run_id = new_run_id()
        self.volume = f"{CONTAINER_PREFIX}-vol-{self.run_id}"
        self.passphrase: Secret = generate_passphrase()
        self.scrubber = Scrubber([self.passphrase])
        self._volume_created = False
        self._steps = 0

    # -- lifecycle ----

    def __enter__(self) -> InstallSession:
        done = boot_harness._docker("volume", "create", self.volume, timeout=VOLUME_REMOVE_TIMEOUT_S)
        if done.returncode != 0:
            raise BootEnvironmentError(f"cannot create the Docker volume {self.volume}: {_tail(done.stderr)}")
        self._volume_created = True
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Remove the volume. A failure is reported on stderr and never raised: it must not hide the test's own
        result."""
        if not self._volume_created:
            return
        done = boot_harness._docker("volume", "rm", "--force", self.volume, timeout=VOLUME_REMOVE_TIMEOUT_S)
        if done.returncode != 0:
            print(
                f"warning: the Docker volume {self.volume} was not removed ({_tail(done.stderr)}); "
                "it holds the test's disk and plan medium: `docker volume rm` it",
                file=sys.stderr,
            )
        self._volume_created = False

    def _name(self, role: str) -> str:
        self._steps += 1
        return f"{CONTAINER_PREFIX}-{role}-{self.run_id}-{self._steps}"

    # -- steps ----

    def probe_uefi(self) -> bool:
        """Whether the QEMU image has UEFI firmware (the `probe-uefi` step of container_install.py)."""
        name = self._name("probe")
        done = boot_harness._docker(
            *step_command(name, self.tag, self.volume, ["probe-uefi"])[1:], timeout=PROBE_TIMEOUT_S
        )
        if done.returncode not in {0, NO_UEFI_EXIT_STATUS}:
            raise BootEnvironmentError(
                f"probing the image for UEFI firmware failed: {_tail(done.stderr + done.stdout)}"
            )
        return done.returncode == 0

    def make_media(self) -> None:
        """Build the plan medium (with a fresh plan holding this session's passphrase) and the blank target disk."""
        plan = build_plan(
            self.passphrase,
            kdf_memory_kib=self.config.kdf_memory_kib,
            kdf_iter_time_ms=self.config.kdf_iter_time_ms,
        )
        name = self._name("media")
        # The plan goes in on stdin: argv and the environment of a process are readable by every account on the host.
        command = step_command(
            name, self.tag, self.volume, ["make-media", "--disk-gib", str(self.config.disk_gib)], interactive=True
        )
        try:
            done = boot_harness._docker(*command[1:], input_bytes=plan_bytes(plan), timeout=MEDIA_STEP_TIMEOUT_S)
        except boot_harness.subprocess.TimeoutExpired:
            boot_harness.kill_container(name)
            raise BootEnvironmentError(
                f"building the plan medium did not finish within {MEDIA_STEP_TIMEOUT_S} s"
            ) from None
        if done.returncode != 0:
            text = self.scrubber.scrub((done.stdout + done.stderr).decode("utf-8", errors="replace"))
            raise BootEnvironmentError(f"building the plan medium failed (status {done.returncode}): {text[-800:]}")

    def install(self, iso: Path) -> StepResult:
        """Boot `iso` with the plan medium and the target disk; ends when the guest powers off or the engine's result
        event has been printed (and a grace period has passed)."""
        name = self._name("install")
        outcome = stream_container(
            step_command(name, self.tag, self.volume, install_step_args(self.config.boot), iso=iso),
            name,
            self.config.install_timeout_s,
            echo=_echo_for(self.config),
            handler=boot_harness.LineWatcher(_is_result_event),
            scrub=self.scrubber.scrub,
        )
        require_a_real_run(outcome, "install")
        problems = install_problems(
            parse_install_events(outcome.output),
            timed_out=outcome.timed_out,
            powered_off=outcome.ended_by_itself and outcome.returncode == 0,
            echoed_secret=self.scrubber.hits > 0,
        )
        return StepResult(outcome, problems, save_log("install", outcome.output))

    def boot_installed(self, firmware: str) -> StepResult:
        """Boot the installed disk through `firmware` ("bios" or "uefi"), type the passphrase at the unlock prompt and
        read the self-check; ends at its RESULT line (then the guest powers itself off) or at the timeout."""
        name = self._name(f"boot-{firmware}")
        typer = PromptTyper([self.passphrase])
        hits_before = self.scrubber.hits
        outcome = stream_container(
            step_command(
                name, self.tag, self.volume, boot_disk_step_args(self.config.boot, firmware), interactive=True
            ),
            name,
            self.config.boot_timeout_s,
            echo=_echo_for(self.config),
            handler=FirstOf(typer, boot_harness.LineWatcher(boot_harness._has_result_line)),
            scrub=self.scrubber.scrub,
            interactive=True,
        )
        require_a_real_run(outcome, f"{firmware} boot")
        problems = installed_boot_problems(
            outcome.output,
            prompts_seen=typer.prompts_seen,
            typed=typer.typed,
            timed_out=outcome.timed_out,
            powered_off=outcome.ended_by_itself and outcome.returncode == 0,
            echoed_secret=self.scrubber.hits > hits_before,
        )
        return StepResult(outcome, problems, save_log(f"installed-boot-{firmware}", outcome.output))

    def boot_with_wrong_passphrases(self, firmware: str = "bios") -> StepResult:
        """Boot the installed disk and answer the unlock prompt with WRONG_ATTEMPTS wrong passphrases. The result is a
        pass when the system never came up; the run ends when the guest gave up, fell silent or the timeout passed."""
        name = self._name(f"wrong-{firmware}")
        wrong = [generate_wrong_passphrase(self.passphrase) for _ in range(WRONG_ATTEMPTS)]
        scrubber = Scrubber([self.passphrase, *wrong])  # the wrong ones are secrets of the test too: scrub them as well
        typer = PromptTyper(wrong)
        outcome = stream_container(
            step_command(
                name, self.tag, self.volume, boot_disk_step_args(self.config.boot, firmware), interactive=True
            ),
            name,
            self.config.negative_timeout_s,
            echo=_echo_for(self.config),
            handler=FirstOf(typer, UnlockFailedWatcher(typer, attempts=WRONG_ATTEMPTS, settle_s=self.config.settle_s)),
            scrub=scrubber.scrub,
            interactive=True,
        )
        require_a_real_run(outcome, f"{firmware} wrong-passphrase boot")
        problems = wrong_passphrase_problems(
            outcome.output,
            prompts_seen=typer.prompts_seen,
            typed=typer.typed,
            attempts=WRONG_ATTEMPTS,
            echoed_secret=scrubber.hits > 0,
        )
        return StepResult(outcome, problems, save_log(f"wrong-passphrase-{firmware}", outcome.output))


def _tail(data: bytes) -> str:
    return printable_console_text(data.decode("utf-8", errors="replace")[-500:]).strip()
