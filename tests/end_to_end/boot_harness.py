"""Host side of the boot test: runs the built ISO under QEMU inside a container and collects the serial console.

There is no hypervisor on the development machine, so the guest runs under QEMU's software emulation (TCG) inside a
Docker container (docs/development/BOOT_TESTING.md). The container has no network, no capabilities and a read-only
root; the ISO is mounted read-only. Whatever happens, the container this module started is removed before it returns.

Run it directly for a boot with live output:  python -m tests.end_to_end.boot_harness [--iso PATH]
Exit status: 0 the self-check passed, 1 it did not, 2 the boot could not be performed (an environment problem).
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from tests.end_to_end.selfcheck_output import RESULT_NAME, parse_selfcheck, selfcheck_problems

HARNESS_DIR = Path(__file__).resolve().parent
REPO_ROOT = HARNESS_DIR.parents[1]
DOCKERFILE = HARNESS_DIR / "Dockerfile"

ENV_ISO = "PAI_ISO"
ENV_TIMEOUT = "PAI_BOOT_TIMEOUT"
ENV_MEMORY = "PAI_QEMU_MEMORY"
ENV_CPUS = "PAI_QEMU_CPUS"
DEFAULT_TIMEOUT_S = 1800  # software emulation is slow; a normal boot is minutes, a loaded machine needs headroom
DEFAULT_MEMORY_MIB = 2048
DEFAULT_CPUS = 2

IMAGE_REPOSITORY = "pai-e2e-qemu"
CONTAINER_PREFIX = "pai-e2e-boot"
IN_CONTAINER_ISO = "/iso/boot.iso"
IN_CONTAINER_HARNESS = "/harness"
# The latest boot's full console output; a fixed place, because pytest keeps only the last few temporary directories.
SERIAL_LOG = Path(tempfile.gettempdir()) / "pai-e2e-last-boot.log"
POWEROFF_GRACE_S = 60  # after the verdict the guest powers itself off; give it this long before the container is killed
DOCKER_PROBE_TIMEOUT_S = 30
IMAGE_BUILD_TIMEOUT_S = 1800


class ConfigError(ValueError):
    """An environment variable holds an unusable value."""


class IsoNotFoundError(Exception):
    """No ISO to boot; the message says where it looked."""


class BootEnvironmentError(RuntimeError):
    """The boot could not be performed (image build, docker, the ISO or the emulator failed).

    Distinct from a self-check that ran and did not pass: callers report it as an environment problem, not as a
    finding about the image.
    """


@dataclass(frozen=True)
class BootConfig:
    timeout_s: float = DEFAULT_TIMEOUT_S
    memory_mib: int = DEFAULT_MEMORY_MIB
    cpus: int = DEFAULT_CPUS

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> BootConfig:
        return cls(
            timeout_s=_positive_number(env, ENV_TIMEOUT, DEFAULT_TIMEOUT_S),
            memory_mib=int(_positive_number(env, ENV_MEMORY, DEFAULT_MEMORY_MIB, whole=True)),
            cpus=int(_positive_number(env, ENV_CPUS, DEFAULT_CPUS, whole=True)),
        )


def _positive_number(env: Mapping[str, str], name: str, default: float, *, whole: bool = False) -> float:
    """The variable's value as a finite number of at least 1 (a whole number when `whole`), else ConfigError.

    `float()` also accepts "nan" and "inf", which compare false against every limit: a NaN timeout would never
    expire, so finiteness is checked explicitly.
    """
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None
    if not math.isfinite(value) or value < 1:
        raise ConfigError(f"{name} must be a finite number of at least 1, got {raw!r}")
    if whole and value != int(value):
        raise ConfigError(f"{name} must be a whole number, got {raw!r}")
    return value


@dataclass(frozen=True)
class BootOutcome:
    output: str  # everything the guest and the container printed, in order
    timed_out: bool  # the overall timeout ended the run
    powered_off: bool  # the container ended on its own, i.e. the guest shut itself down
    echo_error: str = ""  # why live echoing stopped, if it did; collecting the output went on regardless


def locate_iso(repo_root: Path = REPO_ROOT, env: Mapping[str, str] | None = None) -> Path:
    """The ISO named by PAI_ISO, else the newest dist/*.iso. Raises IsoNotFoundError when there is none."""
    env = os.environ if env is None else env
    if explicit := env.get(ENV_ISO, "").strip():
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise IsoNotFoundError(f"{ENV_ISO} points to {path}, which is not a file")
        return path.resolve()
    candidates = sorted((repo_root / "dist").glob("*.iso"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise IsoNotFoundError(f"no ISO: set {ENV_ISO} or build one (bash os/build/build-iso.sh writes dist/*.iso)")
    return candidates[0].resolve()


def _docker(
    *args: str, input_bytes: bytes | None = None, timeout: float | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run `docker <args>` (fixed argument vector, no shell) and capture its output."""
    return subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        input=input_bytes,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def docker_unavailable_reason() -> str | None:
    """None when a Docker daemon answers; otherwise a one-line reason."""
    if shutil.which("docker") is None:
        return "the docker command is not installed or not on PATH"
    try:
        probe = _docker("info", "--format", "{{.ServerVersion}}", timeout=DOCKER_PROBE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return f"docker did not answer within {DOCKER_PROBE_TIMEOUT_S} s"
    if probe.returncode != 0:
        return f"the Docker daemon is not reachable: {probe.stderr.decode('utf-8', errors='replace').strip()[-200:]}"
    return None


def image_tag(dockerfile: Path = DOCKERFILE) -> str:
    """Tag derived from the Dockerfile's content: unchanged Dockerfile, same tag, no rebuild; any edit, a new tag.

    The tag is the only thing that triggers a rebuild, so the Dockerfile pins everything it installs (base image
    digest, package snapshot): the same text then builds the same image on every machine.
    """
    digest = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
    return f"{IMAGE_REPOSITORY}:{digest[:12]}"


def ensure_image(tag: str | None = None, *, dockerfile: Path = DOCKERFILE) -> str:
    """Build the QEMU image unless this Dockerfile's image already exists; returns its tag.

    Raises BootEnvironmentError when the build fails or does not finish within IMAGE_BUILD_TIMEOUT_S.
    """
    tag = tag or image_tag(dockerfile)
    if _docker("image", "inspect", tag).returncode == 0:
        return tag
    # The Dockerfile copies nothing from the context, so it is sent on stdin and no build context is uploaded.
    try:
        build = _docker("build", "--tag", tag, "-", input_bytes=dockerfile.read_bytes(), timeout=IMAGE_BUILD_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise BootEnvironmentError(
            f"building the QEMU image {tag} did not finish within {IMAGE_BUILD_TIMEOUT_S} s"
        ) from None
    if build.returncode != 0:
        tail = (build.stdout + build.stderr).decode("utf-8", errors="replace")[-1500:]
        raise BootEnvironmentError(f"building the QEMU image {tag} failed: {tail}")
    return tag


def docker_run_command(name: str, iso: Path, tag: str, config: BootConfig) -> list[str]:
    """`docker run` for one boot: no network, no capabilities, read-only root, ISO and harness mounted read-only."""
    for path in (iso, HARNESS_DIR):
        if "," in str(path):
            raise ConfigError(f"a comma in {path} breaks the docker --mount syntax; move or rename it")
    return [
        "docker", "run", "--rm", "--name", name,
        "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512",
        "--tmpfs", "/work:rw,size=512m,mode=1777",  # the extracted kernel and initrd
        "--mount", f"type=bind,source={iso},target={IN_CONTAINER_ISO},readonly",
        "--mount", f"type=bind,source={HARNESS_DIR},target={IN_CONTAINER_HARNESS},readonly",
        tag,
        "python3", f"{IN_CONTAINER_HARNESS}/container_boot.py", IN_CONTAINER_ISO,
        "--memory-mib", str(config.memory_mib), "--cpus", str(config.cpus),
    ]  # fmt: skip


def kill_container(name: str) -> None:
    """Remove the container this run started (`name` is unique to the run); no other container is touched."""
    _docker("rm", "--force", name, timeout=120)


def _has_result_line(line: str) -> bool:
    return any(result.name == RESULT_NAME for result in parse_selfcheck(line))


def printable_console_text(text: str) -> str:
    """`text` with every control and format character made visible, safe to show in a terminal or to save.

    The console stream comes from an ISO that is treated as untrusted. Written raw, its escape sequences could set
    the terminal's clipboard or title (OSC), make the terminal type reply bytes into the developer's shell (cursor
    position queries) or overdraw earlier lines. Newlines and tabs stay, and the carriage return of the serial
    console's CRLF line ending is dropped; everything else becomes <ESC> or <U+XXXX>.
    """
    return "".join(_visible(char) for char in text.replace("\r\n", "\n"))


def _visible(char: str) -> str:
    if char in "\n\t" or unicodedata.category(char) not in {"Cc", "Cf"}:
        return char
    return "<ESC>" if char == "\x1b" else f"<U+{ord(char):04X}>"


def boot_iso(iso: Path, config: BootConfig, *, tag: str, echo: Callable[[str], None] | None = None) -> BootOutcome:
    """Boot `iso` and return the serial console output.

    Ends when the container exits (the guest powered off), when the guest has printed its final RESULT line (after a
    short grace period for it to power off), or when config.timeout_s elapses, whichever comes first. The container
    is always removed, also on an exception or Ctrl-C. A failing `echo` stops the echoing only; the output is still
    collected in full. Raises BootEnvironmentError when the container itself failed before any verdict (docker could
    not start it, the ISO could not be read, the emulator crashed).
    """
    name = f"{CONTAINER_PREFIX}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    lines: list[str] = []
    echo_failures: list[str] = []
    result_seen = threading.Event()
    process = subprocess.Popen(  # noqa: S603
        docker_run_command(name, iso, tag, config),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    def pump() -> None:
        assert process.stdout is not None
        show = echo
        for raw in process.stdout:
            line = raw.decode("utf-8", errors="replace")
            lines.append(line)
            if show is not None:
                try:
                    show(line)
                except Exception as error:  # display is best effort; the verdict must not depend on it
                    show = None
                    echo_failures.append(f"{type(error).__name__}: {error}")
            if _has_result_line(line):
                result_seen.set()

    reader = threading.Thread(target=pump, name="serial-reader", daemon=True)
    reader.start()
    timed_out = False
    ended_by_itself = False
    try:
        deadline = time.monotonic() + config.timeout_s
        while reader.is_alive():
            if time.monotonic() >= deadline:
                timed_out = True
                break
            if result_seen.is_set():
                reader.join(POWEROFF_GRACE_S)
                break
            reader.join(0.5)
        ended_by_itself = not reader.is_alive() and not timed_out
    finally:
        kill_container(name)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        reader.join(timeout=10)
    # The container's exit status is QEMU's own: 0 after the guest powered off. A container that ended any other way
    # (docker failed to start it, the boot script gave up) closed the output stream too, but that is not a power-off.
    output = "".join(lines)
    if ended_by_itself and process.returncode != 0 and not result_seen.is_set():
        raise BootEnvironmentError(
            f"the boot container exited with status {process.returncode} before the guest printed a verdict; "
            "docker, the ISO or the emulator failed, which says nothing about the self-check. Last output:\n"
            + printable_console_text(output[-1500:])
        )
    powered_off = ended_by_itself and process.returncode == 0
    return BootOutcome(output=output, timed_out=timed_out, powered_off=powered_off, echo_error="; ".join(echo_failures))


def boot_problems(outcome: BootOutcome) -> list[str]:
    """Why this boot does not count as a clean self-check; empty when it does."""
    problems = selfcheck_problems(parse_selfcheck(outcome.output))
    if outcome.timed_out:
        problems.insert(0, "the boot timed out before the self-check finished (see PAI_BOOT_TIMEOUT)")
    return problems


def save_serial_log(outcome: BootOutcome) -> Path:
    """Write the console output to SERIAL_LOG (replacing the previous boot's) and return its path.

    Control characters are written as visible markers (see printable_console_text), so opening or `cat`-ing the log
    cannot run the guest's escape sequences in a terminal.
    """
    SERIAL_LOG.write_text(printable_console_text(outcome.output), encoding="utf-8", newline="\n")
    return SERIAL_LOG


def _console_echo(line: str) -> None:
    """Show one console line on stdout, sanitised and encodable whatever the terminal's encoding (cp1252, ...)."""
    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.write(printable_console_text(line).encode(encoding, errors="replace").decode(encoding))
    sys.stdout.flush()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Boot the Private AI OS ISO under QEMU (TCG) and check the self-check."
    )
    parser.add_argument("--iso", type=Path, help=f"ISO to boot (default: ${ENV_ISO}, else the newest dist/*.iso)")
    args = parser.parse_args(argv)

    env = dict(os.environ)
    if args.iso is not None:
        env[ENV_ISO] = str(args.iso)
    try:
        config = BootConfig.from_env(env)
        iso = locate_iso(env=env)
        if reason := docker_unavailable_reason():
            print(f"cannot boot: {reason}", file=sys.stderr)
            return 2
        print(f"booting {iso} (timeout {config.timeout_s:.0f} s)", file=sys.stderr)
        outcome = boot_iso(iso, config, tag=ensure_image(), echo=_console_echo)
    except (ConfigError, IsoNotFoundError, BootEnvironmentError) as error:
        print(f"cannot boot: {error}", file=sys.stderr)
        return 2

    if outcome.echo_error:
        print(f"console echo stopped ({outcome.echo_error}); the verdict below is unaffected", file=sys.stderr)
    problems = boot_problems(outcome)
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    print(f"console log: {save_serial_log(outcome)}", file=sys.stderr)
    print("self-check PASSED" if not problems else "self-check did NOT pass", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
