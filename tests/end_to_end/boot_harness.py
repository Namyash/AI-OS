"""Host side of the boot test: runs the built ISO under QEMU inside a container and collects the serial console.

There is no hypervisor on the development machine, so the guest runs under QEMU's software emulation (TCG) inside a
Docker container (docs/development/BOOT_TESTING.md). The container has no network, no capabilities and a read-only
root; the ISO is mounted read-only. Whatever happens, the container this module started is removed before it returns.

Run it directly for a boot with live output:  python -m tests.end_to_end.boot_harness [--iso PATH]
Exit status: 0 the self-check passed, 1 it did not, 2 the boot could not be performed (an environment problem).
"""

from __future__ import annotations

import argparse
import codecs
import contextlib
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
from typing import Protocol

from tests.end_to_end.container_boot import validate_extra_kernel_args
from tests.end_to_end.selfcheck_output import RESULT_NAME, parse_selfcheck, selfcheck_problems

HARNESS_DIR = Path(__file__).resolve().parent
REPO_ROOT = HARNESS_DIR.parents[1]
DOCKERFILE = HARNESS_DIR / "Dockerfile"

ENV_ISO = "PAI_ISO"
ENV_TIMEOUT = "PAI_BOOT_TIMEOUT"
ENV_MEMORY = "PAI_QEMU_MEMORY"
ENV_CPUS = "PAI_QEMU_CPUS"
ENV_EXTRA_ARGS = "PAI_BOOT_EXTRA_ARGS"
DEFAULT_TIMEOUT_S = 1800  # software emulation is slow; a normal boot is minutes, a loaded machine needs headroom
# The image runs a kiosk, Chromium under software emulation (cage, a Wayland compositor with the pixman renderer, and a
# browser with several processes), next to the backend and the system: 2048 MiB left it too little to render the page.
DEFAULT_MEMORY_MIB = 3072
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
    extra_kernel_args: str = ""  # words appended to the guest's kernel command line (PAI_BOOT_EXTRA_ARGS)

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> BootConfig:
        try:
            extra = validate_extra_kernel_args(env.get(ENV_EXTRA_ARGS, ""))
        except ValueError as error:
            raise ConfigError(f"{ENV_EXTRA_ARGS} {error}") from None
        return cls(
            timeout_s=_positive_number(env, ENV_TIMEOUT, DEFAULT_TIMEOUT_S),
            memory_mib=int(_positive_number(env, ENV_MEMORY, DEFAULT_MEMORY_MIB, whole=True)),
            cpus=int(_positive_number(env, ENV_CPUS, DEFAULT_CPUS, whole=True)),
            extra_kernel_args=extra,
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


def hardened_run_prefix(name: str, *, interactive: bool = False) -> list[str]:
    """The start of every `docker run` of the tests: no network, no capabilities, a read-only root, a scratch /work.

    `interactive` keeps the container's standard input open (docker run -i), which is how a test types on the guest's
    serial console (QEMU's standard input).
    """
    return [
        "docker", "run", "--rm", *(["-i"] if interactive else []), "--name", name,
        "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512",
        "--tmpfs", "/work:rw,size=512m,mode=1777",  # the extracted kernel and initrd
    ]  # fmt: skip


def bind_mount_option(source: Path, target: str) -> list[str]:
    """`--mount` for a read-only bind mount; a comma in the path would end the option early, so it is refused."""
    if "," in str(source):
        raise ConfigError(f"a comma in {source} breaks the docker --mount syntax; move or rename it")
    return ["--mount", f"type=bind,source={source},target={target},readonly"]


def docker_run_command(name: str, iso: Path, tag: str, config: BootConfig) -> list[str]:
    """`docker run` for one boot: no network, no capabilities, read-only root, ISO and harness mounted read-only."""
    return [
        *hardened_run_prefix(name),
        *bind_mount_option(iso, IN_CONTAINER_ISO),
        *bind_mount_option(HARNESS_DIR, IN_CONTAINER_HARNESS),
        tag,
        "python3", f"{IN_CONTAINER_HARNESS}/container_boot.py", IN_CONTAINER_ISO,
        "--memory-mib", str(config.memory_mib), "--cpus", str(config.cpus),
        # One argument, in the --name=value form: a value that starts with "-" is not read as an option.
        *([f"--extra-kernel-args={config.extra_kernel_args}"] if config.extra_kernel_args else []),
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


class ConsoleHandler(Protocol):
    """Reacts to a container's console while it is read. Both methods return True when the run has reached its goal and
    should end (after the grace period). `send` types text on the console (the container's standard input)."""

    def feed(self, chunk: str, send: Callable[[str], None]) -> bool: ...

    def poll(self, send: Callable[[str], None]) -> bool: ...


@dataclass(frozen=True)
class StreamOutcome:
    output: str  # everything the container printed, in order, as the `scrub` function left it
    timed_out: bool  # the overall timeout ended the run
    ended_by_itself: bool  # the container ended on its own (the guest powered off, or docker or the script failed)
    stopped_by_handler: bool  # the handler said the goal was reached
    returncode: int | None  # the container's exit status (QEMU's own after a power-off: 0)
    echo_error: str = ""  # why live echoing stopped, if it did; collecting the output went on regardless


POLL_INTERVAL_S = 0.5
READ_SIZE = 4096


class LineWatcher:
    """The handler of a plain boot: ends the run when a complete console line satisfies `predicate`."""

    def __init__(self, predicate: Callable[[str], bool]) -> None:
        self._predicate = predicate
        self._pending = ""

    def feed(self, chunk: str, send: Callable[[str], None]) -> bool:
        self._pending += chunk
        *complete, self._pending = self._pending.split("\n")
        return any(self._predicate(line) for line in complete)

    def poll(self, send: Callable[[str], None]) -> bool:
        return False


def stream_container(
    argv: Sequence[str],
    name: str,
    timeout_s: float,
    *,
    echo: Callable[[str], None] | None = None,
    handler: ConsoleHandler | None = None,
    scrub: Callable[[str], str] | None = None,
    interactive: bool = False,
    grace_s: float | None = None,
) -> StreamOutcome:
    """Run `argv` (a `docker run` of the container called `name`) and read its console until it ends, the handler's goal
    is reached (then `grace_s`, default POWEROFF_GRACE_S, more for the guest to power off) or `timeout_s` elapses.

    The console is read in raw chunks, so a prompt that has no newline is seen at once; `handler` gets every chunk,
    and what it types goes to the container's standard input when `interactive`. `scrub` is applied to each complete
    line before it is echoed or kept (the console is the one place a secret could leak to). The container is always
    removed, also on an exception or Ctrl-C. A failing `echo` stops the echoing only; the output is still collected.
    """
    lines: list[str] = []
    echo_failures: list[str] = []
    goal = threading.Event()
    process = subprocess.Popen(  # noqa: S603
        list(argv),
        stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    typing_lock = threading.Lock()

    def send(text: str) -> None:
        if process.stdin is None:
            return
        with typing_lock:
            try:
                process.stdin.write(text.encode("utf-8"))
                process.stdin.flush()
            except OSError:  # the container is gone; the run is ending anyway
                pass

    def keep(line: str) -> None:
        nonlocal echo
        clean = scrub(line) if scrub is not None else line
        lines.append(clean)
        if echo is not None:
            try:
                echo(clean)
            except Exception as error:  # display is best effort; the verdict must not depend on it
                echo = None
                echo_failures.append(f"{type(error).__name__}: {error}")

    reader_errors: list[BaseException] = []

    def pump() -> None:
        assert process.stdout is not None
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        pending = ""
        try:
            while chunk := process.stdout.read1(READ_SIZE):  # type: ignore[attr-defined]
                text = decoder.decode(chunk)
                if handler is not None and handler.feed(text, send):
                    goal.set()
                pending += text
                while (newline := pending.find("\n")) != -1:
                    keep(pending[: newline + 1])
                    pending = pending[newline + 1 :]
            if tail := pending + decoder.decode(b"", final=True):
                keep(tail)
        except BaseException as error:  # a bug in a handler must fail the run, not end it quietly as "the guest exited"
            reader_errors.append(error)

    reader = threading.Thread(target=pump, name="console-reader", daemon=True)
    reader.start()
    timed_out = False
    try:
        deadline = time.monotonic() + timeout_s
        while reader.is_alive():
            if time.monotonic() >= deadline:
                timed_out = True
                break
            if handler is not None and handler.poll(send):
                goal.set()
            if goal.is_set():
                reader.join(POWEROFF_GRACE_S if grace_s is None else grace_s)
                break
            reader.join(POLL_INTERVAL_S)
        ended_by_itself = not reader.is_alive() and not timed_out
    finally:
        kill_container(name)
        if process.stdin is not None:
            with typing_lock, contextlib.suppress(OSError):
                process.stdin.close()  # so that a docker client still waiting on its input can end
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        reader.join(timeout=10)
    if reader_errors:
        raise reader_errors[0]
    return StreamOutcome(
        output="".join(lines),
        timed_out=timed_out,
        ended_by_itself=ended_by_itself,
        stopped_by_handler=goal.is_set(),
        returncode=process.returncode,
        echo_error="; ".join(echo_failures),
    )


def require_a_real_run(outcome: StreamOutcome, what: str) -> None:
    """Raise BootEnvironmentError when the container ended with a failing status before the goal was reached.

    The status of a container whose guest powered off is QEMU's own, 0. Anything else (docker could not start it, the
    ISO or the disk could not be read, the emulator crashed) says nothing about the image under test.
    """
    if outcome.ended_by_itself and outcome.returncode != 0 and not outcome.stopped_by_handler:
        raise BootEnvironmentError(
            f"the {what} container exited with status {outcome.returncode} before the guest printed a verdict; "
            "docker, the ISO or the emulator failed, which says nothing about the image. Last output:\n"
            + printable_console_text(outcome.output[-1500:])
        )


def boot_iso(iso: Path, config: BootConfig, *, tag: str, echo: Callable[[str], None] | None = None) -> BootOutcome:
    """Boot `iso` and return the serial console output.

    Ends when the container exits (the guest powered off), when the guest has printed its final RESULT line (after a
    short grace period for it to power off), or when config.timeout_s elapses, whichever comes first. The container
    is always removed, also on an exception or Ctrl-C. A failing `echo` stops the echoing only; the output is still
    collected in full. Raises BootEnvironmentError when the container itself failed before any verdict (docker could
    not start it, the ISO could not be read, the emulator crashed).
    """
    name = f"{CONTAINER_PREFIX}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    outcome = stream_container(
        docker_run_command(name, iso, tag, config),
        name,
        config.timeout_s,
        echo=echo,
        handler=LineWatcher(_has_result_line),
    )
    require_a_real_run(outcome, "boot")
    return BootOutcome(
        output=outcome.output,
        timed_out=outcome.timed_out,
        powered_off=outcome.ended_by_itself and outcome.returncode == 0,
        echo_error=outcome.echo_error,
    )


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
