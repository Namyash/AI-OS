"""The one way the installer runs a program.

``Runner`` is the seam tests replace: ``run`` takes an argument *list* (never a shell string), a timeout, and optional
bytes for standard input. ``SubprocessRunner`` is the real one; its environment is built from scratch, so nothing the
installer was started with (and no secret) is inherited. ``Commander`` wraps a runner with the rules every step
shares: argument validation, logging, redaction of whatever is logged or raised, and failing on a non-zero status.

Secrets reach a program only as ``stdin``. They are never in ``argv`` (visible in ``ps``) or in the environment.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shlex
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from installer.errors import CommandError, CommandTimeout
from installer.log import LOGGER_NAME, redact
from installer.secret import Secret

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
BASE_ENVIRONMENT: Mapping[str, str] = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
# The only variables a step may add. A whitelist, so a secret cannot be passed through the environment by mistake.
ALLOWED_EXTRA_ENVIRONMENT = frozenset({"DEBIAN_FRONTEND"})
_ERROR_TAIL_CHARS = 800

log = logging.getLogger(f"{LOGGER_NAME}.runner")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class Runner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        stdin: bytes | None = None,
        extra_env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        """Run ``argv`` and return its result whatever the exit status. Raises ``CommandTimeout`` on timeout."""
        ...


def build_environment(extra_env: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = dict(BASE_ENVIRONMENT)
    for name, value in (extra_env or {}).items():
        if name not in ALLOWED_EXTRA_ENVIRONMENT:
            raise ValueError(f"environment variable {name!r} is not allowed")
        environment[name] = value
    return environment


class SubprocessRunner:
    """Runs real programs. No shell, an explicit environment, standard input only from the bytes given."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        stdin: bytes | None = None,
        extra_env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        try:
            process = subprocess.Popen(  # noqa: S603 - argv is a validated list and shell=False
                list(argv),
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=build_environment(extra_env),
                start_new_session=os.name == "posix",  # so a timeout can stop the whole process group
            )
        except FileNotFoundError:
            return CommandResult(127, "", f"{argv[0]}: command not found")
        try:
            out, err = process.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            self._kill(process)
            process.communicate()
            raise CommandTimeout(f"{argv[0]} timed out after {timeout:g} s", argv) from None
        return CommandResult(
            process.returncode, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace")
        )

    @staticmethod
    def _kill(process: subprocess.Popen[bytes]) -> None:
        if os.name == "posix":
            import signal

            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()


class Commander:
    """What the steps call: validates, logs and checks every command, on top of any ``Runner``."""

    def __init__(self, runner: Runner) -> None:
        self._runner = runner

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        stdin: Secret | bytes | None = None,
        check: bool = True,
        extra_env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        """Run ``argv``. With ``check`` a non-zero status raises ``CommandError``. The result is the raw output:
        callers parse it, and only what is logged or raised here is redacted."""
        if isinstance(argv, str) or not argv or not all(isinstance(part, str) and "\0" not in part for part in argv):
            raise TypeError("a command is a non-empty list of strings without NUL, never a shell string")
        if extra_env:
            build_environment(extra_env)  # fail early on a variable that is not allowed
        data = stdin.reveal_bytes() if isinstance(stdin, Secret) else stdin
        log.info("run: %s%s", shlex.join(argv), f" (stdin: {len(data)} bytes)" if data is not None else "")
        result = self._runner.run(list(argv), timeout=timeout, stdin=data, extra_env=extra_env)
        if check and result.returncode != 0:
            detail = redact((result.stderr.strip() or result.stdout.strip())[-_ERROR_TAIL_CHARS:])
            raise CommandError(
                f"{argv[0]} failed (exit {result.returncode}){': ' + detail if detail else ''}",
                argv,
                result.returncode,
            )
        return result
