"""The command line: ``python3 -m installer --plan plan.json``.

Root only. Progress goes to stdout as JSON lines (``installer.events``), the log to stderr. With
``"passphrase_source": "stdin"`` the passphrase is the whole of standard input minus one trailing newline; with
``"plan"`` it is read from the plan file (unattended use: the file then holds a secret). Exit status 0 means every step
finished and the result was verified; see ``installer.errors`` for the others.
"""

from __future__ import annotations

import argparse
import os
import secrets
import signal
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

from installer.engine import Engine
from installer.errors import EXIT_FAILURE, EXIT_OK, InstallerError, NotRootError, PlanError
from installer.events import EventSink
from installer.host import Host, LinuxHost
from installer.log import configure_logging, redact, register_secret
from installer.plan import MAX_PASSPHRASE_LENGTH, MAX_PLAN_BYTES, Plan, load_plan_text
from installer.runner import Runner, SubprocessRunner

# One character more than the longest accepted passphrase: enough to see that it is too long, never unbounded.
_STDIN_LIMIT = MAX_PASSPHRASE_LENGTH + 2


def _read_plan_file(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_PLAN_BYTES + 1)
    except OSError as exc:
        raise PlanError(f"cannot read the plan file: {exc.strerror or 'unreadable'}") from None
    if len(data) > MAX_PLAN_BYTES:
        raise PlanError(f"the plan file is larger than {MAX_PLAN_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise PlanError("the plan file is not UTF-8 text") from None


def _read_passphrase(stream: TextIO) -> str:
    text = stream.read(_STDIN_LIMIT)
    if text.endswith("\r\n"):
        return text[:-2]
    return text[:-1] if text.endswith("\n") else text


def _interrupt(signum: int, _frame: object) -> None:
    raise KeyboardInterrupt(f"signal {signum}")


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner | None = None,
    host: Host | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    geteuid: Callable[[], int] | None = None,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> int:
    """Run the installer. The keyword arguments are for tests: a fake runner and host, and a fake system."""
    parser = argparse.ArgumentParser(prog="python3 -m installer", description="Install the live system to a disk.")
    parser.add_argument("--plan", required=True, help="path of the plan JSON file (see docs/development/INSTALLER.md)")
    arguments = parser.parse_args(argv)

    events = EventSink(sys.stdout if stdout is None else stdout)
    configure_logging(stderr)
    try:
        plan = _load(arguments.plan, sys.stdin if stdin is None else stdin, geteuid or _effective_uid)
        if plan.passphrase is not None:
            register_secret(plan.passphrase.reveal())
        engine = Engine(
            plan,
            runner or SubprocessRunner(),
            host or LinuxHost(),
            events,
            random_bytes=random_bytes,
        )
    except InstallerError as exc:
        events.result(False, redact(str(exc)))
        return exc.exit_code

    previous = {sig: signal.signal(sig, _interrupt) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        return EXIT_OK if engine.run() else EXIT_FAILURE
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _effective_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else -1  # no root concept (a development machine): refused below


def _load(plan_path: str, stdin: TextIO, geteuid: Callable[[], int]) -> Plan:
    if geteuid() != 0:
        raise NotRootError("the installer must run as root")
    plan = load_plan_text(_read_plan_file(plan_path))
    if plan.passphrase_source == "stdin":  # noqa: S105 - a source name, not a password
        plan = plan.with_passphrase(_read_passphrase(stdin))
    return plan
