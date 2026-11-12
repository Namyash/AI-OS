"""Failures of the installer and the process exit status each one ends it with.

Messages must never contain the passphrase or the recovery key: they reach stdout (the result event) and the journal.
Every message is built from field names, device names and command names, never from a secret's value.
"""

from __future__ import annotations

from collections.abc import Sequence

EXIT_OK = 0
EXIT_FAILURE = 1  # a step failed, a safety rule refused the target, or verification failed
EXIT_NOPERM = 77  # not run as root (sysexits.h EX_NOPERM)
EXIT_CONFIG = 78  # the plan is invalid (sysexits.h EX_CONFIG, the value the backend and the kiosk use too)


class InstallerError(Exception):
    """A failure the installer can describe in one line. ``exit_code`` is the status it ends the process with."""

    exit_code = EXIT_FAILURE


class PlanError(InstallerError):
    exit_code = EXIT_CONFIG


class NotRootError(InstallerError):
    exit_code = EXIT_NOPERM


class SafetyError(InstallerError):
    """A safety rule refused the target. ``reason`` is a stable identifier tests and the wizard can match on."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class VerificationError(InstallerError):
    """A result was checked after a step and does not match the design."""


class CommandError(InstallerError):
    """A command exited non-zero or could not run. ``argv`` never holds a secret: secrets travel on stdin only."""

    def __init__(self, message: str, argv: Sequence[str], returncode: int | None = None) -> None:
        super().__init__(message)
        self.argv = tuple(argv)
        self.returncode = returncode


class CommandTimeout(CommandError):
    pass
