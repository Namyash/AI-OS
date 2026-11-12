"""Failures of the launcher and the process exit status each one ends it with.

The service manager acts on the status: ``pai-kiosk.service`` restarts the launcher after a failure but not after
``EXIT_CONFIG`` (its ``RestartPreventExitStatus=``), because restarting cannot fix a wrong configuration. The value is
the one ``python -m backend`` uses for the same condition (sysexits.h ``EX_CONFIG``).

Messages must never contain the bearer token or a session id: they reach the journal.
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_FAILURE = 1  # the backend or the browser misbehaved, or a timeout elapsed: a restart may fix it
EXIT_CONFIG = 78  # invalid configuration, or the browser executable is missing: a restart cannot fix it


class KioskError(Exception):
    """A failure the launcher can describe in one line. ``exit_code`` is the status it ends the process with."""

    exit_code = EXIT_FAILURE


class ConfigError(KioskError):
    exit_code = EXIT_CONFIG
