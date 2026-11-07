"""Exit codes of ``python -m backend``.

Kept apart from the entrypoint, which imports the web stack, so a policy test (the systemd unit's
``RestartPreventExitStatus=``) can read them without it. Values follow sysexits.h where one fits.
"""

from __future__ import annotations

EXIT_STARTUP_FAILED = 3  # the same value uvicorn itself uses: the application or the listening socket failed
EXIT_REFUSED_ROOT = 77  # refused to run as root; no override exists
EXIT_CONFIG = 78  # invalid configuration
