"""Immutable launcher settings, loaded from environment variables.

This module is the only place defaults live. ``PAI_ENDPOINT_FILE`` and ``PAI_TOKEN_FILE`` are the backend's own
variables with the backend's own defaults (``backend/core/config.py``; a test keeps them equal), because the launcher
reads what the backend publishes. Everything that is only the kiosk's is ``PAI_KIOSK_*``. Other ``PAI_*`` variables
are ignored (the ISO build inputs share the prefix).

The defaults for the state and runtime paths match ``StateDirectory=pai-ui`` and ``RuntimeDirectory=pai-ui`` of
``pai-kiosk.service``; a test keeps them in step. Defaults are validated like explicit values: on a host where a
default is not an absolute path (a Windows development machine) leaving the variable unset is an error naming it.
"""

from __future__ import annotations

import math
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from kiosk.errors import ConfigError

DEFAULT_ENDPOINT_FILE = Path("/run/pai/endpoint")
DEFAULT_TOKEN_FILE = Path("/run/pai/token")
DEFAULT_READY_FILE = Path("/run/pai-ui/ready")
DEFAULT_PROFILE_DIR = Path("/var/lib/pai-ui/profile")
DEFAULT_CHROMIUM = "chromium"

# Seconds. The launcher never waits without a bound, and each phase has its own: the backend publishing its files,
# one HTTP request, one DevTools command, the page appearing, and the pause between two looks at a running page. The
# browser and render bounds are generous because a virtual machine under software CPU emulation starts Chromium many
# times slower than hardware does; a healthy start on real or hardware-assisted virtual CPUs takes a few seconds.
DEFAULT_HANDOFF_TIMEOUT = 60.0
DEFAULT_REQUEST_TIMEOUT = 10.0
DEFAULT_BROWSER_TIMEOUT = 60.0
DEFAULT_RENDER_TIMEOUT = 120.0
DEFAULT_STATUS_INTERVAL = 5.0
MAX_TIMEOUT = 3600.0


@dataclass(frozen=True)
class Settings:
    endpoint_file: Path
    token_file: Path
    ready_file: Path
    profile_dir: Path
    chromium: str
    chromium_flags: tuple[str, ...]
    handoff_timeout: float
    request_timeout: float
    browser_timeout: float
    render_timeout: float
    status_interval: float


def _path(environ: Mapping[str, str], variable: str, default: Path, problems: list[str]) -> Path:
    path = Path(environ.get(variable, default))
    if not path.is_absolute():
        problems.append(f"{variable}: must be an absolute path on this platform")
    return path


def _seconds(environ: Mapping[str, str], variable: str, default: float, problems: list[str]) -> float:
    raw = environ.get(variable)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        problems.append(f"{variable}: must be a number of seconds")
        return default
    if not math.isfinite(value) or not 0 < value <= MAX_TIMEOUT:
        problems.append(f"{variable}: must be greater than 0 and at most {MAX_TIMEOUT:g} seconds")
        return default
    return value


def _flags(environ: Mapping[str, str], variable: str, problems: list[str]) -> tuple[str, ...]:
    try:
        return tuple(shlex.split(environ.get(variable, "")))
    except ValueError:
        problems.append(f"{variable}: unbalanced quotes")
        return ()


def load_settings(environ: Mapping[str, str]) -> Settings:
    """Build settings from ``environ``; raise ``ConfigError`` naming every invalid variable."""
    problems: list[str] = []
    chromium = environ.get("PAI_KIOSK_CHROMIUM", DEFAULT_CHROMIUM)
    if not chromium.strip():
        problems.append("PAI_KIOSK_CHROMIUM: must name the browser executable")
    settings = Settings(
        endpoint_file=_path(environ, "PAI_ENDPOINT_FILE", DEFAULT_ENDPOINT_FILE, problems),
        token_file=_path(environ, "PAI_TOKEN_FILE", DEFAULT_TOKEN_FILE, problems),
        ready_file=_path(environ, "PAI_KIOSK_READY_FILE", DEFAULT_READY_FILE, problems),
        profile_dir=_path(environ, "PAI_KIOSK_PROFILE_DIR", DEFAULT_PROFILE_DIR, problems),
        chromium=chromium,
        chromium_flags=_flags(environ, "PAI_KIOSK_CHROMIUM_FLAGS", problems),
        handoff_timeout=_seconds(environ, "PAI_KIOSK_HANDOFF_TIMEOUT", DEFAULT_HANDOFF_TIMEOUT, problems),
        request_timeout=_seconds(environ, "PAI_KIOSK_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT, problems),
        browser_timeout=_seconds(environ, "PAI_KIOSK_BROWSER_TIMEOUT", DEFAULT_BROWSER_TIMEOUT, problems),
        render_timeout=_seconds(environ, "PAI_KIOSK_RENDER_TIMEOUT", DEFAULT_RENDER_TIMEOUT, problems),
        status_interval=_seconds(environ, "PAI_KIOSK_STATUS_INTERVAL", DEFAULT_STATUS_INTERVAL, problems),
    )
    if problems:
        raise ConfigError("Invalid configuration: " + "; ".join(problems))
    return settings
