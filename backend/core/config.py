"""Immutable service settings, loaded from ``PAI_*`` environment variables.

This module is the only place defaults live. Every field ``name`` is read from ``PAI_<NAME>``; other
``PAI_*`` variables (the ISO build inputs share the prefix) are ignored. The defaults for ``data_dir`` and
``token_file`` are the Linux deployment paths and match the ``StateDirectory=`` and ``RuntimeDirectory=`` of
``pai-backend.service``; a test in ``tests/security/test_systemd_units.py`` keeps them in step. ``endpoint_file``
lives in the same runtime directory as the token, and ``static_dir`` (the built UI) under the unit's
``WorkingDirectory=``, which the unit can read through ``ProtectSystem=strict``; ``backend/tests/core/test_config.py``
keeps those in step too.

Defaults are validated like explicit values. On a host where a default is not an absolute path (a Windows
development machine: ``/var/lib/pai`` is rooted but has no drive), leaving the variable unset is an error naming
it, never a directory created under the root of the current drive.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, ValidationInfo, field_validator

ENV_PREFIX = "PAI_"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MIN_PORT = 1024  # the service runs unprivileged and cannot bind lower
MAX_PORT = 65535
DEFAULT_DATA_DIR = Path("/var/lib/pai")
DEFAULT_TOKEN_FILE = Path("/run/pai/token")
# Where the backend publishes the URL it listens on, for the kiosk launcher; next to the token, in the same directory.
DEFAULT_ENDPOINT_FILE = Path("/run/pai/endpoint")
# The built UI (frontend/dist), installed read-only by the image; served behind the same guard as the API.
DEFAULT_STATIC_DIR = Path("/opt/pai/frontend")
# A browser session's absolute lifetime, in seconds, and the range an operator may set it to.
DEFAULT_SESSION_TTL = 12 * 60 * 60
MIN_SESSION_TTL = 60
MAX_SESSION_TTL = 7 * 24 * 60 * 60
# Mode of the data directory when the service creates it. Only the service account needs to list or enter it, so
# nothing is shared with a group. Under systemd, StateDirectoryMode= creates it; a test keeps the two equal.
DATA_DIR_MODE = 0o700
DATABASE_FILENAME = "pai.sqlite3"

LogLevel = Literal["debug", "info", "warning", "error", "critical"]


class ConfigError(ValueError):
    """The environment holds invalid settings. The message names each offending variable."""


def _is_loopback_literal(value: str) -> bool:
    """True only for a literal loopback IP: 127.0.0.0/8 or ::1.

    Host names are refused (they resolve at bind time, outside this check). IPv4-mapped and scoped IPv6
    forms are refused too, because ``ipaddress`` treats them differently across Python versions.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return address.is_loopback
    return address == ipaddress.IPv6Address("::1")


def host_literal(host: str) -> str:
    """``host`` as it is written in a URL or a Host header: an IPv6 literal in brackets, in its compressed form."""
    address = ipaddress.ip_address(host)
    return f"[{address.compressed}]" if address.version == 6 else str(address)


def _is_within(path: Path, directory: Path) -> bool:
    """True when ``path`` is ``directory`` or lies below it, with symbolic links that already exist resolved."""
    return path.resolve().is_relative_to(directory.resolve())


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", validate_default=True)

    host: str = DEFAULT_HOST
    port: int = Field(default=DEFAULT_PORT, ge=MIN_PORT, le=MAX_PORT)
    data_dir: Path = DEFAULT_DATA_DIR
    token_file: Path = DEFAULT_TOKEN_FILE
    # Declared after data_dir and token_file: the validators below compare against them.
    endpoint_file: Path = DEFAULT_ENDPOINT_FILE
    static_dir: Path = DEFAULT_STATIC_DIR
    session_ttl: int = Field(default=DEFAULT_SESSION_TTL, ge=MIN_SESSION_TTL, le=MAX_SESSION_TTL)
    log_level: LogLevel = "info"

    @property
    def database_path(self) -> Path:
        return self.data_dir / DATABASE_FILENAME

    @property
    def endpoint_url(self) -> str:
        """The origin a client reaches the service at: what ``endpoint_file`` holds."""
        return f"http://{host_literal(self.host)}:{self.port}"

    @field_validator("host")
    @classmethod
    def _require_loopback(cls, value: str) -> str:
        if not _is_loopback_literal(value):
            raise ValueError(f"must be a literal loopback IP address (127.0.0.0/8 or ::1), got {value!r}")
        return value

    @field_validator("data_dir", "token_file", "endpoint_file", "static_dir")
    @classmethod
    def _require_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("must be an absolute path on this platform")
        return value

    @field_validator("endpoint_file")
    @classmethod
    def _differ_from_token_file(cls, value: Path, info: ValidationInfo) -> Path:
        # Both are published by replacing the file at the path, so they would overwrite each other.
        if value == info.data.get("token_file"):
            raise ValueError("must not be the same file as PAI_TOKEN_FILE")
        return value

    @field_validator("static_dir")
    @classmethod
    def _keep_secrets_out_of_the_ui(cls, value: Path, info: ValidationInfo) -> Path:
        # Everything under static_dir is handed to the browser, whose page scripts must never see the token or the data.
        for name in ("token_file", "data_dir"):
            secret = info.data.get(name)
            if secret is not None and _is_within(secret, value):
                raise ValueError(
                    f"must not be, or contain, PAI_{name.upper()}: everything in it is served to the browser"
                )
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _lowercase_level(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value


def _describe(error: ValidationError) -> str:
    problems = []
    for item in error.errors():
        variable = f"{ENV_PREFIX}{str(item['loc'][0]).upper()}" if item["loc"] else "settings"
        problems.append(f"{variable}: {item['msg'].removeprefix('Value error, ')}")
    return "Invalid configuration: " + "; ".join(problems)


def load_settings(environ: Mapping[str, str]) -> Settings:
    """Build settings from ``environ``; raise ``ConfigError`` naming every invalid variable."""
    values = {
        name: environ[variable]
        for name in Settings.model_fields
        if (variable := f"{ENV_PREFIX}{name.upper()}") in environ
    }
    try:
        return Settings.model_validate(values)
    except ValidationError as exc:
        # `from None`: the raw validation error repeats the rejected input, which must not reach logs.
        raise ConfigError(_describe(exc)) from None
