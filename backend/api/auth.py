"""The per-start bearer token (generation, constant-time verification), who a request was authenticated as, and the
atomic publication of the files the service shares with the kiosk (the token and the endpoint)."""

from __future__ import annotations

import os
import secrets
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from starlette.types import Scope

TOKEN_BYTES = 32  # 256 bits of entropy
# Owner reads and writes; the group (which contains the kiosk user) reads; nobody else has any access. Every file the
# service publishes for the kiosk (the token and the endpoint) gets this mode.
TOKEN_FILE_MODE = 0o640
# Mode of the directory holding those files when the service creates it; the unit's RuntimeDirectoryMode= must equal it.
TOKEN_DIRECTORY_MODE = 0o750
# Where the guard leaves the result of authenticating a request, for the routes that need to know it.
CALLER_STATE_KEY = "pai_caller"


def issue_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def publish_file(path: Path, content: str) -> None:
    """Atomically replace ``path`` with ``content`` (the token, or the endpoint URL), without a trailing newline.

    The content is written to a private temporary file in the same directory, given its final mode while still
    empty, then renamed over ``path``. Readers therefore never see a partial or too-permissive file, and a
    symlink at ``path`` is replaced rather than followed. The mode is set explicitly because the service umask
    (0077) would otherwise strip the group read bit.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=TOKEN_DIRECTORY_MODE)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            if os.name == "posix":  # Windows development hosts have no POSIX modes to set
                os.fchmod(handle.fileno(), TOKEN_FILE_MODE)
            handle.write(content)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


class TokenAuthenticator:
    """Checks presented credentials against the token installed at startup.

    Until a token is installed every check fails, so a request that arrives early is refused, never allowed.
    """

    def __init__(self) -> None:
        self._expected: bytes | None = None

    def install(self, token: str) -> None:
        self._expected = token.encode("ascii")

    def verify(self, presented: bytes) -> bool:
        expected = self._expected
        return expected is not None and secrets.compare_digest(presented, expected)


class Credential(Enum):
    """What a request presented that the guard accepted."""

    BEARER = "bearer"  # the per-start token: tools (the launcher, the self-check, a developer with curl)
    SESSION = "session"  # a browser session cookie


@dataclass(frozen=True, slots=True)
class Caller:
    """Who the guard authenticated. ``session_key`` identifies the session (its hash, never its id) for ``SESSION``."""

    credential: Credential
    session_key: bytes | None = None


def caller_from_scope(scope: Scope) -> Caller | None:
    """The result of the guard for this request, or None when no guard ran (a route must then refuse: fail closed)."""
    caller = scope.get("state", {}).get(CALLER_STATE_KEY)
    return caller if isinstance(caller, Caller) else None
