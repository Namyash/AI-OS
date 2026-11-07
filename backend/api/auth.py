"""The per-start bearer token: generation, atomic publication to a file, and constant-time verification."""

from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

TOKEN_BYTES = 32  # 256 bits of entropy
# Owner reads and writes; the group (which contains the kiosk user) reads; nobody else has any access.
TOKEN_FILE_MODE = 0o640
# Mode of the directory holding the token when the service creates it; the unit's RuntimeDirectoryMode= must equal it.
TOKEN_DIRECTORY_MODE = 0o750


def issue_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def write_token_file(path: Path, token: str) -> None:
    """Atomically replace ``path`` with ``token``.

    The token is written to a private temporary file in the same directory, given its final mode while still
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
            handle.write(token)
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
