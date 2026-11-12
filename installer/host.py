"""The installer's view of the machine it runs on: device nodes, sysfs, procfs and a few files.

Everything the engine reads from the live system goes through ``Host``, so tests can describe a machine (disks,
mounts, swaps, mappings) without root or Linux. ``LinuxHost`` is the real one. Changing the system is not done here:
that is what commands are for.
"""

from __future__ import annotations

import contextlib
import os
import stat
import time
from typing import Protocol


class Host(Protocol):
    def realpath(self, path: str) -> str: ...

    def exists(self, path: str) -> bool: ...

    def is_block_device(self, path: str) -> bool: ...

    def devt(self, path: str) -> str | None:
        """``"major:minor"`` of a block device node, ``None`` for anything else."""
        ...

    def read_text(self, path: str) -> str:
        """Raises ``OSError`` when the file cannot be read."""
        ...

    def listdir(self, path: str) -> list[str]:
        """Raises ``OSError`` when the directory cannot be read."""
        ...

    def write_secret_file(self, path: str, content: str) -> None:
        """Create ``path`` (and missing parents, mode 0700) with mode 0600, failing if it already exists."""
        ...

    def remove_file(self, path: str) -> None:
        """Remove ``path``; no error when it is already gone."""
        ...

    def sleep(self, seconds: float) -> None: ...

    def monotonic(self) -> float: ...


class LinuxHost:
    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def is_block_device(self, path: str) -> bool:
        try:
            return stat.S_ISBLK(os.stat(path).st_mode)
        except OSError:
            return False

    def devt(self, path: str) -> str | None:
        try:
            status = os.stat(path)
        except OSError:
            return None
        if not stat.S_ISBLK(status.st_mode):
            return None
        return f"{os.major(status.st_rdev)}:{os.minor(status.st_rdev)}"

    def read_text(self, path: str) -> str:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()

    def listdir(self, path: str) -> list[str]:
        return sorted(os.listdir(path))

    def write_secret_file(self, path: str, content: str) -> None:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        # O_EXCL: never follow a planted symlink and never overwrite; 0600 is applied at creation, not afterwards.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            self.remove_file(path)
            raise

    def remove_file(self, path: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def monotonic(self) -> float:
        return time.monotonic()
