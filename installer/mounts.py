"""Parsing of the kernel's mount and swap tables (``/proc/self/mountinfo``, ``/proc/swaps``)."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from installer.errors import SafetyError

_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")


def unescape(field: str) -> str:
    """Undo the kernel's octal escaping (a space is written as a backslash and 040) in path fields."""
    return _OCTAL_ESCAPE.sub(lambda match: chr(int(match[1], 8)), field)


@dataclass(frozen=True)
class Mount:
    devt: str  # "major:minor" of the backing device ("0:NN" for filesystems without a block device)
    mountpoint: str
    fstype: str
    source: str


def parse_mountinfo(text: str) -> list[Mount]:
    """Parse ``mountinfo``. A line that cannot be parsed raises: a mount that is not seen could be a mounted target."""
    mounts: list[Mount] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(" ")
        try:
            separator = fields.index("-", 6)
            mounts.append(
                Mount(
                    devt=fields[2],
                    mountpoint=unescape(fields[4]),
                    fstype=fields[separator + 1],
                    source=unescape(fields[separator + 2]),
                )
            )
        except (ValueError, IndexError):
            raise SafetyError("mount-table-unreadable", "cannot parse the kernel mount table") from None
    return mounts


def parse_swaps(text: str) -> list[str]:
    """The swap areas listed in ``/proc/swaps`` (paths of block devices or files)."""
    lines = text.splitlines()[1:]  # the first line is the header
    return [unescape(line.split()[0]) for line in lines if line.strip()]


def mounts_at_or_below(mounts: list[Mount], path: str) -> list[Mount]:
    """The mounts whose mount point is ``path`` or lies under it."""
    root = posixpath.normpath(path)
    prefix = root.rstrip("/") + "/"
    return [
        mount for mount in mounts if posixpath.normpath(mount.mountpoint) == root or mount.mountpoint.startswith(prefix)
    ]
