"""State shared by the steps of one installation, and the stack that undoes what they acquired.

A step that acquires something (a mapping, a mount) registers how to release it *before* acquiring it, and the undo
only acts if the resource is really there. So a failure, a timeout or an interrupt at any point, even in the middle of
the acquiring command, still ends with everything released: rollback is the same stack the normal ending unwinds.
"""

from __future__ import annotations

import logging
import posixpath
from collections.abc import Callable
from dataclasses import dataclass, field

from installer.errors import InstallerError
from installer.host import Host
from installer.log import LOGGER_NAME, redact
from installer.plan import Plan
from installer.runner import Commander
from installer.secret import Secret
from installer.target import Target

log = logging.getLogger(f"{LOGGER_NAME}.context")

DEFAULT_WORK_DIR = "/run/pai-install"
MAPPING_NAME = "cryptroot"  # the name inside the installed system's crypttab too: grub-probe and initramfs agree on it


@dataclass(frozen=True)
class Partitions:
    """Device nodes of the four partitions of the layout."""

    bios_boot: str
    esp: str
    boot: str
    root: str  # the LUKS container


@dataclass(frozen=True)
class Uuids:
    luks: str  # the LUKS container, referenced by crypttab
    root_fs: str  # the ext4 inside it, referenced by fstab
    boot_fs: str
    esp_fs: str


class ResourceStack:
    """Releases acquired resources in reverse order, continuing past a failed release and reporting every failure."""

    def __init__(self) -> None:
        self._undo: list[tuple[str, Callable[[], None]]] = []

    def push(self, description: str, undo: Callable[[], None]) -> None:
        self._undo.append((description, undo))

    def __len__(self) -> int:
        return len(self._undo)

    def unwind(self) -> list[str]:
        """Run every undo, newest first. Returns one message per undo that failed (empty: all released).

        An undo that failed stays registered, so a later unwind (the rollback after a failed ending) tries it again.
        """
        failures: list[str] = []
        failed: list[tuple[str, Callable[[], None]]] = []
        while self._undo:
            description, undo = self._undo.pop()
            try:
                undo()
            except Exception as exc:  # a failed release must not stop the others: report it and go on
                message = f"could not release {description}: {redact(str(exc))}"
                log.error("%s", message)
                failures.append(message)
                failed.append((description, undo))
        self._undo = failed[::-1]
        return failures


@dataclass
class InstallContext:
    plan: Plan
    cmd: Commander
    host: Host
    work_dir: str = DEFAULT_WORK_DIR
    target: Target | None = None
    layers: list[str] = field(default_factory=list)
    recovery_key: Secret | None = None
    recovery_key_written: bool = False
    installation_complete: bool = False  # set once everything is closed: from then on the installed disk needs its key
    partitions: Partitions | None = None
    uuids: Uuids | None = None
    resources: ResourceStack = field(default_factory=ResourceStack)

    @property
    def target_root(self) -> str:
        return posixpath.join(self.work_dir, "target")

    @property
    def mapper_path(self) -> str:
        return f"/dev/mapper/{MAPPING_NAME}"

    def require_target(self) -> Target:
        if self.target is None:
            raise InstallerError("internal error: the target was not resolved before a step needed it")
        return self.target

    def require_partitions(self) -> Partitions:
        if self.partitions is None:
            raise InstallerError("internal error: the layout was not verified before a step needed it")
        return self.partitions

    def require_uuids(self) -> Uuids:
        if self.uuids is None:
            raise InstallerError("internal error: the filesystems were not identified before a step needed it")
        return self.uuids

    def require_passphrase(self) -> Secret:
        if self.plan.passphrase is None:
            raise InstallerError("internal error: no passphrase is available")
        return self.plan.passphrase

    def require_recovery_key(self) -> Secret:
        if self.recovery_key is None:
            raise InstallerError("internal error: the recovery key was not prepared before a step needed it")
        return self.recovery_key
