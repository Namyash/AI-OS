"""Filesystems: create them, read back their identifiers, mount the target tree, and unmount reliably.

Mounts are registered for undo before they are made, and an undo only unmounts what the kernel's table shows as
mounted, so the same code serves rollback after a failed ``mount`` and the orderly ending.
"""

from __future__ import annotations

import posixpath
import re

from installer import timeouts
from installer.context import InstallContext, Uuids
from installer.errors import CommandError, VerificationError
from installer.mounts import mounts_at_or_below, parse_mountinfo
from installer.target import MOUNTINFO

LABEL_ESP = "PAI-ESP"
LABEL_BOOT = "pai-boot"
LABEL_ROOT = "pai-root"
_UNMOUNT_ATTEMPTS = 3
_UUID = re.compile(r"[0-9A-Fa-f-]{4,64}")


def make_filesystems(ctx: InstallContext) -> str:
    parts = ctx.require_partitions()
    ctx.cmd.run(["mkfs.vfat", "-F", "32", "-n", LABEL_ESP, parts.esp], timeout=timeouts.MKFS)
    ctx.cmd.run(["mkfs.ext4", "-F", "-q", "-L", LABEL_BOOT, parts.boot], timeout=timeouts.MKFS)
    ctx.cmd.run(["mkfs.ext4", "-F", "-q", "-L", LABEL_ROOT, ctx.mapper_path], timeout=timeouts.MKFS)
    return "vfat on the ESP, ext4 on /boot and on the encrypted root"


def _probe(ctx: InstallContext, device: str, expected_type: str) -> str:
    """Filesystem UUID of ``device`` by low-level probing (no cache, which can be stale just after mkfs)."""
    result = ctx.cmd.run(["blkid", "--probe", "--output", "export", device], timeout=timeouts.QUICK)
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if values.get("TYPE") != expected_type:
        raise VerificationError(f"{device} holds {values.get('TYPE', 'nothing')}, expected {expected_type}")
    uuid = values.get("UUID", "")
    if not _UUID.fullmatch(uuid):
        raise VerificationError(f"{device} has no usable UUID")
    return uuid


def identify_filesystems(ctx: InstallContext) -> str:
    parts = ctx.require_partitions()
    ctx.uuids = Uuids(
        luks=_probe(ctx, parts.root, "crypto_LUKS"),
        root_fs=_probe(ctx, ctx.mapper_path, "ext4"),
        boot_fs=_probe(ctx, parts.boot, "ext4"),
        esp_fs=_probe(ctx, parts.esp, "vfat"),
    )
    return "read the UUIDs of the container and the three filesystems"


def is_mounted(ctx: InstallContext, path: str) -> bool:
    return bool(mounts_at_or_below(parse_mountinfo(ctx.host.read_text(MOUNTINFO)), path))


def mounts_below(ctx: InstallContext, path: str) -> list[str]:
    """Mount points strictly below ``path`` (not ``path`` itself).

    A mount AT the work directory is not ours to judge: systemd bind-mounts every ReadWritePaths= entry onto itself in
    the service's mount namespace, so ``/run/pai-install`` is a mount point under the real unit. Everything the engine
    mounts lies below it.
    """
    root = posixpath.normpath(path)
    found = mounts_at_or_below(parse_mountinfo(ctx.host.read_text(MOUNTINFO)), path)
    return sorted(m.mountpoint for m in found if posixpath.normpath(m.mountpoint) != root)


def unmount(ctx: InstallContext, path: str) -> None:
    """Unmount ``path`` and anything mounted below it. Does nothing if it is not mounted; retries a busy mount."""
    for attempt in range(_UNMOUNT_ATTEMPTS):
        if not is_mounted(ctx, path):
            return
        # --recursive handles the submounts of a rbind (/dev/pts); the binds are made --make-rslave, so this cannot
        # propagate an unmount into the live system.
        ctx.cmd.run(["umount", "--recursive", path], timeout=timeouts.QUICK, check=False)
        if not is_mounted(ctx, path):
            return
        if attempt + 1 < _UNMOUNT_ATTEMPTS:
            ctx.host.sleep(1.0)
    raise CommandError(f"{path} is still mounted after {_UNMOUNT_ATTEMPTS} attempts to unmount it", ["umount", path])


def push_unmount(ctx: InstallContext, path: str) -> None:
    """Register the undo for a mount that is about to be made at ``path``."""
    ctx.resources.push(f"the mount at {path}", lambda: unmount(ctx, path))


def mount_target_tree(ctx: InstallContext) -> str:
    """Root at the target directory, then /boot and /boot/efi inside it. Each is registered for undo first."""
    parts = ctx.require_partitions()
    root = ctx.target_root
    ctx.cmd.run(["install", "-d", "-m", "0700", ctx.work_dir], timeout=timeouts.QUICK)
    ctx.cmd.run(["install", "-d", "-m", "0755", root], timeout=timeouts.QUICK)

    push_unmount(ctx, root)
    ctx.cmd.run(["mount", "-t", "ext4", ctx.mapper_path, root], timeout=timeouts.QUICK)

    boot = f"{root}/boot"
    ctx.cmd.run(["install", "-d", "-m", "0755", boot], timeout=timeouts.QUICK)
    push_unmount(ctx, boot)
    ctx.cmd.run(["mount", "-t", "ext4", parts.boot, boot], timeout=timeouts.QUICK)

    efi = f"{boot}/efi"
    ctx.cmd.run(["install", "-d", "-m", "0755", efi], timeout=timeouts.QUICK)
    push_unmount(ctx, efi)
    ctx.cmd.run(["mount", "-t", "vfat", "-o", "umask=0077", parts.esp, efi], timeout=timeouts.QUICK)
    return f"mounted root, /boot and /boot/efi under {root}"
