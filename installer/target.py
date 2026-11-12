"""Resolving the target disk and enforcing safety rules 1 to 4 of INSTALLER_DESIGN.md.

The plan names the disk explicitly; nothing here ever chooses one. The disk is resolved to a whole block device and
then everything that could make wiping it harmful is read from the running system (sysfs, mountinfo, swaps): the live
medium is *discovered* from the mounts the live system made, never named. Every refusal is a ``SafetyError`` with a
stable ``reason``, raised before any command that changes a disk has run.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from installer.errors import SafetyError
from installer.host import Host
from installer.mounts import Mount, parse_mountinfo, parse_swaps
from installer.plan import TargetSpec

GIB = 1024**3
MIN_TARGET_BYTES = 16 * GIB
SECTOR_BYTES = 512  # sysfs reports sizes in 512-byte units whatever the device's logical sector size is

DEV = "/dev"
SYS_BLOCK = "/sys/block"
SYS_CLASS_BLOCK = "/sys/class/block"
MOUNTINFO = "/proc/self/mountinfo"
SWAPS = "/proc/swaps"
BY_ID = "/dev/disk/by-id"
# Where live-boot mounts what it booted from (the medium, the squashfs layers, the overlay). Part of live-boot's
# layout, not a device: which device is behind them is read from the mount table.
LIVE_MOUNT_ROOTS = ("/run/live", "/lib/live/mount")


@dataclass(frozen=True)
class Target:
    path: str  # the whole-disk device node, e.g. /dev/sda
    name: str
    devt: str
    size_bytes: int


@dataclass
class _DeviceTree:
    """The disk, its partitions, and everything stacked on them (mappings, RAID), as device numbers."""

    devts: set[str] = field(default_factory=set)
    holders: list[str] = field(default_factory=list)


def is_live_mount(mount: Mount) -> bool:
    return any(mount.mountpoint == root or mount.mountpoint.startswith(root + "/") for root in LIVE_MOUNT_ROOTS)


def resolve_target(spec: TargetSpec, host: Host) -> Target:
    """The whole disk named by ``spec``, or a ``SafetyError`` saying which rule refused it."""
    candidate = posixpath.join(BY_ID, spec.by_id) if spec.by_id else spec.path
    if candidate is None or not host.exists(candidate):
        raise SafetyError("not-found", f"the target {candidate or '(none)'} does not exist")
    real = host.realpath(candidate)
    name = posixpath.basename(real)
    if posixpath.dirname(real) != DEV:
        raise SafetyError("not-a-disk", f"{candidate} does not resolve to a device node directly under {DEV}")
    if not host.is_block_device(real):
        raise SafetyError("not-a-block-device", f"{real} is not a block device")
    _require_whole_plain_disk(host, real, name)

    tree = _device_tree(host, name)
    mounts = _mount_table(host)
    _refuse_live_medium(real, tree, mounts)
    _refuse_in_use(host, real, tree, mounts)

    size = _read_int(host, f"{SYS_BLOCK}/{name}/size", real) * SECTOR_BYTES
    if size < MIN_TARGET_BYTES:
        raise SafetyError(
            "too-small",
            f"{real} is {size / GIB:.1f} GiB; the installation needs at least {MIN_TARGET_BYTES // GIB} GiB",
        )
    return Target(path=real, name=name, devt=_read_devt(host, f"{SYS_BLOCK}/{name}", real), size_bytes=size)


def _require_whole_plain_disk(host: Host, real: str, name: str) -> None:
    if not host.exists(f"{SYS_BLOCK}/{name}"):
        if host.exists(f"{SYS_CLASS_BLOCK}/{name}/partition"):
            raise SafetyError("partition", f"{real} is a partition; name the whole disk instead")
        raise SafetyError("not-a-disk", f"{real} is not a whole disk known to the kernel")
    if name.startswith("dm-") or host.exists(f"{SYS_BLOCK}/{name}/dm"):
        raise SafetyError("mapper-device", f"{real} is a device-mapper device, not a disk")
    if host.exists(f"{SYS_BLOCK}/{name}/md"):
        raise SafetyError("mapper-device", f"{real} is a software RAID device, not a plain disk")
    if _read_text(host, f"{SYS_BLOCK}/{name}/ro", real) == "1":
        raise SafetyError("read-only", f"{real} is read-only")


def _read_text(host: Host, path: str, device: str) -> str:
    try:
        return host.read_text(path).strip()
    except OSError:
        raise SafetyError("unreadable", f"cannot read {path} to examine {device}") from None


def _read_int(host: Host, path: str, device: str) -> int:
    text = _read_text(host, path, device)
    if not text.isdigit():
        raise SafetyError("unreadable", f"{path} does not hold a number")
    return int(text)


def _read_devt(host: Host, sysfs_dir: str, device: str) -> str:
    return _read_text(host, f"{sysfs_dir}/dev", device)


def _device_tree(host: Host, name: str) -> _DeviceTree:
    tree = _DeviceTree()
    disk_dir = f"{SYS_BLOCK}/{name}"
    sysfs_dirs = [disk_dir]
    try:
        for entry in host.listdir(disk_dir):
            if host.exists(f"{disk_dir}/{entry}/partition"):
                sysfs_dirs.append(f"{disk_dir}/{entry}")
    except OSError:
        raise SafetyError("unreadable", f"cannot list {disk_dir}") from None
    for sysfs_dir in sysfs_dirs:
        tree.devts.add(_read_devt(host, sysfs_dir, name))
        _add_holders(host, sysfs_dir, name, tree, depth=0)
    return tree


def _add_holders(host: Host, sysfs_dir: str, name: str, tree: _DeviceTree, depth: int) -> None:
    """Follow ``holders/`` (the devices stacked on this one) recursively, with a depth bound against cycles."""
    holders_dir = f"{sysfs_dir}/holders"
    if depth > 16 or not host.exists(holders_dir):
        return
    try:
        holders = host.listdir(holders_dir)
    except OSError:
        raise SafetyError("unreadable", f"cannot list {holders_dir}") from None
    for holder in holders:
        holder_dir = f"{SYS_BLOCK}/{holder}"
        tree.holders.append(holder)
        tree.devts.add(_read_devt(host, holder_dir, name))
        _add_holders(host, holder_dir, name, tree, depth + 1)


def _mount_table(host: Host) -> list[Mount]:
    try:
        return parse_mountinfo(host.read_text(MOUNTINFO))
    except OSError:
        raise SafetyError("mount-table-unreadable", f"cannot read {MOUNTINFO}") from None


def _refuse_live_medium(real: str, tree: _DeviceTree, mounts: list[Mount]) -> None:
    for mount in mounts:
        if is_live_mount(mount) and mount.devt in tree.devts:
            raise SafetyError(
                "live-medium", f"{real} is, contains or backs the live medium (mounted at {mount.mountpoint})"
            )


def _refuse_in_use(host: Host, real: str, tree: _DeviceTree, mounts: list[Mount]) -> None:
    for mount in mounts:
        if mount.devt in tree.devts:
            raise SafetyError("mounted", f"{real} (or something on it) is mounted at {mount.mountpoint}")
    try:
        swap_paths = parse_swaps(host.read_text(SWAPS))
    except OSError:
        raise SafetyError("swap-table-unreadable", f"cannot read {SWAPS}") from None
    for swap in swap_paths:
        if host.devt(host.realpath(swap)) in tree.devts:
            raise SafetyError("swap", f"{real} (or something on it) is in use as swap")
    if tree.holders:
        raise SafetyError("active-mapping", f"{real} has active mappings on it: {', '.join(sorted(set(tree.holders)))}")
