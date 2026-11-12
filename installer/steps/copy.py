"""Copying the system: the read-only squashfs layer(s) live-boot mounted, never the live overlay.

What is installed is exactly the image that was tested, without whatever the live session changed in RAM. The layers
are *discovered* from the mount table (squashfs mounts live-boot made), never named. With several layers they are
copied in mount order, base first, so a later layer overrides an earlier one as it does in the live overlay.
"""

from __future__ import annotations

from installer import timeouts
from installer.context import InstallContext
from installer.errors import SafetyError
from installer.host import Host
from installer.mounts import parse_mountinfo
from installer.target import LIVE_MOUNT_ROOTS, MOUNTINFO

# Directories whose contents are runtime state; the (empty) directories themselves are still created from the source.
RUNTIME_DIRECTORIES = ("proc", "sys", "dev", "run", "tmp", "mnt", "media")
RUNTIME_EXCLUDES = (*(f"/{name}/*" for name in RUNTIME_DIRECTORIES), "/lost+found")
# The ESP is FAT: it cannot hold the owners and modes of the source, and rsync would fail trying to set them. It is
# mounted before the copy and filled by grub-install.
MOUNTED_FILESYSTEM_EXCLUDES = ("/boot/efi",)


def discover_live_layers(host: Host) -> list[str]:
    """Mount points of the squashfs layers the live system booted from, in mount order."""
    try:
        mounts = parse_mountinfo(host.read_text(MOUNTINFO))
    except OSError:
        raise SafetyError("mount-table-unreadable", f"cannot read {MOUNTINFO}") from None
    layers = [
        mount.mountpoint
        for mount in mounts
        if mount.fstype == "squashfs" and any(mount.mountpoint.startswith(f"{root}/") for root in LIVE_MOUNT_ROOTS)
    ]
    if not layers:
        raise SafetyError(
            "no-live-system", "this is not a live system: no squashfs layer mounted by live-boot was found"
        )
    return layers


def find_source(ctx: InstallContext) -> str:
    ctx.layers = discover_live_layers(ctx.host)
    return f"{len(ctx.layers)} live layer(s): {', '.join(ctx.layers)}"


def copy_system(ctx: InstallContext) -> str:
    for layer in ctx.layers:
        ctx.cmd.run(
            [
                "rsync",
                "--archive",
                "--hard-links",
                "--acls",
                "--xattrs",
                "--numeric-ids",
                "--one-file-system",
                *(f"--exclude={pattern}" for pattern in (*RUNTIME_EXCLUDES, *MOUNTED_FILESYSTEM_EXCLUDES)),
                f"{layer.rstrip('/')}/",
                f"{ctx.target_root}/",
            ],
            timeout=timeouts.COPY,
        )
    ctx.cmd.run(["sync"], timeout=timeouts.COPY)
    return f"copied {len(ctx.layers)} layer(s) to {ctx.target_root}"
