"""Making the installed system bootable: initramfs with disk unlock, GRUB for BIOS and UEFI, and a check of the result.

``grub-install`` runs twice into the same ``/boot``: ``i386-pc`` to the disk (GPT with the BIOS boot partition) and
``x86_64-efi --removable --no-nvram`` to the ESP (``EFI/BOOT/BOOTX64.EFI``, no firmware variables, so it works in a
virtual machine and on firmware that forgets its boot entries). These steps need a real system (kernel, the target's
GRUB packages, device nodes), so they are verified by the QEMU install test, not by the unit tests.
"""

from __future__ import annotations

from installer import timeouts
from installer.context import InstallContext
from installer.errors import VerificationError
from installer.steps.configure import chroot_run

# What must exist on the installed system for either firmware to find a boot loader, relative to its root.
BOOT_ARTIFACTS = ("/boot/grub/grub.cfg", "/boot/grub/i386-pc/core.img", "/boot/efi/EFI/BOOT/BOOTX64.EFI")


def build_initramfs(ctx: InstallContext) -> str:
    chroot_run(ctx, ["update-initramfs", "-u", "-k", "all"], timeouts.INITRAMFS)
    return "initramfs rebuilt for every installed kernel"


def install_bootloader(ctx: InstallContext) -> str:
    disk = ctx.require_target().path
    chroot_run(ctx, ["grub-install", "--target=i386-pc", "--recheck", disk], timeouts.BOOTLOADER)
    chroot_run(
        ctx,
        ["grub-install", "--target=x86_64-efi", "--efi-directory=/boot/efi", "--removable", "--no-nvram", "--recheck"],
        timeouts.BOOTLOADER,
    )
    chroot_run(ctx, ["update-grub"], timeouts.BOOTLOADER)
    return "GRUB installed for BIOS and UEFI, grub.cfg generated"


def verify_boot_files(ctx: InstallContext) -> str:
    missing = [path for path in BOOT_ARTIFACTS if not ctx.host.exists(f"{ctx.target_root}{path}")]
    if missing:
        raise VerificationError(f"the boot loader is incomplete: missing {', '.join(missing)}")
    return "the BIOS and UEFI boot loaders and grub.cfg are in place"
