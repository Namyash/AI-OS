"""Upper bounds, in seconds, for each kind of command. The installer never waits without one.

They are generous because the installer also runs under QEMU with software CPU emulation, where argon2id, mkfs and
copying take many times longer than on hardware. A command that exceeds its bound is killed and the step fails.
"""

QUICK = 60.0  # blkid, mkdir, mount, umount, truncate, userdel, useradd, passwd, sfdisk --json
WIPE = 300.0  # wipefs
PARTITION = 120.0  # sfdisk writing the table
KDF = 900.0  # luksFormat, luksAddKey, open: argon2id with a large memory cost
MKFS = 900.0
COPY = 14_400.0  # rsync of the system
PACKAGES = 1_800.0  # apt-get purge
INITRAMFS = 1_800.0  # update-initramfs for all kernels
BOOTLOADER = 900.0  # grub-install, update-grub
DEVICE_NODES = 30.0  # waiting for the kernel/udev to create partition nodes
