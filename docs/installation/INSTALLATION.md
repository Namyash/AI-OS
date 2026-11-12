# Installation

**Status: there is no installable release yet.** The ISO builds from source (see DEVELOPMENT.md), but the installer, encrypted storage
and the AI interface are later milestones (M1.3 to M1.5). This page records the target procedure and the VM settings that matter for privacy.

## Target virtual machine

| Setting | Recommended |
|---|---|
| RAM | 8 GB (16 GB allows 7–8B parameter models) |
| CPU | 4 cores |
| Disk | 100 GB, thin provisioned |
| Firmware | UEFI |
| Network | NAT (the OS is offline by default until you allow access) |
| GPU | Virtual GPU only; passthrough is rarely available in desktop hypervisors and is optional |

## Hypervisor privacy settings (do this before first boot)

The guest cannot enforce these; they are controlled by the host. Disable:

- Shared clipboard (VMware: *Guest Isolation → Enable copy and paste*; VirtualBox: *General → Advanced → Shared Clipboard = Disabled*)
- Drag and drop (same locations)
- Shared folders (VMware: *Options → Shared Folders = Disabled*; VirtualBox: remove all shared folders)
- Do not use suspend or snapshots with memory for sensitive sessions: they write guest RAM, including the disk key, to the host disk.
- Keep the host's own disk encrypted (BitLocker, FileVault, LUKS) and consider the hypervisor's VM encryption as an extra layer.

## What exists today

The installer **engine** exists and is tested end to end under QEMU: it installs the live system onto a blank disk with an encrypted root
(LUKS2, argon2id, your passphrase plus a random recovery key), BIOS and UEFI bootloaders, and no default account; the installed system boots,
asks for the passphrase at startup, and passes the same security self-checks as the live image. What does **not** exist yet is the guided
screen that asks for the passphrase and disk inside the interface: today the installer is driven by a plan file
(`docs/development/INSTALLER.md`, `docs/development/INSTALL_TESTING.md`), meant for provisioning and testing. It has not been run on VMware,
VirtualBox or real hardware.

## Target install flow (once the wizard exists)

1. Boot the ISO; the interface offers to install.
2. Choose the target disk (it will be erased), choose your encryption passphrase (at least 12 characters) and store the recovery key it displays once. **Losing both makes your data unrecoverable.**
3. First boot: type the passphrase at the unlock prompt, then create your account, pick or download a model, resource check, interface opens.

Limits worth knowing now: `/boot` is not encrypted (a GRUB limitation with LUKS2/argon2id), and a malicious host can still read the running VM
(see the [threat model](../security/THREAT_MODEL.md)).
