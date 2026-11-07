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

## Planned install flow

1. Boot the ISO, start the installer.
2. Choose your encryption passphrase and store the recovery key it displays. **Losing both makes your data unrecoverable.**
3. First boot: create your account, pick or download a model, resource check, interface opens.

Limits worth knowing now: `/boot` is not encrypted (a GRUB limitation with LUKS2/argon2id), and a malicious host can still read the running VM
(see the [threat model](../security/THREAT_MODEL.md)).
