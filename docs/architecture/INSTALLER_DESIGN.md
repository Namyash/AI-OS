# Installer design (milestone M1.5)

Status: design, decided 2026-11-10. The contract the installer engine, the image integration and the install test are built against.

## Decision: a small custom installer engine, not Calamares

This reverses the Phase 0 choice (Calamares). Reasons:

| Concern | Calamares | Custom engine |
|---|---|---|
| Needs a display and Qt (hundreds of MB), cannot be driven by our own wizard | yes | no: plain Python, driven by the kiosk wizard later |
| Testable headless under QEMU software emulation | poorly | yes: one command, JSON progress events |
| Control of the dangerous parts (which disk, LUKS2 parameters, secret handling) | configuration of a large generic tool | explicit code with tests |
| Risk | brittle customisation (R8) | a disk-destroying bug (new R17), so guardrails below are mandatory |

The engine installs by **copying the running live root filesystem** onto the target (no network, no debootstrap), so what is installed is exactly the image that was tested.

## Layout (GPT, works on BIOS and UEFI)

| Partition | Size | Content |
|---|---|---|
| 1 | 1 MiB | BIOS boot (type ef02) for `grub-install --target=i386-pc` |
| 2 | 512 MiB | EFI system partition, FAT32 (`grub-install --target=x86_64-efi --removable --no-nvram`: no firmware variables needed, works in VMs) |
| 3 | 1 GiB | `/boot`, ext4, **unencrypted** (GRUB cannot unlock LUKS2 argon2id; see threat model T10) |
| 4 | rest | **LUKS2**, argon2id, containing one ext4 root filesystem (no LVM, no swap yet) |

Everything, including `/var/lib/pai` and all application data, lives on the encrypted root.

## Plan and CLI

`python3 -m installer --plan <plan.json>` (root only, stdlib only, installed at `/opt/pai/installer`). A plan is validated strictly (unknown keys rejected):

```json
{
  "version": 1,
  "target": {"by_id": "<name under /dev/disk/by-id>"},        // or {"path": "/dev/sdX"}; exactly one
  "confirm_wipe": true,                                          // required; the target's contents are destroyed
  "hostname": "pai",
  "username": "<login name for the primary user>",
  "passphrase_source": "stdin" | "plan",                         // "plan" puts the passphrase in the file: unattended use only
  "passphrase": "...",                                           // only with passphrase_source = plan
  "recovery_key_file": "/run/pai-install/recovery-key",          // written 0600, shown to the user once, never logged
  "kdf": {"memory_kib": null, "iter_time_ms": null},             // null = cryptsetup defaults. Smaller values only for tests; luksDump must still show argon2id
  "extra_kernel_args": "",                                       // validated printable words, appended to GRUB_CMDLINE_LINUX
  "after": "poweroff" | "reboot" | "none"
}
```

Output: one JSON object per line on stdout: `{"event": "step", "name": "...", "state": "start|done|failed", "detail": "..."}` and a final `{"event": "result", "ok": true|false, "error": "..."}`. Exit 0 only when every step finished and verification passed. No secret ever appears in stdout, stderr, argv, environment or logs.

## Safety rules (each gets a test)

1. The target must be an existing whole **block device**, never a partition, never a mapper device.
2. Refuse when the target is, contains, or backs the **live medium** (`/run/live/medium`) or any mounted filesystem, or holds an active swap or mapping.
3. `confirm_wipe` must be `true`; the target is named explicitly (by id or path); there is no "auto-select a disk".
4. Minimum size 16 GiB.
5. Partition table, filesystems and LUKS header are verified after creation (`sfdisk`/`lsblk`/`cryptsetup luksDump` show GPT, the expected partitions, LUKS2, argon2id) before anything is copied.
6. The passphrase reaches `cryptsetup` only on its standard input (`--key-file=-`), never argv or environment. Minimum 12 characters, rejected if it is only one repeated character. A second keyslot holds a random 256-bit **recovery key** (shown once, written to `recovery_key_file`).
7. On any failure: unmount everything, close the mapping, report; never leave a mapping open or a target mounted.
8. Everything runs as separate steps through one command runner so tests can replace it; no shell string interpolation of plan values.

## What the engine configures on the target

fstab and crypttab by UUID; kernel root on the mapper device; `update-initramfs` (cryptsetup unlock on boot); GRUB for BIOS and UEFI; hostname; the primary user with a **locked password** and no sudo (the kiosk is the interface; administration comes later through authorised functions); root locked; **no default credentials anywhere**; live-boot, live-config and the live user removed; regenerated machine-id; getty autologin remnants removed; the same units (backend, kiosk, nftables) enabled as in the live image.

## Unattended and test use

`pai-install-auto.service` runs the engine only when the kernel command line contains `pai.install=auto` **and** a block device labelled `PAI-PLAN` carries `plan.json`. Whoever controls the kernel arguments and the attached devices already controls the machine, so this is a provisioning interface (like a preseed), not a new privilege. The unit is root-justified under the unit-lint convention.

## Verification (what "done" means)

1. Unit tests with a fake command runner: command order, no secret in any argv/environment, every safety rule, rollback.
2. Real tools in a privileged container on a loop device: GPT, LUKS2/argon2id, filesystems, recovery-key keyslot, open and close.
3. **End-to-end under QEMU:** boot the ISO with a blank sparse disk and a `PAI-PLAN` medium; the engine installs and powers off; boot from the disk (BIOS; UEFI if OVMF is available); type the passphrase at the initramfs prompt; the self-check on the **installed** system passes, including two extra checks (root on dm-crypt LUKS2 argon2id; no live remnants). A wrong passphrase must not boot.

## Out of scope

The wizard UI in the kiosk (M1.5b), disk resizing or dual boot, LVM, swap, Secure Boot, TPM unlock, OS upgrades.
