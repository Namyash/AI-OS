# Install testing (milestone M1.5)

Proves the whole install flow of `docs/architecture/INSTALLER_DESIGN.md` on the built ISO, under QEMU software emulation in
Docker (there is no hypervisor on the development machine; same reasons and container as `BOOT_TESTING.md`).

## What it does

`tests/end_to_end/test_install_iso.py` (marker `e2e`, deselected by default), four tests in order:

1. **Install.** A throwaway Docker volume gets a sparse raw 20 GiB disk and `plan.iso`, an ISO9660 image with volume id `PAI-PLAN`
   holding `plan.json` (built with `xorriso` in the QEMU container). The live ISO boots under TCG with both attached and
   `pai.install=auto`; the target is named by id (`-drive ...,if=virtio,serial=PAITARGET`, so `/dev/disk/by-id/virtio-PAITARGET`).
   `pai-install-auto.service` runs the engine; the test parses its JSON-lines events from the serial console and requires a
   successful `result` event, no failed step and the guest powering itself off. The install boot does not carry `pai.selfcheck=1`
   (the self-check powers the machine off) and masks `pai-kiosk.service` for that boot only.
2. **Installed boot, BIOS.** QEMU boots the disk through SeaBIOS and the GRUB the installer wrote. The test watches the console for the
   cryptsetup prompt and types the passphrase on QEMU's stdin, then requires the self-check to end with `RESULT|PASS|18/18` (the
   sixteen checks plus `root-encrypted` and `no-live-remnants`) and the guest to power off.
3. **Installed boot, UEFI.** The same through OVMF (the QEMU image installs `ovmf`; the firmware files come from QEMU's firmware
   descriptors). Skipped with the reason when the image has none or `PAI_INSTALL_UEFI=off`.
4. **Wrong passphrases.** Three wrong passphrases are typed. The system must never reach a self-check line, a login prompt or the
   multi-user target; the run ends when the initramfs gives up, the console falls silent, or the timeout passes. A run that never
   saw the prompt, or typed fewer than three, is inconclusive and fails.

A missing or partial result is always a failure (no events, no result event, no prompt, no self-check, a missing check). A failed
install fails the three boots instead of skipping them.

## Running it

```
python -m pytest tests/end_to_end/test_install_iso.py -m e2e -s
```

Needs Docker and an ISO that contains the installer (`PAI_ISO` or the newest `dist/*.iso`; build with `bash os/build/build-iso.sh`).
The first run builds the QEMU image (`tests/end_to_end/Dockerfile`, which now also holds `ovmf` and a `/disks` mount point). Expect
tens of minutes; software emulation is about ten times slower again when the host is loaded. `-s` shows the paths of the logs.
`PAI_INSTALL_ECHO=1` also prints the (scrubbed) consoles live.

The fast tests (no Docker) for everything pure run with the normal suite:
`test_install_plan.py`, `test_install_console.py`, `test_install_harness.py`, `test_container_install.py`,
`test_installer_component.py`.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `PAI_ISO` | newest `dist/*.iso` | ISO to install |
| `PAI_QEMU_MEMORY`, `PAI_QEMU_CPUS` | 3072, 2 | guest memory (MiB) and CPUs, for every boot (shared with the boot test) |
| `PAI_BOOT_EXTRA_ARGS` | none | extra words for the **install** boot's kernel line (for example `systemd.log_level=debug`) |
| `PAI_INSTALL_TIMEOUT` | 5400 s | install boot, until the guest powers off or the engine's result event is printed |
| `PAI_INSTALL_BOOT_TIMEOUT` | 2400 s | each installed boot (GRUB, unlock, whole self-check with the kiosk) |
| `PAI_INSTALL_NEGATIVE_TIMEOUT` | 1500 s | the wrong-passphrase boot |
| `PAI_INSTALL_UNLOCK_SETTLE` | 180 s | silence after the last wrong passphrase that ends the negative run |
| `PAI_INSTALL_DISK_GIB` | 20 | size of the sparse target disk (the engine refuses less than 16) |
| `PAI_INSTALL_UEFI` | `auto` | `auto`: run the UEFI boot when the image has firmware; `on`: and fail when it has none; `off`: BIOS only |
| `PAI_INSTALL_KDF_MEMORY_KIB`, `PAI_INSTALL_KDF_ITER_MS` | 65536, 100 | argon2id cost put in the plan (small enough for emulation; the self-check still requires argon2id) |
| `PAI_INSTALL_ECHO` | off | print the scrubbed consoles while the guests run |

A malformed value stops the run with a message naming the variable. Exit codes and `cannot run` messages mean docker, the ISO, the
image or the emulator failed, not the image under test.

## Secrets

The passphrase is random per run (24 random bytes, URL-safe) and exists only in memory (a `Secret` that prints as `<secret>`), in
`plan.json` on the plan medium inside the volume (deleted with it), and as keystrokes on QEMU's stdin. It reaches the media step on
stdin, never argv or the environment of any process. Everything shown or saved from a console passes a scrubber; if the scrubber had to
replace anything the run fails with "the passphrase appeared on the console" (the guest is not supposed to echo it). The three wrong
passphrases are scrubbed the same way.

## Reading a failure

Logs (latest of each replaces the previous, control characters made visible): `%TEMP%` or `/tmp` of the host,
`pai-e2e-last-install.log`, `pai-e2e-last-installed-boot-bios.log`, `pai-e2e-last-installed-boot-uefi.log`,
`pai-e2e-last-wrong-passphrase-bios.log`. The failure message ends with the last 60 lines of the console.

| Message | Meaning and first things to look at |
|---|---|
| `the engine printed no events` | The unit did not run it: `pai.install=auto` on the line? a device labelled `PAI-PLAN` with `plan.json` (the plan medium is a second CD-ROM)? unit enabled by `os/installer/hooks`? The ISO may predate the installer. Add `PAI_BOOT_EXTRA_ARGS="systemd.journald.forward_to_console=1"`. |
| `no result event: the engine did not finish; last step: X` | The engine stopped or the install timed out at step X; look at the console above, then `PAI_INSTALL_TIMEOUT`. `Read-only file system` or `Operation not permitted` in the engine's output points at the unit's sandbox (`os/installer/README.md`, "What the unit assumes"). |
| `the engine reported failure: ...` | The engine's own reason, with its failed steps. |
| `the guest did not power itself off after the install` | Result printed but no power-off: the engine's `after`, or `systemctl poweroff` denied. |
| `the disk-unlock prompt never appeared` | GRUB or the kernel did not get to ask: is `console=ttyS0` on the installed kernel line (plan `extra_kernel_args`)? Is `/boot` readable? For UEFI: removable boot path `\EFI\BOOT\BOOTX64.EFI`. |
| `the unlock prompt appeared N times but ... typed 1` | The passphrase was not accepted (keyslot, keyboard layout in the initramfs, or crypttab). |
| `required check(s) missing ... root-encrypted` | The system was taken for live (`boot=live` still on its line) or `pai-selfcheck-crypt.service` is missing. |
| `root-encrypted FAILED` / `no-live-remnants FAILED` | The detail names what is wrong (a `pbkdf2` slot, a leftover package, an autologin drop-in); see `BOOT_TESTING.md`. |
| `the system came up although every passphrase was wrong` | Serious: the disk booted without the right key. |
| `inconclusive: ...` | The negative test did not get to try three passphrases; fix the boot first. |

Leftovers: containers are named `pai-instharness-<step>-<pid>-<id>` and removed with `--rm` and by name on a timeout or Ctrl-C;
volumes are `pai-instharness-vol-<pid>-<id>` and removed when the session ends. After a crash of the test process itself:
`docker ps -a --filter name=pai-instharness` and `docker volume ls --filter name=pai-instharness`, then `docker rm -f` and
`docker volume rm` them (they hold the throwaway disk and the plan medium with its passphrase).

## Limits

* Software emulation only: timing, and anything that depends on real hardware (firmware quirks, real disks, TPM) is not covered.
* The UEFI boot uses OVMF without Secure Boot; GRUB is unsigned. The BIOS and UEFI boots share one disk, so the second boot starts from
  what the first left.
* The negative test shows that three wrong passphrases do not unlock; it does not test brute-force resistance or the recovery key
  (the recovery-key slot is only checked to be argon2id by `root-encrypted`).
* The ISO passes only what the engine of that build does; this harness was validated with stand-ins (a scripted guest that prompts
  for a passphrase, recorded `docker` calls) and a real container for the media step, firmware lookup and volume lifecycle, not
  with a real install.
