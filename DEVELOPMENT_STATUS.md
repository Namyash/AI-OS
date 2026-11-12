# Development Status

Last updated: 2026-11-12. Read this first when resuming. Two commits exist on `main`: `Initial commit of Private AI OS` (not made by the assistant) and `Phase 1: kiosk session handoff and encrypted LUKS2 installer (M1.2-M1.5)`, which holds the work described below. The initial commit is on `origin/main`; the Phase 1 commit was local only when this was written (check `git status -sb` for the current state).

## Where we are

Phase 0 is complete. Phase 1 (bootable Linux foundation) is **in progress: M1.1 to M1.5 are done and verified under QEMU; the installer wizard in the kiosk and M1.6 are not done.** Phase 2 (local AI) has not started and must not until Phase 1's acceptance criteria are met.

| Milestone | State | Evidence |
|---|---|---|
| M0 architecture, threat model, schema | Done | `docs/`, `backend/database` (schema tests) |
| M1.1 build foundation | Done | ISO builds, checksum verified, policy tests |
| M1.2 boot self-check + QEMU boot harness | Done | Real boots under QEMU: `PAI-SELFCHECK\|RESULT\|PASS` |
| M1.3 backend service + hardened systemd unit | Done | Unit tests on Python 3.12 and Debian 3.13; verified on the booted image |
| M1.4a frontend shell | Done | 249 tests, typecheck, lint, build, `npm audit` 0 |
| M1.4b kiosk, UI served by the backend, session handoff, live-login lock | Done in QEMU | Self-check 16/16 on the live ISO |
| **M1.5 installer engine, encrypted install, boot, unlock** | **Done in QEMU (engine and test flow); the wizard UI is not built** | Full install, BIOS boot, UEFI boot, wrong-passphrase test: see below |
| M1.5b wizard in the kiosk that drives the installer | **Not started** | |
| M1.6 VMware / VirtualBox runs | **Not started; needs a human with those hypervisors** | |

## M1.5: what was proven (real logs, final ISO, idle host)

`tests/end_to_end/test_install_iso.py -m e2e`: **4 passed in 19m24s**.
1. The live ISO booted with a blank 20 GiB virtual disk and a `PAI-PLAN` medium; `pai-install-auto.service` ran the engine: every step `done` (find-source, recovery key, wipe, partition, verify-layout, luks-format, luks-recovery-key, luks-verify, luks-open, mkfs, identify-filesystems, mount, copy-system, configure-files, chroot-mounts, remove-live-session, accounts, machine-id, initramfs, bootloader, verify-installation, close, after); final event `ok: true`; the guest powered off.
2. The installed disk booted through **BIOS** (SeaBIOS and GRUB), the passphrase was typed at the initramfs unlock prompt, and the self-check reported **`RESULT|PASS|18/18`**: the 16 live-image checks plus `root-encrypted` (root on dm-crypt, LUKS2, 2 keyslots, every one argon2id) and `no-live-remnants`.
3. The same through **UEFI** (OVMF): 18/18.
4. Three wrong passphrases: "No key available with this passphrase" three times, then "maximum number of tries exceeded"; no login prompt, no self-check output, no boot.

Before that, the engine passed its own checks: 389 tests on Debian 13 (Python 3.13, non-root), 100 of 101 safety/secret/rollback mutations caught (the survivor is an equivalent change), and a run with the real `cryptsetup`, `sfdisk`, `mkfs` and `rsync` on a loop device in a privileged container (GPT with 4 partitions, LUKS2/argon2id, passphrase and recovery key both open it, wrong ones do not, nothing left mapped or mounted).

Real bugs found only by the real install and fixed at the root (each has a regression test):
- apt could not drop to its `_apt` user inside the install unit: `NoNewPrivileges` blocks it unless `CAP_SETUID`/`CAP_SETGID` are also **ambient** (found by bisecting the real unit under systemd 257 in a container).
- The engine's final "nothing left mounted" check counted `/run/pai-install` itself (systemd bind-mounts every `ReadWritePaths=` entry onto itself) as its own leftover, so every successful install reported failure. It now fails only on mounts strictly below the work directory, and names them. The plan medium also moved to its own `/run/pai-plan`.
- `install-auto.sh` accepted volume labels like `-n` and `..`.

## What was verified (other)

- Full default suite on the Windows dev host: **2280 passed, 90 skipped, 6 deselected, 1 failed, 17 errors** in 11m41s. All 18 non-passing results are in `tests/end_to_end/test_installer_component.py`, which runs Linux shell scripts under Git Bash: they fail only on this host (Git Bash maps `/tmp` to a Windows path, and `python3` is not on PATH there). The same tests pass on Debian (next line). Ruff check and format clean (190 files).
- Backend, kiosk, installer, security and the fast end-to-end tests inside `debian:trixie-slim` (Python 3.13.5, Debian's python3-fastapi/uvicorn/pydantic, Node, non-root): **1981 passed, 4 skipped, 0 failed** (the skips need root).
- Earlier milestones' evidence still stands (frontend 249 tests; backend, kiosk and security suites on Debian 13; kiosk end-to-end in a container; live ISO 16/16).
- ISO now 626 MB; a build takes 12 to 25 minutes depending on the network.

## What was NOT verified

- **Anything on VMware Workstation or VirtualBox**, or real hardware. QEMU (software emulation) is neither. The installer has only ever written to virtual disks.
- The install test used small key-derivation settings so it finishes under emulation; the production defaults (cryptsetup's argon2id) were not exercised in a boot. `luksDump` shows argon2id either way.
- No wizard: passphrase and disk are given by a plan file. The unattended path can hold the passphrase in a plain file (`passphrase_source: plan`).
- The kiosk on a real display (see `docs/security/SECURITY.md`, Known gaps).
- After the last test run, no further changes were made to the shipped image (only docs).

## Architecture decisions made in M1.5

- **Custom installer instead of Calamares** (reverses Phase 0; see `docs/architecture/INSTALLER_DESIGN.md`): copies the live root's squashfs layer, so what is installed is exactly the image that was tested. GPT with BIOS-boot, ESP, unencrypted `/boot`, LUKS2 root (no LVM, no swap).
- Safety rules enforced before any destructive command; passphrase on stdin only; recovery key as a 0600 file written before anything is destroyed; rollback on every failure.
- Unattended and test interface: `pai.install=auto` plus a `PAI-PLAN` labelled medium; the unit is root-justified with measured waivers.
- Installed-system self-check adds `root-encrypted` and `no-live-remnants` (18 checks); live boots keep 16. The harness is strict in both modes.
- Console logins on other virtual terminals are disabled (`NAutoVTs=0`).

## Known issues and deferred findings

See the "Known gaps" table in `docs/security/SECURITY.md`. New with M1.5: `/boot` unencrypted; plan-file passphrase for unattended use; a failed install leaves the disk partly formatted; the installer is untested on real hardware and hypervisors. Older ones remain (launcher and Chromium share one account; no `meta skuid` rule for `pai-ui`; port squatting only narrowed; kiosk untested on a real display).

## Process notes

- The account's 5-hour and weekly usage limits stopped large agent runs several times. Prefer few focused agents; run builds and boots directly; resume stopped agents from their saved state; finish small remaining work directly.
- Real runs found what unit tests could not (four bugs in the install flow). Reproducing a failure in a container with the real unit under real systemd took minutes where a rebuild cycle takes 25.
- Do not run heavy tests while a boot test runs: software emulation slows about tenfold on a loaded host. Transient network and Docker-disk errors can fail a build; retry once before debugging.
- On Windows the `bash` on PATH may be the WSL launcher with no distribution; tests look for Git Bash. A few tests that compare Linux paths fail on Windows only (Git Bash maps `/tmp`) and pass on Debian: judge those scripts on Debian.

## Next recommended milestone

M1.5b: a wizard in the kiosk (disk choice, passphrase, recovery key shown once) driving the installer through an authenticated backend endpoint and a narrow privileged helper (the engine must not run inside the backend's sandbox), then first-boot account and model choice. Then M1.6: ask the user to run the ISO and the install in VMware and VirtualBox and record the integration lockdown checklist. Consider committing the work first.
