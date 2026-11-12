# installer (image component)

Puts the install tooling on the image. Milestone M1.5. The engine itself is `installer/` at the repository root (Python,
stdlib only) and is installed at `/opt/pai/installer` by `os/build/assemble-config.sh`, root-owned and read-only like the backend
and the kiosk. The contract it is built against is `docs/architecture/INSTALLER_DESIGN.md`. Overlay root: `rootfs/`; chroot
hooks: `hooks/`; packages: the "Installer" block of `os/configuration/package-lists/pai-base.list.chroot` (fdisk, dosfstools,
e2fsprogs, rsync, GRUB for BIOS and UEFI; **not** os-prober, which `tests/security/test_os_hardening.py` forbids).

| File | Purpose |
|---|---|
| `rootfs/etc/systemd/system/pai-install-auto.service` | Unattended install: starts only when the kernel command line has `pai.install=auto`; runs `install-auto.sh PAI-PLAN`. Root, so it carries the `# pai-lint:` justifications (root, `CAP_SYS_ADMIN`, and each sandbox directive it cannot keep, with its reason); offline `systemd-analyze security` score 3.9. No time limit, no restart. Logs to the journal and the console. |
| `rootfs/usr/lib/pai/install-auto.sh` | Waits for udev, finds the device labelled `PAI-PLAN`, mounts it read-only (`ro,nosuid,nodev,noexec`), checks `plan.json` is a regular file of at most 1 MiB, runs `python3 -s -B -m installer --plan <file>` from `/opt/pai`, unmounts. Never reads or prints the plan. No medium (or no plan) is "nothing to install", exit 0. The engine's exit status is its own. |
| `rootfs/etc/systemd/system/pai-selfcheck-crypt.service` | Self-check boots only (`pai.selfcheck=1`), before `pai-selfcheck.service`: gathers the facts the `root-encrypted` check needs. Runs as the self-check's account with only `CAP_DAC_READ_SEARCH`. |
| `rootfs/usr/lib/pai/selfcheck-crypt-facts.py` | The program that unit runs; see `docs/development/BOOT_TESTING.md`, "Installed-system checks". |
| `hooks/0400-enable-pai-installer.hook.chroot` | Enables both units. |

A normal boot and a plain self-check boot skip both units at once on their kernel-command-line condition; `pai-install-auto`
deliberately has no `Conflicts=` and does not pull in `systemd-udev-settle` (either would act on every boot).

## What the unit assumes about the engine (check these when an install fails with "Read-only file system" or "Operation not permitted")

* It writes only under `/run/pai-install` (the recovery key, per the design) and mounts the target below `/run/pai-install` or `/mnt`
  (`ReadWritePaths=`; everything else is read-only under `ProtectSystem=strict`).
* It needs no network, no kernel module loading by itself, no `sethostname`, no clock change and no namespaces.
* It copies the live root with one filesystem per `rsync` (`/usr/lib/modules` must stay visible, hence `ProtectKernelModules=no`).
* `after=poweroff` goes through systemd (`systemctl poweroff`), not the `reboot(2)` system call, which the unit's filter denies.

None of this was run against the real engine yet: the unit's sandbox is checked by the lint and `systemd-analyze` offline, and
`install-auto.sh` by `tests/end_to_end/test_installer_component.py` with the tools replaced. The end-to-end proof is
`docs/development/INSTALL_TESTING.md`.
