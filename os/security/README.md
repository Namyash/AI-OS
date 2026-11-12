# security

Security baseline copied into the image: firewall, sysctl, module lockdown, later AppArmor. Overlay root: `rootfs/`.

- `rootfs/etc/nftables.conf`, `sysctl.d/`, `modprobe.d/`: the firewall, kernel hardening and host-integration lockdown.
- `rootfs/usr/lib/pai/security-selfcheck.sh` and `pai-selfcheck.service`: the boot self-check (16 checks: the firewall, modules,
  sysctl, listeners, the backend, the kiosk, credentials in process state, default passwords). It only runs when the kernel command
  line has `pai.selfcheck=1`, as the unprivileged account `pai-selfcheck` with the three read-only capabilities its checks need.
  How it works, what each check proves and how to read a failure: `docs/development/BOOT_TESTING.md`.
- `rootfs/usr/lib/live/config/9980-pai-lock-live-user`: a live-config component that runs at boot, after Debian's own, and
  locks the well-known login live-config creates (and removes its passwordless sudo). Risk R16. The self-check's
  `no-default-credentials` check is what proves it on a booted image.
