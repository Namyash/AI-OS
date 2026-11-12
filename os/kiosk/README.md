# kiosk (image component)

Puts the kiosk on the image. Milestone M1.4b. Overlay root: `rootfs/`; chroot hooks: `hooks/`. The launcher itself is
`kiosk/` at the repository root and is installed at `/opt/pai/kiosk` by `os/build/assemble-config.sh`, next to the production
build of the frontend at `/opt/pai/frontend`; its packages are in `os/configuration/package-lists/pai-base.list.chroot`.

| File | Purpose |
|---|---|
| `rootfs/etc/systemd/system/pai-kiosk.service` | `cage` on tty1 as `pai-ui` through a PAM login session, running the launcher; after, and restarted with, `pai-backend.service`. Sandboxed; every deviation from the baseline carries a `# pai-lint:` justification with its measurement. |
| `rootfs/etc/chromium/policies/managed/pai-kiosk.json` | Chromium managed policy: only loopback URLs, no telemetry, sync, updates, background networking, downloads, extensions or capture devices. |
| `hooks/0300-enable-pai-kiosk.hook.chroot` | Enables the unit; masks `getty@tty1`, which also defeats the live image's tty1 autologin. |

The account `pai-ui` (and its membership of group `pai`, which lets it read the token) is defined by `os/systemd`.
