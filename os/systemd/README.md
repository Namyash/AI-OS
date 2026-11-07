# systemd

systemd units for the platform services, each sandboxed. Milestone M1.3. Overlay root: `rootfs/`; chroot hooks: `hooks/`.

| File | Purpose |
|---|---|
| `rootfs/etc/systemd/system/pai-backend.service` | The backend API (`python3 -s -m backend` from `/opt/pai`; `-s` keeps the interpreter from loading code out of the service's own writable home), user `pai`, full sandbox. |
| `rootfs/usr/lib/sysusers.d/pai.conf` | System accounts `pai` (backend), `pai-llm` (model runtime, a later phase) and `pai-ui` (kiosk, M1.4). No unit uses the last two yet; they are created now so their UIDs are fixed in the image. `pai-ui` is a member of group `pai` so it can read, not write, the token; `pai-llm` joins no group. |
| `hooks/0200-enable-pai-backend.hook.chroot` | Creates the accounts (fixing their UIDs in the image) and enables the unit. |

The state directory `/var/lib/pai` is `0700` (private to `pai`); only `/run/pai`, which holds the token, is shared with the kiosk group.

`/opt/pai` (the code) is put there by the image installer step, and the Debian packages `python3-fastapi`, `python3-uvicorn` and
`python3-pydantic` must be in the package list; neither is wired into the build yet, so the unit cannot start on a built image until
that integration step lands.

## Unit policy

`tests/security/test_systemd_units.py` lints **every** `*.service` it finds under `os/**` in the directories systemd loads system units
from (`etc/systemd/system`, `usr/lib/systemd/system`, `lib/systemd/system`, `usr/local/lib/systemd/system`, `run/systemd/system`).
A new unit gets the baseline sandbox (see the policy tables in that file) or fails the test. It also fails on:

- **drop-ins** (`<unit>.service.d/*.conf`, `service.d/*.conf`): a drop-in changes a unit after the fact, so the lint of the unit file would
  say nothing about it. Put the setting in the unit file.
- **command lines run with full privileges**: an `Exec*=` command prefixed `+`, `!` or `!!` runs outside the unit's `User=`, capability
  bound and sandbox.
- **a `SystemCallFilter=` that systemd reads as weaker than it looks**: the first line must be an allow list (no `~`), `~` counts only at
  the very start of a value, and the `~@privileged @resources` removals must come after every line that allows calls.
- **writable paths** (`ReadWritePaths=`, `BindPaths=`) at `/`, `/run` or `/var`, or inside `/etc`, `/usr`, `/opt`, `/boot`, `/bin`, `/sbin`,
  `/lib`, `/lib64`, `/proc`, `/sys`, `/dev` or `/run/systemd`.

A unit may deviate only with a documented need, written as a comment line in the unit with a non-empty reason:

```
# pai-lint: root-justified: <reason>            runs as root; also needs NoNewPrivileges and a non-empty
                                                 CapabilityBoundingSet narrower than all capabilities
# pai-lint: capabilities-justified: <reason>    a non-root unit keeps the listed capabilities
# pai-lint: network-justified: <reason>         needs more than loopback IP traffic or extra socket families
# pai-lint: waive <Directive>: <reason>         one baseline, path or Exec* directive is deliberately weaker (never NoNewPrivileges)
```
