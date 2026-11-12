# Kiosk shell (milestone M1.4b)

The kiosk shows the web UI full screen on the image and hands the browser a session without a secret ever being on a
command line, in an environment, or in a URL. The design and its reasons are in
[KIOSK_SESSION_DESIGN](../architecture/KIOSK_SESSION_DESIGN.md); this page is how it is built, what was measured, how to
run and test it, and what is still unverified.

| Part | Where |
|---|---|
| The launcher, `python3 -m kiosk` (standard library only, imports nothing from `backend/`) | [`kiosk/`](../../kiosk/README.md) |
| The unit, the Chromium policy, the hook | [`os/kiosk/`](../../os/kiosk/README.md) |
| Packages | the end of `os/configuration/package-lists/pai-base.list.chroot` |
| UI build and installation of `/opt/pai/{backend,kiosk,frontend}` | `os/build/` (`build-frontend.sh`, `assemble-config.sh`) |
| Integration test without a virtual machine | `kiosk/tests/integration/` |

## What happens at boot

```
pai-backend.service        binds 127.0.0.1:<port>, publishes /run/pai/endpoint and /run/pai/token
pai-kiosk.service          user pai-ui, PAM login session on tty1, PartOf= the backend
  cage -d -- python3 -s -m kiosk
    1. wait (bounded) for the two files; refuse an endpoint that is not http://<loopback literal>:<port>
    2. POST /v1/session  (Authorization: Bearer <token>, no redirects, no proxies)  ->  {session_id, expires_in}
    3. empty private profile; start Chromium: DevTools pipe on descriptors 3/4, no secret in argv or environment
    4. over the pipe: Target.getTargets, Target.attachToTarget, Storage.setCookies (pai_session, HttpOnly,
       SameSite=Strict, host-only, expiry = now + expires_in), Page.navigate to the plain endpoint URL
    5. poll until the page is complete on the backend's origin and the app shell is in it; write /run/pai-ui/ready
    6. supervise: every PAI_KIOSK_STATUS_INTERVAL s look at the status bar (the ready file follows it), renew the
       session at 80 % of its lifetime (new POST, new cookie), exit non-zero when the browser dies
```

Exit status: 0 only when asked to stop (SIGTERM/SIGINT); 78 for an invalid setting or a missing browser (the unit does not
restart on it); 1 for everything else (restarted after `RestartSec=2`; systemd's default start limit gives up after five
failures in ten seconds). The launcher never logs, prints or stores the token or a session id (`kiosk/log.py` redacts both
anywhere in a log line, as a second line of defence) and its readiness file holds neither.

## Configuration

`PAI_ENDPOINT_FILE` and `PAI_TOKEN_FILE` are the backend's variables with the backend's defaults (a test keeps them equal).
Everything else is `PAI_KIOSK_*`; the unit sets none of them, the defaults match its `StateDirectory=`/`RuntimeDirectory=`.

| Variable | Default | Meaning |
|---|---|---|
| `PAI_ENDPOINT_FILE` / `PAI_TOKEN_FILE` | `/run/pai/endpoint` / `/run/pai/token` | What the backend publishes |
| `PAI_KIOSK_READY_FILE` | `/run/pai-ui/ready` | Readiness file (JSON, mode 0644, no secret) |
| `PAI_KIOSK_PROFILE_DIR` | `/var/lib/pai-ui/profile` | Private profile, deleted and recreated at every start; refused unless it is owned by the account and closed to others |
| `PAI_KIOSK_CHROMIUM` / `PAI_KIOSK_CHROMIUM_FLAGS` | `chromium` / none | Browser executable; extra flags (shell-style quoting) appended after the fixed ones |
| `PAI_KIOSK_HANDOFF_TIMEOUT` | 60 s | Backend files to appear; also how long a refused connection is retried |
| `PAI_KIOSK_REQUEST_TIMEOUT` | 10 s | One HTTP request |
| `PAI_KIOSK_BROWSER_TIMEOUT` | 60 s | One DevTools command; the page to appear |
| `PAI_KIOSK_RENDER_TIMEOUT` | 120 s | Page load and app shell. Generous on purpose: software CPU emulation (the QEMU boot test) starts Chromium many times slower than hardware |
| `PAI_KIOSK_STATUS_INTERVAL` | 5 s | Pause between two looks at the running page |

## Readiness: the contract with the frontend

The launcher reads the page through two selectors, both in `kiosk/readiness.py` and both checked against `frontend/src` by a
test, so a frontend change that breaks them fails a test:

| Constant | Value | Source in the frontend |
|---|---|---|
| `SHELL_SELECTOR` | `#root .app-shell` | `index.html` (`#root`), `App.tsx` (`className="app-shell"`) |
| `STATUS_SELECTOR` | `.app-shell section[aria-label="System status"] [role="status"]` | `StatusBar.tsx`: the first live status line, the backend's |

**Gap, reported and not fixed here (no edit under `frontend/**`):** the frontend has no dedicated machine-readable marker, so
these selectors lean on a CSS class and an accessibility label. A stable pair of attributes would be better, for example
`data-pai-shell="ready"` on the shell and `data-pai-backend="connected|connecting|unreachable|unauthorized"` on the backend
status line; then `readiness.py` would not depend on styling names or on translated words. Until then, "backend connected"
is only visible as the text the status bar shows, which the readiness file carries verbatim in `status_bar`.

The file, written when what it says changes:

```json
{"version":1,"state":"ready","shell_rendered":true,"status_bar":"Backend connected Version 0.0.1","updated":"2026-11-07T11:47:35+00:00"}
```

`state` is `ready` only while the shell is rendered. When the launcher exits, a `ready` file becomes `not-ready` (it never
outlives the process that wrote it); a `not-ready` record that says why the page never rendered is kept; a run that never
reached a page leaves no file.

## The browser

* **Command line**: `--app=data:text/html,...` and not `--app=about:blank` as the design text says. Measured on Debian's
  Chromium 156: `about:blank` as an app URL is treated as "no app" and opens a normal tabbed window with the new-tab page and
  an omnibox; any other URL gives an app window (one `page` target, no browser UI). `--kiosk` makes it full screen
  (1280x720 fullscreen under headless cage). `--ozone-platform=wayland`, `--disable-gpu` (software compositing, no GL or
  Vulkan probing), no `--no-sandbox` ever.
* **Environment**: built, not inherited: `PATH`, `LANG`, `LC_ALL`, `TZ`, `XDG_RUNTIME_DIR`, `XDG_SESSION_TYPE`,
  `WAYLAND_DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`, plus `HOME` and the XDG config/cache directories inside the private
  profile. No `PAI_*` variable reaches it. (Debian's `/usr/bin/chromium` wrapper adds its own flags and its public API-key
  variables from `/etc/chromium.d`; none is ours.)
* **Descriptors**: the DevTools pipe is two inherited descriptors, 3 (commands in) and 4 (replies out), made with
  `os.posix_spawn` file actions; every other descriptor Python opens is close-on-exec, and stdin is `/dev/null`.
* **Policy** (`/etc/chromium/policies/managed/pai-kiosk.json`, 41 policies, all reported "OK" by `chrome://policy`):
  `URLBlocklist ["*", chrome://*, chrome-untrusted://*, devtools://*, view-source:*, file://*, javascript:*]` with
  `URLAllowlist [http://127.0.0.1, http://[::1]]` (the URL filter has no CIDR and no wildcard port, so these two literals
  cover the backend's default address on any port; `*` alone does not block `chrome://` pages, measured); metrics, safe
  browsing, background mode, sync, sign-in, component updates, variations, network prediction, DNS-over-HTTPS and the built-in
  DNS client, media router (mDNS), spell-check, search suggestions, error-page lookups, downloads, file pickers, printing,
  extensions, password manager, geolocation/notifications/pop-ups/sensors/USB/serial/Bluetooth, microphone, camera and screen
  capture are off or denied. `https://example.com` is answered with `net::ERR_BLOCKED_BY_ADMINISTRATOR`.
* **DevTools, measured and not what the task assumed**: `DeveloperToolsAvailability=2` (DevTools disallowed) makes
  `Target.attachToTarget` fail with "Not allowed", so the launcher could neither navigate the page nor look at it. The pipe
  works with 0 and 1, so the policy sets 1, `RemoteDebuggingAllowed` true, and blocks the DevTools front-end URL
  (`devtools://*`). **Not verified**: whether F12 with a physical keyboard still opens a DevTools window that shows the
  page's HttpOnly cookie (headless cage has no input device). Someone at the console of the user's own VM can see the session
  id this way; they could not before the session id existed either, but it is a residual exposure to know about.
* **Crash reporting**: Chromium 156 starts `chrome_crashpad_handler` whatever `--disable-breakpad` or
  `--disable-crash-reporter` say (measured, so neither flag is passed). Nothing is uploaded: consent was never given
  (`settings.dat` records uploads off) and `MetricsReportingEnabled` is false. Local dumps land in the private profile (under
  `XDG_CONFIG_HOME`), which is emptied at the next start.

## The unit

`pai-kiosk.service` carries the sandbox baseline wherever the kiosk tolerates it. Each row was measured by starting the real
launcher and Chromium under that directive in a systemd 257 container (`--privileged`, headless cage) and checking that the
shell rendered and the renderers were sandboxed (own user namespace, seccomp mode 2, no capabilities):

| Directive | In the unit | Why it differs from the baseline (and how it was measured) |
|---|---|---|
| `ProtectHome` | `no` + `InaccessiblePaths=/home /root` | `yes` also hides `/run/user`, where logind creates `XDG_RUNTIME_DIR`: cage fails with "Unable to open Wayland socket". `read-only` and `tmpfs` variants failed or needed the account's uid (`%U` is 0 in a system unit) |
| `PrivateDevices` | `no` | cage and libseat look devices up by path before logind hands over descriptors. Not measurable headless; stated from how libseat's logind backend works |
| `ProcSubset` | `all` | `pid` makes the browser exit at start |
| `RestrictNamespaces` | `user pid net` | `user pid`, `user net` and the baseline `yes` all end in "No usable sandbox" |
| `MemoryDenyWriteExecute` | `no` | `yes`: the browser starts but never renders (V8) |
| `SystemCallFilter` | `@system-service @sandbox chroot`, `SystemCallErrorNumber=EPERM` | The baseline's `~@privileged` removes `chroot`, which the sandbox setup calls: "No usable sandbox". Without `chroot` the browser exits at once. Still an allow list. `mincore` and `pkey_alloc` stay denied (harmless EPERM log lines) |
| `RestrictAddressFamilies` | adds `AF_NETLINK` | libudev's uevent socket (cage's DRM and libinput backends). Chromium alone did not need it (`navigator.onLine` true without it). Stated from libudev, not measured headless |
| `IPAddressDeny`/`IPAddressAllow` | **not set** | See the next section |
| `DevicePolicy`/`DeviceAllow` | **not set** | See the next section |

Everything else of the baseline holds (`NoNewPrivileges`, empty `CapabilityBoundingSet`, `ProtectSystem=strict`, `PrivateTmp`,
`ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`, `RestrictRealtime`,
`RestrictSUIDSGID`, `LockPersonality`, `SystemCallArchitectures=native`, `UMask=0077`). `systemd-analyze security` scores the
unit 2.4 (the backend's is 1.1). Writable: `StateDirectory=pai-ui` (profile), `RuntimeDirectory=pai-ui` (ready file),
`/run/user` (the session's runtime directory). Nothing under `/var/lib/pai` or `/run/pai`.

### A consequence of `PAMName=login` that the baseline cannot see

With `PAMName=` logind moves the session's processes out of the unit's cgroup into `session-N.scope` under `user-<uid>.slice`
(`systemctl status` shows no tasks; `journalctl -u pai-kiosk.service` shows only systemd's lines, read the launcher with
`journalctl -t pai-kiosk`). Everything enforced by the process itself is inherited (mount namespace, seccomp, capabilities,
`NoNewPrivileges`; checked on every Chromium process) but **cgroup-attached controls are not**. Measured with the same
properties on a plain service and on one with `PAMName=login`: `IPAddressDeny=any` made `connect()` to an outside address time
out in the first and succeed in the second; `DevicePolicy=closed` refused `/dev/fuse` in the first and allowed it in the
second. So the unit sets neither, and a test fails if one is added: they would look like controls and do nothing. Egress is
confined by the system firewall (nftables output policy drop, loopback only) and by the browser's managed policy. **Follow-up
for the firewall (`os/security`, not touched here):** a `meta skuid` rule that lets `pai-ui` reach loopback only, which the
threat model's T4 already plans.

### tty1 and the live image's autologin

`hooks/0300-enable-pai-kiosk.hook.chroot` enables the unit and masks `getty@tty1.service`. live-config's getty generator
writes an autologin drop-in for `getty@tty1` to `getty@tty6` at boot; a masked unit ignores its drop-ins (checked with the
generator's file in place), so the kiosk owns tty1 and the autologin cannot start there. Serial consoles are other units
(`serial-getty@ttyS0`), untouched. **Not closed:** `getty@tty2` to `tty6` still get live-config's autologin, so someone at the
VM's keyboard can switch to a shell (cage runs without `-s`, but the kernel's VT switching is not disabled). That is risk R16
as documented; closing it means masking those gettys or the kernel parameter `live-config.nottyautologin`, a decision for
the image build and the boot harness (which compares kernel arguments).

`seatd` (a root daemon libseat1 can pull in) is not installed with systemd present (the dependency is satisfied by
`systemd`); the integration test and `FORBIDDEN_PACKAGES` keep it that way.

## Build pipeline

`build-iso.sh` mounts `os/`, `backend/`, `kiosk/` and `frontend/` read-only. `in-container-build.sh` runs
`build-frontend.sh` (a copy of `frontend/` without `node_modules` and `dist`; `npm ci --ignore-scripts` so the lockfile's
integrity hashes apply and no install hook runs; `npm run build`; only the **contents of `dist/`** are output), then
`assemble-config.sh <os> <backend> <kiosk> <frontend-dist> <config>`. The old `install_backend` is now `install_tree`, used for
all three trees: root-owned, directories 0755, files 0644, no symbolic links, no tests, caches or documentation in the Python
trees, `index.html` required in the frontend build. The builder image gains Debian's `nodejs` and `npm` (Node 20.19.2, npm
9.2.0; 201 MB to 602 MB). Building the frontend in that image took 49 s (38 s of it `npm ci`).

## Testing

| What | Command | Result on this machine |
|---|---|---|
| Unit tests (fake HTTP backend, fake Chromium on the real pipe protocol) | `python -m pytest -q kiosk` | Windows: 279 passed, 60 skipped (POSIX only: spawn, profile modes, launcher subprocesses). Debian 13 container: **339 passed**, none skipped |
| Image policy: units, packages, assembly, build scripts | `python -m pytest -q tests/security` | with `kiosk`: Windows 656 passed, 67 skipped; Debian 13 container (root): **723 passed**, none skipped |
| Integration, no virtual machine | `bash kiosk/tests/integration/run.sh` | RESULT PASS (every check below), 226 s of which 207 s are `apt` |
| Mutation check on a scratch copy | (not committed; described below) | 33 of 35 killed at first; the 2 survivors were weak tests, strengthened, then killed: 35 of 35 |

`kiosk/tests/` plays the backend with a real HTTP server and Chromium with `fake_chromium.py`, started exactly like the real
one (command line, environment, descriptors 3 and 4); the launcher under test runs as `python -m kiosk`, so exit status,
log, signals and files are the shipped ones. The skipped tests are skipped with their reason in the summary: a skipped
module is not a pass.

### Integration test (`kiosk/tests/integration/run.sh`)

A `debian:trixie-slim` container (`--init`, seccomp unconfined: Docker's default profile forbids the user namespaces
Chromium's sandbox is made of; the image's unit allows exactly those) installs the packages of `pai-base.list.chroot`
(minus kernel, live-boot, initramfs and VM tools), creates the image's accounts from `sysusers.d/pai.conf`, installs
`/opt/pai` with `assemble-config.sh`, runs the real backend as `pai`, then the real launcher under headless cage as `pai-ui`
with a test fixture (`tee_browser.py`) between launcher and Chromium that writes the DevTools conversation to a file (the
only way to learn the session id: it exists nowhere else in plain text). It checks: the UI is refused without a session
(401), so rendering it proves the cookie; the ready file says ready, shell rendered, "Backend connected"; the cookie
attributes and the plain navigate URL as Chromium received them; the recorded session id opens the UI (200) and the token is
not a valid cookie (401); **a scan of `/proc/*/cmdline` and `/proc/*/environ` of every process as root finds neither the
token nor the session id** (after a control that finds a token deliberately placed on a command line); no secret in the
ready file, the log, the profile or the runtime directory; every kiosk process runs as `pai-ui`; no `--no-sandbox` or
debugging port; every renderer in its own user namespace under seccomp; no listening socket outside loopback; a clean stop.

### Mutation check

Done once, on a scratch copy in a Linux container (not committed): 35 one-line mutations of the launcher (token in the URL,
redirects followed, proxies honoured, non-loopback endpoint accepted, cookie not HttpOnly / Lax / with a Domain / no expiry,
page without the shell counted as ready, wrong origin accepted, browser death ignored, `--no-sandbox`, a debugging port, the
whole environment inherited, profile not private / not cleared, session never renewed, ...), each run against the whole
`kiosk/` suite with `-x`. 33 were killed at first. Two survived and both were weak tests: the redirect test used a 307, which
urllib does not follow for a POST (a 301, 302 or 303 would have resent the token), and the status-line bound test compared
against the very constant it checked. Both tests were fixed (all five redirect statuses; the literal 200) and the two
mutations re-run: killed. The runner is a throw-away script; to repeat the idea, change one line of `kiosk/*.py` and run
`python -m pytest -x kiosk`.

### What the integration run printed

Real backend as `pai`, real built frontend (built in the builder image from a copy of `frontend/`), real launcher under
headless cage as `pai-ui`, real Chromium 156 with its sandbox, cage 0.2.0:

* backend published endpoint and token 0.7 s after start; launcher started to readiness file 1.1 s; the DevTools timeline had
  the cookie installed 0.48 s and the navigation 0.56 s after the launcher's first command; stop took 1.1 s.
* status bar text in the readiness file: `Backend connected Version 0.0.1`.
* scan of `/proc/*/cmdline` and `/proc/*/environ` as root: 23 processes, 0 findings for the bearer token and the session id.
* 20 listed packages install as 336 packages, 930 MiB (this container has no kernel, live-boot or VM tools).

### Size of the new packages

Measured by installing the base userland of the package list in `debian:trixie-slim`, then the four kiosk entries with
`--no-install-recommends`: 98 packages, 228 MiB installed before; 272 packages, 964 MiB after: **+174 packages, +718 MiB
installed**. Download about 198 MiB (sum of the `.deb` sizes). The 3002 new files compress to 183 MiB with `xz -6` and 254 MiB
with `gzip -6`, so the **ISO grows by roughly 185 to 255 MiB** depending on the squashfs compressor (not checked). Largest:
`chromium` 316 MiB, `libllvm19` 124, `chromium-common` 65, `mesa-libgallium` 41, `libgtk-3-common` 30, `libz3-4` 27,
`adwaita-icon-theme` 13, `libgtk-3-0t64` 10. The LLVM, Mesa, Z3, GTK and icon packages are hard dependencies of cage
(wlroots' GL stack) and Chromium (GTK), not choices; none ships a service, a socket or a setuid binary (checked). The code
under `/opt/pai` adds 84 KiB (kiosk) and 320 KiB (frontend).

## Operating notes

* Logs: `journalctl -t pai-kiosk` (see above). Readiness: `cat /run/pai-ui/ready`.
* `Restart=on-failure`: a browser that dies, a backend that restarts (`PartOf=`), a session that cannot be renewed after it
  expired, all end the launcher with status 1 and a fresh handoff follows. A wrong setting ends with 78 and stays down.
* Session lifetime is the backend's (`PAI_SESSION_TTL`, 12 h); the launcher renews at 80 % and keeps the old session while
  renewal fails.

## What was not verified

* A boot on a display: tty1, the VT hand-over (`TTYPath`, `TTYVTDisallocate`, `StandardInput=tty-fail`), logind's seat and the
  DRM and libinput backends of cage, input, and the pixman renderer on a real or emulated display adapter. The unit was
  started under systemd 257 with the real PAM session, sandbox and cage, but with `WLR_BACKENDS=headless` and without the TTY
  lines. The conductor's QEMU boot is the first test of those.
* F12 with a keyboard (see above), and the QEMU-under-TCG timing of Chromium (the timeouts are generous but unmeasured).
* GPU acceleration (out of scope), multi-seat, voice.
