# Boot testing (milestone M1.2)

The boot test starts the built ISO in a virtual machine, lets it reach `multi-user.target`, and has the image check
itself: the firewall, the module lockdown, the kernel hardening values, the listening sockets, the core services, the
backend service (running, unprivileged, loopback only, refusing anonymous requests, answering an authenticated one, sandboxed),
the kiosk (running as its own account with Chromium below it, and reporting that the shell rendered and the backend is
connected), that no process holds a live credential in its command line or environment, and that no account has a password
that ships in the image. The verdict is read from the VM's serial console. It runs on a machine with no hypervisor (risk R1): QEMU emulates the
CPU in software (TCG) inside a Docker container.

What a pass proves: the kernel, initrd and root filesystem on the ISO boot under QEMU, systemd reaches
`multi-user.target`, and the live system matches the security configuration the image ships (see
[the checks](#what-each-check-means)). What it does not prove: see [TCG limitations](#tcg-limitations).

## Running it

Needs Docker and an ISO. Build one with `bash os/build/build-iso.sh` (writes `dist/*.iso`), or point at one with `PAI_ISO`.

```bash
python -m pytest tests/end_to_end -m e2e -s          # the boot test; -s shows the console while it boots
python -m tests.end_to_end.boot_harness              # same boot, console output only, exit code 0 = passed
python -m tests.end_to_end.boot_harness --iso path/to/image.iso
python -m pytest tests/end_to_end                     # fast tests only; the boot test is deselected by default
```

The boot test **skips**, with the reason in the summary, when Docker is not reachable or no ISO is found. The first run
builds the QEMU image once (it downloads Debian packages, so it needs network access; about two minutes); later runs reuse it
because the image tag is derived from the Dockerfile's content. On the development machine (Windows 11, Docker Desktop, no KVM)
a boot of the image took roughly two minutes from `docker run` to the verdict before the kiosk was added. The self-check now also
waits for Chromium to start and the page to render (up to `PAI_SELFCHECK_KIOSK_TIMEOUT`, 300 s by default), so expect longer: a
boot of an image with the kiosk has not been timed yet.

The fast tests need no Docker. `test_selfcheck_script.py` runs the real self-check script under `bash` against a simulated
machine ([how](#the-simulated-machine)), so it needs a working `bash`. It is about 190 runs of the script; they are started
together (eight at a time) and each test reads its own finished run, so `tests/end_to_end` together with `tests/security` took
7 minutes 40 seconds on the development machine (Windows, where starting a process is slow; one run alone takes about six seconds,
because the script starts five `python3` programs and the backend's settings loader imports pydantic). Every `bash` on `PATH` is tried until
one runs (on Windows the first can be the WSL launcher with no distribution behind it, which fails every command while Git Bash
is further down `PATH`), so the result does not depend on which shell pytest was started from. Without any working `bash` those
tests skip, and the skip reason says so: look for it in the summary, because a skipped module is not a pass.

### Exit status of the command line

| Code | Meaning |
|---|---|
| 0 | The self-check ran and passed |
| 1 | The self-check ran and did not pass (the problems are printed) |
| 2 | The boot could not be performed: an unusable environment variable, no ISO, Docker unreachable, the QEMU image failed to build or timed out, or the container failed before the guest printed a verdict. These say nothing about the image. In pytest the same cases are a setup error of the boot test, not a failed assertion |

### Environment variables

All optional.

| Variable | Default | Meaning |
|---|---|---|
| `PAI_ISO` | newest `dist/*.iso` | ISO to boot. Set but not a file: the test skips and says so, it does not fall back to `dist/` |
| `PAI_BOOT_TIMEOUT` | `1800` | Overall limit in seconds for one boot. Software emulation is slow and a loaded machine slower still |
| `PAI_QEMU_MEMORY` | `3072` | Guest RAM in MiB (a whole number). The kiosk's Chromium under software emulation needs more than the 2048 the backend-only image ran in |
| `PAI_BOOT_EXTRA_ARGS` | none | Words appended to the guest's kernel command line, after the harness's own (`boot=live components console=ttyS0 pai.selfcheck=1 panic=-1`). For looking inside a failing image without rebuilding it, e.g. `PAI_BOOT_EXTRA_ARGS="systemd.journald.forward_to_console=1"` makes systemd print the journal on the serial console. Printable ASCII only (no newline, tab or escape), at most 512 characters, runs of spaces become one; anything else is refused with the variable's name and the boot does not start. The words reach QEMU through the `--extra-kernel-args=...` argument of `container_boot.py` (one argument, validated again there) |
| `PAI_QEMU_CPUS` | `2` | Guest CPUs (a whole number; emulated, they share the container's host threads) |
| `PAI_SELFCHECK_READY_TIMEOUT` | `120` | Read by the self-check script, not the harness: whole seconds it waits for the backend to finish starting. The simulated runs of the script tests set it to `0`. A value that is not a whole number makes the backend checks fail with that reason |
| `PAI_SELFCHECK_KIOSK_TIMEOUT` | `300` | Read by the self-check script, not the harness: whole seconds, one budget for everything it waits for about the kiosk (the unit becoming active, Chromium running below it, the readiness file saying ready). The launcher's own bounds add up to 240 s (backend files 60, browser 60, page 120), so the default is one full attempt with margin. The simulated runs of the script tests set it to `0`. A value that is not a whole number makes both kiosk checks fail with that reason. |

A value that is not a finite number of at least 1 (`abc`, `0`, `-3`, `nan`, `inf`) is rejected with the variable's name, and so
is a fractional memory or CPU count (`1.9`), which would otherwise be truncated to a different size.

## How it works

1. **Image.** `tests/end_to_end/Dockerfile`: `debian:trixie-slim` with `qemu-system-x86`, `xorriso` and `python3`. Everything is
   pinned (threat T12): the base image by digest and the packages by a `snapshot.debian.org` timestamp, so the same file builds
   the same image on every machine. The tag is `pai-e2e-qemu:<12 hex digits of the Dockerfile's SHA-256>`, so editing a pin builds a
   new image on the next run. The pins do not move by themselves: see [Updating the pins](#updating-the-pins).
2. **Container.** One `docker run --rm` with a unique name per boot. No network (`--network none`), no capabilities
   (`--cap-drop ALL`), `no-new-privileges`, read-only root with a small tmpfs for the extracted kernel, a process limit, an
   unprivileged user. The ISO and the harness directory are mounted read-only. Nothing is ever mounted writable from the repository.
3. **Kernel and initrd.** `container_boot.py` lists the ISO with `xorriso` and picks the kernel and initrd from the
   listing: a `vmlinuz*` and an `initrd*` that share a directory and a version suffix, preferring the directory that holds
   the squashfs and then the highest version. No kernel version or path is written down anywhere, so a different media directory
   or kernel naming works unchanged. The kernel *arguments* are not read from the ISO (see step 5). They are extracted without
   mounting the ISO.
4. **QEMU.** `qemu-system-x86_64 -accel tcg -machine pc -cpu max`, `-nographic` with the serial port on stdio, the ISO
   attached as a **read-only CD-ROM** (live-boot searches the block devices for the squashfs), a user-mode NIC with
   `restrict=on` (the guest gets DHCP from QEMU and has no route anywhere else), a virtio RNG so boot does not wait for
   entropy, `-no-reboot`.
5. **Kernel command line.** `boot=live components console=ttyS0 pai.selfcheck=1 panic=-1`, without `quiet`.
   - `boot=live components` are the words the build bakes into the ISO (`--bootappend-live` in `os/build/in-container-build.sh`);
     a test fails when the build gains a word the harness does not pass, so the two cannot drift silently. A medium that boots
     differently (another `boot=` value) would need its own arguments.
   - `pai.selfcheck=1` makes `pai-selfcheck.service` run; on a normal boot the unit is skipped by its `ConditionKernelCommandLine=`.
   - `panic=-1` makes a kernel panic, or live-boot failing to find its medium, reboot at once, and `-no-reboot` turns that into QEMU
     exiting. Measured on the ISO without a CD-ROM: without it the guest sat in an initramfs shell (which waits for input that never
     comes, QEMU's stdin is `/dev/null`) and was still running after 200 s, so a broken image cost the full timeout; with it QEMU
     exited after 108 s with `Rebooting automatically due to panic= boot argument`.
6. **In the guest.** `pai-selfcheck.service` (enabled at build time by `os/security/hooks/0100-enable-selfcheck.hook.chroot`)
   starts after `multi-user.target`, `nftables.service`, `systemd-networkd.service`, `pai-backend.service` and
   `pai-kiosk.service`, runs `/usr/lib/pai/security-selfcheck.sh` as the unprivileged user `pai-selfcheck` (a member of the
   backend's group, so it can read the bearer token), prints the verdict to the journal and the console, and powers the machine off
   (`SuccessAction=` and `FailureAction=poweroff-force`), whatever the outcome. `TimeoutStartSec=` is 900 s: the script waits up to
   120 s for the backend and then up to 300 s for the kiosk, and a test keeps the limit above their sum. The account holds exactly
   three capabilities, each for one check and none of them able to write: `CAP_NET_ADMIN` (listing the firewall),
   `CAP_SYS_PTRACE` (reading other accounts' `/proc/<pid>/environ`) and `CAP_DAC_READ_SEARCH` (reading the root-only
   `/etc/shadow`). It does not run as root: as uid 0 `systemctl` would reach PID 1 over its private socket, which accepts root
   without any capability, so a flaw in a check could start units outside the unit's sandbox.
7. **Streaming and ending.** The harness streams the serial output and stops at the first of: the container exits (the
   guest powered itself off); the guest printed its final `RESULT` line (it then waits up to 60 s for the power-off); the
   overall timeout. The container is removed in every case, also on an exception or Ctrl-C. Only the container the run
   started is touched. A container that exits with a non-zero status **before** any `RESULT` line is not a self-check failure: it
   is reported as a boot that could not be performed (`cannot boot: the boot container exited with status N ...`, with the last
   output), because docker, the ISO or the emulator failed.
8. **Verdict.** `selfcheck_output.parse_selfcheck()` reads the `PAI-SELFCHECK|...` lines; `selfcheck_problems()` decides.
   **A boot that never prints the final `RESULT` line is a failure, never a pass, and so is a run that checked nothing**: the
   output must contain every check in `REQUIRED_CHECKS` (the sixteen below; an *installed* system adds `INSTALLED_ONLY_CHECKS`, two more, see "Installed-system checks"), so `RESULT|PASS|0/0`, an unrelated check with a matching
   count, or an ISO built before a check existed cannot pass. `REQUIRED_CHECKS` is written down in `selfcheck_output.py` on
   purpose instead of being read from the script (a script edited to drop a check must not lower the bar the harness holds an
   image to); `test_selfcheck_wiring.py` keeps it equal to the script's `CHECKS` table, in order, and checks that every table
   entry is a defined function, that none is listed twice and that no `check_*` function is left out of the table. The required set depends on what was booted
   (`required_checks(installed=...)`): the boot test of the ISO is a live session and requires the sixteen; the install test
   (`docs/development/INSTALL_TESTING.md`) boots an installed disk and requires eighteen. Output that reports an installed-only check on
   a live boot, or lacks one on an installed boot, is a failure either way: image and harness disagree about what was booted.

### The console is untrusted

The text on the serial console comes from the ISO under test. The harness parses the raw output in memory, but everything shown
to a person (the live echo, the failure message's last lines, the saved `pai-e2e-last-boot.log`) has control and format
characters replaced by visible markers (`<ESC>`, `<U+0007>`), so a hostile image cannot set your clipboard or window title, query
your terminal, or redraw earlier lines. The `<ESC>` marker is the same one the parser fixtures use. A failing live echo (a closed
pipe, a terminal that cannot encode a character) stops the echo only; the run and the verdict are unaffected and the command line
says so.

### Output format

One line per check, then one summary line:

```
PAI-SELFCHECK|<name>|PASS|<detail>
PAI-SELFCHECK|<name>|FAIL|<detail>
PAI-SELFCHECK|RESULT|PASS|<passed>/<total>        (RESULT|FAIL when any check failed)
```

On the console journald puts a prefix in front (`[   72.437420] security-selfcheck.sh[928]: `), and kernel messages, ANSI
colour codes, carriage returns and half-redrawn status lines can surround a line. The parser searches for the pattern
inside each line and ignores everything else. It also cross-checks the summary: the `<passed>/<total>` counts must match
the check lines it found, so a check line lost to console noise is reported instead of silently dropped.

## What each check means

Expectations come from the image's own files, read at run time, or from a policy table at the top of the script. The only
values the script repeats from `os/security/rootfs/etc` are the policy floor of the firewall (the hooks `input`, `forward`,
`output`, which threat model invariant 5 and the baseline require to be default-drop whatever the file says).

| Check | Passes when | Where the expectation comes from |
|---|---|---|
| `live-root` | the script looked at the real `/proc` and `/etc` | The script has a test-only `PAI_SELFCHECK_ROOT` prefix so it can be run against a simulated tree; this check fails whenever it is set, so a simulated run can never report overall success |
| `nft-default-drop` | in `nft -j list ruleset`: each of `input`, `forward`, `output` has at least one `filter` base chain and every such chain has `policy drop`; **no such chain accepts unconditionally** (a catch-all `accept` rule, also one reached through an unconditional `jump` or `goto`, turns policy drop into accept-everything); and **every base chain `/etc/nftables.conf` declares is loaded** with the hook, type and policy it was declared with | Policy table `REQUIRED_DROP_HOOKS` (the floor) and the shipped `nftables.conf` (read at run time). A hook with no chain at all fails: an empty ruleset must not pass. A rule counts as conditional when it holds a `match`, `limit` or `quota` statement; any other statement before an `accept` still leaves it unconditional. The file is read with a small parser of base-chain declarations (`table`, `chain`, `type ... hook ...; policy ...;`); a file with no base chain fails with "nothing to verify" |
| `modules-blocked` | every `install <module> /bin/false` (or `/bin/true`) line under `/etc/modprobe.d/*.conf` is really blocked: the module is not in `/proc/modules`, and a `modprobe -n -v` dry run shows modprobe would run that blocking command | The `modprobe.d` files themselves. No such line at all fails: there would be nothing to verify. Only the dry run is ever executed: a real `modprobe` after it would only run `/bin/false`, whose outcome is fixed by the line already proven, and (without `CAP_SYS_MODULE`, which the unit does not have) could not load anything anyway, so the check can never load a module |
| `sysctl-live` | every `key = value` under `/etc/sysctl.d/*.conf` equals the live value in `/proc/sys` | The `sysctl.d` files (later lines win, as `systemd-sysctl` does; a `-key` prefix means "optional"; whitespace is normalised so `/proc/sys` tabs match config spaces). Does not use the `sysctl` binary. Wildcard keys are not supported and fail loudly |
| `no-external-listeners` | no TCP socket in `LISTEN` and no unconnected bound UDP socket on any address other than loopback (`127.0.0.0/8`, `::1`, `::ffff:127.x`), in `/proc/net/tcp`, `tcp6`, `udp`, `udp6`, other than the allow-table entries | Allow-table `LISTEN_ALLOW` in the script, one line and one justification per entry, found by booting the image: UDP 68 and UDP6 546, the DHCP client sockets. An entry covers a socket bound to **one specific address only**: a wildcard bind (`0.0.0.0`, `::`, `::ffff:0.0.0.0`) is never allowed, because the firewall rule that justifies the entry (server replies, source port 67 or 547, from any source address) would then admit traffic from the whole network to it. The detail lists every exception that was used |
| `units-active` | `nftables.service` and `systemd-networkd.service` are `active` | Policy table `REQUIRED_ACTIVE_UNITS` |
| `backend-active` | `pai-backend.service` is up and answering: within `PAI_SELFCHECK_READY_TIMEOUT` seconds the unit is `active` (a unit that is `failed` or not installed ends the wait at once), its port accepts a connection and its token file exists and is not empty. A unit with `EnvironmentFile=` fails: the script cannot see what such a file sets | `BACKEND_UNIT`. The address, port and token path come from the backend's own settings loader (`backend.core.config.load_settings`, in `/opt/pai`) fed with the `Environment=` that `systemctl show` reports for the unit, so no default is repeated in the script |
| `backend-unprivileged` | the unit names a `User=` that exists and is not uid 0, and the main process (`/proc/<MainPID>/status`) has that uid as real, effective, saved and filesystem uid, no effective capability and `NoNewPrivs` 1 | The unit as systemd loaded it. Needs the process's own `/proc` entry, which `pai-selfcheck.service` therefore does not hide (`ProtectProc` waiver) |
| `backend-loopback-only` | something listens on the configured address, and every TCP listener on the backend's port is a loopback address | `/proc/net/tcp` and `tcp6`, the configured port from the settings loader. A backend that opens a wildcard socket fails this check and `no-external-listeners` |
| `backend-refuses-anonymous` | `GET /health` without credentials is answered `401` (a redirect is not followed and is reported as it is) | The backend's documented contract |
| `backend-health` | `GET /health` with the bearer token from the token file is answered `200` with a body holding `status` `ok`, an integer `schema_version` and a text `version`. The token is read to authenticate this one request and is never printed | The backend's `HealthResponse` model |
| `backend-sandbox-exposure` | `systemd-analyze security` scores the running unit at most `BACKEND_MAX_EXPOSURE_TENTHS` (1.2; the shipped unit scores 1.1) | Policy value in the script, with the measurement that sets it. It scores the unit as the running systemd loaded it, drop-ins and overrides included, which the lint of the file cannot see |
| `kiosk-active` | `pai-kiosk.service` is up as its own account with the browser running: within `PAI_SELFCHECK_KIOSK_TIMEOUT` seconds the unit is `active` (a unit that is `failed` or not installed ends the wait at once), its `User=` names an existing account that is not uid 0, the main process (`/proc/<MainPID>/status`) has that uid as real, effective, saved and filesystem uid, and a process with the browser's name is among the **descendants** of that main process (parent links in `/proc/<pid>/stat`, so cage's launcher and every Chromium child count) | `KIOSK_UNIT`. The account is the unit's `User=` as systemd loaded it; the browser's name is the basename of `settings.chromium` from the kiosk's own settings loader (`kiosk.config.load_settings`, in `/opt/pai`, fed with the unit's `Environment=`, so a different `PAI_KIOSK_CHROMIUM` is followed and no browser name is written in the script). The process name is the 15 characters the kernel keeps, so a longer name is cut the same way. A kiosk that systemd restarts during the wait has a new main process whose browser is not below the old pid: when the unit names another `MainPID` after the wait, the probe looks once more (without waiting) at the new one and the checks judge it. A main process that is gone when the check looks is said to be gone (`the main process of pai-kiosk.service, pid N, is gone (cannot read /proc/N/status)`) with what systemd reports now: `systemd still names that pid`, or `systemd now reports MainPID=M`, which means the unit restarted or died after the wait began. **When either kiosk check fails, its detail ends with the unit's state and journal** (below) |
| `kiosk-ready` | the readiness file the kiosk publishes says the page is up: it is a JSON object with the schema `version` of `kiosk/readiness.py`, `state` `ready`, `shell_rendered` `true`, and a `status_bar` that is `Backend connected` or starts with `Backend connected ` (a connecting, unreachable or no-session page does not match, and neither does a longer word that merely starts with it) | The file's path from the kiosk's settings loader (`PAI_KIOSK_READY_FILE`, default `/run/pai-ui/ready`), the version and state names from `kiosk.readiness` itself, and the label from the script's `KIOSK_BACKEND_CONNECTED_LABEL`, which a test keeps equal to `frontend/src/components/StatusBar.tsx` (the readiness file carries no machine-readable "connected" fact, only that line's text). The same wait as `kiosk-active`, one budget for both. Anything the file holds is cut to 60 characters before it reaches the detail |
| `no-secret-in-process-state` | no process holds a live credential in its argument list or environment. For **every** process under `/proc` the script reads `cmdline` and `environ`; the bearer token (read from the token file inside the checking program, never passed to it) must not occur in either, and every *credential-shaped* string (urlsafe base64 characters, exactly 43 of them, bounded by other characters: what `secrets.token_urlsafe(32)` makes) is sent to the backend as a bearer token and as the `pai_session` cookie (`GET /health`) and must get anything but a `200`. A browser session id is not known to the check, which is why candidates are tried against the live backend instead of looked up. It also fails when a process's files cannot be read (a process that ended meanwhile is skipped, any other error is named), when the backend does not answer a candidate, when there are more than 200 candidates (testing only some would prove nothing), and when no process could be examined | The token file and the endpoint file are the paths the backend's settings loader gives (the backend unit's `Environment=`); the request goes to the loopback `http` origin the backend published in the endpoint file, and the check refuses any other (a name, or an address beyond loopback), so a candidate is never sent anywhere else. `CREDENTIAL_LENGTH` and `SESSION_COOKIE` are tables in the script that a test keeps equal to `backend/api/auth.py` and `backend/api/sessions.py`. The detail holds counts, process ids and process names only: never the token, a session id or a candidate, whether the backend accepted it or not (every simulated run asserts that). A secret glued to other urlsafe characters is not a credential-shaped string; the token itself is still found by the substring search, a session id is not |
| `no-default-credentials` | every account in `/etc/shadow` has a lock marker (`!` or `*`, also with a hash behind it) as its password field, and the file's mode gives nothing to "other". An account with a usable hash, **or an empty field** (a login that needs no password), fails and is named; a malformed line, an empty file, an unreadable file and a mode that cannot be read fail too | The file itself. Hashes are never printed, only account names. Reading the root-only file needs `CAP_DAC_READ_SEARCH`, the mode alone needs nothing. On the image this proves the live-config component `os/security/rootfs/usr/lib/live/config/9980-pai-lock-live-user` worked (risk R16, below) |

The script runs every check even when one fails; a check that crashes counts as a failure and the rest still report.
If the script itself dies before the summary, a trap prints `RESULT|FAIL|self-check aborted before completion`. A script whose
`CHECKS` table is empty prints `RESULT|FAIL|0/0` and exits 1 instead of reading zero of zero as success.

The backend checks share one probe: `probe_backend` runs before any check, waits for the unit, and has one `python3` process
(`-s -B`, so no per-user site code and no bytecode) ask the running service its questions; a failing probe is recorded and
reported by each check that needs its answer. A crashed probe fails those checks with the crash's last line and never stops the others.
`probe_kiosk` does the same for the kiosk, after the backend wait: it waits for the unit, then one more `python3` process waits (one
budget, `PAI_SELFCHECK_KIOSK_TIMEOUT`) until a browser process exists below the main process and the readiness file says ready, and
reports each fact. The details of a failing `kiosk-active` or `kiosk-ready` end with what systemd reports for the unit (`ActiveState`, `SubState`, `Result`, `MainPID`, `ExecMainStatus`, `ExecMainCode`, `NRestarts`, from `systemctl show`) and the last 20 lines of the unit's journal (`journalctl -u <unit> -n 20 --no-pager -o cat`), lines joined by ` / ` and each cut to 160 characters, so the cause can be read from the console alone. Anything shaped like a credential in them (a run of 43 or more urlsafe base64 characters) is replaced by `[masked]` as a precaution; a call that fails says so in the text (`journalctl failed: ...`, `the journal of ... has no line`); each call is bounded to 20 s and made after the wait, so none stretches it. A detail is cut at 4000 characters (`DETAIL_LIMIT`). The journal is readable because the unit has `CAP_DAC_READ_SEARCH`; that has not been confirmed on a booted image. `no-secret-in-process-state` is its own program (it needs the backend's token and endpoint, and the whole process
table), and `no-default-credentials` is plain bash. The three programs share one loader of a service's settings from its unit's
`Environment=` (`PY_UNIT_SETTINGS`) and one HTTP client (`PY_HTTP`).

### Installed-system checks

The script decides from the running system whether it is a live session (`is_live_session`: `boot=live` on the kernel command line, or
the medium mounted at `/run/live/medium`; a command line that cannot be read counts as installed, which only adds checks). A live
session runs the sixteen checks above and prints exactly those. An installed system (milestone M1.5, `docs/architecture/INSTALLER_DESIGN.md`)
prints them and then two more, from the `INSTALLED_CHECKS` table, so a successful installed boot reports `RESULT|PASS|18/18`.

| Check | Passes when | Source and notes |
|---|---|---|
| `root-encrypted` | the root filesystem is on a device-mapper mapping whose uuid says dm-crypt LUKS2 (`CRYPT-LUKS2-...`), the LUKS header is version 2, there is at least one keyslot and **every** keyslot derives its key with `argon2id` (a `pbkdf2` or `argon2i` slot fails and is named) | Facts file `/run/pai-selfcheck/crypt-facts`, written by `pai-selfcheck-crypt.service` (`os/installer/rootfs/usr/lib/pai/selfcheck-crypt-facts.py`) because the self-check's own sandbox has a private `/dev` and cannot open the block device. That unit is the self-check's account with one capability, `CAP_DAC_READ_SEARCH`, and runs `cryptsetup luksDump --dump-json-metadata` on the one device under the mapping; salts and digests never reach the facts. A missing file, `error=` or a missing fact fails. On a live session the unit records only that the root is not on a mapping |
| `no-live-remnants` | no installed package named `live-boot*`, `live-config*` or `live-tools*` (removed with only configuration left is fine), no `/etc/live`, no account whose full name is the one live-config writes ("Debian Live user"; the account's name is not assumed), no `ExecStart=` with `--autologin` or `--skip-login` in any unit or drop-in under `/etc`, `/usr/lib`, or `/run/systemd` (generator output included), no `NOPASSWD` rule in `/etc/sudoers` or `/etc/sudoers.d` | `/var/lib/dpkg/status`, `/etc/passwd`, the systemd unit directories and the sudoers files; an unreadable package database or passwd file fails. That no account has a usable password is `no-default-credentials`, which runs in both modes |

Limits: a live user whose full name was changed with a live-config option is caught by the package and `/etc/live` rules, not by the
name rule. The facts program was run against a real LUKS2 volume (loop device, argon2id and pbkdf2 keyslots) as an unprivileged
user holding only `CAP_DAC_READ_SEARCH`; the unit's systemd sandbox around it has been checked offline only.

### The simulated machine

`tests/end_to_end/selfcheck_sim.py` builds a machine the real script can be run against without booting anything, using the
script's test-only `PAI_SELFCHECK_ROOT` prefix (it redirects `/proc`, `/etc` and `/opt`) and fakes of the commands it runs,
placed first on `PATH`. Each fake refuses an argument list the script is not meant to send, so a changed command line fails a
test instead of differing silently from the real tool:

| Simulated | How |
|---|---|
| `nft`, `modprobe`, `systemctl is-active`, `systemd-analyze security`, `id -u`, `stat -c %a` | Small `sh` fakes reading files in a state directory (`stat` answers from a per-file mode, because a Windows checkout has no real modes). `modprobe` only ever answers a dry run and logs every call; `systemd-analyze` prints the real report of the backend unit (`fixtures/systemd_analyze_security_backend.txt`) with the verdict a scenario chooses |
| `systemctl show` | Answers only the properties asked for, from a per-unit file (`LoadState`, `ActiveState`, `User`, `MainPID`, `Environment`, `EnvironmentFiles`) for the backend and the kiosk unit; a unit can report `activating` for the first N calls, the command can fail, and a scenario can have something appear (a browser process, the readiness file) a few seconds after the script first asks about the unit |
| `/proc`, `/etc`, `/proc/<pid>/{status,stat,comm,cmdline,environ}` | Files in a temporary tree: every simulated process has the five files, as the kernel shows them (NUL-separated argument list and environment). The default machine has init, the backend, an unrelated daemon holding one credential-shaped string that is no credential, and the kiosk's cage -> launcher -> Chromium tree; `/etc/shadow` holds only locked accounts |
| The backend's and the kiosk's code | A copy of the real `backend/core/config.py` and of the real `kiosk/{config,errors,readiness}.py` under `/opt/pai` (the readiness file of the simulated kiosk is written by the kiosk's own `write_ready_file`). The simulated `python3` hides the repository's own editable install, so a missing app directory is a failure here as it would be on the image |
| The backend service | A real HTTP server on a loopback port: `401` without credentials, `200` and the documented body (built by the backend's own `HealthResponse` model) with the right bearer token, or with a live session id as the `pai_session` cookie when the request has no `Authorization` header (as the backend's guard does); a scenario can make it answer anything else, drop connections, or stop |

Every simulated run also checks that the output never contains the backend's token, a live session id or the string that only looked like a credential. The `live-root` check always fails under the
prefix (a simulated run can never report overall success), and passes in a scenario that runs without it.

`test_selfcheck_script.py` is a table of scenarios, one run of the script each: a healthy machine, and for every check at least
one break per thing it guards, with the exact set of checks that must then fail, text their details must contain, and the
summary count. The scenarios of a session are started together on a thread pool (`MAX_PARALLEL_RUNS`), so a `-k` selection runs
only the selected ones.

### Adding a check

Write `check_<what>()` in `security-selfcheck.sh` (print a one-line detail, return 0 or non-zero, handle every failure
explicitly instead of relying on `set -e`), add `<name>:check_<what>` to the `CHECKS` table **and to `REQUIRED_CHECKS` in
`tests/end_to_end/selfcheck_output.py`** (`test_selfcheck_wiring.py` fails until both agree), teach the simulated machine to
break it if it needs state the simulation lacks, and add scenarios for both outcomes to `tests/end_to_end/test_selfcheck_script.py`.
Refresh the `serial_*.log` fixtures from a real boot of an ISO that has the check (see below), and run `shellcheck` on the script. A check that reads
another service's state through that service's own settings loader needs that code in the simulated machine (`selfcheck_sim.py` copies it from the repository).

### Regenerating the shipped-ruleset fixture

`tests/end_to_end/fixtures/nft_ruleset_shipped.json` is what real `nft` (v1.1.3) printed after loading the shipped
`nftables.conf`; one script scenario feeds it, with that file, through the `nft-default-drop` check, so the script's reading of nft's
JSON is tested against the real thing. If `nftables.conf` changes in a way that changes chains, regenerate it:

```bash
docker run --rm --cap-add NET_ADMIN -v "$PWD/os/security/rootfs/etc/nftables.conf:/t/nftables.conf:ro" \
  debian:trixie-slim sh -c 'apt-get update -qq && apt-get install -y -qq nftables >/dev/null && nft -f /t/nftables.conf && nft -j list ruleset' \
  > tests/end_to_end/fixtures/nft_ruleset_shipped.json
```

### The serial-log fixtures

`fixtures/serial_installed_all_pass.log` is `serial_all_pass.log` brought to an installed boot by hand: the two installed-only check lines
(in the script's own wording), `RESULT|PASS|18/18`, a kernel line with `root=/dev/mapper/cryptroot` instead of `boot=live` and
"Booting from Hard Disk". It is not a capture; replace it with one from the install test's `pai-e2e-last-installed-boot-bios.log`.

`fixtures/serial_all_pass.log` is an excerpt of the saved console log (`pai-e2e-last-boot.log`) of one real boot of the ISO, with
the checks passing; the harness's `<ESC>` / `<U+000D>` markers are kept, and `test_selfcheck_output.py` turns them back into
the characters before parsing. `serial_one_failure.log` is that excerpt with one check line replaced by a failure and the summary
changed to 15/16, and `serial_no_result.log` is that excerpt cut before the summary; `serial_garbage.log` is boot noise with no
self-check. **The excerpt is from the boot that printed 12/12.** It was brought up to the 16 checks by hand: the four new check lines
(in the script's own wording, with plausible numbers), the kiosk unit in the status stream (no getty on tty1), later timestamps (the
self-check now waits for the kiosk) and the new memory default in the QEMU command line were composed around the captured lines. No
boot of an image with the kiosk has been captured yet; replace the fixtures with an excerpt of one as soon as there is one. To refresh after a check is added: boot a rebuilt ISO (`python -m pytest -m e2e tests/end_to_end -s`), keep the
head of the log, the status noise before the first check line, every `PAI-SELFCHECK` line, and the start of the shutdown, and
check with `grep -i token` that the only mentions are the script's own wording (a test does this too).

### Updating the pins

`tests/end_to_end/Dockerfile` pins `DEBIAN_IMAGE` (the base image digest) and `SNAPSHOT` (a `snapshot.debian.org` timestamp for the
`debian` and `debian-security` archives). They never refresh by themselves, which is the price of a QEMU that does not change
under the test. To take newer QEMU or xorriso fixes, move both together:

```bash
docker pull debian:trixie-slim
docker image inspect debian:trixie-slim --format '{{index .RepoDigests 0}}'                 # -> DEBIAN_IMAGE
docker run --rm debian:trixie-slim grep -m1 snapshot.debian.org /etc/apt/sources.list.d/debian.sources   # -> SNAPSHOT
```

Editing either value changes the Dockerfile's hash, so the next run builds a new image. Remove the old one with
`docker image rm pai-e2e-qemu:<old tag>` when you no longer need it.

## Reading a failure

The pytest failure message lists the problems and the last 80 console lines. The full console output of the latest boot is
saved to `pai-e2e-last-boot.log` in the operating system's temporary directory (replaced by every run; the path is printed by
`-s` and by the command-line harness; control characters in it are written as `<ESC>`-style markers).

| What you see | What it means |
|---|---|
| `no PAI-SELFCHECK output` and a normal boot log | The ISO boots but does not contain the self-check: it was built before the unit and script existed, or the hook did not run. Rebuild the ISO. Check `dist/` holds the ISO you meant (`PAI_ISO` overrides) |
| `no PAI-SELFCHECK output` and the log ends with `BOOT FAILED!` / `Unable to find a medium containing a live file system` / `Rebooting automatically due to panic= boot argument` | live-boot could not find the squashfs on the medium: a media layout or squashfs path problem, not the self-check. The guest rebooted and QEMU exited, so this ends in about two minutes instead of the timeout |
| `no PAI-SELFCHECK output` and the log stops early | The guest hung or crashed before userspace; read the kernel and initrd messages. Under TCG a slow boot is normal, a stall is not |
| `the boot timed out` | Nothing finished within `PAI_BOOT_TIMEOUT`; the last console lines show where it was. Raise the limit before assuming a hang |
| `required check(s) missing from the output: ...` | The run printed some checks but not all that this harness expects. The usual cause is an ISO built from an older `security-selfcheck.sh` (rebuild it); the other is console output that was lost |
| `backend-active FAILED: pai-backend.service is ...` (with the other `backend-*` checks failing too) | The backend never became active within the wait (`failed`: read its journal; `activating`: it is slow under emulation; `not installed`: the image lacks the unit). The other `backend-*` checks then report that they were not asked |
| `backend-active FAILED: ... is not ready` | The unit is active but its port does not accept a connection or its token file is missing or empty: the service is crashing, still starting, or listening somewhere else than its settings say |
| `kiosk-active FAILED: pai-kiosk.service is ...` (with `kiosk-ready` failing the same way) | The kiosk unit did not become `active` within `PAI_SELFCHECK_KIOSK_TIMEOUT` (`failed`: read `journalctl -t pai-kiosk` and `journalctl -u pai-kiosk.service`; `activating`: it keeps restarting or is slow under emulation; `not installed`: the image has no kiosk unit) |
| `kiosk-active FAILED: ... no chromium process descends from pid N` | The unit is active but the browser never ran below its main process: the launcher is still waiting for the backend or the browser, or the browser died (`journalctl -t pai-kiosk`). A guest with too little memory is a common cause (`PAI_QEMU_MEMORY`); so is a kiosk that restarted after the wait began (the check keeps the pid it first saw) |
| `kiosk-active FAILED: the main process of pai-kiosk.service, pid N, is gone ...` | The process the unit had when the script looked is not there any more. The text after it says whether systemd still names that pid (the process died and the unit has not noticed, or `/proc` is not what the script expects) or reports another `MainPID` (the unit restarted: it is crash-looping if `NRestarts` in the same line keeps rising). The journal lines at the end of the detail are the unit's own last words |
| `kiosk-active FAILED: ... runs as ...` / `uids real/effective/saved/filesystem are ...` | The kiosk's main process does not run as the account its unit names, or that account is uid 0 |
| `kiosk-ready FAILED: ... does not exist` / `the kiosk reports ...` / `the status bar says ...` | The browser runs but the page has not reached "rendered and backend connected": no file means the launcher has not finished (raise `PAI_SELFCHECK_KIOSK_TIMEOUT` before assuming a hang); `the status bar says 'Backend unreachable ...'` or `'No valid session ...'` means the page loaded and its own `/health` request failed (the session cookie was not installed or was refused, or the backend is not answering it) |
| `no-secret-in-process-state FAILED: a live credential is visible in process state: ...` | A real finding. The detail names the process (pid and name), where (argument list or environment) and what (the bearer token, or a value the backend accepts as a bearer token or as the session cookie). The secret has to leave that command line or environment |
| `no-secret-in-process-state FAILED: cannot read the argument list or environment of N process(es): ...` | The self-check could not examine every process, so it says nothing about those: the unit lost `CAP_SYS_PTRACE`, or a process hides its files for another reason |
| `no-secret-in-process-state FAILED: ... gave no answer ...` / `credentials cannot be tested without the backend: ...` | The check tests candidates against the live backend and cannot when it does not answer or was not examined; fix the backend failures above first |
| `no-default-credentials FAILED: account(s) with a usable password hash: ...` / `... with an empty password ...` | An account can log in with a password that ships in the image. On a live image that is Debian live-config's login: look in `/var/log/live/config.log` for the component `pai-lock-live-user` (it runs last and locks every ordinary login account) |
| `no-default-credentials FAILED: /etc/shadow has mode ...` | The file that holds the password hashes is readable (or writable) by every account |
| A kiosk check detail ending in `systemd reports for pai-kiosk.service: ... journal of pai-kiosk.service (last N lines): ...` | The explanation the self-check adds to a kiosk failure: systemd's state for the unit and the journal's last lines. `Result=exit-code` with an `ExecMainStatus` and a rising `NRestarts` is a crash loop (the journal lines show why); `Result=timeout` is a unit that never finished starting. If the lines say `journalctl failed`, the self-check could not read the journal: boot with `PAI_BOOT_EXTRA_ARGS="systemd.journald.forward_to_console=1"` to have the whole journal on the console |
| `no check lines: a run that checked nothing proves nothing` | A `RESULT` line without any check line: the script ran with an empty or broken `CHECKS` table |
| `no final RESULT line` | Check lines appeared but the summary did not: the unit was killed, the machine reset, or the console was cut |
| `RESULT reports N/M but ... check lines were seen` | Console noise swallowed a line, or a line was echoed twice with different text. Re-run; if it repeats, read the log for what interleaves with the output |
| `<check> FAILED: <detail>` | The check found a real deviation; the detail names it. See the table above for what to fix and where the expectation lives |
| `cannot boot: ...` (exit code 2 from the CLI; a setup error in pytest) | Docker unreachable, ISO missing, an unusable environment variable, the image build failed or timed out, or the container exited with a non-zero status before any verdict (`the boot container exited with status N`, followed by its last output, for example a permission problem reading the ISO). The message says which; none of it is a finding about the image |
| `console echo stopped (...)` on the command line | The live echo failed (closed pipe, unencodable output); the verdict and the saved log are complete |
| `test_guest_powers_itself_off_after_the_selfcheck` fails on its own | The verdict was printed (and passed) but `SuccessAction`/`FailureAction` did not stop the machine within 60 s. When the self-check test fails too, fix that one first |

### Findings on the current image

The first findings came from booting the ISO that was in `dist/` when the self-check was written, with the unit, script and
hook applied to a copy of its root filesystem (six checks then). The ISO built after that carried all of it and booted to
`RESULT|PASS|12/12` through this harness; the serial fixtures of the parser tests come from that boot (see
[the serial-log fixtures](#the-serial-log-fixtures)). The four checks added with the kiosk (`kiosk-active`, `kiosk-ready`,
`no-secret-in-process-state`, `no-default-credentials`) and the live-config component that locks the live login have been run
against the simulated machine only: **no image that has them has been booted yet**, so what the real guest reports for them
(Chromium's start time under emulation, whether the kiosk's processes are readable with the unit's capabilities, what live-config
leaves in `/etc/shadow` and `/etc/sudoers.d`) is unknown until it is.

- **`no-external-listeners` failed because of systemd-resolved's LLMNR responder (fixed in the image).** `systemd-resolved`
  listened on `0.0.0.0:5355` and `[::]:5355` (TCP and UDP) although `20-wired.network` sets `LLMNR=no` per link: the global
  default is `yes`. The firewall input chain has no rule for 5355 so the sockets were unreachable, but the check is about
  sockets, and it was right to fail. The drop-in `os/configuration/rootfs/etc/systemd/resolved.conf.d/10-pai.conf` now ships
  with the image and the check passes; it was not given an exception.
- **Two DHCP clients run on the same interface.** `networking.service` (ifupdown, with `allow-hotplug ens3` and
  `iface ens3 inet dhcp` in `/etc/network/interfaces`) starts `dhcpcd` next to `systemd-networkd`. That is why UDP 68 and UDP6
  546 are held twice. It is a configuration question (one network manager) for `os/configuration`; the allow-table only
  covers the DHCP client ports, only for sockets bound to a specific address, and would not hide a listener on any other port.

## TCG limitations

- **Slow.** Software emulation runs the guest at a small fraction of native speed. Timings in a boot test say nothing about
  real performance, and timeouts must be generous. Do not use this harness to measure latency, memory use or model speed.
- **No hardware acceleration, no hypervisor.** It cannot show how the image behaves under VMware or VirtualBox (VMware
  Tools, `vboxsf` for real, clipboard and drag-and-drop, display, vTPM). Manual validation on both is still required
  before any release claim (R1, milestone M1.6).
- **The bootloader is bypassed.** The kernel and initrd are loaded straight from the ISO with `-kernel`/`-initrd`, so
  ISOLINUX, GRUB, the EFI image, isohybrid layout and the kernel arguments in the bootloader configuration are **not**
  exercised. The kernel arguments in a boot test are the harness's, not the image's (a test only keeps the build's
  `--bootappend-live` words and the harness's in step). Secure Boot and UEFI are not covered.
- **A synthetic machine.** A `pc` machine with a virtio NIC, IDE CD-ROM and a QEMU CPU model (`-cpu max`). Drivers for
  other hardware are not tested; QEMU's DHCP is not a real network.
- **Serial console only.** There is no display; the kiosk shell (M1.4) needs a different harness for screenshots.
- **Only the live session.** Installation, LUKS2 and persistent storage are M1.5.

## Security note: default live-session credentials (risk R16)

Debian live images create a well-known login at boot (`user` / `live`, with passwordless sudo and console autologin).
Images built before `os/security/rootfs/usr/lib/live/config/9980-pai-lock-live-user` still have it, and the serial console used
here is a login prompt. The component is a live-config script, which live-config runs as root on every boot after its own
(`0030-user-setup` creates the account, `0040-sudo` writes `/etc/sudoers.d/live`, `1080-policykit` gives the sudo group
administrator rights without a prompt): it finds every ordinary login account (a uid in the range `login.defs` gives) whose password
is not already locked, sets its password field to `!` (the old hash is gone, so unlocking does not bring the known password back),
takes it out of the `sudo` group and removes `/etc/sudoers.d/live`; it exits non-zero, and live-config logs it, when a password is
still usable afterwards. The account is found by what it is, not by the name `user`.

What this does **not** cover, and what is not proven yet:

- **Not booted.** The component and the `no-default-credentials` check that proves its result were tested against simulated
  machines only (`tests/end_to_end/test_live_user_lock.py`, `test_selfcheck_script.py`). Whether live-config on the real image runs
  the file (it needs the executable bit, which `os/build/assemble-config.sh` gives to every file that starts with `#!`) and leaves
  `/etc/shadow` as the check expects is shown by the first boot of a rebuilt image.
- **Autologin is a different door.** live-config's getty generator logs the live account in on `getty@tty1` to `tty6` without asking
  for a password, so a locked password does not stop it. The kiosk masks `getty@tty1` and runs without a way to switch virtual
  terminals (`cage` without `-s`), and the serial console asks for a login that no password opens; nothing in the boot test
  examines the other terminals. live-config has its own switch for it (`noautologin`, as `live-config.noautologin` on the kernel
  command line); the image's boot options do not set it, and its effect was not checked here.
- The harness never logs in and never sends input (QEMU's stdin is `/dev/null`); the guest has no outside network (`restrict=on`,
  `--network none`) and its firewall drops everything inbound, so the only way in is a console that exists only inside the
  container.
- A passing boot test still does not make the image safe to distribute: the *installed* system must have no default credentials
  either (M1.5).
