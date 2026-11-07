# Boot testing (milestone M1.2)

The boot test starts the built ISO in a virtual machine, lets it reach `multi-user.target`, and has the image check
itself: the firewall, the module lockdown, the kernel hardening values, the listening sockets and the core services.
The verdict is read from the VM's serial console. It runs on a machine with no hypervisor (risk R1): QEMU emulates the
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
a boot of the current image takes roughly two minutes from `docker run` to the verdict.

The fast tests need no Docker. `test_selfcheck_script.py` runs the real self-check script under `bash` against a simulated
`/proc` and `/etc`, so it needs a working `bash` and takes about a minute and a half. Every `bash` on `PATH` is tried until
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
| `PAI_QEMU_MEMORY` | `2048` | Guest RAM in MiB (a whole number) |
| `PAI_QEMU_CPUS` | `2` | Guest CPUs (a whole number; emulated, they share the container's host threads) |

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
   starts after `multi-user.target`, `nftables.service` and `systemd-networkd.service`, runs
   `/usr/lib/pai/security-selfcheck.sh` as the unprivileged user `nobody` holding only `CAP_NET_ADMIN` (listing the firewall needs it;
   nothing else does), prints the verdict to the journal and the console, and powers the machine off
   (`SuccessAction=` and `FailureAction=poweroff-force`), whatever the outcome. It does not run as root: as uid 0 `systemctl` would
   reach PID 1 over its private socket, which accepts root without any capability, so a flaw in a check could start units outside
   the unit's sandbox.
7. **Streaming and ending.** The harness streams the serial output and stops at the first of: the container exits (the
   guest powered itself off); the guest printed its final `RESULT` line (it then waits up to 60 s for the power-off); the
   overall timeout. The container is removed in every case, also on an exception or Ctrl-C. Only the container the run
   started is touched. A container that exits with a non-zero status **before** any `RESULT` line is not a self-check failure: it
   is reported as a boot that could not be performed (`cannot boot: the boot container exited with status N ...`, with the last
   output), because docker, the ISO or the emulator failed.
8. **Verdict.** `selfcheck_output.parse_selfcheck()` reads the `PAI-SELFCHECK|...` lines; `selfcheck_problems()` decides.
   **A boot that never prints the final `RESULT` line is a failure, never a pass, and so is a run that checked nothing**: the
   output must contain every check in `REQUIRED_CHECKS` (the six below), so `RESULT|PASS|0/0`, an unrelated check with a matching
   count, or an ISO built before a check existed cannot pass. A test keeps `REQUIRED_CHECKS` equal to the script's `CHECKS` table.

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

The script runs every check even when one fails; a check that crashes counts as a failure and the rest still report.
If the script itself dies before the summary, a trap prints `RESULT|FAIL|self-check aborted before completion`. A script whose
`CHECKS` table is empty prints `RESULT|FAIL|0/0` and exits 1 instead of reading zero of zero as success.

### Adding a check

Write `check_<what>()` in `security-selfcheck.sh` (print a one-line detail, return 0 or non-zero, handle every failure
explicitly instead of relying on `set -e`), add `<name>:check_<what>` to the `CHECKS` table **and to `REQUIRED_CHECKS` in
`tests/end_to_end/selfcheck_output.py`** (`test_selfcheck_wiring.py` fails until both agree), and add a simulated-tree test for
both outcomes in `tests/end_to_end/test_selfcheck_script.py`. Run `shellcheck` on the script.

### Regenerating the shipped-ruleset fixture

`tests/end_to_end/fixtures/nft_ruleset_shipped.json` is what real `nft` (v1.1.3) printed after loading the shipped
`nftables.conf`; one script test feeds it, with that file, through the `nft-default-drop` check, so the script's reading of nft's
JSON is tested against the real thing. If `nftables.conf` changes in a way that changes chains, regenerate it:

```bash
docker run --rm --cap-add NET_ADMIN -v "$PWD/os/security/rootfs/etc/nftables.conf:/t/nftables.conf:ro" \
  debian:trixie-slim sh -c 'apt-get update -qq && apt-get install -y -qq nftables >/dev/null && nft -f /t/nftables.conf && nft -j list ruleset' \
  > tests/end_to_end/fixtures/nft_ruleset_shipped.json
```

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
| `no check lines: a run that checked nothing proves nothing` | A `RESULT` line without any check line: the script ran with an empty or broken `CHECKS` table |
| `no final RESULT line` | Check lines appeared but the summary did not: the unit was killed, the machine reset, or the console was cut |
| `RESULT reports N/M but ... check lines were seen` | Console noise swallowed a line, or a line was echoed twice with different text. Re-run; if it repeats, read the log for what interleaves with the output |
| `<check> FAILED: <detail>` | The check found a real deviation; the detail names it. See the table above for what to fix and where the expectation lives |
| `cannot boot: ...` (exit code 2 from the CLI; a setup error in pytest) | Docker unreachable, ISO missing, an unusable environment variable, the image build failed or timed out, or the container exited with a non-zero status before any verdict (`the boot container exited with status N`, followed by its last output, for example a permission problem reading the ISO). The message says which; none of it is a finding about the image |
| `console echo stopped (...)` on the command line | The live echo failed (closed pipe, unencodable output); the verdict and the saved log are complete |
| `test_guest_powers_itself_off_after_the_selfcheck` fails on its own | The verdict was printed (and passed) but `SuccessAction`/`FailureAction` did not stop the machine within 60 s. When the self-check test fails too, fix that one first |

### Findings on the current image

Found by booting the ISO that was in `dist/` when this was written. It already had the M1.1 firewall, sysctl and module
lockdown but not the self-check, so the unit, script and hook were applied to a copy of its root filesystem the way the
build applies them, and that copy was booted through this harness. The captured serial fixtures come from that earlier
script version: their detail texts differ from the current script's wording, and the parser does not read details.

- **`no-external-listeners` fails because of systemd-resolved's LLMNR responder.** `systemd-resolved` listens on
  `0.0.0.0:5355` and `[::]:5355` (TCP and UDP) although `20-wired.network` sets `LLMNR=no` per link: the global default is
  `yes`. The firewall input chain has no rule for 5355 so the sockets are unreachable, but the check is about sockets, and it
  is right to fail. Verified fix: a drop-in `/etc/systemd/resolved.conf.d/*.conf` with `[Resolve]`, `LLMNR=no`,
  `MulticastDNS=no` removes every listener, after which all six checks pass (6/6). The drop-in belongs under
  `os/configuration/rootfs`; it is not applied yet, and the check is deliberately not given an exception for it.
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

Debian live images ship a well-known default login (`user` / `live`) with autologin on the console. The image under test
**still has it**, and the serial console used here is a login prompt. This is a known open risk (R16 in
[RISKS](../architecture/RISKS.md), to be closed before M1.5), not something the boot test fixes or hides:

- The harness never logs in and never sends input: QEMU's stdin is `/dev/null`.
- The guest has no outside network (`restrict=on`, and the container has `--network none`), and its firewall drops
  everything inbound, so the only way in is that console, which exists only inside the container.
- Nothing about a passing boot test means the image is safe to distribute: while R16 is open the live session is
  install-only and offline, and the *installed* system must have no default credentials.
