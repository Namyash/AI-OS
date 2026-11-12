# end_to_end

Boot tests that run the built ISO under QEMU in a container. Milestone M1.2. How to run them, the environment variables,
what each check means and how to read a failure: [docs/development/BOOT_TESTING.md](../../docs/development/BOOT_TESTING.md).

| File | Role |
|---|---|
| `Dockerfile` | QEMU + xorriso + python3 on a digest-pinned `debian:trixie-slim` with packages from a pinned snapshot; the image tag follows the Dockerfile content |
| `boot_harness.py` | Host side: finds the ISO, builds the image, runs one boot in a locked-down container, streams the serial console (sanitised for display) with an overall timeout, always removes the container. `python -m tests.end_to_end.boot_harness` boots with live output; exit 0 passed, 1 self-check failed, 2 the boot could not be performed |
| `container_boot.py` | Runs inside the container: discovers the kernel and initrd on the ISO, extracts them, starts QEMU (TCG) |
| `selfcheck_output.py` | `parse_selfcheck()` / `selfcheck_problems()` and `REQUIRED_CHECKS`: read the `PAI-SELFCHECK|...` lines out of a noisy serial log and refuse a pass that lacks a required check |
| `bash_support.py` | Finds a `bash` that runs (tries every one on `PATH`), for the tests that execute shell scripts |
| `test_boot_iso.py` | The `e2e` test: boots the ISO and asserts the self-check passed (`-m e2e`; skips when Docker or an ISO is missing) |
| `selfcheck_sim.py` | The simulated machine the real `security-selfcheck.sh` runs against: a `/proc` + `/etc` + `/opt` tree, fakes of `nft`, `modprobe`, `systemctl`, `systemd-analyze`, `id`, `stat` and `python3`, the processes of the backend and of the kiosk (cage, launcher, Chromium), `/etc/shadow`, and a loopback HTTP server standing in for the backend (see BOOT_TESTING.md, "The simulated machine") |
| `test_selfcheck_script.py` | A table of scenarios, one run of the real `security-selfcheck.sh` each (needs bash, no Docker): all sixteen checks shown to pass and to fail (the backend, the kiosk, credentials in process state, default passwords), run in parallel |
| `test_selfcheck_wiring.py` | Static checks that the unit, build hook, script, overlay, harness, backend, kiosk and frontend name each other correctly (flag, paths, unit names; the unit's capabilities and time limit against the script's waits; a credential's length and cookie against the backend's; the connected label against the frontend's; the check table: names equal to `REQUIRED_CHECKS`, no duplicates, every entry a defined function, no `check_*` function left out) |
| `test_live_user_lock.py` | The live-config component that locks the live session's well-known login (risk R16) run against simulated machines with fakes of `usermod` and `gpasswd` (needs bash, no Docker) |
| `test_selfcheck_output.py`, `test_container_boot.py`, `test_boot_harness.py`, `test_bash_support.py` | Fast unit tests, no Docker |
| `fixtures/` | Excerpts of the console log of one real boot (twelve checks, brought up to sixteen by hand: see BOOT_TESTING.md) used by the parser tests, the ruleset real `nft` prints for the shipped `nftables.conf`, and the real `systemd-analyze security` report of the backend unit |

## Install test (milestone M1.5)

Installs the ISO onto a blank disk under QEMU and boots the result; how to run it, the variables and how to read a failure:
[docs/development/INSTALL_TESTING.md](../../docs/development/INSTALL_TESTING.md).

| File | Role |
|---|---|
| `install_plan.py` | The plan (INSTALLER_DESIGN.md) with a fresh random passphrase held in a `Secret` that never prints |
| `install_console.py` | Pure: engine event parsing and install verdict, the unlock-prompt detector, the typer and watchers that react to the console, the scrubber, the installed-boot and wrong-passphrase verdicts |
| `install_harness.py` | Host side: configuration, the throwaway volume, the media / install / boot / wrong-passphrase steps in locked-down containers (reuses `boot_harness.stream_container`) |
| `container_install.py` | Inside the container: builds `plan.iso` (volume `PAI-PLAN`) and the sparse target disk, boots the ISO with both, boots the installed disk through BIOS or OVMF |
| `test_install_iso.py` | The `e2e` test (`-m e2e`; skips without Docker or an ISO) |
| `test_install_plan.py`, `test_install_console.py`, `test_install_harness.py`, `test_container_install.py`, `test_installer_component.py` | Fast tests, no Docker; the last also runs `os/installer`'s `install-auto.sh` under bash with fakes |
