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
| `test_selfcheck_script.py` | Runs the real `security-selfcheck.sh` against a simulated `/proc` and `/etc` (needs bash, no Docker) |
| `test_selfcheck_wiring.py` | Static checks that the unit, build hook, script, overlay and harness name each other correctly (flag, paths, unit name, check list) |
| `test_selfcheck_output.py`, `test_container_boot.py`, `test_boot_harness.py`, `test_bash_support.py` | Fast unit tests, no Docker |
| `fixtures/` | Excerpts of real serial logs used by the parser tests, and the ruleset real `nft` prints for the shipped `nftables.conf` |
