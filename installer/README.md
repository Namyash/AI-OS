# installer

The installer engine: `python3 -m installer --plan plan.json`, run as root on the live image. It copies the running live
system onto a blank disk that it partitions and encrypts (GPT, LUKS2 with argon2id, a recovery key in a second keyslot,
BIOS and UEFI boot). Standard library only; it imports nothing from `backend/` or `kiosk/` (a test enforces both). The design and
its safety rules are [INSTALLER_DESIGN](../docs/architecture/INSTALLER_DESIGN.md); how to run, test and extend it is
[INSTALLER.md](../docs/development/INSTALLER.md).

| Module | Responsibility |
|---|---|
| `plan.py` | Strict parsing and validation of the plan (unknown keys, types, passphrase rules); errors never echo the passphrase. |
| `runner.py` | The one way a program is run: list argv, per-command timeout, explicit environment, secrets on stdin only, redacted errors. `Runner` is the seam tests replace. |
| `host.py` | What the engine reads from the machine (device nodes, sysfs, procfs, the 0600 key file); `LinuxHost` is the real one. |
| `mounts.py` | Parsing of `/proc/self/mountinfo` and `/proc/swaps`. |
| `target.py` | Resolving the named disk and safety rules 1 to 4 (whole disk, not the live medium, nothing mounted or mapped, at least 16 GiB). |
| `context.py` | State shared by the steps, and the resource stack that undoes what they acquired (rollback and the orderly ending use the same stack). |
| `steps/` | One function per step: `preflight`, `disk`, `luks`, `filesystems`, `copy`, `configure`, `boot`, `finish`. |
| `engine.py` | The steps in order, one event per step, rollback on any failure. |
| `events.py`, `log.py`, `secret.py` | JSON-lines progress events, redacting log, a wrapper that cannot be printed. |
| `cli.py`, `__main__.py` | The command line and its exit statuses (0 success, 1 failure, 77 not root, 78 invalid plan). |
| `tests/` | Unit tests on a fake machine (`fakes.py`); `tests/integration/` runs the real disk tools in a privileged container. |
