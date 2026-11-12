# kiosk

The launcher behind `pai-kiosk.service`: `python3 -m kiosk`, run by `cage` on tty1 as the account `pai-ui`. Standard library
only; it imports nothing from `backend/` (a test enforces both). The design is
[KIOSK_SESSION_DESIGN](../docs/architecture/KIOSK_SESSION_DESIGN.md); how to run, test and debug it is
[KIOSK.md](../docs/development/KIOSK.md).

| Module | Responsibility |
|---|---|
| `config.py` | Immutable `Settings` from `PAI_*` variables; the only place defaults live. |
| `handoff.py` | Read the backend's endpoint and token files, trade the token for a session (`POST /v1/session`). |
| `chromium.py` | Browser command line, built environment, private profile, spawn with the DevTools pipe on descriptors 3 and 4. |
| `cdp.py` | DevTools Protocol client for that pipe (NUL-terminated JSON, bounded waits). |
| `readiness.py` | What "the UI is up" means (the selectors shared with the frontend), and the readiness file. |
| `launcher.py` | The sequence of the design and the supervision loop; `main()` and signal handling. |
| `log.py` | Logging to stderr with redaction of the token and the session id. |
| `errors.py` | Failure types and exit statuses (78 = configuration: the unit does not restart on it). |
| `tests/` | Unit tests; a real HTTP server plays the backend and a script plays Chromium (`fake_chromium.py`). |
