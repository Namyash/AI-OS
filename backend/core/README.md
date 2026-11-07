# core

Configuration, logging, ids, error types. Imports nothing else from the project (enforced by `backend/tests/core/test_layering.py`, which follows relative imports and nested modules).

| Module | Responsibility |
|---|---|
| `config.py` | Immutable `Settings` loaded from `PAI_*` environment variables by `load_settings`; the only place defaults live. Defaults are validated like explicit values. |
| `logging.py` | JSON logging to stdout with secret redaction (linear-time; header values masked to the end of their line). |
| `errors.py` | Error classes carrying a stable code, an HTTP status and a fixed message. |
| `exit_codes.py` | The exit codes of `python -m backend` (77 root refused, 78 bad configuration, 3 startup failed), importable without the web stack. |
| `version.py` | The backend version (kept equal to `pyproject.toml` by a test). |
