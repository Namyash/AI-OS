# API Documentation

Status: milestone M1.3. The backend service exists and serves **one endpoint**, `GET /health`. Everything else in this
document is how that service is run, how a client authenticates to it, and the rules every future endpoint inherits.

## Running the service

```bash
python -m pip install -e ".[dev]"   # development: the dev extra includes the api extra (fastapi, uvicorn) and the test tools
python -m backend                   # from the repository root, or from /opt/pai in the image (pai-backend.service)
```

The image takes the same dependencies from Debian packages (`python3-fastapi`, `python3-uvicorn`, `python3-pydantic`); they are
not wired into the image build yet, so the unit cannot start on a built image until that integration step lands.

It runs uvicorn with one worker, no reload, no `Server` header, no access log, no WebSocket support and no trust in
forwarded headers. It **refuses to run as root** (exit code 77, no override). The systemd unit
(`os/systemd/rootfs/etc/systemd/system/pai-backend.service`) runs it as the `pai` user under a full sandbox.

### Settings

Read once at start from environment variables. Defaults live in `backend/core/config.py`, the only place they are defined.
Invalid values stop the service with exit code 78 and a message naming each variable. Other `PAI_*` variables (the ISO build
inputs share the prefix) are ignored.

| Variable | Default | Rule |
|---|---|---|
| `PAI_HOST` | `127.0.0.1` | A literal loopback IP address (`127.0.0.0/8` or `::1`). Anything else, including host names and `0.0.0.0`, is rejected at load time. |
| `PAI_PORT` | `8765` | 1024-65535 (the service is unprivileged). |
| `PAI_DATA_DIR` | `/var/lib/pai` | Absolute path; created with mode `0700` if missing. Matches the unit's `StateDirectory=pai`. |
| `PAI_TOKEN_FILE` | `/run/pai/token` | Absolute path; its directory is created (mode `0750`) if missing. Matches the unit's `RuntimeDirectory=pai`. |
| `PAI_LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error` or `critical` (case-insensitive). |

The SQLite database is `<PAI_DATA_DIR>/pai.sqlite3`.

The two path defaults are the Linux deployment paths, and defaults are validated like any other value. On a development
machine where `/var/lib/pai` is not an absolute path (Windows: it has no drive), leaving `PAI_DATA_DIR` or `PAI_TOKEN_FILE` unset
stops the service with exit code 78 naming the variable, rather than creating a directory under the root of the current drive.
Set both to absolute paths of your own there.

### Startup and failing closed

1. The service binds `PAI_HOST:PAI_PORT` **before** the application starts. If another process already holds the port, the
   process logs the reason and exits with code 3 without having published a token. Connections that arrive while startup is
   still running wait in the kernel's queue and are answered once the application is up; every request is refused until the
   token is installed.
2. The data directory is created and the database opened with `migrate.connect`; pending migrations are applied with
   `apply_migrations`. Any migration or database error is logged at `CRITICAL` and **aborts startup** (exit code 3).
3. Only then is a fresh bearer token generated and published (see below). A service that failed to start never publishes a token.

Exit codes (`backend/core/exit_codes.py`): `77` refused to run as root, `78` invalid configuration, `3` startup failed (the port
was taken, or the application did not start). The unit does not restart after 77 or 78.

## Authentication and request checks

Every request to every path (including `/openapi.json` and paths that do not exist) passes three checks, in this order.
The first failure ends the request, so an unauthenticated client learns nothing about which paths exist.

| # | Check | Failure |
|---|---|---|
| 1 | `Host` must be exactly one of `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, or `<PAI_HOST>:<port>` (case-insensitive, port required; an IPv6 literal in brackets). Only the configured address is added, not the rest of `127.0.0.0/8`. Defeats DNS rebinding. | `400 invalid_host` |
| 2 | If an `Origin` header is present it must be exactly one header equal to `http://<the Host header>` (same origin). There is no CORS: no `Access-Control-*` header is ever sent, so preflights fail. A request with no `Origin` (curl, native code) passes this check. | `403 forbidden_origin` |
| 3 | `Authorization: Bearer <token>` with the current token, compared in constant time. The scheme is case-insensitive. A token in the query string is not accepted. Missing, malformed, repeated or wrong credentials all get the same response. | `401 unauthorized` with `WWW-Authenticate: Bearer` |

Each rejection is also logged (see [Logging](#logging)).

### The token file contract

- A new token is generated at every start: `secrets.token_urlsafe(32)`, 256 bits, 43 characters of `[A-Za-z0-9_-]`. **The backend is the
  only place a token is generated.** It has no setting, argument or file through which a token can be supplied to it.
- It is written to `PAI_TOKEN_FILE` (`/run/pai/token`), replacing any previous file. The write is atomic (private temporary
  file in the same directory, then rename), so a reader never sees a partial token, and a symlink at that path is replaced, not followed.
- The file contains the token only, with no trailing newline. Clients should still strip whitespace.
- Mode `0640`, owner `pai`, group `pai`. The kiosk user `pai-ui` is a member of group `pai` (`usr/lib/sysusers.d/pai.conf`), so it can
  **read but not write** the token; other users have no access. Only the runtime directory (`/run/pai`, `0750`, holding nothing but the
  token) is shared with that group: the data directory (`/var/lib/pai`) is `0700`, so the kiosk user cannot list or enter it. Files the
  service creates are also private by default (the unit sets `UMask=0077`). On Windows development hosts no POSIX mode is applied.
- A previous token stops working the moment the service restarts. The backend does not delete the file on shutdown;
  systemd removes `/run/pai` when the unit stops.

```bash
curl -H "Authorization: Bearer $(cat /run/pai/token)" http://127.0.0.1:8765/health
```

### What the kiosk and the frontend can rely on today

- The service listens on `127.0.0.1:8765` unless `PAI_PORT` (or `PAI_HOST`) says otherwise. Any client default, proxy target or document
  that names a port must agree with `DEFAULT_PORT` in `backend/core/config.py`.
- The token is generated by the backend at each start and published at `/run/pai/token`, readable by the `pai-ui` account through its
  membership of group `pai`. The kiosk launcher does not generate it and cannot hand one to the backend.
- **The kiosk launcher does not exist yet** (milestone M1.4b), so nothing delivers the token to a browser today. Its mechanism is decided
  there; the constraints are fixed now: the token must never appear in a process argument or environment (every local account can read both
  through `/proc`), nor in a URL passed on a command line. Candidates are a bootstrap page in a `0700` per-user directory that redirects to
  the app with a `#token=` fragment, or an `HttpOnly; SameSite=Strict` cookie handshake.
- The frontend reads the token from the URL fragment (`#token=...`), which the browser never sends to the server.
- Every path needs the token, including `/` and any future static files for the UI. Serving the UI shell without one is part of M1.4: it
  needs a deliberate, narrow, tested exemption in the guard, and until it exists nothing is exempt.

## Endpoints

### `GET /health`

Authenticated like everything else. Returns `200`:

```json
{ "status": "ok", "schema_version": 1, "version": "0.0.1" }
```

| Field | Meaning |
|---|---|
| `status` | Always `"ok"` when a response is returned. |
| `schema_version` | Highest migration recorded in `schema_migrations`, read from the database on every call (so it also proves the database is readable). |
| `version` | Backend version (`backend/core/version.py`, kept equal to `pyproject.toml` by a test). |

If the database cannot be read the response is `503 database_unavailable`. The query runs in a worker thread, not on the event loop.

### OpenAPI

`GET /openapi.json` returns the generated OpenAPI document, behind the same three checks. The interactive docs UIs (`/docs`, `/redoc`)
are disabled and return `404`.

## Errors

Every error response, including ones generated by the framework (unknown path, wrong method, invalid input, unexpected failure),
has this exact shape and nothing else:

```json
{ "error": { "code": "unauthorized", "message": "Authentication required" } }
```

`code` is stable and machine-readable; `message` is a fixed human-readable sentence per code. Exception text, file paths and secrets
never appear in a response body. What the server logs for each kind of failure is listed under [Logging](#logging).

| Status | `code` | When |
|---|---|---|
| 400 | `invalid_host` | Host check failed. |
| 401 | `unauthorized` | Missing or invalid bearer token. Carries `WWW-Authenticate: Bearer`. |
| 403 | `forbidden_origin` | Origin check failed. |
| 404 | `not_found` | No such path (after authentication). |
| 405 | `method_not_allowed` | Path exists, method does not. Carries the framework's `Allow` header. |
| 422 | `validation_error` | Request failed validation. The body does not say which field or echo the input. |
| 500 | `internal_error` | Any unexpected failure. |
| 503 | `database_unavailable` | The database could not be read. |
| other | `http_error` | Any other HTTP error raised by the framework; same status, message `Request failed`. |

Python code raises the matching class from `backend/core/errors.py`; messages are class constants, so a caller cannot put text in a response.

## Logging

Structured JSON, one object per line on stdout (journald collects it): `ts`, `level`, `logger`, `message`, plus any structured fields.
There is no access log. A redaction filter on the handler masks, before anything is written: the live bearer token wherever it appears;
`key=value` / `"key": "value"` pairs and structured fields whose key contains `authorization`, `token`, `password`, `passwd`, `secret`,
`credential`, `cookie` or `key`; and `Bearer <credentials>` anywhere in a message. For an `authorization` or `cookie` key the whole
value to the end of the line is masked (`Basic <credentials>`, `a=1; b=2`); for the others one word or one quoted string is. The list is
deliberately broad; a harmless name that gets masked costs a log line. Redaction takes time linear in the length of the text.

| Event | Logged |
|---|---|
| Unexpected exception in a route | The traceback (by uvicorn), redacted, at `ERROR`. The response is the generic 500. |
| `/health` cannot read the database | The database error, at `ERROR`. The response is the 503. |
| Request rejected by the Host, Origin or token check | `request rejected` at `WARNING` with a `reason` field holding the error code (`invalid_host`, `forbidden_origin`, `unauthorized`) and nothing else: no header value, path or query string. |
| Request fails validation (422) | `request validation failed` at `INFO` with `error_types`, the fixed pydantic error-type codes (`int_parsing`, `missing`, ...): no input and no field name, which a client can choose. |
| 404 and 405 | Not logged: they carry no information beyond the response. |
| Startup failure | `CRITICAL`, then exit code 3. |

A client that sends many rejected requests produces one `WARNING` line for each; journald applies its own rate limit per service.

## Known limitations

- **Nothing authenticates the server to the client.** The bearer token proves who the client is. A local process that holds
  `127.0.0.1:8765` before the service starts, or in the two seconds between a crash and the restart, can answer in its place; the service
  then fails to bind and exits (code 3) without publishing a token, but a client that loads its UI from that origin would be served by
  the other process. Closing this needs the listening socket to belong to systemd (socket activation) or the kiosk to verify the server.
  Neither exists yet; the decision belongs with the kiosk (M1.4).
- **Connections are not time-limited before their first complete request.** uvicorn starts its idle timer only after a response, so a
  local process can hold connections open without sending anything until the service runs out of file descriptors (1024 by default
  under systemd). It needs no token. A read deadline and a connection cap are needed, which depends on the server software chosen for
  the final image.

## Conventions for the endpoints that follow

These are fixed now so the first real endpoints follow them. Only `/health` exists, so none is exercised beyond it yet.

- Transport: HTTP on loopback only; the checks above apply to every route because they are middleware, not per-route dependencies.
  A path that must be reachable without the token (the static UI shell in M1.4) needs an explicit exemption in `BoundaryGuard`, with a
  test that nothing else is exempt.
- Schemas: Pydantic v2 models, request models with `extra="forbid"`; the OpenAPI document is generated from them.
- Errors: raise a `backend.core.errors` class; add a new class (with a new stable `code`) rather than a free-text message.
- Blocking work (SQLite, file I/O) must not run on the event loop: use plain `def` endpoints or a worker thread.
- Long-running work (tasks, model downloads) returns an id and streams progress over server-sent events; every task is cancellable.
- Approvals are explicit API operations carrying the operation hash shown to the user; there is no "approve everything" endpoint.
