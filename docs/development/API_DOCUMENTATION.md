# API Documentation

Status: milestone M1.4b (backend part). The backend service serves the built UI at `/`, `GET /health`, and the two session endpoints
`POST /v1/session` and `DELETE /v1/session`. This document is how that service is run, how a client authenticates to it, and the
rules every future endpoint inherits. The design behind the session handoff is
[KIOSK_SESSION_DESIGN](../architecture/KIOSK_SESSION_DESIGN.md).

## Running the service

```bash
python -m pip install -e ".[dev]"   # development: the dev extra includes the api extra (fastapi, uvicorn) and the test tools
python -m backend                   # from the repository root, or from /opt/pai in the image (pai-backend.service)
```

The image takes the same dependencies from Debian packages (`python3-fastapi`, `python3-uvicorn`, `python3-pydantic`); they are
not wired into the image build yet, so the unit cannot start on a built image until that integration step lands. The backend
tests (and the systemd unit tests) are also run against exactly those Debian packages (trixie: Starlette 0.46, FastAPI 0.115,
uvicorn 0.32) as well as the newest releases, so the UI serving below does not depend on a recent Starlette.

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
| `PAI_ENDPOINT_FILE` | `/run/pai/endpoint` | Absolute path, not the same file as `PAI_TOKEN_FILE`; published like the token (see [The endpoint file](#the-endpoint-file)). |
| `PAI_STATIC_DIR` | `/opt/pai/frontend` | Absolute path of the built UI. It must not be, or contain, `PAI_TOKEN_FILE` or `PAI_DATA_DIR` (symbolic links that exist are resolved), because everything under it is served to the browser. It need not exist (see [The UI](#the-ui)). |
| `PAI_SESSION_TTL` | `43200` (12 hours) | Whole seconds, 60 to 604800 (7 days): the absolute lifetime of a browser session. |
| `PAI_LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error`, `critical` (case-insensitive). |

The SQLite database is `<PAI_DATA_DIR>/pai.sqlite3`.

The path defaults are the Linux deployment paths, and defaults are validated like any other value. On a development
machine where `/var/lib/pai` is not an absolute path (Windows: it has no drive), leaving `PAI_DATA_DIR`, `PAI_TOKEN_FILE`,
`PAI_ENDPOINT_FILE` or `PAI_STATIC_DIR` unset stops the service with exit code 78 naming the variable, rather than creating a
directory under the root of the current drive. Set all four to absolute paths of your own there.

### Startup and failing closed

1. The service binds `PAI_HOST:PAI_PORT` **before** the application starts. If another process already holds the port, the
   process logs the reason and exits with code 3 without having published anything. Connections that arrive while startup is
   still running wait in the kernel's queue and are answered once the application is up; every request is refused until the
   token is installed.
2. The data directory is created and the database opened with `migrate.connect`; pending migrations are applied with
   `apply_migrations`. Any migration or database error is logged at `CRITICAL` and **aborts startup** (exit code 3).
3. Only then are the endpoint file and a fresh bearer token published (see below), in that order, so a reader that waits for the
   token finds the endpoint already there. A service that failed to start never publishes a token. Sessions are held in memory
   and start empty: a restart ends every session.

Exit codes (`backend/core/exit_codes.py`): `77` refused to run as root, `78` invalid configuration, `3` startup failed (the port
was taken, or the application did not start). The unit does not restart after 77 or 78.

## Authentication and request checks

Every request to every path (including `/openapi.json`, the UI files and paths that do not exist) passes three checks, in this
order. The first failure ends the request, so an unauthenticated client learns nothing about which paths exist.

| # | Check | Failure |
|---|---|---|
| 1 | `Host` must be exactly one of `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, or `<PAI_HOST>:<port>` (case-insensitive, port required; an IPv6 literal in brackets). Only the configured address is added, not the rest of `127.0.0.0/8`. Defeats DNS rebinding. | `400 invalid_host` |
| 2 | If an `Origin` header is present it must be exactly one header equal to `http://<the Host header>` (same origin). There is no CORS: no `Access-Control-*` header is ever sent, so preflights fail. A request with no `Origin` (curl, native code) passes this check. | `403 forbidden_origin` |
| 3 | Authentication, by exactly one of the two credentials below. Missing, malformed, repeated or wrong credentials all get the same response. | `401 unauthorized` with `WWW-Authenticate: Bearer` |
| 3b | A request authenticated by **cookie** whose method is not `GET`, `HEAD` or `OPTIONS` must carry an `Origin` header (which check 2 has already required to be its own origin). | `403 forbidden_origin` |

The credentials:

- **Bearer token**: `Authorization: Bearer <token>` with the current token, compared in constant time. The scheme is
  case-insensitive. A token in the query string is not accepted. This is the credential of tools: the kiosk launcher, the boot
  self-check, a developer with curl.
- **Session cookie**: `Cookie: pai_session=<session id>` naming a live session (below). It is considered **only when the request
  has no `Authorization` header at all**: any `Authorization` header means the bearer token or nothing, so a wrong or malformed
  token fails even when a valid cookie comes with it, and a valid token wins over whatever cookie accompanies it.

A browser attaches its cookie to anything it is told to request, including requests another page causes. That is why check 3b
exists: only a page of this origin names its origin, so a state-changing request that rides on the cookie from elsewhere is
refused. (The cookie is also `SameSite=Strict`, set by the launcher.) `GET` and `HEAD` never change state in this API.

The `Cookie` header is read defensively. Pairs that are not `name=value` are skipped; the name `pai_session` is case-sensitive; a
request with the cookie **more than once** (in one header or several) is treated as having none (another web server on the same
host can plant a second cookie of the same name, and the server does not guess which the browser meant); an empty value, a
`Cookie` header longer than 16 KiB, or a value longer than 128 bytes authenticates nothing. None of these is an error: the request
is simply not authenticated.

Each rejection is also logged (see [Logging](#logging)).

### Sessions

A session is how the kiosk browser authenticates without ever holding the bearer token. The launcher, which reads the token,
mints one and gives the browser its id as the `pai_session` cookie. **The server never sets a cookie.**

- Ids are 256 random bits (`secrets.token_urlsafe(32)`, 43 characters). The server keeps only the SHA-256 hash of each id, in
  memory, and compares hashes in constant time (every live session is compared, without stopping at a match).
- A session has an absolute lifetime, `PAI_SESSION_TTL` from the moment it was minted: using it does not extend it. The lifetime
  is measured on the monotonic clock, so time the machine spends suspended does not count against it.
- At most **8** sessions are alive. Minting another evicts the oldest. Expired sessions are dropped on every use, so the store
  never holds more than 8 entries.
- A restart ends every session; so does the service stopping for any reason.
- The id is registered with the log redaction filter while the session is alive (like the token), and taken out when it ends.

### The token file contract

- A new token is generated at every start: `secrets.token_urlsafe(32)`, 256 bits, 43 characters of `[A-Za-z0-9_-]`. **The backend is the
  only place a token is generated.** It has no setting, argument or file through which a token can be supplied to it.
- It is written to `PAI_TOKEN_FILE` (`/run/pai/token`), replacing any previous file. The write is atomic (private temporary
  file in the same directory, then rename), so a reader never sees a partial token, and a symlink at that path is replaced, not followed.
- The file contains the token only, with no trailing newline. Clients should still strip whitespace.
- Mode `0640`, owner `pai`, group `pai`. The kiosk user `pai-ui` is a member of group `pai` (`usr/lib/sysusers.d/pai.conf`), so it can
  **read but not write** the token; other users have no access. Only the runtime directory (`/run/pai`, `0750`, holding nothing but the
  token and the endpoint file) is shared with that group: the data directory (`/var/lib/pai`) is `0700`, so the kiosk user cannot list or
  enter it. Files the service creates are also private by default (the unit sets `UMask=0077`). On Windows development hosts no POSIX mode is applied.
- A previous token stops working the moment the service restarts. The backend does not delete the file on shutdown;
  systemd removes `/run/pai` when the unit stops.

```bash
curl -H "Authorization: Bearer $(cat /run/pai/token)" http://127.0.0.1:8765/health
```

### The endpoint file

- `PAI_ENDPOINT_FILE` (`/run/pai/endpoint`) holds the origin the service listens on, `http://<host>:<port>` (an IPv6 address in
  brackets, as in a URL), with **no trailing newline**: `http://127.0.0.1:8765` by default. It is what the launcher navigates to.
- It is published by the same mechanism as the token (atomic replace, a stale file or symlink replaced, mode `0640`, directory
  `0750`), at the same moment and **only once the listening socket is bound**: a process that did not get the port publishes
  neither file. It is written before the token.
- It is not a secret (the port is visible to every local account), but it is shared with the same group for the same reason as the
  token. Like the token it is left in place when the service stops and removed with `/run/pai` by systemd.

### What the kiosk and the frontend can rely on

- The service listens on `127.0.0.1:8765` unless `PAI_PORT` (or `PAI_HOST`) says otherwise, and says so in the endpoint file. Any
  client default, proxy target or document that names a port must agree with `DEFAULT_PORT` in `backend/core/config.py`.
- The token is generated by the backend at each start and published at `/run/pai/token`, readable by the `pai-ui` account through its
  membership of group `pai`. The kiosk launcher does not generate it and cannot hand one to the backend.
- The launcher reads the token and the endpoint, calls `POST /v1/session` with the token, installs the returned id as the
  `pai_session` cookie (`HttpOnly`, `SameSite=Strict`, host-only) over the DevTools pipe, then navigates to the endpoint. The token
  and the session id never appear in a process argument, environment variable or URL (every local account can read the first two
  through `/proc`).
- The page does no token handling: its same-origin requests carry the cookie. A `401` from `/health` means "this window has no valid
  session" (never minted, expired, evicted by newer sessions, revoked, or the service restarted).
- Every path needs a credential, including `/` and the UI files: **there is no unauthenticated route**, so the shell itself needs the cookie.

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

### `POST /v1/session`

Mints a browser session. Needs the **bearer token**: a request authenticated by session cookie is refused with the usual
`401 unauthorized`, so a browser can never create more sessions. Takes no body. Returns `201` with `Cache-Control: no-store` and no
`Set-Cookie`:

```json
{ "session_id": "<43 characters of [A-Za-z0-9_-]>", "expires_in": 43200 }
```

`expires_in` is the lifetime in seconds (`PAI_SESSION_TTL`). **This response is the only place the id is ever returned**: it appears
in no other response body, header, error or log line.

### `DELETE /v1/session`

Revokes the session the request was authenticated by (the cookie), and answers `204` with no body. A request authenticated by the bearer
token has no session, so nothing is revoked and the answer is the same; a cookie that is already revoked or expired is `401` like any
other bad credential. Authenticating by cookie means the unsafe-method rule applies: the request must carry the page's own `Origin`.

### The UI

Everything no API route claims is answered from `PAI_STATIC_DIR`, for `GET` and `HEAD`, behind the checks above:

- `/` is `index.html`. There are no directory listings, no `404.html` page and no redirects. A path that is not a file, and any
  other method, gets the standard JSON error (`404 not_found`); API paths always win, and a wrong method on one of them keeps
  its own `405` and `Allow` header.
- Serving is done by Starlette's `StaticFiles`: paths are normalised, anything that resolves outside the directory (`..` however
  it is encoded, absolute paths, symbolic links that lead out) is a `404`, as is a path no file system can hold (a NUL byte, an over-long
  name). The directory itself may be a symbolic link (a release switch); links inside it that stay inside are followed. A file or
  directory the service may not read is `500 internal_error` and a log line without the path, never a `401`.
- Every UI response carries `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'` (the same policy the frontend is tested under),
  `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`; HTML also carries `Cache-Control: no-store`. Other files keep
  the validators `StaticFiles` sends (`ETag`, `Last-Modified`) and answer conditional requests with `304`.
- The directory is looked at once, at start. If it does not exist (or is not a directory) the API runs alone and one `WARNING`,
  `UI directory not found; serving the API only`, is logged with the configured path; every UI path is then a `404`. A directory that
  appears later is picked up by the next start.

### OpenAPI

`GET /openapi.json` returns the generated OpenAPI document, behind the same checks. The interactive docs UIs (`/docs`, `/redoc`)
are disabled and return `404`. The UI files are not part of the document.

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
| 401 | `unauthorized` | No acceptable credential: missing or invalid bearer token or session cookie, or a cookie where only the token is accepted (`POST /v1/session`). Carries `WWW-Authenticate: Bearer`. |
| 403 | `forbidden_origin` | Origin check failed, or a cookie-authenticated request that could change state carried no `Origin`. |
| 404 | `not_found` | No such path or file (after authentication). |
| 405 | `method_not_allowed` | Path exists, method does not. Carries the framework's `Allow` header. |
| 422 | `validation_error` | Request failed validation. The body does not say which field or echo the input. |
| 500 | `internal_error` | Any unexpected failure, including a UI file the service cannot read. |
| 503 | `database_unavailable` | The database could not be read. |
| other | `http_error` | Any other HTTP error raised by the framework; same status, message `Request failed`. |

Python code raises the matching class from `backend/core/errors.py`; messages are class constants, so a caller cannot put text in a response.

## Logging

Structured JSON, one object per line on stdout (journald collects it): `ts`, `level`, `logger`, `message`, plus any structured fields.
There is no access log. A redaction filter on the handler masks, before anything is written: the live bearer token and every live
session id wherever they appear; `key=value` / `"key": "value"` pairs and structured fields whose key contains `authorization`, `token`,
`password`, `passwd`, `secret`, `credential`, `cookie`, `key` or `session` (so `pai_session=...` and `session_id` are covered whatever
the value); and `Bearer <credentials>` anywhere in a message. For an `authorization` or `cookie` key the whole value to the end of
the line is masked (`Basic <credentials>`, `a=1; b=2`); for the others one word or one quoted string is. The list is deliberately
broad; a harmless name that gets masked costs a log line. Redaction takes time linear in the length of the text. Session ids are
registered while their session lives and removed when it ends, so the registry never holds more than the 8 live ones.

| Event | Logged |
|---|---|
| Unexpected exception in a route | The traceback (by uvicorn), redacted, at `ERROR`. The response is the generic 500. |
| `/health` cannot read the database | The database error, at `ERROR`. The response is the 503. |
| Request rejected by the Host, Origin or credential check, or a cookie used where only the token is accepted | `request rejected` at `WARNING` with a `reason` field holding the error code (`invalid_host`, `forbidden_origin`, `unauthorized`) and nothing else: no header value, cookie, path or query string. |
| Request fails validation (422) | `request validation failed` at `INFO` with `error_types`, the fixed pydantic error-type codes (`int_parsing`, `missing`, ...): no input and no field name, which a client can choose. |
| A UI file the service may not read | `a UI file could not be read` at `ERROR`, without the path (it came from the client). |
| No UI directory at start | `UI directory not found; serving the API only` at `WARNING`, with the configured `static_dir`. |
| 404 and 405 | Not logged: they carry no information beyond the response. |
| Startup failure | `CRITICAL`, then exit code 3. |

A client that sends many rejected requests produces one `WARNING` line for each; journald applies its own rate limit per service.

## Known limitations

- **Nothing authenticates the server to the client.** The bearer token proves who the client is. A local process that holds
  `127.0.0.1:8765` before the service starts, or in the two seconds between a crash and the restart, can answer in its place; the service
  then fails to bind and exits (code 3) without publishing anything, but a client that loads its UI from that origin would be served by
  the other process. Closing this needs the listening socket to belong to systemd (socket activation) or the kiosk to verify the server.
  Neither exists yet.
- **The kiosk account can read the token.** It has to, to mint a session, so code running as that account (the launcher, and the browser
  process if it were compromised) can read `/run/pai/token` and mint sessions. `HttpOnly` keeps the cookie from page scripts; it does not
  protect it from the account. The browser is meant to run with no way to read the token file, which is a property of the kiosk setup
  (separate account or sandboxing), not of this API.
- **Cookies are not scoped by port.** Another web server on the same host name can read, replace or delete `pai_session` (it cannot
  make a valid one). The worst it can do is end the browser's session; a second planted cookie of the same name is treated as no cookie.
- **A session lifetime is time spent running.** It is measured on the monotonic clock, so a machine suspended for hours does not age its
  sessions by that time.
- **Connections are not time-limited before their first complete request.** uvicorn starts its idle timer only after a response, so a
  local process can hold connections open without sending anything until the service runs out of file descriptors (1024 by default
  under systemd). It needs no token. A read deadline and a connection cap are needed, which depends on the server software chosen for
  the final image.

## Conventions for the endpoints that follow

These are fixed now so the next endpoints follow them.

- Transport: HTTP on loopback only; the checks above apply to every route because they are middleware, not per-route dependencies.
  There is no unauthenticated route and no exemption in `BoundaryGuard`; a new one would need a deliberate, narrow, tested exception.
- Credentials: a route that must not be reachable by a browser session (it creates credentials, or is for tools only) asks for the
  bearer token explicitly, as `POST /v1/session` does (`caller_from_scope` in `backend/api/auth.py`). Every other route is open to a
  session too, so anything that changes state is protected by the Origin rule above, and `GET`/`HEAD` must never change state.
- Schemas: Pydantic v2 models, request models with `extra="forbid"`; the OpenAPI document is generated from them.
- Errors: raise a `backend.core.errors` class; add a new class (with a new stable `code`) rather than a free-text message.
- Blocking work (SQLite, file I/O) must not run on the event loop: use plain `def` endpoints or a worker thread.
- Long-running work (tasks, model downloads) returns an id and streams progress over server-sent events; every task is cancellable.
- Approvals are explicit API operations carrying the operation hash shown to the user; there is no "approve everything" endpoint.
