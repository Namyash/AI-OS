# Kiosk shell and session handoff (milestone M1.4b)

Status: design, decided 2026-11-07. This is the contract the backend, frontend and kiosk work is built against.

## Problem

The kiosk browser must load the UI from the backend and call its API. The backend authenticates every request with a per-start secret
(`/run/pai/token`, readable by the kiosk user `pai-ui`). Anything a process receives on its command line or environment is readable by every
local account through `/proc/<pid>/cmdline` and `/proc/<pid>/environ`, and a secret in a URL ends up in history, referrers and
page-readable navigation-timing data. So the secret must reach the browser without touching any of those.

## Decision: session cookie installed over the DevTools pipe

```
pai-backend ──publishes──► /run/pai/token, /run/pai/endpoint        (after the port is bound)
kiosk launcher (user pai-ui, stdlib Python)
   1. reads the token file and the endpoint file
   2. POST /v1/session  with  Authorization: Bearer <token>   → { "session_id": ..., "expires_in": ... }
   3. starts Chromium under cage with --app=about:blank --remote-debugging-pipe  (no secret in argv or environment)
   4. over the pipe (CDP): Storage.setCookies { pai_session=<session_id>, HttpOnly, SameSite=Strict, host-only on the endpoint origin }
   5. Page.navigate to the endpoint URL (plain, no query, no fragment)
   6. checks the page rendered, writes a readiness file (no secrets), then supervises Chromium
the page and its API calls then carry the cookie automatically; page scripts can never read it (HttpOnly)
```

Why this and not the alternatives:

| Alternative | Rejected because |
|---|---|
| `#token=` in the URL on Chromium's command line | Visible to every local account in `/proc`; stays in navigation-timing data |
| Bootstrap HTML file that redirects with the token | Token still lands in the URL/history/timing data; a file with a secret to clean up |
| One-time code in the URL | Still in argv; a local attacker can read it and race the kiosk to redeem it |
| Browser extension injecting a header | Large new attack surface and packaging burden for one header |

The bearer token stays the credential of **tools** (the launcher, the boot self-check, developers with curl). The browser only ever holds a
revocable, expiring session id that is not the token.

## Backend contract

- **Endpoint file**: `PAI_ENDPOINT_FILE` (default `/run/pai/endpoint`), mode 0640 owner `pai` group `pai`, content `http://<host>:<port>` with no
  trailing newline. Written atomically, at the same moment as the token (only after the listening socket is bound). One default, in `backend/core/config.py`.
- **Sessions**: `POST /v1/session` accepts a valid **bearer token only** (a cookie cannot mint sessions) and returns `201 {"session_id", "expires_in"}`.
  `DELETE /v1/session` revokes the calling session. Ids are 256-bit random values; the server keeps only a hash. In memory, per start, absolute
  lifetime `PAI_SESSION_TTL` (default 12 h), at most 8 live sessions (oldest evicted). A restart invalidates every session.
- **Cookie** `pai_session`: set by the launcher, never by the server. HttpOnly, SameSite=Strict, Path=/, host-only.
- **Guard** (global middleware, unchanged order: Host, Origin, auth): a request is authenticated by a valid bearer token **or**, when there is no
  `Authorization` header, a valid session cookie. A wrong bearer token fails even if a valid cookie is present. A cookie-authenticated request with an
  unsafe method (anything except GET, HEAD, OPTIONS) must carry an `Origin` header equal to its own origin. GET and HEAD never change state.
- **Static UI**: `PAI_STATIC_DIR` (default `/opt/pai/frontend`) is served at `/` behind the same guard, so the shell itself needs the cookie too: there is
  no unauthenticated route. Missing directory: the API still runs and a warning is logged. Responses carry
  `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'` (deny by default; identical to `frontend/security-headers.ts`, enforced by a test), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` for HTML. Unknown paths keep the JSON error shape.

## Frontend contract

No token handling at all. Same-origin `fetch` (the cookie rides along). `/health` returning 401 means "this window has no valid session" and is shown as such.
Development: the Vite dev proxy may inject an `Authorization` header from a developer-supplied token file (dev only, loopback target only).

## Kiosk contract

- Runs as `pai-ui` under `cage` on tty1 (logind session through PAM). `getty@tty1` is not used (the live image's autologin on tty1 is neutralised).
- Chromium: private profile directory, telemetry and background networking off, managed policy allowing only loopback, no DevTools UI. The
  `--remote-debugging-pipe` is a pair of inherited file descriptors owned by the launcher, not a network port.
- Readiness file `/run/pai-ui/ready` (JSON, no secrets): whether the shell rendered and what the status bar reports.
- The launcher never logs, prints or stores the token or the session id.

## Verification (boot self-check additions)

| Check | Proves |
|---|---|
| `kiosk-active` | the kiosk unit runs as `pai-ui`, not root, and Chromium is its child |
| `kiosk-ready` | the shell rendered and reports the backend connected |
| `no-secret-in-process-state` | neither the bearer token nor any session id appears in any process's argv or environment |
| `no-default-credentials` | no account in `/etc/shadow` has a usable password hash |

## Out of scope here

GPU acceleration, multi-seat, voice, the installer (M1.5), and anything that changes the backend API beyond the session endpoints.
