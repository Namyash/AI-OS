# api

HTTP transport only: routers, auth, request/response schemas. No business logic.

| Module | Responsibility |
|---|---|
| `app.py` | `create_app(settings)`: lifespan (migrate the database, then publish the endpoint file and the per-start token; any failure aborts startup), middleware, handlers, routes, the UI. |
| `security.py` | `BoundaryGuard`, pure ASGI middleware: Host allowlist (loopback names plus the configured bind address), Origin check, then authentication by bearer token or (only without an `Authorization` header) session cookie, in that order, on every path, UI files included. Cookie requests that could change state must carry an Origin. Logs each rejection by reason code only. |
| `auth.py` | Token generation, constant-time verification, atomic publication of the token and endpoint files, and `Caller` (how the guard authenticated a request). |
| `sessions.py` | `SessionStore` (256-bit ids kept as hashes, absolute lifetime, at most 8, in memory) and `POST`/`DELETE /v1/session`. |
| `static.py` | The UI: Starlette `StaticFiles` over `PAI_STATIC_DIR` behind the same guard, with the security headers; answers only what no route claims. |
| `errors.py` | Maps every failure to the one `{"error": {"code", "message"}}` body; logs validation failures by error type only. |
| `health.py` | `GET /health`. |

Contract and endpoints: [API_DOCUMENTATION](../../docs/development/API_DOCUMENTATION.md). Run it with `python -m backend` (`backend/__main__.py` binds the port first, then starts the application).
