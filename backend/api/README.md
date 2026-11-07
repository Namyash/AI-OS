# api

HTTP transport only: routers, auth, request/response schemas. No business logic.

| Module | Responsibility |
|---|---|
| `app.py` | `create_app(settings)`: lifespan (migrate the database, then publish the per-start token; any failure aborts startup), middleware, handlers, routes. |
| `security.py` | `BoundaryGuard`, pure ASGI middleware: Host allowlist (loopback names plus the configured bind address), Origin check, bearer authentication, in that order, on every path. Logs each rejection by reason code only. |
| `auth.py` | Token generation, atomic token-file publication, constant-time verification. |
| `errors.py` | Maps every failure to the one `{"error": {"code", "message"}}` body; logs validation failures by error type only. |
| `health.py` | `GET /health`. |

Contract and endpoints: [API_DOCUMENTATION](../../docs/development/API_DOCUMENTATION.md). Run it with `python -m backend` (`backend/__main__.py` binds the port first, then starts the application).
