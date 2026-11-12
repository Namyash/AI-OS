# services

Typed API client for the backend; the only place the UI performs I/O.

- `api-client.ts`, `api-error.ts`: same-origin GET requests with timeout and typed errors. The page holds no credential:
  the browser attaches the HttpOnly session cookie by itself, and a 401 becomes the `unauthorized` error.
- `health.ts`: the `/health` contract and its runtime type guard.
