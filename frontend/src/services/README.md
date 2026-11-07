# services

Typed API client for the backend; the only place the UI performs I/O.

- `token.ts`: reads the access token from the URL fragment once and strips it from the address bar.
- `api-client.ts`, `api-error.ts`: same-origin requests with `Authorization: Bearer`, timeout, typed errors.
- `health.ts`: the `/health` contract and its runtime type guard.
