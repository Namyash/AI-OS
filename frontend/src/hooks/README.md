# hooks

Shared React hooks.

- `useBackendHealth`: polls `GET /health` with backoff and reports `connecting`, `connected`, `unreachable` or `unauthorized`.
  A failure that is not an `ApiError` is reported as unreachable (cause `unexpected`) and retried; polling never stops silently.
- `useBrowserOnline`: the browser's own online/offline report (`navigator.onLine`), not a connectivity test.
