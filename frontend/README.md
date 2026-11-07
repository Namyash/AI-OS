# frontend

React + TypeScript interface for Private AI OS: the shell that runs full-screen in the Chromium kiosk and talks to the
backend over loopback with a per-boot bearer token. It shows only what is backed by real data; features that do not exist
yet have no controls.

```bash
npm ci && npm test && npm run build     # output in dist/
```

Setup, scripts, structure, the token and Content-Security-Policy contracts, backend and kiosk integration, and known limits:
[docs/development/FRONTEND.md](../docs/development/FRONTEND.md). Run npm only inside this directory.
