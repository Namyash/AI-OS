# frontend

React + TypeScript interface for Private AI OS: the shell that runs full-screen in the Chromium kiosk and talks to the
backend over loopback. The page holds no credential; the kiosk launcher signs the window in with an HttpOnly session cookie.
It shows only what is backed by real data; features that do not exist yet have no controls.

```bash
npm ci && npm test && npm run build     # output in dist/
```

Setup, scripts, structure, the session and Content-Security-Policy contracts, signing in during development
(`PAI_DEV_TOKEN_FILE`), backend and kiosk integration, and known limits:
[docs/development/FRONTEND.md](../docs/development/FRONTEND.md). Run npm only inside this directory.
