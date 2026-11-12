# build

Container-based ISO build (live-build): `build-iso.sh` on the host, `in-container-build.sh` inside.

| File | Purpose |
|---|---|
| `Dockerfile` | The builder image: live-build and its tools, plus Debian's own `nodejs` and `npm` for the UI build. |
| `build-iso.sh` | Host entry point. Mounts `os/`, `backend/`, `kiosk/`, `installer/` and `frontend/` read-only into the container. |
| `in-container-build.sh` | Builds the UI, assembles the live-build tree, runs `lb build`, copies the ISO out. |
| `build-frontend.sh` | `npm ci` (lockfile integrity, no install scripts) and `npm run build` in a copy of `frontend/`; outputs only the contents of `dist/`. |
| `assemble-config.sh` | Fills live-build's `config/` from `os/*` components and installs `/opt/pai/backend`, `/opt/pai/kiosk`, `/opt/pai/installer` (no tests, caches or documentation) and `/opt/pai/frontend` (the build output) as root-owned, never group- or world-writable files. |
