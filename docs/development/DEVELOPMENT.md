# Development Guide

## Prerequisites

- Python ≥ 3.12 (the image ships Debian's 3.13; the backend tests are also run there in a container)
- Docker (building the ISO, boot tests, validating firewall rules and unit files; no hypervisor is required)
- Git Bash or any POSIX shell for `os/build/build-iso.sh`
- Node 20.18.1 or newer for the frontend (Debian 13's own Node 20.19 / npm 9 also work)

One command sets up everything the Python tests need (the `dev` extra includes the `api` extra):

```bash
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"     # Windows; use .venv/bin/python elsewhere
```

## Everyday commands

```bash
python -m pytest            # backend, security-policy and fast boot-harness tests (e2e boots are deselected)
python -m ruff check .      # lint
python -m ruff format .     # format
```

```bash
cd frontend && npm ci && npm run typecheck && npm test && npm run build && npm run lint
```

Details for the UI: [FRONTEND.md](FRONTEND.md). The backend's contract: [API_DOCUMENTATION.md](API_DOCUMENTATION.md).

## Building and booting the ISO

```bash
bash os/build/build-iso.sh                      # builds dist/*.iso + .sha256 inside a container (many minutes)
python -m pytest -m e2e tests/end_to_end -s     # boots dist/*.iso under QEMU (software emulation) in a container
```

Build inputs (environment variables, all optional): `PAI_DISTRIBUTION`, `PAI_ARCH`, `PAI_MIRROR`,
`PAI_SNAPSHOT` (e.g. `20251101T000000Z`; pins the package set to a snapshot.debian.org timestamp for reproducibility),
`PAI_BUILDER_IMAGE`. See `.env.example`. For a release build also pin the builder's base image by digest.

Boot-test inputs and how to read a failure: [BOOT_TESTING.md](BOOT_TESTING.md). A boot only counts as a pass when the guest prints
the final `PAI-SELFCHECK|RESULT|PASS` line; a run that checked nothing, or never printed it, is a failure.

Validate the firewall ruleset with the real `nft` binary (Windows has none):

```bash
docker run --rm --cap-add NET_ADMIN -v "$PWD/os/security/rootfs/etc/nftables.conf:/t/nftables.conf:ro" \
  debian:trixie-slim sh -c 'apt-get update -qq && apt-get install -y -qq nftables && nft -c -f /t/nftables.conf'
```

## Layout and layering

See [ARCHITECTURE](../architecture/ARCHITECTURE.md) §4. Dependencies point downward; `backend/security` must never import
`backend/llm` or `backend/agents`; `backend/core` imports nothing else from the project (both enforced by tests).
Each source directory has a `README.md` stating its responsibility.

## Image sources

Each component `os/<name>/` may hold `package-lists/`, `rootfs/` (copied onto the image root) and `hooks/`
(`*.hook.chroot`, run inside the image at build time). `os/build/assemble-config.sh` discovers components, refuses two
components shipping the same file, normalises modes (directories 0755, files 0644, `#!` scripts 0755) and installs
`backend/` at `/opt/pai/backend` without tests or caches. `tests/security/test_image_assembly.py` runs that same script
against a scratch directory.

Policy about the image is enforced as tests, not convention. They are tables you change deliberately, with a reason:
- `tests/security/test_os_hardening.py`: firewall defaults, forbidden/required packages, sysctl values, module lockdown, LF endings, shell fail-fast.
- `tests/security/test_systemd_units.py`: every unit under `os/**` must carry the sandbox baseline; a root unit needs a
  `# pai-lint: root-justified: <reason>` comment and a narrow capability set.
- `os/security/rootfs/usr/lib/pai/security-selfcheck.sh` re-checks the same posture on the booted image.

Image sources must use LF line endings (`.gitattributes` enforces it; a test rejects CRLF).

## Database changes

Add a new `NNNN_name.sql` under `backend/database/migrations/`. Never edit an applied migration (the runner checksums them).
Add tests for any new invariant. Update `docs/database/DATABASE_SCHEMA.md`.

## Conventions

- Type annotations everywhere; Pydantic models at every external boundary; explicit exception handling; structured logging.
- Reuse and extend before adding. Remove what a change makes obsolete. Tests accompany every behaviour change.
- No secrets, keys or credentials in code, logs or fixtures.
- A security control that no test can fail is not a control: new controls come with a test that fails when the control is removed.
- Windows note: debootstrap cannot run on bind-mounted Windows directories, which is why the build work directory is a Docker volume
  (`pai-live-build`). Remove it with `docker volume rm pai-live-build` to force a clean build. The Windows `bash` on PATH is often the
  WSL launcher with no distribution behind it; tests that need bash look for a working one (Git Bash).
