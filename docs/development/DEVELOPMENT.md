# Development Guide

## Prerequisites

- Python ≥ 3.12 (target image ships 3.13; test on both when possible)
- Docker (building the ISO and validating firewall rules; no hypervisor is required)
- Git Bash or any POSIX shell for `os/build/build-iso.sh`
- Node 20+ (needed from milestone M1.4, when the frontend appears)

```bash
python -m pip install -e ".[dev]"
```

## Everyday commands

```bash
python -m pytest            # all tests (backend/tests + tests)
python -m ruff check .      # lint
python -m ruff format .     # format
```

```bash
bash os/build/build-iso.sh  # builds dist/*.iso + .sha256 inside a container
```

Build inputs (environment variables, all optional): `PAI_DISTRIBUTION`, `PAI_ARCH`, `PAI_MIRROR`,
`PAI_SNAPSHOT` (e.g. `20251101T000000Z`; pins the package set to a snapshot.debian.org timestamp for reproducibility),
`PAI_BUILDER_IMAGE`. See `.env.example`. For a release build also pin the builder's base image by digest.

Validate the firewall ruleset with the real `nft` binary (Windows has none):

```bash
docker run --rm --cap-add NET_ADMIN -v "$PWD/os/security/rootfs/etc/nftables.conf:/t/nftables.conf:ro" \
  debian:trixie-slim sh -c 'apt-get update -qq && apt-get install -y -qq nftables && nft -c -f /t/nftables.conf'
```

## Layout and layering

See [ARCHITECTURE](../architecture/ARCHITECTURE.md) §4. Dependencies point downward; `backend/security` must never import
`backend/llm` or `backend/agents`; `backend/core` imports nothing else from the project.
Each source directory has a `README.md` stating its responsibility.

## Image sources

`os/<component>/rootfs/` is copied into the image root; `os/<component>/hooks/*.hook.chroot` run in the image at build time;
package lists live in `os/configuration/package-lists/`. Image sources must use LF line endings (enforced by test).
Policy rules about the image (forbidden packages, firewall defaults, sysctl values) are tables in
`tests/security/test_os_hardening.py`: changing one is a deliberate security decision.

## Database changes

Add a new `NNNN_name.sql` under `backend/database/migrations/`. Never edit an applied migration (the runner checksums them).
Add tests for any new invariant. Update `docs/database/DATABASE_SCHEMA.md`.

## Conventions

- Type annotations everywhere; Pydantic models at every external boundary; explicit exception handling; structured logging.
- Reuse and extend before adding. Remove what a change makes obsolete. Tests accompany every behaviour change.
- No secrets, keys or credentials in code, logs or fixtures.
- Windows note: debootstrap cannot run on bind-mounted Windows directories, which is why the build work directory is a Docker volume
  (`pai-live-build`). Remove it with `docker volume rm pai-live-build` to force a clean build.
