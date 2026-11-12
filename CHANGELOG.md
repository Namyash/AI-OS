# Changelog

## Unreleased

### Added
- Phase 0: architecture, threat model, technology evaluation, tool execution model, memory architecture, risk register, Phase 1 plan.
- SQLite schema (`0001_initial.sql`) with database-level safety invariants and a checksum-verifying forward-only migration runner.
- M1.1 build foundation: containerized live-build ISO builder, default-deny nftables ruleset, sysctl hardening, host-integration module lockdown, minimal package list, `os/build/assemble-config.sh` (component discovery, collision refusal, mode normalisation, backend install).
- M1.2 boot verification: in-image security self-check (12 data-driven checks, `pai-selfcheck.service`, run only with kernel argument `pai.selfcheck=1`) and a QEMU boot harness (software emulation in a container) that fails on a missing, empty or partial verdict.
- M1.3 backend service: authenticated loopback-only FastAPI skeleton (`GET /health`), per-start bearer token file, Host/Origin checks, structured redacting logs, migrations at start, refuses to run as root; hardened `pai-backend.service`, system accounts, and a general systemd unit linter.
- M1.4a frontend shell: React + TypeScript app with offline fonts, in-memory token handling, truthful status bar and a disabled composer with a visible reason.
- Policy-as-code tests for the image sources, layering and unit hardening.

- M1.4b kiosk: `kiosk/` launcher (stdlib only) that mints an expiring session and installs it as an HttpOnly cookie over Chromium's DevTools pipe; `pai-kiosk.service` (cage + Chromium on tty1 as `pai-ui`) with a loopback-only managed policy; the backend serves the production UI behind the same guard; `POST/DELETE /v1/session`, endpoint file, cookie authentication, deny-by-default CSP shared with the frontend (contract test).
- Boot self-check grew to 16 checks (kiosk, credentials in process state, default credentials) with failure diagnostics; `PAI_BOOT_EXTRA_ARGS`; live-config script locking the stock live login; logind no longer starts login prompts on other virtual terminals.
- Build pipeline builds the production UI inside the builder container and installs backend, kiosk and UI through one rule; ISO is now 610 MB.

- M1.5 installer: `installer/` engine (stdlib Python, root-only) that installs the live system onto an explicitly named disk with GPT, BIOS and UEFI GRUB and a LUKS2 (argon2id) root with a passphrase and a random recovery key; safety rules, rollback, strict plan validation; `pai-install-auto.service` for unattended and test installs from a `PAI-PLAN` medium; installed-system self-checks (`root-encrypted`, `no-live-remnants`); QEMU install test (install, BIOS boot, UEFI boot, unlock, 18 checks, wrong passphrases).
- Design decision: custom installer instead of Calamares (`docs/architecture/INSTALLER_DESIGN.md`).

### Changed
- The frontend no longer handles any token (cookie-based, same-origin); the dev proxy can inject a token from a developer-supplied file.
- Dev install is one command: the `dev` extra now includes the `api` extra.
- `.gitattributes` forces LF line endings.

### Fixed (found by the real install)
- The installer could not drop apt's privileges under `NoNewPrivileges` (needs ambient `CAP_SETUID`/`CAP_SETGID`); its final mount check flagged systemd's own bind mount of the work directory and made every successful install report failure; the auto-install script accepted volume labels such as `-n` and `..`.

### Security
- Fixed during review: log-redaction regex was super-linear and missed non-Bearer authorization schemes; the service could load user-site code from its writable state directory; the kiosk account could list the data directory; the self-check could pass with a dormant firewall or `RESULT PASS 0/0`; token capture could leave the token in the address bar.
- Open items are listed in `docs/security/SECURITY.md` ("Known gaps").
