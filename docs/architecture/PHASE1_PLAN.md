# Phase 1 Implementation Plan: Bootable Linux Foundation

Goal: boot an ISO in VMware/VirtualBox, install it onto an encrypted disk, and reach the AI-first interface shell.
Each milestone is independently testable and has an acceptance test; later milestones depend only on earlier ones.

| # | Milestone | Deliverables | Acceptance test |
|---|---|---|---|
| M0 | Architecture, schema | Docs in `docs/`, `0001_initial.sql`, migration runner | Schema/migration tests pass (done) |
| M1.1 | Build foundation | Builder container, live-build config, baseline firewall/sysctl/modprobe, policy-as-code tests | `nft -c` accepts the ruleset; policy tests pass; builder produces an ISO + SHA-256 |
| M1.2 | Boot smoke test | `tests/end_to_end` harness: boots the ISO headless under QEMU in a container, reads the serial console | Reaches `multi-user.target`; `nft list ruleset` shows policy drop on all hooks; no listening TCP/UDP sockets; `vboxsf` cannot load |
| M1.3 | Service accounts + backend skeleton | Users `pai`, `pai-llm`; FastAPI app (`/health`, config, structured logging); hardened systemd unit; unit-hardening linter | API tests pass; `systemd-analyze security` score target met in the boot test; service runs as non-root |
| M1.4 | Kiosk shell | `cage` + Chromium kiosk, React/TypeScript shell served by the backend, per-boot bearer token | Boot test screenshot shows the shell; frontend unit tests pass; unauthenticated requests are refused |
| M1.5 | Installer + LUKS2 | Calamares config (LUKS2 argon2id, unencrypted `/boot`, ESP), first-boot wizard (account, passphrase, recovery key), `/var/lib/pai` on the encrypted volume | Automated QEMU install, reboot, unlock; `cryptsetup luksDump` shows LUKS2/argon2id; wrong passphrase fails |
| M1.6 | Hypervisor matrix | VMware Workstation and VirtualBox VM recipes, guest-integration lockdown checklist | Manual run recorded in `docs/installation/`; clipboard, drag-and-drop and shared folders confirmed disabled |

## Status (2026-11-07)

Done and verified: M0, M1.1, M1.2, M1.3, M1.4a, M1.4b and M1.5 (as an engine plus an automated install test under QEMU; the wizard in the
kiosk and the first-boot account step are not built, so M1.5's "first-boot wizard" deliverable is only partly met). M1.4's acceptance test ("boot screenshot shows the shell") is met in the form the dev
machine allows: the booted image's self-check reports the kiosk running and the shell rendered with the backend connected (QEMU has no screen to
photograph). Not started: the M1.5 wizard, M1.6. Evidence and caveats: `DEVELOPMENT_STATUS.md`.

## Order of work and why

1. **Firewall and integration lockdown before any service** (M1.1): there is nothing to protect later if the base is open.
2. **Automated boot test before more features** (M1.2): every later milestone gets regression coverage for free.
3. **Backend skeleton before the shell** (M1.3 → M1.4): the shell needs something authenticated to talk to.
4. **Installer last** (M1.5): it is the highest-risk piece (R8) and depends on the final disk layout and first-boot flow.

## Out of scope for Phase 1

LLM runtime, agent, memory, tools: they start in Phases 2–4. The schema and backend skeleton exist only so the OS
foundation has a real service to run and the later phases have an agreed data model.

## Definition of done per milestone

Code and configuration reviewed; tests added and passing; docs and `DEVELOPMENT_STATUS.md` updated; known issues listed;
no capability claimed that was not exercised by a test or a recorded manual run.
