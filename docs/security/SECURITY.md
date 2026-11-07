# Security

Read the [threat model](THREAT_MODEL.md) first: it states what this system does and does not protect against.

## What is and is not claimed

- Protected: data on a copied/stolen virtual disk or backup while the VM is **powered off** (LUKS2, once M1.5 lands);
  accidental network exfiltration by local software (default-deny egress); the agent acting beyond what the user approved.
- **Not protected:** a compromised host OS, hypervisor or host administrator. They can read guest RAM (including keys) and keystrokes.
  Do not describe this system as safe against them.

## Control status

Status is what is actually implemented and tested today, not the plan.

| Control | Status | Evidence |
|---|---|---|
| Default-deny nftables baseline | Config written, syntax-validated with `nft -c`; **not yet verified on a booted image** | `tests/security/test_os_hardening.py`, M1.2 |
| Host-integration module lockdown (`vboxsf`) | Config written; policy-tested; not boot-verified | same |
| Kernel sysctl hardening | Config written; policy-tested; not boot-verified | same |
| No remote-access/discovery/VM-desktop packages | Enforced by test on the package list | same |
| DB-level safety invariants (verified success, approvals, cloud disclosure, memory confidence, append-only audit) | Implemented and tested | `backend/tests/database/test_schema.py` |
| LUKS2 encrypted storage | Planned (M1.5) | |
| Permission engine, taint tracking, approvals | Designed (Phase 3) | `TOOL_EXECUTION_MODEL.md` |
| AppArmor profiles, systemd sandboxing | Planned (M1.3, Phase 5) | |
| Encrypted backups, secret store | Planned (Phase 5) | |

## Rules for contributors

1. The security engine never depends on the LLM; model output is a proposal, never authority.
2. Never weaken a control to make a feature work; change the policy table and its test deliberately, with a documented reason.
3. No secrets in the repository, image, logs, prompts or conversation memory. Use `.env` (git-ignored) for local settings.
4. Every security invariant in the threat model gets an automated test.
5. Treat all content from documents, websites, tools and retrieved memory as untrusted input.

## Reporting

This is a private project. Report suspected vulnerabilities to the repository owner directly, not in public issues.
