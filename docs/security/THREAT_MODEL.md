# Threat Model

## 1. Protected assets

| Asset | Examples |
|---|---|
| A1 Personal data | conversations, memories, documents, embeddings |
| A2 Credentials | passwords, tokens, private keys the user hands to the system |
| A3 System integrity | OS files, services, security policy, audit log |
| A4 User intent | the user's approvals must be the only source of authority for sensitive actions |

## 2. Actors and trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Kernel / systemd | root, kernel | every service user |
| Service ↔ service | each service for its own role | other services' inputs (all validated) |
| Agent ↔ model | deterministic code | **model output** (proposals only) |
| Agent ↔ content | user's typed requests | documents, web pages, tool output, retrieved memories |
| Guest ↔ host | the guest | the hypervisor, host OS and host administrator |

## 3. Explicit limits (stated plainly)

A VM guest **cannot** defend against a compromised or hostile host, a malicious hypervisor, or a host administrator:
- The host can read guest RAM, which holds the LUKS volume key and decrypted data while the VM runs.
- Suspend/snapshot files contain guest RAM and therefore keys and plaintext.
- The host can log keystrokes, including the unlock passphrase.
- Shared clipboard/folders, if the user enables them, bypass the guest boundary entirely.

LUKS2 therefore protects against: a copied or stolen virtual disk, backups, or a disk image shared by accident,
**while the VM is powered off**. Hypervisor-level VM encryption (VMware, VirtualBox) and host disk encryption
are complementary and recommended in the installation guide. Documentation and UI must not promise more than this.

## 4. Threats and mitigations

| ID | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Prompt injection via documents/web/memory causing harmful actions | Taint tracking: content from untrusted sources marks the turn; any proposed action at level ≥ 2 in a tainted turn needs explicit approval showing provenance. Security engine is deterministic and runs outside the LLM. | User approves without reading. Previews must be specific and exact. |
| T2 | Model proposes destructive command | 4-level permission model; tools expose typed operations, not a raw shell; level 3–4 need approval with a preview; dry-run where possible. | A generic "run script" tool is inherently level 4. |
| T3 | Agent process compromise → root | Agent runs as an unprivileged user under systemd sandboxing + AppArmor; privileged verbs live in `pai-privd` with approval tokens bound to operation hashes. | Bugs in `pai-privd`; keep it tiny and fuzz-tested. |
| T4 | Data exfiltration over the network | nftables default-deny egress; per-service-user rules (`meta skuid`); LLM runtime user has no route; outbound allow-list empty by default and user-controlled. Telemetry off. | Allowed destinations can still carry data; the audit log records connections by tool. |
| T5 | Silent cloud inference | Provider abstraction refuses cloud providers unless `is_cloud` config has a recorded disclosure acknowledgement (also a DB CHECK constraint); no automatic fallback between providers. | None known beyond bugs. |
| T6 | Credential leakage through memory/logs/prompts | Credentials only in `pai-secretd`, referenced by handle; secret-pattern detector blocks semantic-memory writes; log redaction filter. | Pattern detection is heuristic. |
| T7 | Tampering with the audit trail | Append-only DB triggers + hash chain (`prev_hash`/`event_hash`); periodic chain verification at boot. | An attacker with root can rewrite everything; the chain detects, not prevents. |
| T8 | Malicious model file (GGUF parser bugs) | Models run in the network-less, AppArmor-confined `pai-llm` service; SHA-256 verification on download; HTTPS only; pin sources. | Memory-safety bugs in llama.cpp. |
| T9 | Local web UI attacked from the VM (other users, browser content) | Loopback only, per-boot bearer token, Origin/Host checks, no CORS wildcard, browser kiosk locked to the UI origin. Browser automation runs in a separate profile and user. | Compromised browser user can reach loopback; token not exposed to it. |
| T10 | Boot-chain tampering | `/boot` is unencrypted by design (GRUB/LUKS2 limitation); documented. Later: Secure Boot, signed UKI, measured boot with vTPM. | Open in initial release. |
| T11 | Data loss (corruption, bad AI action) | SQLite WAL + online backups, restic encrypted backups, trash instead of unlink for level-3 deletes, task rollback metadata. | Backup passphrase loss is unrecoverable. |
| T12 | Supply chain (pip/npm/apt/models) | Pinned and hashed dependencies, reproducible ISO via snapshot.debian.org, minimal packages. | Upstream compromise before pinning. |

## 5. Security invariants (each gets a test)

1. `backend/security` imports nothing from `backend/llm` or `backend/agents`.
2. No tool executes at level ≥ 3 without a matching approved approval record.
3. A task cannot be `succeeded` without `verification_status = 'verified'`.
4. A cloud model config cannot exist without a disclosure acknowledgement.
5. Default nftables policy for `output` and `forward` is `drop`.
6. Shared-folder/clipboard kernel modules are blacklisted by default.
7. No encryption key or credential appears in the repository, image or logs.
