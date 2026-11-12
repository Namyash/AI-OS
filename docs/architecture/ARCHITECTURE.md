# Architecture

Status: Phase 0 design. Nothing in this document is implemented unless `DEVELOPMENT_STATUS.md` says so.

## 1. Goals and non-goals

Goals: a Debian-based OS image that boots into an AI-first interface, runs local models offline, executes
user requests through a deterministic and audited tool layer, and keeps persistent memory inside an encrypted volume.

Non-goals (initial release): a custom kernel, protection from a malicious hypervisor/host (see
[THREAT_MODEL](../security/THREAT_MODEL.md)), multi-user desktops, mandatory cloud services.

## 2. Base system

| Decision | Choice | Reason |
|---|---|---|
| Distribution | Debian 13 "trixie" (current stable) | No snap/telemetry/Pro-advert components to strip, small minimal base, AppArmor on by default, `snapshot.debian.org` allows reproducible builds. Ubuntu Server remains an acceptable fallback; nothing above the package layer depends on the choice. |
| ISO build | `live-build` inside a pinned Debian container | Official Debian tool, scriptable, runs from Docker on a Windows dev machine. |
| Installer | A small custom, root-only engine (`installer/`) that copies the live root onto a LUKS2 layout; the kiosk wizard will drive it later | Reverses the Phase 0 choice (Calamares needs Qt and a display, cannot be driven by our wizard or tested headless). The disk-destroying risk is handled by hard guardrails and tests: see [INSTALLER_DESIGN](INSTALLER_DESIGN.md). |
| Init | systemd | Required by spec; gives sandboxing directives and per-service cgroups. |
| Boot layout | EFI/BIOS + **unencrypted `/boot`**, LUKS2 root (argon2id) | GRUB cannot unlock argon2id LUKS2 volumes. Cost: kernel/initramfs are not confidentiality- or integrity-protected on disk. Mitigation path: Secure Boot + signed UKI in a later phase. |

## 3. Runtime topology

```
 tty1 ─ cage (Wayland kiosk) ─ chromium --app ──HTTP 127.0.0.1 + HttpOnly session cookie──┐
                                                                               ▼
 pai-backend (FastAPI, user pai) ── Unix socket ──► pai-llm  (llama-server, user pai-llm, NO network)
        │  │  └─ Unix socket ─────► pai-privd (root helper, allow-listed verbs, approval-token gated)
        │  └──── Unix socket ─────► pai-secretd (credential store, user pai-secret)
        ▼
 /var/lib/pai (on the LUKS volume): SQLite (WAL) · vector store · documents · models · backups
```

Each box is a separate systemd unit with its own Linux user, `ProtectSystem=strict`, `NoNewPrivileges`,
restricted address families and an AppArmor profile. Only `pai-privd` runs with elevated rights, and it only
exposes a fixed set of operations (it is not a shell).

Process rules:
- The LLM process can only produce text. It has no network and no filesystem access beyond the model directory.
- The backend cannot become root. Privileged operations are requests to `pai-privd`, which verifies an
  **approval token**: single-use, short TTL, bound to the SHA-256 of the exact operation and arguments.
- Credentials never enter prompts or conversation memory. Tools receive opaque secret handles that
  `pai-secretd` resolves only for an approved execution.

## 4. Backend layering (dependency direction is downward only)

```
api  →  agents  →  tools · memory · llm   →  storage · database
                     ↘      ↓
                      security  (no import of llm; enforced by a test)
core  (config, logging, ids, errors) is imported by everyone and imports nobody.
```

- `llm/` defines a `ModelProvider` protocol (chat, stream, embed, capabilities). The agent never imports a
  concrete runtime. Adapters live in `model_runtime/adapters` (llama.cpp first, Ollama optional).
- `security/` (permission engine, taint tracking, approval issuer, audit chain) must work with the LLM absent.
  A static test asserts that `backend/security` does not import `backend/llm` or `backend/agents`.
- `tools/` each tool = Pydantic input model + Pydantic output model + declared permission level + verifier.

## 5. Agent lifecycle mapped to components

| Spec step | Component |
|---|---|
| 1–2 request, intent | `agents.orchestrator`, `agents.intent` |
| 3 memory retrieval | `memory.retrieval` (token-budgeted, see MEMORY_ARCHITECTURE) |
| 4–6 info needs, plan, tool choice | `agents.planner` → structured plan validated against the tool registry |
| 7 argument validation | `tools.registry` (Pydantic) |
| 8–9 permission, approval | `security.policy`, `security.approvals` |
| 10–12 execute, inspect, recover | `tasks.executor`, `tasks.recovery` |
| 13 verify | per-tool `verify()` that re-observes system state; a task cannot reach `succeeded` otherwise (also enforced by a DB CHECK) |
| 14–15 history, response | `tasks.state`, `memory.writer`, `agents.responder` |

Detail: [TOOL_EXECUTION_MODEL](TOOL_EXECUTION_MODEL.md), [MEMORY_ARCHITECTURE](MEMORY_ARCHITECTURE.md).

## 6. Resource budget (8 GB RAM / 4 vCPU target)

Estimates, to be measured in Phase 2:

| Consumer | Approx. RAM |
|---|---|
| Kernel + systemd + services | 0.4 GB |
| Cage + Chromium kiosk | 0.6–0.9 GB |
| Backend + SQLite + vector store | 0.3 GB |
| Model weights + KV cache | the remainder, ≈ 5 GB |

KV cache size = `2 × layers × context × kv_heads × head_dim × bytes_per_element`. The model manager computes this
from GGUF metadata before loading and refuses or warns when `weights + KV + headroom > available`.
Consequence: on 8 GB the default tier is a 3–4B parameter model at Q4; 7–8B models are offered only when free
memory allows (typically ≥ 12–16 GB VM). Only one large model is loaded at a time.

## 7. Challenges to the original proposal

1. **Tauri deferred.** Tauri needs a Rust toolchain and WebKitGTK in the image; the same React UI runs in a
   Chromium kiosk, which Playwright can also reuse (`executable_path`) so there is one browser, not two.
   Revisit in Phase 6 if native shell integration needs it.
2. **Qdrant is not the default.** A separate Rust daemon costs RAM and complicates consistent backups.
   Vector search sits behind a `VectorStore` interface; Phase 4 benchmarks sqlite-vec (embedded, one encrypted
   file, brute force) against Qdrant and picks by measured latency/RAM at the target corpus size.
3. **No SQLCipher on top of LUKS.** For the disk-theft threat it is redundant; for a compromised agent process it
   does not help because that process holds the key. Encryption is applied where it matters: LUKS2 at rest and
   passphrase-encrypted backups/exports (restic).
4. **Embeddings through llama.cpp** (`--embedding` with a small GGUF embedder) instead of PyTorch, avoiding a
   multi-GB dependency.
5. **Loopback HTTP, not a Unix socket, for the UI.** A browser cannot speak to a Unix socket. Host and Origin checks plus
   authentication on every route protect the loopback listener. Tools authenticate with a per-start bearer token; the
   browser never holds it: the kiosk launcher exchanges it for an expiring session and installs that as an HttpOnly
   cookie over Chromium's DevTools pipe (see [KIOSK_SESSION_DESIGN](KIOSK_SESSION_DESIGN.md)).

## 8. Repository layout deviations

Documentation files live under `docs/<area>/` as in the proposed tree; `CHANGELOG.md` and `README.md` stay at
the root. Each source directory carries a short `README.md` stating its responsibility.
