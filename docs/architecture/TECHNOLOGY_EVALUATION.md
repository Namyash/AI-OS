# Technology Evaluation

Verdicts are decisions for the initial release, with the condition under which each would be revisited.

| Area | Chosen | Alternatives considered | Why / revisit when |
|---|---|---|---|
| Base distro | Debian 13 stable | Ubuntu Server LTS | Smaller, no snap/Pro/telemetry stack to remove, `snapshot.debian.org` for reproducible package sets. Revisit if a required driver/package only exists on Ubuntu. |
| ISO tooling | live-build in a container | Cubic, mkosi, debos | Official, declarative, scriptable on CI and Windows-via-Docker. mkosi is a candidate if reproducibility needs exceed live-build. |
| Installer | Custom engine (stdlib Python, copies the live root; BIOS and UEFI GRUB; LUKS2 argon2id) | Calamares, Debian-installer preseed | Decided 2026-11-10, reversing Phase 0: Calamares needs Qt and a display and cannot be driven by our own wizard or tested headless under emulation. Cost: we own a disk-destroying component (risk R17), so it has strict guardrails, fake-runner and real-tool tests, and an end-to-end QEMU install test. |
| Disk encryption | LUKS2, argon2id, unencrypted `/boot` | Encrypted `/boot` (needs pbkdf2) | GRUB cannot do argon2id; weaker KDF for the whole volume is the worse trade. Revisit with Secure Boot + UKI. |
| UI shell | React + TypeScript in a Chromium kiosk under `cage` | Tauri (WebKitGTK + Rust), Electron | One browser reused by Playwright; no Rust toolchain in the image. Revisit in Phase 6 for native integration needs. |
| Backend | Python ≥ 3.12, FastAPI, Pydantic v2, asyncio | Go, Rust | Mandated; best local-AI ecosystem. Debian 13 ships Python 3.13, so CI tests 3.12 and 3.13. |
| LLM runtime | `llama-server` (llama.cpp), OpenAI-compatible HTTP over a Unix socket | Ollama, vLLM, in-process bindings | GGUF, GBNF grammars for structured output, mmap, explicit context/GPU control, out-of-process isolation. Ollama only as an optional adapter: extra daemon and its own model store. vLLM needs CUDA and more RAM than the target. |
| Embeddings | Small GGUF embedder served by llama.cpp | sentence-transformers/PyTorch, ONNX | Avoids a multi-GB dependency and a second inference stack. Benchmark candidates in Phase 4. |
| Metadata DB | SQLite (WAL, STRICT, FTS5), plain SQL migrations | PostgreSQL, SQLAlchemy+Alembic | No daemon, trivial backups. Plain SQL + a ~100-line runner avoids an ORM dependency; revisit if schema churn makes it painful. |
| Vector search | `VectorStore` interface; sqlite-vec vs Qdrant decided by Phase 4 benchmark | Qdrant default, FAISS, Chroma | Minimise resident services on 8 GB; vectors are rebuildable derived data so the decision is cheap to reverse. |
| Firewall | nftables (`meta skuid` per-service rules) | iptables, ufw | Native, atomic rule loads, per-user matching. |
| MAC / sandboxing | AppArmor + systemd sandbox directives | SELinux, bubblewrap-only | AppArmor is Debian's default; systemd directives give cheap, declarative confinement. Bubblewrap may wrap document extractors. |
| Secrets | `pai-secretd` (separate user, Unix socket, handle-based) | kernel keyring only, systemd-creds/TPM | Agent never sees values. A vTPM may not exist in VMware/VirtualBox, so TPM sealing is optional, not required. |
| Backups | restic (encrypted, deduplicated) + SQLite online backup | borg, tar+age | Built-in encryption, single binary in Debian, verifiable. |
| Browser automation | Playwright driving the system Chromium | Selenium | Mandated; reuse the kiosk browser binary with a separate profile and user. |
| Voice (Phase 6) | whisper.cpp (STT), Piper (TTS) | cloud APIs | Local-only, CPU-capable. Latency to be measured. |
| Tests | pytest, httpx; QEMU in a container for boot tests | VM-per-test on hypervisor | Works on any CI/dev host with Docker; no hypervisor required. TCG (no KVM) is slow, so boot tests stay few. |

## Model compatibility analysis

| Capability | Native tool calls | Grammar-constrained JSON | Prompted JSON |
|---|---|---|---|
| Reliability on small (≤ 4B) models | low–medium | **high** | low |
| Needs template support | yes | no | no |
| Cost | none | small decoding overhead | retries |

Because small local models are unreliable at free-form tool calling, grammar-constrained decoding is the default strategy whenever
the runtime supports it; native tool calls are used only after a per-model probe passes. Plans always go through schema validation,
so a wrong guess fails closed instead of executing. Context length is capped by the memory estimate, not by what the model advertises.
