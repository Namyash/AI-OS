# Technical Risk Register

| ID | Risk | Likelihood / Impact | Mitigation | Status |
|---|---|---|---|---|
| R1 | Dev host has no VMware/VirtualBox/QEMU and no hardware virtualisation exposed to Docker, so ISO boot cannot be tested natively | Certain / High | Boot-test under QEMU TCG (software emulation) inside a container; manual VMware/VirtualBox validation required before any release claim | Open |
| R2 | GRUB cannot unlock LUKS2 argon2id volumes | Certain / Medium | Unencrypted `/boot`, encrypted root; documented in the threat model; Secure Boot/UKI later | Mitigated by design |
| R3 | 8 GB RAM is tight for OS + Chromium + model | High / High | Resource-aware model selection, KV-cache estimate before load, 3–4B default tier, single model resident | Open (Phase 2) |
| R4 | CPU-only inference is slow, multiplying latency over multi-step plans | High / High | Short prompts, grammar-constrained output, streaming progress UI, small plan steps; measure tokens/s on the target VM | Open (Phase 2) |
| R5 | Small models are unreliable at tool calling and planning | High / High | Compatibility layer, schema validation, bounded repair, verify-before-success, fail closed | Designed |
| R6 | GPU passthrough is rarely available in VMware Workstation/VirtualBox | High / Medium | CPU is the baseline; GPU is an optional accelerator detected at run time | Designed |
| R7 | Prompt injection (documents, web, memories) | Certain / High | Taint tracking, deterministic policy, approvals with provenance | Designed (Phase 3) |
| R8 | Calamares customisation (LUKS2 layout, first-boot flow) is brittle | Medium / Medium | Isolate our config; automated install test under QEMU; fall back to d-i preseed | Open (M1.5) |
| R9 | live-build output is not bit-for-bit reproducible | High / Low | Target a reproducible *package set* via snapshot.debian.org first; bit-identical ISO is a stretch goal | Open (Phase 7) |
| R10 | Chromium kiosk uses significant RAM | Medium / Medium | Measure; fallback to a lighter WebKit-based kiosk browser | Open (M1.4) |
| R11 | Model and dependency licences constrain redistribution | Medium / Medium | Do not bundle models; record licences; main-only Debian archive (no non-free firmware by default) | Open |
| R12 | Windows-hosted development: CRLF in scripts, bind-mount limits for debootstrap | Medium / Low | `.gitattributes` forces LF, a test rejects CRLF in image sources, build work dir is a Docker volume | Mitigated |
| R13 | Debian 13 ships Python 3.13 while dev machine runs 3.12 | Medium / Low | CI matrix on 3.12 and 3.13 | Open |
| R14 | Security-critical `pai-privd` bugs give root | Low / Critical | Tiny verb allow-list, no shell, fuzzing, AppArmor, review gate | Designed (Phase 3/5) |
| R16 | Debian live images ship a well-known default login (`user` / `live`) and autologin; the live session is reachable by anything that can reach its console | Certain / Medium | Live session is install-only and offline by default (no SSH, firewall default-deny); remove/replace the default account in the live config before any release; the *installed* system must have no default credentials | Open (before M1.5) |
| R15 | Backup passphrase loss makes data unrecoverable | Medium / High | Recovery key shown once at setup, explicit confirmation, documented procedure | Designed (Phase 5) |
