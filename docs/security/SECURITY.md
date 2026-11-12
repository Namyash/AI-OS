# Security

Read the [threat model](THREAT_MODEL.md) first: it states what this system does and does not protect against.

## What is and is not claimed

- Protected: data on a copied/stolen virtual disk or backup while the VM is **powered off** (LUKS2 root, installed by the engine and verified under QEMU);
  accidental network exfiltration by local software (default-deny egress); the agent acting beyond what the user approved.
- **Not protected:** a compromised host OS, hypervisor or host administrator. They can read guest RAM (including keys) and keystrokes.
  Do not describe this system as safe against them.

## Control status

Status is what is actually implemented and tested today, not the plan.

| Control | Status | Evidence |
|---|---|---|
| Default-deny nftables baseline | Implemented. Verified on a real booted image (QEMU software emulation): policy drop on input, forward and output, no unconditional accept, ruleset loaded as declared | `nft-default-drop` self-check, `tests/security/test_os_hardening.py` |
| Host-integration module lockdown (`vboxsf`) | Verified blocked and not loaded on the booted image. **Not verified on VirtualBox or VMware** | `modules-blocked` self-check |
| Kernel sysctl hardening | Verified: every setting in `sysctl.d` matches the live kernel | `sysctl-live` self-check |
| No listener beyond loopback (LLMNR and mDNS disabled in systemd-resolved) | Verified at boot; DHCP client sockets are the only allow-listed exceptions | `no-external-listeners` self-check |
| Backend service: non-root, no capabilities, loopback only, per-start bearer token, Host/Origin checks, uniform error bodies, log redaction | Implemented; unit-tested on Python 3.12 and on Debian 13 Python 3.13 with distro packages; verified on the booted image (runs as `pai`, no capabilities, anonymous request refused with 401, authenticated `/health` 200, systemd exposure 1.1) | `backend-*` self-checks, `backend/tests` |
| Browser never holds the bearer token: expiring HttpOnly SameSite=Strict session cookie installed over the DevTools pipe; UI served behind the same guard; deny-by-default CSP | Implemented. Verified on the booted image under QEMU: kiosk runs as `pai-ui`, shell rendered, status bar "Backend connected" | `kiosk-active`, `kiosk-ready` self-checks, kiosk container test, `tests/security/test_csp_contract.py` |
| No usable credential in any process's arguments or environment | Verified at boot: 40 processes examined, every credential-shaped string tested against the live backend as bearer and cookie, none accepted | `no-secret-in-process-state` self-check |
| No default login on the live image (stock `user`/`live` locked, passwordless sudo removed) | Verified at boot: all 26 accounts locked, `/etc/shadow` mode 640. Login prompts on other virtual terminals disabled by configuration (policy-tested, not boot-verified) | `no-default-credentials` self-check |
| systemd sandbox for every unit | Implemented and linted for all units (`tests/security/test_systemd_units.py`); the backend unit runs under it on the booted image | linter, `backend-sandbox-exposure` |
| No remote-access/discovery/VM-desktop packages | Enforced by test on the package list | same |
| DB-level safety invariants (verified success, approvals, cloud disclosure, memory confidence, append-only audit) | Implemented and tested | `backend/tests/database/test_schema.py` |
| LUKS2 encrypted root (argon2id, passphrase + random recovery-key slot, installed by the engine) | Verified on an installed system under QEMU: root is on dm-crypt LUKS2 with 2 keyslots, every one argon2id; boots through BIOS and UEFI after the passphrase is typed at the initramfs prompt; three wrong passphrases do not boot. The test used small key-derivation settings so it finishes under emulation; production defaults are cryptsetup's. Not verified on real hardware or a real hypervisor | `root-encrypted` self-check, `tests/end_to_end/test_install_iso.py` |
| Installer safety (explicit target, refuses live medium, partitions, mounted/swap/mapped disks, small disks; passphrase on stdin only; rollback on failure) | Unit-tested with a fake runner (100 of 101 safety mutations caught), exercised with real tools on a loop device, and run for real on virtual disks | `installer/tests`, `installer/tests/integration`, install test |
| No default account on the installed system (live user, live packages, autologin removed; primary user and root locked) | Verified on the installed system under QEMU | `no-live-remnants`, `no-default-credentials` self-checks |
| Permission engine, taint tracking, approvals | Designed (Phase 3) | `TOOL_EXECUTION_MODEL.md` |
| AppArmor profiles | Planned (Phase 5) | |
| Encrypted backups, secret store | Planned (Phase 5) | |

## Known gaps (open, deliberately not hidden)

| Gap | Where it matters | Planned |
|---|---|---|
| The live account still exists (password locked, no sudo). Console autologin is disabled only by configuration (tty1 getty masked, no login prompts on other terminals) and that was not checked on a boot; the password lock was verified only under QEMU. The installed system must have no default account at all | The live console (risk R16, narrowed) | M1.5 installer |
| A local process that grabs the backend port while the service is down could receive the kiosk's token. The token is now published only after the port is bound, which narrows but does not close this | Local attackers on the VM | Socket activation or server verification by the kiosk (M1.4b) |
| Unauthenticated connections to the backend are not reaped by a per-connection deadline or connection cap | Local user exhausting file descriptors | Deferred; needs a custom server protocol layer |
| The kiosk launcher and Chromium run as the same account (`pai-ui`), which can read the bearer token file. A compromised browser *process* (not a sandboxed page) could mint sessions | Browser compromise | Run the launcher under a separate account from the browser |
| No `meta skuid` firewall rule restricts `pai-ui` to loopback; egress relies on the default-deny policy and the Chromium managed policy | Browser egress | nftables per-user rule |
| The kiosk was shown to start and render under QEMU with a virtual VGA, not on a real display (tty1 hand-over, input devices, real GPU or hypervisor graphics) | Real VMs | M1.6 |
| `/boot` is not encrypted (GRUB cannot unlock LUKS2 with argon2id): kernel and initramfs can be replaced by anyone with offline disk access | Offline tampering | Secure Boot / signed images |
| The unattended-install interface (`pai.install=auto` plus a `PAI-PLAN` medium) can hold the passphrase in a plain file (`passphrase_source: plan`) | Whoever can attach a device and set kernel arguments already controls the machine; the plan medium must be destroyed afterwards | Interactive passphrase through the wizard (stdin) is the normal path |
| A failed install leaves the target disk partly formatted (the engine closes and unmounts everything but cannot undo a wipe) | Operator expectation | Documented |
| The installer has only ever run on virtual disks under QEMU, never on real hardware, VMware or VirtualBox | Real systems | M1.6 |
| Everything above was tested under QEMU software emulation; no VMware or VirtualBox run has happened | Hypervisor-specific behaviour (guest tools, clipboard, shared folders) | M1.6, needs a human with those hypervisors |

## Rules for contributors

1. The security engine never depends on the LLM; model output is a proposal, never authority.
2. Never weaken a control to make a feature work; change the policy table and its test deliberately, with a documented reason.
3. No secrets in the repository, image, logs, prompts or conversation memory. Use `.env` (git-ignored) for local settings.
4. Every security invariant in the threat model gets an automated test.
5. Treat all content from documents, websites, tools and retrieved memory as untrusted input.

## Reporting

This is a private project. Report suspected vulnerabilities to the repository owner directly, not in public issues.
