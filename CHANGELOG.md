# Changelog

## Unreleased

### Added
- Phase 0 documentation: architecture, threat model, technology evaluation, tool execution model, memory architecture, risk register, Phase 1 plan.
- SQLite schema (`0001_initial.sql`) with database-level safety invariants, and a checksum-verifying forward-only migration runner.
- M1.1 build foundation: containerized live-build ISO builder, baseline default-deny nftables ruleset, sysctl hardening, host-integration module lockdown, minimal package list.
- Policy-as-code tests for the image sources.
