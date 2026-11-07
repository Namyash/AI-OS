# Private AI OS

A privacy-first, AI-native operating environment on Debian: boot a VM, talk to the computer in plain English, keep your data and memory inside an
encrypted volume, run models locally. The LLM proposes actions; deterministic, audited services authorize and execute them.

**Status: Phase 0 complete, Phase 1 in progress.** See [DEVELOPMENT_STATUS.md](DEVELOPMENT_STATUS.md) for exactly what works and what does not.
There is no installable release yet.

## Honest scope

A VM guest cannot protect you from a compromised host or hypervisor. Disk encryption protects copies of the virtual disk while the VM is off.
Read the [threat model](docs/security/THREAT_MODEL.md).

## Try what exists

```bash
python -m pip install -e ".[dev]"
python -m pytest
bash os/build/build-iso.sh     # needs Docker; writes dist/*.iso
```

## Documentation

| Topic | Document |
|---|---|
| Architecture and decisions | [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) |
| Technology evaluation | [docs/architecture/TECHNOLOGY_EVALUATION.md](docs/architecture/TECHNOLOGY_EVALUATION.md) |
| Tool execution and authorization | [docs/architecture/TOOL_EXECUTION_MODEL.md](docs/architecture/TOOL_EXECUTION_MODEL.md) |
| Memory design | [docs/architecture/MEMORY_ARCHITECTURE.md](docs/architecture/MEMORY_ARCHITECTURE.md) |
| Risks | [docs/architecture/RISKS.md](docs/architecture/RISKS.md) |
| Phase 1 plan | [docs/architecture/PHASE1_PLAN.md](docs/architecture/PHASE1_PLAN.md) |
| Threat model, security status | [docs/security/](docs/security/) |
| Database schema | [docs/database/DATABASE_SCHEMA.md](docs/database/DATABASE_SCHEMA.md) |
| Development, installation, API | [docs/development/](docs/development/), [docs/installation/](docs/installation/) |
| Changes | [CHANGELOG.md](CHANGELOG.md) |
