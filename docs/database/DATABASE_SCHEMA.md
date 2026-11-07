# Database Schema

The authoritative DDL is [`backend/database/migrations/0001_initial.sql`](../../backend/database/migrations/0001_initial.sql);
this document explains it and does not duplicate it. Tests: `backend/tests/database/test_schema.py`.

## Conventions

- SQLite, WAL journal, `synchronous=FULL`, `foreign_keys=ON` (set by `migrate.connect`; a connection without it is a bug).
- `STRICT` tables; ids are TEXT (UUIDv7/ULID, time-sortable); timestamps are INTEGER unix milliseconds UTC.
- JSON columns carry `json_valid()` checks. Full-text search uses FTS5 external-content tables kept in sync by triggers.
- Vectors are **not** stored here: they live in the `VectorStore` and are rebuildable. `chunk_embeddings` / `memory_embeddings`
  record which embedder produced each vector so an embedder change can be detected.

## Tables

| Area | Tables | Notes |
|---|---|---|
| Identity & config | `users`, `app_settings`, `user_permissions`, `projects` | `app_settings.user_id NULL` = system-wide; uniqueness enforced per scope. |
| Models | `model_configs` | Cloud configs require `disclosure_ack_at`. |
| Episodic memory | `conversations`, `messages`, `messages_fts` | `messages.model_name` snapshots the model used. |
| Task memory | `tasks`, `task_steps`, `tool_executions`, `approvals` | Plan, working state, per-step status, exact tool args and results. |
| Semantic memory | `memories`, `memory_sources`, `memories_fts`, `memory_embeddings` | Provenance (`origin`), confidence, review status, supersession. |
| Knowledge memory | `documents`, `document_chunks`, `chunks_fts`, `chunk_embeddings` | Chunks keep page/section/char offsets for citations. |
| Audit | `security_events` | Append-only, hash-chained. |
| Bookkeeping | `schema_migrations` | Created by the runner: version, name, checksum, applied time. |

## Invariants enforced by the database

| Invariant | Mechanism |
|---|---|
| A task is `succeeded` only if verified | `CHECK` on `tasks` |
| Cloud model needs a recorded disclosure acknowledgement | `CHECK` on `model_configs` |
| Level ≥ 3 executions, and level ≥ 2 executions in a tainted turn, reference an approval | `CHECK` on `tool_executions` |
| An approval that was used cannot be deleted | `ON DELETE RESTRICT` from `tool_executions.approval_id` |
| Uncertain model-inferred memory is never an active fact | `CHECK` on `memories` (active needs confidence ≥ 0.7 or user confirmation) |
| Audit rows cannot be updated or deleted | `BEFORE UPDATE/DELETE` triggers on `security_events` |
| Deleting a source never silently deletes derived memory | `ON DELETE SET NULL` + `memory_sources.source_label` snapshot |

The database is a backstop. The application must enforce the same rules first; these constraints make a bug fail loudly
instead of corrupting the guarantees.

## Migration policy

- Files are `NNNN_name.sql`, contiguous from 0001, forward-only. Never edit an applied migration: the runner records a SHA-256 and refuses a modified one.
- Each migration runs atomically with its bookkeeping row; failure rolls back completely.
- Backup restoration runs `apply_migrations` afterwards, so an old backup is upgraded and a backup from a *newer* schema is refused.
- Hash-chain computation for `security_events` lives in the application (`backend/security`, not yet implemented).

## Open questions

- Retention/rotation of `security_events`: append-only triggers block deletion; rotation will be an export + new-epoch design in Phase 5.
- Whether `messages` needs a separate attachment table: deferred until the document upload flow exists.
