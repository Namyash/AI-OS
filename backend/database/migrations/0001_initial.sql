-- 0001_initial: core schema.
-- Conventions: ids are TEXT (UUIDv7/ULID, time-sortable); timestamps are INTEGER unix milliseconds (UTC);
-- JSON columns are validated with json_valid(); all tables are STRICT. Connections must enable
-- PRAGMA foreign_keys (see migrate.connect). Design rationale: docs/database/DATABASE_SCHEMA.md.

-- ---------------------------------------------------------------- identity & settings
CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    disabled_at  INTEGER
) STRICT;

CREATE TABLE app_settings (
    id         INTEGER PRIMARY KEY,
    user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,   -- NULL = system-wide setting
    key        TEXT NOT NULL,
    value_json TEXT NOT NULL CHECK (json_valid(value_json)),
    updated_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX app_settings_scope_key ON app_settings (COALESCE(user_id, ''), key);

CREATE TABLE user_permissions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    capability TEXT NOT NULL,                                  -- e.g. 'fs.read', 'net.http'
    scope      TEXT NOT NULL,                                  -- path prefix, host, or '*'
    max_level  INTEGER NOT NULL CHECK (max_level BETWEEN 1 AND 4),
    mode       TEXT NOT NULL CHECK (mode IN ('allow', 'ask', 'deny')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER
) STRICT;
CREATE INDEX user_permissions_lookup ON user_permissions (user_id, capability);

CREATE TABLE projects (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    created_at  INTEGER NOT NULL,
    archived_at INTEGER,
    UNIQUE (user_id, name)
) STRICT;

-- ---------------------------------------------------------------- models
CREATE TABLE model_configs (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    runtime            TEXT NOT NULL CHECK (runtime IN ('llama.cpp', 'ollama', 'cloud')),
    source             TEXT NOT NULL,                          -- local path or provider reference
    sha256             TEXT CHECK (sha256 IS NULL OR length(sha256) = 64),
    quantization       TEXT,
    context_length     INTEGER NOT NULL CHECK (context_length > 0),
    capabilities_json  TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(capabilities_json)),
    is_cloud           INTEGER NOT NULL DEFAULT 0 CHECK (is_cloud IN (0, 1)),
    disclosure_ack_at  INTEGER,
    created_at         INTEGER NOT NULL,
    last_loaded_at     INTEGER,
    -- Cloud inference must be explicit: a cloud config cannot exist without a recorded acknowledgement.
    CHECK ((runtime = 'cloud') = (is_cloud = 1)),
    CHECK (is_cloud = 0 OR disclosure_ack_at IS NOT NULL)
) STRICT;

-- ---------------------------------------------------------------- episodic memory
CREATE TABLE conversations (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id         TEXT REFERENCES projects(id) ON DELETE SET NULL,
    title              TEXT,
    summary            TEXT,
    summary_updated_at INTEGER,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    archived_at        INTEGER
) STRICT;
CREATE INDEX conversations_user_recent ON conversations (user_id, updated_at DESC);

CREATE TABLE tasks (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id     TEXT REFERENCES conversations(id) ON DELETE SET NULL,
    project_id          TEXT REFERENCES projects(id) ON DELETE SET NULL,
    objective           TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN (
                            'pending', 'planning', 'awaiting_approval', 'running', 'verifying',
                            'succeeded', 'failed', 'cancelled', 'interrupted')),
    plan_json           TEXT CHECK (plan_json IS NULL OR json_valid(plan_json)),
    working_state_json  TEXT CHECK (working_state_json IS NULL OR json_valid(working_state_json)),
    result_summary      TEXT,
    error               TEXT,
    verification_status TEXT NOT NULL DEFAULT 'unverified'
                            CHECK (verification_status IN ('unverified', 'verified', 'failed')),
    created_at          INTEGER NOT NULL,
    started_at          INTEGER,
    finished_at         INTEGER,
    updated_at          INTEGER NOT NULL,
    -- A task is never successful merely because the model said so.
    CHECK (status != 'succeeded' OR verification_status = 'verified')
) STRICT;
CREATE INDEX tasks_user_status ON tasks (user_id, status);

CREATE TABLE messages (
    id              TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL CHECK (seq >= 0),
    role            TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system', 'tool')),
    content         TEXT NOT NULL,
    model_config_id TEXT REFERENCES model_configs(id) ON DELETE SET NULL,
    model_name      TEXT,                                       -- snapshot; survives config deletion
    task_id         TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    token_count     INTEGER CHECK (token_count IS NULL OR token_count >= 0),
    created_at      INTEGER NOT NULL,
    UNIQUE (conversation_id, seq)
) STRICT;
CREATE INDEX messages_task ON messages (task_id);

CREATE VIRTUAL TABLE messages_fts USING fts5(
    content, content='messages', content_rowid='rowid', tokenize='unicode61 remove_diacritics 2');
CREATE TRIGGER messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, content) VALUES (new.rowid, new.content);
END;
CREATE TRIGGER messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
END;
CREATE TRIGGER messages_au AFTER UPDATE OF content ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
    INSERT INTO messages_fts(rowid, content) VALUES (new.rowid, new.content);
END;

-- ---------------------------------------------------------------- task memory & execution
CREATE TABLE task_steps (
    id               TEXT PRIMARY KEY,
    task_id          TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    idx              INTEGER NOT NULL CHECK (idx >= 0),
    description      TEXT NOT NULL,
    tool_name        TEXT NOT NULL,
    args_json        TEXT NOT NULL CHECK (json_valid(args_json)),
    permission_level INTEGER NOT NULL CHECK (permission_level BETWEEN 1 AND 4),
    status           TEXT NOT NULL CHECK (status IN (
                         'pending', 'awaiting_approval', 'running', 'succeeded', 'failed', 'skipped', 'cancelled')),
    attempt_count    INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    verification_json TEXT CHECK (verification_json IS NULL OR json_valid(verification_json)),
    started_at       INTEGER,
    finished_at      INTEGER,
    UNIQUE (task_id, idx)
) STRICT;

CREATE TABLE approvals (
    id             TEXT PRIMARY KEY,
    task_id        TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    step_id        TEXT REFERENCES task_steps(id) ON DELETE SET NULL,
    tool_name      TEXT NOT NULL,
    operation_hash TEXT NOT NULL CHECK (length(operation_hash) = 64),  -- SHA-256 of canonical operation
    effective_level INTEGER NOT NULL CHECK (effective_level BETWEEN 1 AND 4),
    preview_json   TEXT NOT NULL CHECK (json_valid(preview_json)),
    tainted        INTEGER NOT NULL DEFAULT 0 CHECK (tainted IN (0, 1)),
    status         TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
    requested_at   INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    decided_at     INTEGER,
    consumed_at    INTEGER,
    CHECK (status NOT IN ('approved', 'denied', 'consumed') OR decided_at IS NOT NULL),
    CHECK (status != 'consumed' OR consumed_at IS NOT NULL)
) STRICT;
CREATE INDEX approvals_open ON approvals (status, expires_at);

CREATE TABLE tool_executions (
    id               TEXT PRIMARY KEY,
    task_id          TEXT REFERENCES tasks(id) ON DELETE CASCADE,
    step_id          TEXT REFERENCES task_steps(id) ON DELETE CASCADE,
    approval_id      TEXT REFERENCES approvals(id) ON DELETE RESTRICT,
    tool_name        TEXT NOT NULL,
    tool_version     TEXT NOT NULL,
    args_json        TEXT NOT NULL CHECK (json_valid(args_json)),
    args_hash        TEXT NOT NULL CHECK (length(args_hash) = 64),
    permission_level INTEGER NOT NULL CHECK (permission_level BETWEEN 1 AND 4),
    tainted          INTEGER NOT NULL DEFAULT 0 CHECK (tainted IN (0, 1)),
    status           TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'cancelled', 'timed_out')),
    exit_code        INTEGER,
    result_json      TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
    error            TEXT,
    started_at       INTEGER NOT NULL,
    finished_at      INTEGER,
    -- Sensitive/critical operations, and level>=2 operations in a tainted turn, need an approval record.
    CHECK (permission_level < 3 OR approval_id IS NOT NULL),
    CHECK (tainted = 0 OR permission_level < 2 OR approval_id IS NOT NULL)
) STRICT;
CREATE INDEX tool_executions_task ON tool_executions (task_id, started_at);

-- ---------------------------------------------------------------- semantic memory
CREATE TABLE memories (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id      TEXT REFERENCES projects(id) ON DELETE SET NULL,
    content         TEXT NOT NULL,
    category        TEXT NOT NULL CHECK (category IN (
                        'preference', 'project', 'interest', 'decision', 'instruction', 'workflow', 'knowledge', 'fact')),
    origin          TEXT NOT NULL CHECK (origin IN ('user_stated', 'model_inferred', 'user_edited')),
    status          TEXT NOT NULL DEFAULT 'pending_review' CHECK (status IN ('active', 'pending_review', 'rejected')),
    confidence      REAL NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    importance      INTEGER NOT NULL DEFAULT 3 CHECK (importance BETWEEN 1 AND 5),
    user_confirmed  INTEGER NOT NULL DEFAULT 0 CHECK (user_confirmed IN (0, 1)),
    superseded_by   TEXT REFERENCES memories(id) ON DELETE SET NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    last_accessed_at INTEGER,
    access_count    INTEGER NOT NULL DEFAULT 0 CHECK (access_count >= 0),
    expires_at      INTEGER,
    -- Uncertain model-generated assumptions are never active facts unless confident or user-confirmed.
    CHECK (status != 'active' OR origin != 'model_inferred' OR confidence >= 0.7 OR user_confirmed = 1)
) STRICT;
CREATE INDEX memories_retrieval ON memories (user_id, status, category);

CREATE TABLE memory_sources (
    id              TEXT PRIMARY KEY,
    memory_id       TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    conversation_id TEXT REFERENCES conversations(id) ON DELETE SET NULL,
    message_id      TEXT REFERENCES messages(id) ON DELETE SET NULL,
    document_id     TEXT REFERENCES documents(id) ON DELETE SET NULL,   -- SQLite resolves forward references lazily
    chunk_id        TEXT REFERENCES document_chunks(id) ON DELETE SET NULL,
    source_label    TEXT NOT NULL,                              -- snapshot so "source deleted" stays explainable
    quote           TEXT,
    created_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX memory_sources_memory ON memory_sources (memory_id);

CREATE VIRTUAL TABLE memories_fts USING fts5(
    content, content='memories', content_rowid='rowid', tokenize='unicode61 remove_diacritics 2');
CREATE TRIGGER memories_ai AFTER INSERT ON memories BEGIN
    INSERT INTO memories_fts(rowid, content) VALUES (new.rowid, new.content);
END;
CREATE TRIGGER memories_ad AFTER DELETE ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
END;
CREATE TRIGGER memories_au AFTER UPDATE OF content ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
    INSERT INTO memories_fts(rowid, content) VALUES (new.rowid, new.content);
END;

-- ---------------------------------------------------------------- knowledge memory
CREATE TABLE documents (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id     TEXT REFERENCES projects(id) ON DELETE SET NULL,
    path           TEXT NOT NULL,
    title          TEXT,
    mime_type      TEXT,
    size_bytes     INTEGER NOT NULL CHECK (size_bytes >= 0),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    status         TEXT NOT NULL CHECK (status IN ('pending', 'extracting', 'indexed', 'failed', 'excluded')),
    error          TEXT,
    file_modified_at INTEGER,
    created_at     INTEGER NOT NULL,
    indexed_at     INTEGER,
    UNIQUE (user_id, path)
) STRICT;
CREATE INDEX documents_sha ON documents (content_sha256);

CREATE TABLE document_chunks (
    id            TEXT PRIMARY KEY,
    document_id   TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    idx           INTEGER NOT NULL CHECK (idx >= 0),
    text          TEXT NOT NULL,
    token_count   INTEGER NOT NULL CHECK (token_count >= 0),
    char_start    INTEGER CHECK (char_start IS NULL OR char_start >= 0),
    char_end      INTEGER,
    page          INTEGER,
    section       TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE (document_id, idx),
    CHECK (char_end IS NULL OR char_start IS NULL OR char_end >= char_start)
) STRICT;

CREATE VIRTUAL TABLE chunks_fts USING fts5(
    text, content='document_chunks', content_rowid='rowid', tokenize='unicode61 remove_diacritics 2');
CREATE TRIGGER chunks_ai AFTER INSERT ON document_chunks BEGIN
    INSERT INTO chunks_fts(rowid, text) VALUES (new.rowid, new.text);
END;
CREATE TRIGGER chunks_ad AFTER DELETE ON document_chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, text) VALUES ('delete', old.rowid, old.text);
END;
CREATE TRIGGER chunks_au AFTER UPDATE OF text ON document_chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, text) VALUES ('delete', old.rowid, old.text);
    INSERT INTO chunks_fts(rowid, text) VALUES (new.rowid, new.text);
END;

-- Vectors live in the VectorStore (derived data, rebuildable). These tables record which embedder produced
-- a vector for which row, so an embedder change can be detected and re-indexed.
CREATE TABLE chunk_embeddings (
    chunk_id   TEXT NOT NULL REFERENCES document_chunks(id) ON DELETE CASCADE,
    embedder   TEXT NOT NULL,
    dim        INTEGER NOT NULL CHECK (dim > 0),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (chunk_id, embedder)
) STRICT;

CREATE TABLE memory_embeddings (
    memory_id  TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    embedder   TEXT NOT NULL,
    dim        INTEGER NOT NULL CHECK (dim > 0),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (memory_id, embedder)
) STRICT;

-- ---------------------------------------------------------------- audit
-- Append-only and hash-chained: event_hash = SHA256(prev_hash || canonical event body), computed by the
-- application; the database guarantees rows cannot be altered or removed through normal SQL.
-- user_id is deliberately not a foreign key so the trail outlives the user row.
CREATE TABLE security_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    user_id      TEXT,
    category     TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('info', 'notice', 'warning', 'critical')),
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    subject      TEXT,
    details_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json)),
    prev_hash    TEXT NOT NULL CHECK (length(prev_hash) = 64),
    event_hash   TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64)
) STRICT;
CREATE INDEX security_events_ts ON security_events (ts);
CREATE TRIGGER security_events_no_update BEFORE UPDATE ON security_events BEGIN
    SELECT RAISE(ABORT, 'security_events is append-only');
END;
CREATE TRIGGER security_events_no_delete BEFORE DELETE ON security_events BEGIN
    SELECT RAISE(ABORT, 'security_events is append-only');
END;
