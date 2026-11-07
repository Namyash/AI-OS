"""Schema and migration tests: the safety invariants must hold at the database level."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from backend.database.migrate import (
    Migration,
    MigrationError,
    apply_migrations,
    connect,
    discover,
)

NOW = 1_700_000_000_000
HASH = "a" * 64


@pytest.fixture
def db() -> sqlite3.Connection:
    conn = connect(":memory:")
    apply_migrations(conn)
    conn.execute("INSERT INTO users (id, username, display_name, created_at) VALUES ('u1', 'sam', 'Sam', ?)", (NOW,))
    return conn


def _conversation(db: sqlite3.Connection, conv_id: str = "c1") -> None:
    db.execute(
        "INSERT INTO conversations (id, user_id, created_at, updated_at) VALUES (?, 'u1', ?, ?)",
        (conv_id, NOW, NOW),
    )


def _message(db: sqlite3.Connection, msg_id: str, seq: int, content: str, conv_id: str = "c1") -> None:
    db.execute(
        "INSERT INTO messages (id, conversation_id, seq, role, content, created_at) VALUES (?, ?, ?, 'user', ?, ?)",
        (msg_id, conv_id, seq, content, NOW),
    )


def _task(db: sqlite3.Connection, status: str = "running", verification: str = "unverified") -> None:
    db.execute(
        "INSERT INTO tasks (id, user_id, objective, status, verification_status, created_at, updated_at)"
        " VALUES ('t1', 'u1', 'do something', ?, ?, ?, ?)",
        (status, verification, NOW, NOW),
    )


def _execution(db: sqlite3.Connection, level: int, tainted: int, approval_id: str | None) -> None:
    db.execute(
        "INSERT INTO tool_executions (id, tool_name, tool_version, args_json, args_hash, permission_level,"
        " tainted, approval_id, status, started_at) VALUES ('e1', 'tool', '1', '{}', ?, ?, ?, ?, 'running', ?)",
        (HASH, level, tainted, approval_id, NOW),
    )


def _memory(db: sqlite3.Connection, origin: str, status: str, confidence: float, confirmed: int = 0) -> None:
    db.execute(
        "INSERT INTO memories (id, user_id, content, category, origin, status, confidence, user_confirmed,"
        " created_at, updated_at) VALUES ('m1', 'u1', 'likes tea', 'preference', ?, ?, ?, ?, ?, ?)",
        (origin, status, confidence, confirmed, NOW, NOW),
    )


# ------------------------------------------------------------------ migration runner
def test_migrations_apply_once_and_are_idempotent() -> None:
    conn = connect(":memory:")
    first = apply_migrations(conn)
    assert first == [m.version for m in discover()]
    assert apply_migrations(conn) == []


def test_modified_migration_is_detected() -> None:
    conn = connect(":memory:")
    apply_migrations(conn)
    tampered = [Migration(m.version, m.name, m.sql + "\n-- edited") for m in discover()]
    with pytest.raises(MigrationError, match="modified"):
        apply_migrations(conn, tampered)


def test_failed_migration_rolls_back_completely() -> None:
    conn = connect(":memory:")
    broken = [Migration(1, "broken", "CREATE TABLE ok (id INTEGER); CREATE TABLE ok (id INTEGER);")]
    with pytest.raises(MigrationError, match="failed"):
        apply_migrations(conn, broken)
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'ok'").fetchone() is None
    assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone() == (0,)


def test_non_contiguous_versions_rejected(tmp_path: Path) -> None:
    (tmp_path / "0002_late.sql").write_text("SELECT 1;")
    with pytest.raises(MigrationError, match="contiguous"):
        discover(tmp_path)


def test_bad_filename_rejected(tmp_path: Path) -> None:
    (tmp_path / "init.sql").write_text("SELECT 1;")
    with pytest.raises(MigrationError, match="Invalid migration filename"):
        discover(tmp_path)


# ------------------------------------------------------------------ structural integrity
def test_foreign_key_enforcement_is_on(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO conversations (id, user_id, created_at, updated_at) VALUES ('x', 'nobody', 1, 1)")


def test_strict_tables_reject_wrong_types(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO users (id, username, display_name, created_at) VALUES ('u2', 'a', 'A', 'not-a-number')")


def test_deleting_conversation_cascades_and_cleans_search_index(db: sqlite3.Connection) -> None:
    _conversation(db)
    _message(db, "m1", 0, "quarterly budget planning notes")
    assert db.execute("SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'budget'").fetchone() == (1,)
    db.execute("DELETE FROM conversations WHERE id = 'c1'")
    assert db.execute("SELECT count(*) FROM messages").fetchone() == (0,)
    assert db.execute("SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'budget'").fetchone() == (0,)


def test_message_order_is_unique_per_conversation(db: sqlite3.Connection) -> None:
    _conversation(db)
    _message(db, "m1", 0, "first")
    with pytest.raises(sqlite3.IntegrityError):
        _message(db, "m2", 0, "duplicate position")


def test_editing_content_updates_search_index(db: sqlite3.Connection) -> None:
    _conversation(db)
    _message(db, "m1", 0, "alpha topic")
    db.execute("UPDATE messages SET content = 'beta topic' WHERE id = 'm1'")
    assert db.execute("SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'alpha'").fetchone() == (0,)
    assert db.execute("SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'beta'").fetchone() == (1,)


def test_document_chunks_are_searchable_and_cascade(db: sqlite3.Connection) -> None:
    db.execute(
        "INSERT INTO documents (id, user_id, path, size_bytes, content_sha256, status, created_at)"
        " VALUES ('d1', 'u1', '/docs/a.txt', 10, ?, 'indexed', ?)",
        (HASH, NOW),
    )
    db.execute(
        "INSERT INTO document_chunks (id, document_id, idx, text, token_count)"
        " VALUES ('k1', 'd1', 0, 'supplier contract terms', 3)"
    )
    assert db.execute("SELECT count(*) FROM chunks_fts WHERE chunks_fts MATCH 'contract'").fetchone() == (1,)
    db.execute("DELETE FROM documents WHERE id = 'd1'")
    assert db.execute("SELECT count(*) FROM chunks_fts WHERE chunks_fts MATCH 'contract'").fetchone() == (0,)


# ------------------------------------------------------------------ safety invariants
def test_task_cannot_succeed_without_verification(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _task(db, status="succeeded", verification="unverified")


def test_task_can_succeed_when_verified(db: sqlite3.Connection) -> None:
    _task(db, status="succeeded", verification="verified")


def test_cloud_model_requires_disclosure_acknowledgement(db: sqlite3.Connection) -> None:
    insert = (
        "INSERT INTO model_configs (id, name, runtime, source, context_length, is_cloud, disclosure_ack_at, created_at)"
        " VALUES (?, 'm', 'cloud', 'provider', 4096, 1, ?, ?)"
    )
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(insert, ("mc1", None, NOW))
    db.execute(insert, ("mc2", NOW, NOW))


def test_runtime_and_cloud_flag_must_agree(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO model_configs (id, name, runtime, source, context_length, is_cloud, created_at)"
            " VALUES ('mc1', 'm', 'cloud', 'provider', 4096, 0, ?)",
            (NOW,),
        )


@pytest.mark.parametrize("level", [3, 4])
def test_sensitive_execution_requires_approval(db: sqlite3.Connection, level: int) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _execution(db, level=level, tainted=0, approval_id=None)


def test_tainted_level2_execution_requires_approval(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _execution(db, level=2, tainted=1, approval_id=None)


def test_untainted_level2_and_tainted_level1_run_without_approval(db: sqlite3.Connection) -> None:
    _execution(db, level=2, tainted=0, approval_id=None)
    db.execute("DELETE FROM tool_executions")
    _execution(db, level=1, tainted=1, approval_id=None)


def test_sensitive_execution_allowed_with_approval(db: sqlite3.Connection) -> None:
    db.execute(
        "INSERT INTO approvals (id, tool_name, operation_hash, effective_level, preview_json, status,"
        " requested_at, expires_at, decided_at) VALUES ('a1', 'tool', ?, 3, '{}', 'approved', ?, ?, ?)",
        (HASH, NOW, NOW + 600_000, NOW),
    )
    _execution(db, level=3, tainted=0, approval_id="a1")
    with pytest.raises(sqlite3.IntegrityError):  # an approval that was used cannot be deleted
        db.execute("DELETE FROM approvals WHERE id = 'a1'")


def test_approved_status_requires_decision_time(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO approvals (id, tool_name, operation_hash, effective_level, preview_json, status,"
            " requested_at, expires_at) VALUES ('a1', 'tool', ?, 3, '{}', 'approved', ?, ?)",
            (HASH, NOW, NOW + 1),
        )


def test_uncertain_model_inferred_memory_cannot_be_active(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _memory(db, origin="model_inferred", status="active", confidence=0.4)


def test_uncertain_memory_allowed_when_pending_or_user_confirmed(db: sqlite3.Connection) -> None:
    _memory(db, origin="model_inferred", status="pending_review", confidence=0.4)
    db.execute("DELETE FROM memories")
    _memory(db, origin="model_inferred", status="active", confidence=0.4, confirmed=1)


def test_memory_survives_deletion_of_its_source_conversation(db: sqlite3.Connection) -> None:
    _conversation(db)
    _message(db, "m1", 0, "I prefer tea")
    _memory(db, origin="user_stated", status="active", confidence=1.0)
    db.execute(
        "INSERT INTO memory_sources (id, memory_id, conversation_id, message_id, source_label, created_at)"
        " VALUES ('s1', 'm1', 'c1', 'm1', 'Chat on tea', ?)",
        (NOW,),
    )
    db.execute("DELETE FROM conversations WHERE id = 'c1'")
    row = db.execute("SELECT conversation_id, message_id, source_label FROM memory_sources").fetchone()
    assert row == (None, None, "Chat on tea")
    assert db.execute("SELECT count(*) FROM memories").fetchone() == (1,)


def test_security_events_are_append_only(db: sqlite3.Connection) -> None:
    db.execute(
        "INSERT INTO security_events (ts, category, severity, actor, action, prev_hash, event_hash)"
        " VALUES (?, 'approval', 'info', 'user', 'approve', ?, ?)",
        (NOW, "0" * 64, HASH),
    )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("UPDATE security_events SET severity = 'info'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("DELETE FROM security_events")


def test_settings_are_unique_per_scope(db: sqlite3.Connection) -> None:
    insert = "INSERT INTO app_settings (user_id, key, value_json, updated_at) VALUES (?, 'k', '1', 1)"
    db.execute(insert, (None,))
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(insert, (None,))  # NULL scope must still be unique
    db.execute(insert, ("u1",))
