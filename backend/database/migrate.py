"""Forward-only SQL migration runner for the application SQLite database.

Migrations are numbered files ``NNNN_name.sql`` in ``migrations/``. Applied versions and the SHA-256 of
each file are recorded in ``schema_migrations`` so an edited, missing or reordered migration is detected
instead of silently producing a divergent schema.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_FILENAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
_BUSY_TIMEOUT_MS = 5000


class MigrationError(RuntimeError):
    """Raised when migrations are inconsistent with each other or with the database history."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def discover(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    """Load migrations from ``directory``; versions must be unique and contiguous from 1."""
    found: list[Migration] = []
    for path in sorted(directory.glob("*.sql")):
        match = _FILENAME.match(path.name)
        if match is None:
            raise MigrationError(f"Invalid migration filename: {path.name}")
        found.append(Migration(int(match[1]), match[2], path.read_text(encoding="utf-8")))
    versions = [m.version for m in found]
    if versions != list(range(1, len(found) + 1)):
        raise MigrationError(f"Migration versions must be contiguous from 1, got {versions}")
    return found


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a connection with the integrity-oriented settings the schema depends on."""
    conn = sqlite3.connect(path, isolation_level=None)  # explicit transaction control
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA synchronous = FULL")  # favour durability over write speed
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _applied(conn: sqlite3.Connection) -> dict[int, tuple[str, str]]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL"
        ") STRICT"
    )
    rows = conn.execute("SELECT version, name, checksum FROM schema_migrations ORDER BY version")
    return {version: (name, checksum) for version, name, checksum in rows}


def apply_migrations(conn: sqlite3.Connection, migrations: list[Migration] | None = None) -> list[int]:
    """Apply pending migrations, each atomically with its bookkeeping row. Returns applied versions."""
    known = discover() if migrations is None else migrations
    applied = _applied(conn)

    for version, (name, checksum) in applied.items():
        if version > len(known) or known[version - 1].name != name:
            raise MigrationError(f"Database has migration {version} ({name}) that is not in the source tree")
        if known[version - 1].checksum != checksum:
            raise MigrationError(f"Migration {version} ({name}) was modified after it was applied")

    newly_applied: list[int] = []
    for migration in known:
        if migration.version in applied:
            continue
        # executescript commits any open transaction first, so BEGIN/COMMIT live inside the script.
        # The interpolated values are an int, a name matched by _FILENAME, and a hex digest: no user input.
        script = (
            f"BEGIN IMMEDIATE;\n{migration.sql}\n"
            "INSERT INTO schema_migrations (version, name, checksum, applied_at) "
            f"VALUES ({migration.version}, '{migration.name}', '{migration.checksum}', {int(time.time() * 1000)});\n"
            "COMMIT;"
        )
        try:
            conn.executescript(script)
        except sqlite3.Error as exc:
            if conn.in_transaction:
                conn.rollback()
            raise MigrationError(f"Migration {migration.version} ({migration.name}) failed: {exc}") from exc
        newly_applied.append(migration.version)
    return newly_applied
