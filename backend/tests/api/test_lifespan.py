"""Startup: fresh token per start, migrations applied, and fail-closed behaviour."""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.core.config import DATA_DIR_MODE, Settings
from backend.core.logging import redact_text
from backend.database import migrate
from backend.tests.api.support import client_for

StartApp = Callable[[], AbstractContextManager[TestClient]]
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes and symlink semantics")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------ token lifecycle
def test_token_file_is_written_and_authenticates(client: TestClient, settings: Settings) -> None:
    token = settings.token_file.read_text(encoding="ascii")
    assert len(token) >= 43
    assert client.get("/health", headers=_bearer(token)).status_code == 200


@posix_only
def test_token_file_mode_is_0640(client: TestClient, settings: Settings) -> None:
    assert stat.S_IMODE(settings.token_file.stat().st_mode) == 0o640


def test_each_start_replaces_the_token_and_revokes_the_old_one(settings: Settings, start_app: StartApp) -> None:
    with start_app() as first:
        old = settings.token_file.read_text(encoding="ascii")
        assert first.get("/health", headers=_bearer(old)).status_code == 200
    with start_app() as second:
        new = settings.token_file.read_text(encoding="ascii")
        assert new != old
        assert second.get("/health", headers=_bearer(new)).status_code == 200
        assert second.get("/health", headers=_bearer(old)).status_code == 401
    assert [p.name for p in settings.token_file.parent.iterdir()] == ["token"]


@posix_only
def test_a_leftover_world_readable_token_file_is_replaced_by_a_0640_one(
    settings: Settings, start_app: StartApp
) -> None:
    settings.token_file.parent.mkdir(parents=True)
    settings.token_file.write_text("stale-token")
    settings.token_file.chmod(0o666)
    with start_app():
        assert settings.token_file.read_text(encoding="ascii") != "stale-token"
        assert stat.S_IMODE(settings.token_file.stat().st_mode) == 0o640


def test_the_live_token_is_masked_if_it_is_ever_logged(client: TestClient, settings: Settings) -> None:
    token = settings.token_file.read_text(encoding="ascii")
    assert token not in redact_text(f"debug dump: {token} and Authorization: Bearer {token}")


# ------------------------------------------------------------------ migrations
def test_migrations_are_applied_at_startup(client: TestClient, settings: Settings) -> None:
    connection = sqlite3.connect(settings.database_path)
    try:
        applied = [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")]
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        connection.close()
    assert applied == [m.version for m in migrate.discover()]
    assert {"users", "tasks", "messages"} <= tables


def test_restarting_does_not_reapply_migrations(settings: Settings, start_app: StartApp) -> None:
    with start_app():
        pass
    with start_app() as restarted:
        token = settings.token_file.read_text(encoding="ascii")
        health = restarted.get("/health", headers=_bearer(token)).json()
    assert health["schema_version"] == max(m.version for m in migrate.discover())


def test_data_directory_is_created_when_missing(client: TestClient, settings: Settings) -> None:
    assert settings.data_dir.is_dir()
    assert settings.database_path.is_file()


@posix_only
def test_data_directory_is_private_to_the_service_account_even_under_a_permissive_umask(
    settings: Settings, start_app: StartApp
) -> None:
    # The kiosk account shares the service's group (for the token) and must not be able to list or enter the data.
    previous = os.umask(0)
    try:
        with start_app():
            pass
    finally:
        os.umask(previous)
    assert stat.S_IMODE(settings.data_dir.stat().st_mode) == DATA_DIR_MODE == 0o700


# ------------------------------------------------------------------ failing closed
def _use_migrations_from(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    real_discover = migrate.discover
    monkeypatch.setattr(migrate, "discover", lambda: real_discover(directory))


def test_startup_aborts_on_an_unreadable_migration_directory(
    tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    broken = tmp_path / "broken-migrations"
    broken.mkdir()
    (broken / "not-a-valid-name.sql").write_text("SELECT 1;")
    _use_migrations_from(monkeypatch, broken)
    with pytest.raises(migrate.MigrationError, match="Invalid migration filename"), client_for(create_app(settings)):
        pytest.fail("the app must not start")
    assert not settings.token_file.exists(), "no token may be published for a service that did not start"


def test_startup_aborts_when_a_migration_fails(
    tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    broken = tmp_path / "failing-migrations"
    broken.mkdir()
    (broken / "0001_broken.sql").write_text("CREATE TABLE t (id INTEGER); THIS IS NOT SQL;")
    _use_migrations_from(monkeypatch, broken)
    with pytest.raises(migrate.MigrationError, match="failed"), client_for(create_app(settings)):
        pytest.fail("the app must not start")
    assert not settings.token_file.exists()


def test_startup_aborts_when_the_database_cannot_be_opened(tmp_path: Path, settings: Settings) -> None:
    settings.data_dir.mkdir(parents=True)
    settings.database_path.mkdir()  # a directory where the database file should be
    with pytest.raises(sqlite3.Error), client_for(create_app(settings)):
        pytest.fail("the app must not start")
    assert not settings.token_file.exists()


def test_startup_aborts_when_the_token_cannot_be_published(settings: Settings) -> None:
    settings.token_file.mkdir(parents=True)  # a directory where the token file should be
    # The exact OSError subclass differs per operating system (IsADirectoryError, PermissionError).
    with pytest.raises(OSError), client_for(create_app(settings)):
        pytest.fail("the app must not start")


def test_a_failed_start_is_logged_critically(
    tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    broken = tmp_path / "broken-migrations"
    broken.mkdir()
    (broken / "bad.sql").write_text("SELECT 1;")
    _use_migrations_from(monkeypatch, broken)
    with pytest.raises(migrate.MigrationError), client_for(create_app(settings)):
        pytest.fail("the app must not start")
    assert any(r.levelname == "CRITICAL" and "refusing to start" in r.getMessage() for r in caplog.records)
