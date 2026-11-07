"""GET /health: authenticated, reports the migrated schema version, and never blocks the event loop."""

from __future__ import annotations

import asyncio
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.core.config import Settings
from backend.core.version import __version__
from backend.database import migrate


def test_health_reports_status_schema_version_and_package_version(client: TestClient, auth: dict[str, str]) -> None:
    response = client.get("/health", headers=auth)
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "schema_version": max(m.version for m in migrate.discover()),
        "version": __version__,
    }


def test_schema_version_is_read_from_the_database_not_from_the_source_tree(
    client: TestClient, auth: dict[str, str], settings: Settings
) -> None:
    connection = sqlite3.connect(settings.database_path)
    try:
        connection.execute("DELETE FROM schema_migrations WHERE version > 0")
        connection.commit()
    finally:
        connection.close()
    assert client.get("/health", headers=auth).json()["schema_version"] == 0


def test_health_requires_authentication(client: TestClient) -> None:
    assert client.get("/health").status_code == 401


def test_blocking_database_work_runs_off_the_event_loop(
    client: TestClient, auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    ran_on_event_loop: list[bool] = []
    real_connect = migrate.connect

    def observing_connect(path: object) -> sqlite3.Connection:
        try:
            asyncio.get_running_loop()
        except RuntimeError:  # no running loop in this thread: a worker thread, as intended
            ran_on_event_loop.append(False)
        else:
            ran_on_event_loop.append(True)
        return real_connect(path)  # type: ignore[arg-type]

    monkeypatch.setattr("backend.api.health.migrate.connect", observing_connect)
    assert client.get("/health", headers=auth).status_code == 200
    assert ran_on_event_loop == [False]
