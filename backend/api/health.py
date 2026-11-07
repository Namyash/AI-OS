"""``GET /health``: liveness plus proof that the database is readable and migrated."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from backend.core.errors import DatabaseUnavailable
from backend.core.version import __version__
from backend.database import migrate

logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    status: Literal["ok"]
    schema_version: int
    version: str


def _read_schema_version(database_path: Path) -> int:
    """Highest applied migration. sqlite3 connections are bound to their thread, so this opens its own."""
    connection = migrate.connect(database_path)
    try:
        row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    finally:
        connection.close()
    return int(row[0] or 0)


def health_router(database_path: Path) -> APIRouter:
    router = APIRouter()

    # A plain `def` endpoint: FastAPI runs it in a worker thread, so blocking sqlite calls never stall the event loop.
    @router.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        try:
            schema_version = _read_schema_version(database_path)
        except sqlite3.Error as exc:
            logger.error("health check failed: database unreadable (%s)", exc)
            raise DatabaseUnavailable from exc
        return HealthResponse(status="ok", schema_version=schema_version, version=__version__)

    return router
