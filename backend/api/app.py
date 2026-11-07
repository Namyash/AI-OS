"""Application factory for the backend HTTP API."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from backend.api.auth import TokenAuthenticator, issue_token, write_token_file
from backend.api.errors import install_error_handlers
from backend.api.health import health_router
from backend.api.security import BoundaryGuard
from backend.core.config import DATA_DIR_MODE, Settings
from backend.core.logging import register_secret
from backend.core.version import __version__
from backend.database import migrate

logger = logging.getLogger(__name__)


def _migrate_database(settings: Settings) -> list[int]:
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=DATA_DIR_MODE)
    connection = migrate.connect(settings.database_path)
    try:
        return migrate.apply_migrations(connection)
    finally:
        connection.close()


async def _start(settings: Settings, authenticator: TokenAuthenticator) -> None:
    """Fail closed: any error here aborts startup, and the token is published only after the database is ready."""
    try:
        applied = await run_in_threadpool(_migrate_database, settings)
        token = issue_token()
        register_secret(token)
        write_token_file(settings.token_file, token)
        authenticator.install(token)
    except Exception:
        logger.critical("startup failed; refusing to start", exc_info=True)
        raise
    logger.info(
        "backend started",
        extra={"host": settings.host, "port": settings.port, "applied_migrations": applied},
    )


def create_app(settings: Settings) -> FastAPI:
    authenticator = TokenAuthenticator()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _start(settings, authenticator)
        yield

    # The interactive docs UIs are off; /openapi.json stays, behind the same guard as every other path.
    app = FastAPI(title="Private AI OS backend", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.add_middleware(BoundaryGuard, host=settings.host, port=settings.port, authenticator=authenticator)
    install_error_handlers(app)
    app.include_router(health_router(settings.database_path))
    return app
