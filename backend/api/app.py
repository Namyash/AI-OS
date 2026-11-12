"""Application factory for the backend HTTP API."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from backend.api.auth import TokenAuthenticator, issue_token, publish_file
from backend.api.errors import install_error_handlers
from backend.api.health import health_router
from backend.api.security import BoundaryGuard
from backend.api.sessions import SessionStore, session_router
from backend.api.static import install_static_ui
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
    """Fail closed: any error here aborts startup, and nothing is published until the database is ready.

    This runs once the listening socket is bound (``python -m backend`` binds first), so a file published here
    is only ever published by the process that holds the port. The endpoint goes out before the token: a reader
    that waits for the token can read the endpoint the moment it appears.
    """
    try:
        applied = await run_in_threadpool(_migrate_database, settings)
        token = issue_token()
        register_secret(token)
        publish_file(settings.endpoint_file, settings.endpoint_url)
        publish_file(settings.token_file, token)
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
    sessions = SessionStore(settings.session_ttl)  # per start: a restart ends every session

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _start(settings, authenticator)
        yield

    # The interactive docs UIs are off; /openapi.json stays, behind the same guard as every other path.
    app = FastAPI(title="Private AI OS backend", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.add_middleware(
        BoundaryGuard, host=settings.host, port=settings.port, authenticator=authenticator, sessions=sessions
    )
    install_error_handlers(app)
    app.include_router(health_router(settings.database_path))
    app.include_router(session_router(sessions))
    install_static_ui(app, settings.static_dir)  # answers only what no route claims
    return app
