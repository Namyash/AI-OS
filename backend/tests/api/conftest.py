"""Fixtures: a real app on a temporary state directory, driven through Starlette's TestClient."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.core.config import Settings, load_settings
from backend.tests.api.support import PORT, client_for


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return load_settings(
        {
            "PAI_PORT": str(PORT),
            "PAI_DATA_DIR": str(tmp_path / "state"),
            "PAI_TOKEN_FILE": str(tmp_path / "runtime" / "token"),
        }
    )


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with client_for(app) as running:
        yield running


@pytest.fixture
def token(settings: Settings, client: TestClient) -> str:
    """The live token, read the way a real consumer (the kiosk) would: from the token file."""
    return settings.token_file.read_text(encoding="ascii")


@pytest.fixture
def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def start_app(settings: Settings) -> Callable[[], AbstractContextManager[TestClient]]:
    """Start a fresh app on the same settings, to model a service restart."""
    return lambda: client_for(create_app(settings))
