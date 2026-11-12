"""Fixtures: every test starts with no registered secrets, and the installer's log goes to a buffer."""

from __future__ import annotations

import io
import logging
from collections.abc import Iterator

import pytest

from installer import log


@pytest.fixture(autouse=True)
def no_registered_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """The secret registry is process-wide: every test starts with none and leaves none behind."""
    monkeypatch.setattr(log, "_secrets", frozenset())


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    log.configure_logging(stream)
    yield stream
    logger = logging.getLogger(log.LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
