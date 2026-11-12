"""Fixtures: a fake backend and a launcher rig on a temporary directory."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from kiosk import log
from kiosk.tests.fake_backend import FakeBackend
from kiosk.tests.support import Rig


@pytest.fixture
def backend() -> Iterator[FakeBackend]:
    with FakeBackend() as running:
        yield running


@pytest.fixture
def rig(tmp_path: Path, backend: FakeBackend) -> Iterator[Rig]:
    rig = Rig(root=tmp_path, backend=backend)
    yield rig
    rig.finish()


@pytest.fixture(autouse=True)
def no_registered_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """The secret registry is process-wide: every test starts with none and leaves none behind."""
    monkeypatch.setattr(log, "_secrets", frozenset())
