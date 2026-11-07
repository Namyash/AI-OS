"""The version served by /health must equal the one in pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

from backend.core.version import __version__

PYPROJECT = Path(__file__).resolve().parents[3] / "pyproject.toml"


def test_version_matches_pyproject() -> None:
    declared = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert __version__ == declared
