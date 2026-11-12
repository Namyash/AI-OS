"""The launcher is a client of the backend, not part of it: standard library only, no import of ``backend``."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]


def imported_top_level_modules() -> set[str]:
    modules: set[str] = set()
    for path in PACKAGE.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                modules.add(node.module.split(".")[0])
    return modules


def test_the_launcher_does_not_import_the_backend() -> None:
    assert "backend" not in imported_top_level_modules()


def test_the_launcher_needs_nothing_but_the_python_standard_library() -> None:
    imported = imported_top_level_modules()
    assert "kiosk" in imported, "the scan found no import of the package itself: it is not looking at the code"
    assert imported - {"kiosk"} <= set(sys.stdlib_module_names)
