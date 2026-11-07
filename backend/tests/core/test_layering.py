"""Architectural invariant (ARCHITECTURE.md section 4): core is imported by everyone and imports nobody."""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CORE = REPO_ROOT / "backend" / "core"
CORE_PACKAGE = "backend.core"


def _project_imports(source: str, package: str) -> set[str]:
    """Modules of this project (``backend`` and ``backend.*``) that ``source`` imports.

    ``package`` is the dotted package the file lives in; relative imports resolve against it, so
    ``from ..api import x`` inside ``backend.core`` is ``backend.api``. Imports made at run time with
    ``importlib`` are not visible to a static check.
    """
    modules: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level:
            parts = package.split(".")
            base = parts[: len(parts) - (node.level - 1)]  # one level is the file's own package
            modules.add(".".join([*base, *([node.module] if node.module else [])]))
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return {m for m in modules if m == "backend" or m.startswith("backend.")}


def foreign_imports(core_dir: Path, repo_root: Path) -> dict[str, list[str]]:
    """Project modules outside ``backend.core`` imported by any module under ``core_dir``, nested ones included."""
    offenders: dict[str, list[str]] = {}
    for path in sorted(core_dir.rglob("*.py")):
        package = ".".join(path.relative_to(repo_root).parent.parts)
        foreign = {
            module
            for module in _project_imports(path.read_text(encoding="utf-8"), package)
            if module != CORE_PACKAGE and not module.startswith(f"{CORE_PACKAGE}.")
        }
        if foreign:
            offenders[path.relative_to(core_dir).as_posix()] = sorted(foreign)
    return offenders


def test_core_imports_nothing_else_from_the_project() -> None:
    assert list(CORE.rglob("*.py")), f"no core modules found under {CORE}: the check would pass without looking"
    assert foreign_imports(CORE, REPO_ROOT) == {}


def test_the_checker_flags_other_project_packages_and_allows_core_itself() -> None:
    source = "import backend.api.app\nfrom backend import database\nfrom backend.core import config\nimport json\n"
    assert _project_imports(source, CORE_PACKAGE) == {"backend.api.app", "backend", "backend.core"}


def test_the_checker_resolves_relative_imports_against_the_files_package() -> None:
    assert _project_imports("from ..api.auth import issue_token", CORE_PACKAGE) == {"backend.api.auth"}
    assert _project_imports("from .. import api", CORE_PACKAGE) == {"backend"}
    assert _project_imports("from . import config", CORE_PACKAGE) == {"backend.core"}
    assert _project_imports("from .config import load_settings", CORE_PACKAGE) == {"backend.core.config"}
    # One package deeper, the same dots reach one level further up.
    assert _project_imports("from ..api import x", "backend.core.sub") == {"backend.core.api"}
    assert _project_imports("from ... import api", "backend.core.sub") == {"backend"}
    assert _project_imports("from ...api import x", "backend.core.sub") == {"backend.api"}


def test_the_checker_reads_nested_modules_and_relative_imports(tmp_path: Path) -> None:
    core = tmp_path / "backend" / "core"
    (core / "sub").mkdir(parents=True)
    (core / "config.py").write_text("from ..api.auth import issue_token\nfrom . import version\n")
    (core / "sub" / "deep.py").write_text("from ...database import migrate\nfrom ..version import __version__\n")
    (core / "version.py").write_text("import json\n")
    assert foreign_imports(core, tmp_path) == {
        "config.py": ["backend.api.auth"],
        "sub/deep.py": ["backend.database"],
    }
