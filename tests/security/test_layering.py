"""Architectural invariant: the security engine must work with the LLM absent, so it may not import it."""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SECURITY_PACKAGE = REPO / "backend" / "security"
FORBIDDEN_FOR_SECURITY = ("backend.llm", "backend.agents", "model_runtime")


def _imported_modules(source: str) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def forbidden_imports(package_dir: Path, forbidden: tuple[str, ...]) -> list[str]:
    """Return 'file: module' for every import under package_dir that is, or is inside, a forbidden module."""
    violations: list[str] = []
    for path in sorted(package_dir.rglob("*.py")):
        for module in sorted(_imported_modules(path.read_text(encoding="utf-8"))):
            if any(module == name or module.startswith(f"{name}.") for name in forbidden):
                violations.append(f"{path.name}: {module}")
    return violations


def test_security_package_does_not_import_llm_or_agents() -> None:
    assert forbidden_imports(SECURITY_PACKAGE, FORBIDDEN_FOR_SECURITY) == []


def test_checker_detects_violations(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("import backend.llm.provider\nfrom backend.agents import planner\n")
    (tmp_path / "good.py").write_text("import json\nfrom backend.core import config\n")
    assert forbidden_imports(tmp_path, FORBIDDEN_FOR_SECURITY) == [
        "bad.py: backend.agents",
        "bad.py: backend.llm.provider",
    ]


def test_checker_does_not_flag_similarly_named_modules(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import backend.llm_notes\n")
    assert forbidden_imports(tmp_path, FORBIDDEN_FOR_SECURITY) == []
