"""Structure of the package: standard library only, no backend or kiosk, no shell, a timeout on every command."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
MODULES = [path for path in PACKAGE.rglob("*.py") if "tests" not in path.relative_to(PACKAGE).parts]


def parsed() -> list[tuple[Path, ast.Module]]:
    return [(path, ast.parse(path.read_text(encoding="utf-8"))) for path in MODULES]


def imported_top_level_modules() -> set[str]:
    modules: set[str] = set()
    for _, tree in parsed():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                modules.add(node.module.split(".")[0])
    return modules


def test_the_scan_sees_the_package_modules() -> None:
    names = {path.name for path in MODULES}
    assert {"engine.py", "runner.py", "plan.py", "target.py", "luks.py", "configure.py"} <= names


def test_the_installer_does_not_import_the_backend_or_the_kiosk() -> None:
    imported = imported_top_level_modules()
    assert "installer" in imported, "the scan found no import of the package itself: it is not looking at the code"
    assert not imported & {"backend", "kiosk", "model_runtime", "document_engine"}


def test_the_installer_needs_nothing_but_the_python_standard_library() -> None:
    assert imported_top_level_modules() - {"installer"} <= set(sys.stdlib_module_names)


def test_no_module_starts_a_shell_or_runs_a_command_outside_the_runner() -> None:
    offenders = []
    for path, tree in parsed():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                owner = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                if (owner, node.func.attr) in {
                    ("os", "system"),
                    ("os", "popen"),
                    ("subprocess", "run"),
                    ("subprocess", "call"),
                    ("subprocess", "check_output"),
                    ("subprocess", "check_call"),
                }:
                    offenders.append(f"{path.name}:{node.lineno} {owner}.{node.func.attr}")
                if any(
                    keyword.arg == "shell"
                    and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False)
                    for keyword in node.keywords
                ):
                    offenders.append(f"{path.name}:{node.lineno} shell=")
    assert offenders == []


def test_subprocess_is_used_only_by_the_runner_module() -> None:
    users = {
        path.name
        for path, tree in parsed()
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom)) and "subprocess" in ast.dump(node)
    }
    assert users == {"runner.py"}


def test_every_command_a_step_runs_has_a_timeout() -> None:
    calls = 0
    for path, tree in parsed():
        if path.parent.name != "steps" and path.name != "configure.py":
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "cmd"
            ):
                calls += 1
                assert any(keyword.arg == "timeout" for keyword in node.keywords), (
                    f"{path.name}:{node.lineno} has no timeout"
                )
    assert calls > 20, "the scan found too few commands: it is not looking at the steps"


def test_no_command_is_built_from_an_f_string_shell_line() -> None:
    """A command is a list: an f-string passed directly as the whole command would be a shell line."""
    for path, tree in parsed():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run"
                and node.args
            ):
                assert not isinstance(node.args[0], (ast.JoinedStr, ast.Constant)), f"{path.name}:{node.lineno}"
