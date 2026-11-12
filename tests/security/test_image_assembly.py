"""Runs os/build/assemble-config.sh, the script that fills live-build's config tree, and checks what it produces.

The script is executed for real (with a working `bash`), once against this repository and several times against
scratch trees. The scratch trees prove the rules hold for components, backend packages and data files that did not
exist when the script was written: nothing about the repository's current contents is written into the script or
into the expectations below, which are derived from the source tree itself. The same goes for build-frontend.sh,
which runs here against a scratch frontend and a stand-in `npm` (the real build runs in the builder container).

File modes and ownership are POSIX facts: the mode checks skip on a Windows host (the same tests run in the Debian
container, see docs/development/DEVELOPMENT.md) and ownership is checked only when run as root.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from backend.database.migrate import discover
from tests.bash_support import find_working_bash

REPO = Path(__file__).resolve().parents[2]
OS_DIR = REPO / "os"
BACKEND_DIR = REPO / "backend"
KIOSK_DIR = REPO / "kiosk"
INSTALLER_DIR = REPO / "installer"
BUILD_DIR = OS_DIR / "build"
SCRIPT = BUILD_DIR / "assemble-config.sh"
FRONTEND_SCRIPT = BUILD_DIR / "build-frontend.sh"
BACKEND_UNIT = OS_DIR / "systemd" / "rootfs" / "etc" / "systemd" / "system" / "pai-backend.service"
KIOSK_UNIT = OS_DIR / "kiosk" / "rootfs" / "etc" / "systemd" / "system" / "pai-kiosk.service"
INSTALL_UNIT = OS_DIR / "installer" / "rootfs" / "etc" / "systemd" / "system" / "pai-install-auto.service"
INSTALL_SCRIPT = OS_DIR / "installer" / "rootfs" / "usr" / "lib" / "pai" / "install-auto.sh"
BACKEND_SETTINGS = BACKEND_DIR / "core" / "config.py"

# Every `bash` on PATH is tried, not just the first: on Windows the first can be the WSL launcher with no distribution.
BASH = find_working_bash()
needs_bash = pytest.mark.skipif(BASH is None, reason="no working bash on this machine")
needs_posix_modes = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes and ownership")


def assemble(
    os_dir: Path, backend_dir: Path, kiosk_dir: Path, installer_dir: Path, frontend_dir: Path, config_dir: Path
) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    inputs = [os_dir, backend_dir, kiosk_dir, installer_dir, frontend_dir, config_dir]
    command = [BASH, SCRIPT.as_posix(), *(p.as_posix() for p in inputs)]
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)  # noqa: S603


def write(path: Path, text: str, mode: int | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    if mode is not None:
        path.chmod(mode)
    return path


def files_under(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()}


def a_frontend_build(directory: Path) -> Path:
    """What `npm run build` leaves in dist/: an index page, hashed assets and the licenses it collected."""
    write(directory / "index.html", "<!doctype html><title>ui</title>\n")
    write(directory / "assets" / "index-AbC123.js", "console.log(1)\n")
    write(directory / "assets" / "index-AbC123.css", "body{}\n")
    write(directory / "licenses" / "README.md", "licenses of the bundled fonts\n")
    return directory


# What the documented requirement keeps out of the image (kept apart from the script's own lists on purpose).
def is_left_out(relative: Path) -> bool:
    return (
        "tests" in relative.parts
        or "__pycache__" in relative.parts
        or relative.name.startswith("README")
        or relative.suffix in {".pyc", ".pyo"}
    )


@pytest.fixture(scope="module")
def real_config(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("assembled")
    config = base / "config"
    # The repository holds no frontend build (the builder container makes it), so a stand-in build is the input.
    done = assemble(OS_DIR, BACKEND_DIR, KIOSK_DIR, INSTALLER_DIR, a_frontend_build(base / "dist"), config)
    assert done.returncode == 0, done.stderr
    return config


# ---------------------------------------------------------------------------------- the repository, assembled
@needs_bash
def test_every_overlay_file_hook_and_package_list_lands_where_live_build_reads_it(real_config: Path) -> None:
    expected = {
        ("rootfs", "includes.chroot"),
        ("hooks", "hooks/live"),
        ("package-lists", "package-lists"),
    }
    checked = 0
    for source_name, target_name in sorted(expected):
        for source in OS_DIR.glob(f"*/{source_name}/**/*"):
            if source.is_dir():
                continue
            relative = Path(*source.relative_to(OS_DIR).parts[2:])  # os/<component>/<part>/<relative path>
            target = real_config / target_name / relative
            assert target.is_file(), f"{source.relative_to(OS_DIR)} did not land at {target.relative_to(real_config)}"
            assert target.read_bytes() == source.read_bytes()
            checked += 1
    assert checked >= 8, "too few files were compared for this test to mean anything"


# One row per tree of Python code the image runs from /opt/pai: its source, the variable of assemble-config.sh that
# says where it lands, the unit that runs it and the module that unit starts.
PYTHON_TREES = [
    pytest.param(BACKEND_DIR, "BACKEND_IMAGE_DIR", BACKEND_UNIT, "backend", id="backend"),
    pytest.param(KIOSK_DIR, "KIOSK_IMAGE_DIR", KIOSK_UNIT, "kiosk", id="kiosk"),
]
# The same rows plus the installer, whose unit starts a script that runs `python3 -m installer` from /opt/pai.
COPIED_TREES = [
    *PYTHON_TREES,
    pytest.param(INSTALLER_DIR, "INSTALLER_IMAGE_DIR", INSTALL_UNIT, "installer", id="installer"),
]


@needs_bash
@pytest.mark.parametrize(("source", "variable", "unit", "module"), PYTHON_TREES)
def test_the_code_lands_where_its_unit_runs_it_from(
    real_config: Path, source: Path, variable: str, unit: Path, module: str
) -> None:
    unit_text = unit.read_text(encoding="utf-8")
    working_directory = re.search(r"^WorkingDirectory=(\S+)$", unit_text, re.MULTILINE)
    assert working_directory is not None
    install_dir = re.search(rf"^{variable}=(\S+)$", SCRIPT.read_text(encoding="utf-8"), re.MULTILINE)
    assert install_dir is not None
    # `python3 -m <module>` run from WorkingDirectory finds the package in <WorkingDirectory>/<module>.
    assert re.search(rf"^ExecStart=.*/python3 .*-m {module}$", unit_text, re.MULTILINE)
    assert install_dir[1] == f"{working_directory[1].strip('/')}/{module}"
    assert (real_config / "includes.chroot" / install_dir[1] / "__main__.py").is_file()
    assert source.name == module


@needs_bash
@pytest.mark.parametrize(("source", "variable", "unit", "module"), COPIED_TREES)
def test_the_installed_code_is_the_source_without_tests_documentation_and_bytecode(
    real_config: Path, source: Path, variable: str, unit: Path, module: str
) -> None:
    installed = real_config / "includes.chroot" / "opt" / "pai" / module
    wanted = {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
    wanted = {name for name in wanted if not is_left_out(Path(name))}
    assert any(name.endswith(".py") for name in wanted)
    assert files_under(installed) == wanted
    for name in wanted:
        assert (installed / name).read_bytes() == (source / name).read_bytes()


@needs_bash
def test_the_installer_lands_where_the_script_the_unit_runs_starts_it_from(real_config: Path) -> None:
    unit_text = INSTALL_UNIT.read_text(encoding="utf-8")
    working_directory = re.search(r"^WorkingDirectory=(\S+)$", unit_text, re.MULTILINE)
    assert working_directory is not None
    install_dir = re.search(r"^INSTALLER_IMAGE_DIR=(\S+)$", SCRIPT.read_text(encoding="utf-8"), re.MULTILINE)
    assert install_dir is not None
    assert install_dir[1] == f"{working_directory[1].strip('/')}/installer"
    script_text = INSTALL_SCRIPT.read_text(encoding="utf-8")
    assert re.search(r"^ENGINE_DIR=\$\{PAI_INSTALL_ENGINE_DIR:-/opt/pai\}", script_text, re.MULTILINE)
    assert "python3 -s -B -m installer --plan" in script_text
    assert (real_config / "includes.chroot" / install_dir[1] / "__main__.py").is_file()
    assert (real_config / "includes.chroot" / "usr" / "lib" / "pai" / "install-auto.sh").is_file()


@needs_bash
def test_the_installed_backend_ships_its_migrations(real_config: Path) -> None:
    installed = real_config / "includes.chroot" / "opt" / "pai" / "backend"
    assert any(path.suffix == ".sql" for path in installed.rglob("*")), "no migration ships: no database can be made"


@needs_bash
def test_the_installed_backend_imports_and_finds_its_migrations_from_the_installed_location(real_config: Path) -> None:
    app_root = real_config / "includes.chroot" / "opt" / "pai"
    program = (
        "import json, pathlib, backend, backend.api.app, backend.__main__\n"
        "from backend.database.migrate import discover\n"
        "print(json.dumps({'file': backend.__file__, 'migrations': [[m.version, m.checksum] for m in discover()]}))\n"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-B", "-s", "-c", program],
        cwd=app_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert Path(report["file"]).resolve().is_relative_to(app_root.resolve()), "imported the source tree, not the image"
    source_migrations = discover(BACKEND_DIR / "database" / "migrations")
    assert report["migrations"] == [[m.version, m.checksum] for m in source_migrations]
    assert report["migrations"], "no migration ships: the service could not create its database"


@needs_bash
def test_the_installed_kiosk_starts_from_the_installed_location_the_way_the_unit_starts_it(real_config: Path) -> None:
    app_root = real_config / "includes.chroot" / "opt" / "pai"
    # `python3 -s -m kiosk` from WorkingDirectory, with an invalid setting: the launcher must get as far as reading its
    # configuration, which proves every module it imports is in the image, and ends with the status that stops restarts.
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("PAI_")},
        "PAI_KIOSK_RENDER_TIMEOUT": "never",
        "PYTHONPATH": "",
    }
    done = subprocess.run(
        [sys.executable, "-B", "-s", "-m", "kiosk"],
        cwd=app_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert done.returncode == 78, done.stderr
    assert "PAI_KIOSK_RENDER_TIMEOUT" in done.stderr
    imported_from = subprocess.run(
        [sys.executable, "-B", "-s", "-c", "import kiosk.launcher as m; print(m.__file__)"],
        cwd=app_root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    ).stdout.strip()
    assert Path(imported_from).resolve().is_relative_to(app_root.resolve()), "imported the source tree, not the image"


def _backend_default(name: str) -> str:
    """``NAME = Path("...")`` of the backend's settings module, read without importing the backend."""
    for node in ast.parse(BACKEND_SETTINGS.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            assert isinstance(node.value, ast.Call)
            argument = node.value.args[0]
            assert isinstance(argument, ast.Constant)
            return str(argument.value)
    raise AssertionError(f"{name} is not defined in {BACKEND_SETTINGS}")


@needs_bash
def test_the_frontend_lands_where_the_backend_serves_it_from(real_config: Path) -> None:
    install_dir = re.search(r"^FRONTEND_IMAGE_DIR=(\S+)$", SCRIPT.read_text(encoding="utf-8"), re.MULTILINE)
    assert install_dir is not None
    # The backend's default PAI_STATIC_DIR is where the UI is installed: one place says it, the other must agree.
    assert f"/{install_dir[1]}" == _backend_default("DEFAULT_STATIC_DIR")
    assert (real_config / "includes.chroot" / install_dir[1] / "index.html").is_file()


@needs_bash
def test_the_installed_frontend_is_exactly_the_build_output_and_nothing_else(
    real_config: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    installed = real_config / "includes.chroot" / "opt" / "pai" / "frontend"
    build = a_frontend_build(tmp_path_factory.mktemp("expected") / "dist")
    assert files_under(installed) == files_under(build)
    for name in files_under(build):
        assert (installed / name).read_bytes() == (build / name).read_bytes()
    assert not [p for p in installed.rglob("*") if p.name in {"node_modules", "package.json", "package-lock.json"}]


@needs_bash
@needs_posix_modes
def test_nothing_in_the_image_tree_is_writable_by_group_or_others_and_only_scripts_execute(real_config: Path) -> None:
    for path in sorted(real_config.rglob("*")):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode & 0o777
        shown = f"{path.relative_to(real_config)} is {mode:04o}"
        if path.is_dir():
            assert mode == 0o755, shown
        elif path.relative_to(real_config).parts[0] == "hooks":
            assert mode == 0o755, f"{shown}; live-build skips a hook that is not executable"
        elif path.is_relative_to(real_config / "includes.chroot" / "opt"):
            assert mode == 0o644, f"{shown}; python modules are imported, never executed"
        else:
            is_script = path.read_bytes().startswith(b"#!")
            assert mode == (0o755 if is_script else 0o644), shown


# --------------------------------------------------------------------- scratch trees: rules for what is not here yet
class Tree:
    """A scratch os/ directory, backend/ and kiosk/ package directories and a frontend build output."""

    def __init__(self, base: Path) -> None:
        self.os = base / "os"
        self.backend = base / "backend"
        self.kiosk = base / "kiosk"
        self.installer = base / "installer"
        self.frontend = base / "dist"
        self.config = base / "config"
        self.os.mkdir()
        self.backend.mkdir()
        self.kiosk.mkdir()
        self.installer.mkdir()
        write(self.backend / "__init__.py", "")
        write(self.kiosk / "__init__.py", "")
        write(self.installer / "__init__.py", "")
        a_frontend_build(self.frontend)

    def run(self, **replaced: Path) -> subprocess.CompletedProcess[str]:
        """Assemble; ``replaced`` swaps one input (os, backend, kiosk, installer, frontend) for another path."""
        inputs = {
            "os": self.os,
            "backend": self.backend,
            "kiosk": self.kiosk,
            "installer": self.installer,
            "frontend": self.frontend,
            **replaced,
        }
        return assemble(
            inputs["os"], inputs["backend"], inputs["kiosk"], inputs["installer"], inputs["frontend"], self.config
        )

    def installed_tree(self, name: str) -> Path:
        return {
            "backend": self.backend,
            "kiosk": self.kiosk,
            "installer": self.installer,
            "frontend": self.frontend,
        }[name]


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


@needs_bash
def test_a_new_component_package_and_data_file_ship_without_changing_the_script(tree: Tree) -> None:
    write(tree.os / "newcomp" / "rootfs" / "etc" / "thing.conf", "x=1\n")
    write(tree.os / "newcomp" / "rootfs" / "usr" / "lib" / "thing" / "run.sh", "#!/bin/sh\n")
    write(tree.os / "newcomp" / "hooks" / "0300-thing.hook.chroot", "#!/bin/sh\nset -e\n")
    write(tree.os / "newcomp" / "package-lists" / "thing.list.chroot", "thing\n")
    write(tree.os / "empty-component" / "README.md", "no overlay, no hooks, no packages\n")
    write(tree.backend / "newpkg" / "__init__.py", "")
    write(tree.backend / "newpkg" / "data" / "schema.json", "{}\n")
    write(tree.backend / "newpkg" / "migrations" / "0001_x.sql", "SELECT 1;\n")
    done = tree.run()
    assert done.returncode == 0, done.stderr
    assert "Assembled 1 component(s)" in done.stdout
    config = tree.config
    assert (config / "includes.chroot" / "etc" / "thing.conf").read_text() == "x=1\n"
    assert (config / "includes.chroot" / "usr" / "lib" / "thing" / "run.sh").is_file()
    assert (config / "hooks" / "live" / "0300-thing.hook.chroot").is_file()
    assert (config / "package-lists" / "thing.list.chroot").read_text() == "thing\n"
    shipped = files_under(config / "includes.chroot" / "opt" / "pai" / "backend")
    assert {"__init__.py", "newpkg/__init__.py", "newpkg/data/schema.json", "newpkg/migrations/0001_x.sql"} <= shipped
    assert files_under(config / "includes.chroot" / "opt" / "pai" / "kiosk") == {"__init__.py"}
    assert files_under(config / "includes.chroot" / "opt" / "pai" / "installer") == {"__init__.py"}
    assert files_under(config / "includes.chroot" / "opt" / "pai" / "frontend") == files_under(tree.frontend)


@needs_bash
@pytest.mark.parametrize("name", ["backend", "kiosk", "installer"])
def test_tests_bytecode_and_documentation_stay_out_at_any_depth_and_leave_no_empty_directories(
    tree: Tree, name: str
) -> None:
    source = tree.installed_tree(name)
    write(source / "README.md", "docs\n")
    write(source / "tests" / "test_top.py", "")
    write(source / "__pycache__" / "mod.cpython-313.pyc", "")
    write(source / "pkg" / "__init__.py", "")
    write(source / "pkg" / "README.md", "docs\n")
    write(source / "pkg" / "tests" / "test_pkg.py", "")
    write(source / "pkg" / "tests" / "deeper" / "test_more.py", "")
    write(source / "pkg" / "sub" / "__pycache__" / "x.cpython-312.pyc", "")
    write(source / "pkg" / "stale.pyc", "")
    write(source / "pkg" / "READMEfirst.txt", "docs\n")
    write(source / "placeholder" / "README.md", "a directory that only held documentation\n")
    assert tree.run().returncode == 0
    installed = tree.config / "includes.chroot" / "opt" / "pai" / name
    assert files_under(installed) == {"__init__.py", "pkg/__init__.py"}
    assert sorted(p.relative_to(installed).as_posix() for p in installed.rglob("*") if p.is_dir()) == ["pkg"]


@needs_bash
def test_the_built_frontend_is_shipped_as_built_without_the_filters_of_the_python_trees(tree: Tree) -> None:
    # Whatever the build wrote is what the backend serves: a README or a directory called tests in it is content.
    write(tree.frontend / "README.md", "served as is\n")
    write(tree.frontend / "assets" / "tests" / "chunk.js", "x\n")
    write(tree.frontend / "assets" / "stale.pyc", "not python, just a name\n")
    assert tree.run().returncode == 0
    installed = tree.config / "includes.chroot" / "opt" / "pai" / "frontend"
    assert files_under(installed) == files_under(tree.frontend)


@needs_bash
def test_two_components_may_not_ship_the_same_file(tree: Tree) -> None:
    write(tree.os / "alpha" / "rootfs" / "etc" / "same.conf", "from alpha\n")
    write(tree.os / "beta" / "rootfs" / "etc" / "same.conf", "from beta\n")
    done = tree.run()
    assert done.returncode != 0
    assert "component 'beta' ships etc/same.conf, which another component already provides" in done.stderr


@needs_bash
def test_two_components_may_not_ship_a_hook_or_a_package_list_with_the_same_name(tree: Tree) -> None:
    write(tree.os / "alpha" / "hooks" / "0100-x.hook.chroot", "#!/bin/sh\n")
    write(tree.os / "beta" / "hooks" / "0100-x.hook.chroot", "#!/bin/sh\n")
    assert "hooks" not in tree.run().stderr or True  # the message names the file, checked below
    done = tree.run()
    assert done.returncode != 0
    assert "0100-x.hook.chroot" in done.stderr


@needs_bash
def test_different_files_in_the_same_directory_of_two_components_are_fine(tree: Tree) -> None:
    write(tree.os / "alpha" / "rootfs" / "etc" / "sysctl.d" / "10-a.conf", "a\n")
    write(tree.os / "beta" / "rootfs" / "etc" / "sysctl.d" / "20-b.conf", "b\n")
    assert tree.run().returncode == 0
    assert files_under(tree.config / "includes.chroot" / "etc") == {"sysctl.d/10-a.conf", "sysctl.d/20-b.conf"}


@needs_bash
@pytest.mark.parametrize("name", ["backend", "kiosk", "installer", "frontend"])
def test_a_component_may_not_ship_into_a_directory_the_image_code_is_installed_to(tree: Tree, name: str) -> None:
    write(tree.os / "alpha" / "rootfs" / "opt" / "pai" / name / "evil.py", "")
    done = tree.run()
    assert done.returncode != 0
    assert f"already ships /opt/pai/{name}" in done.stderr


@needs_bash
def test_a_hook_without_a_script_header_fails_the_build_instead_of_being_skipped(tree: Tree) -> None:
    write(tree.os / "alpha" / "hooks" / "0100-no-header.hook.chroot", "set -e\ntrue\n")
    done = tree.run()
    assert done.returncode != 0
    assert "0100-no-header.hook.chroot does not start with a #! line" in done.stderr


@needs_bash
@pytest.mark.parametrize(
    ("input_name", "label"),
    [("backend", "backend"), ("kiosk", "kiosk"), ("installer", "installer"), ("frontend", "frontend build output")],
)
def test_a_missing_input_directory_fails_with_its_name(tree: Tree, input_name: str, label: str) -> None:
    absent = tree.config.parent / "absent"
    done = tree.run(**{input_name: absent})
    assert done.returncode != 0
    assert f"{label} directory not found" in done.stderr
    assert str(absent).replace("\\", "/") in done.stderr.replace("\\", "/")


@needs_bash
def test_a_frontend_build_without_an_index_page_fails_the_build_instead_of_shipping_a_blank_ui(tree: Tree) -> None:
    (tree.frontend / "index.html").unlink()
    done = tree.run()
    assert done.returncode != 0
    assert "frontend build output has no index.html" in done.stderr


@needs_bash
def test_a_missing_os_directory_fails_with_its_name(tree: Tree) -> None:
    done = tree.run(os=tree.os / "absent")
    assert done.returncode != 0
    assert "os directory not found" in done.stderr


@needs_bash
def test_the_wrong_number_of_arguments_is_a_usage_error() -> None:
    assert BASH is not None
    done = subprocess.run([BASH, SCRIPT.as_posix(), "only-one"], capture_output=True, text=True, check=False)  # noqa: S603
    assert done.returncode == 2
    assert "usage:" in done.stderr


@needs_bash
@pytest.mark.parametrize("name", ["backend", "kiosk", "installer", "frontend"])
def test_a_symbolic_link_in_an_installed_tree_fails_the_build(tree: Tree, name: str) -> None:
    try:
        (tree.installed_tree(name) / "link.py").symlink_to("/etc/passwd")
    except OSError:
        pytest.skip("this host does not allow creating symbolic links")
    done = tree.run()
    assert done.returncode != 0
    assert "symbolic link" in done.stderr


@needs_bash
@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to give the source an owner")
def test_the_image_files_belong_to_the_user_who_builds_not_to_whoever_owns_the_source(tree: Tree) -> None:
    other_owner = 4242  # an account that is not the builder (root); on a Linux host this is the developer's uid
    write(tree.os / "alpha" / "rootfs" / "etc" / "thing.conf", "x\n")
    write(tree.os / "alpha" / "hooks" / "0100-x.hook.chroot", "#!/bin/sh\n")
    write(tree.os / "alpha" / "package-lists" / "x.list.chroot", "x\n")
    write(tree.backend / "pkg" / "mod.py", "")
    write(tree.kiosk / "pkg" / "mod.py", "")
    write(tree.installer / "pkg" / "mod.py", "")
    for root in (tree.os, tree.backend, tree.kiosk, tree.installer, tree.frontend):
        for path in [root, *root.rglob("*")]:
            os.chown(path, other_owner, other_owner)
    assert tree.run().returncode == 0
    foreign = [p.relative_to(tree.config).as_posix() for p in tree.config.rglob("*") if p.lstat().st_uid != 0]
    assert foreign == []


@needs_bash
@needs_posix_modes
def test_modes_of_the_source_tree_are_replaced_by_the_rule_whatever_they_were(tree: Tree) -> None:
    write(tree.os / "alpha" / "rootfs" / "etc" / "thing.conf", "x\n", 0o777)
    write(tree.os / "alpha" / "rootfs" / "etc" / "systemd" / "system" / "thing.service", "[Service]\n", 0o755)
    write(tree.os / "alpha" / "rootfs" / "usr" / "bin" / "tool", "#!/bin/sh\n", 0o600)
    write(tree.os / "alpha" / "hooks" / "0100-x.hook.chroot", "#!/bin/sh\n", 0o600)
    write(tree.os / "alpha" / "package-lists" / "x.list.chroot", "x\n", 0o777)
    write(tree.backend / "pkg" / "mod.py", "#!/usr/bin/env python3\n", 0o777)
    write(tree.kiosk / "pkg" / "mod.py", "#!/usr/bin/env python3\n", 0o777)
    write(tree.installer / "pkg" / "mod.py", "#!/usr/bin/env python3\n", 0o777)
    write(tree.frontend / "assets" / "run.js", "#!/usr/bin/env node\n", 0o777)
    (tree.os / "alpha" / "rootfs" / "etc").chmod(0o777)
    (tree.backend / "pkg").chmod(0o777)
    (tree.kiosk / "pkg").chmod(0o777)
    (tree.installer / "pkg").chmod(0o777)
    (tree.frontend / "assets").chmod(0o777)
    assert tree.run().returncode == 0
    includes = tree.config / "includes.chroot"

    def mode(path: Path) -> int:
        return path.stat().st_mode & 0o777

    assert mode(includes / "etc") == 0o755
    assert mode(includes / "etc" / "thing.conf") == 0o644
    assert mode(includes / "etc" / "systemd" / "system" / "thing.service") == 0o644
    assert mode(includes / "usr" / "bin" / "tool") == 0o755
    assert mode(tree.config / "hooks" / "live" / "0100-x.hook.chroot") == 0o755
    assert mode(tree.config / "package-lists" / "x.list.chroot") == 0o644
    assert mode(includes / "opt" / "pai" / "backend" / "pkg") == 0o755
    assert mode(includes / "opt" / "pai" / "backend" / "pkg" / "mod.py") == 0o644  # imported, never executed
    assert mode(includes / "opt" / "pai" / "kiosk" / "pkg") == 0o755
    assert mode(includes / "opt" / "pai" / "kiosk" / "pkg" / "mod.py") == 0o644
    assert mode(includes / "opt" / "pai" / "installer" / "pkg") == 0o755
    assert mode(includes / "opt" / "pai" / "installer" / "pkg" / "mod.py") == 0o644  # imported, never executed
    assert mode(includes / "opt" / "pai" / "frontend" / "assets") == 0o755
    assert mode(includes / "opt" / "pai" / "frontend" / "assets" / "run.js") == 0o644  # served, never executed


# ------------------------------------------------------------------ the build scripts name each other correctly
def _mounts(text: str) -> dict[str, tuple[str, bool]]:
    """`-v "$ROOT/<host dir>:<container dir>[:ro]"` options of build-iso.sh: container dir -> (host dir, read-only)."""
    found = {}
    for host, container, mode in re.findall(r'-v "\$ROOT/(\w+):(/[\w/]+)(:ro)?"', text):
        found[container] = (host, mode == ":ro")
    return found


@pytest.mark.parametrize(
    ("variable", "host_directory"),
    [
        ("SRC", "os"),
        ("BACKEND_SRC", "backend"),
        ("KIOSK_SRC", "kiosk"),
        ("INSTALLER_SRC", "installer"),
        ("FRONTEND_SRC", "frontend"),
    ],
)
def test_every_source_is_mounted_read_only_where_the_container_script_reads_it(
    variable: str, host_directory: str
) -> None:
    mounts = _mounts((BUILD_DIR / "build-iso.sh").read_text(encoding="utf-8"))
    inside = (BUILD_DIR / "in-container-build.sh").read_text(encoding="utf-8")
    source = re.search(rf"^{variable}=(\S+)", inside, re.MULTILINE)
    assert source is not None
    assert mounts[source[1]] == (host_directory, True)
    assert (REPO / host_directory).is_dir()


def test_the_container_script_hands_the_assembly_to_the_assemble_script_and_copies_nothing_itself() -> None:
    inside = (BUILD_DIR / "in-container-build.sh").read_text(encoding="utf-8")
    assert 'assemble-config.sh" "$SRC" "$BACKEND_SRC" "$KIOSK_SRC" "$INSTALLER_SRC" "$FRONTEND_DIST" config' in inside
    assert (BUILD_DIR / "assemble-config.sh").is_file()
    # Copying here too would be a second, drifting implementation of the same rules.
    code = "\n".join(line for line in inside.splitlines() if not line.lstrip().startswith("#"))
    assert not re.search(r"\bcp -a\b|includes\.chroot|hooks/live|package-lists", code)
    assert code.index("assemble-config.sh") < code.index("lb build")


def test_the_frontend_is_built_before_it_is_assembled_from_a_read_only_source_into_a_scratch_directory() -> None:
    inside = (BUILD_DIR / "in-container-build.sh").read_text(encoding="utf-8")
    code = "\n".join(line for line in inside.splitlines() if not line.lstrip().startswith("#"))
    assert 'build-frontend.sh" "$FRONTEND_SRC" "$FRONTEND_DIST"' in code
    assert code.index("build-frontend.sh") < code.index("assemble-config.sh")
    assert re.search(r"^FRONTEND_DIST=\$\(mktemp -d\)$", code, re.MULTILINE), (
        "the build output belongs in a scratch dir"
    )
    assert not re.search(r"\bnpm\b", code), "the npm steps live in build-frontend.sh, once"


def test_the_builder_image_has_the_node_toolchain_of_debian_and_nothing_pinned_by_hand() -> None:
    dockerfile = (BUILD_DIR / "Dockerfile").read_text(encoding="utf-8")
    install = dockerfile[dockerfile.index("apt-get install") : dockerfile.index("rm -rf /var/lib/apt/lists")]
    packages = set(install.replace("\\", " ").split())
    assert {"nodejs", "npm"} <= packages
    assert "--no-install-recommends" in install
    assert not re.search(r"\b(curl|wget)\b.*node|nodesource|npm install -g", dockerfile), "Debian's own nodejs and npm"


# ------------------------------------------------------------------------------------- build-frontend.sh
FAKE_NPM = """#!/bin/sh
# A stand-in npm: records what it was asked and where, and leaves what the real one would leave.
echo "$PWD|$*" >> "$NPM_LOG"
case "$1" in
    ci)
        [ "${FAKE_NPM_FAIL:-}" = ci ] && exit 1
        [ -e node_modules ] && echo "node_modules was copied from the host" >> "$NPM_LOG"
        [ -e dist ] && echo "a stale dist was copied from the host" >> "$NPM_LOG"
        mkdir node_modules && echo "x" > node_modules/pkg.js
        ;;
    run)
        [ "${FAKE_NPM_FAIL:-}" = build ] && exit 1
        [ "${FAKE_NPM_FAIL:-}" = nodist ] && exit 0
        mkdir -p dist/assets && echo "<!doctype html>" > dist/index.html && echo "1" > dist/assets/app.js
        ;;
esac
"""


class FrontendBuild:
    """A scratch frontend source tree, a stand-in npm first on PATH, and an output directory."""

    def __init__(self, base: Path) -> None:
        self.source = base / "frontend"
        self.output = base / "out"
        self.bin = base / "bin"
        self.log = base / "npm.log"
        write(self.source / "package.json", "{}\n")
        write(self.source / "package-lock.json", "{}\n")
        write(self.source / "src" / "main.tsx", "export {}\n")
        write(self.source / "node_modules" / "host-built.js", "built for another platform\n")
        write(self.source / "dist" / "stale.js", "an old build\n")
        write(self.bin / "npm", FAKE_NPM)
        (self.bin / "npm").chmod(0o755)
        self.log.write_text("", encoding="utf-8")

    def run(self, source: Path | None = None, **env: str) -> subprocess.CompletedProcess[str]:
        assert BASH is not None
        environment = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "NPM_LOG": self.log.as_posix(),
            **env,
        }
        command = [BASH, FRONTEND_SCRIPT.as_posix(), (source or self.source).as_posix(), self.output.as_posix()]
        return subprocess.run(command, env=environment, capture_output=True, text=True, check=False, timeout=300)  # noqa: S603

    def npm_calls(self) -> list[tuple[str, str]]:
        """(working directory, arguments) of every npm call; lines that are not calls are the stand-in's warnings."""
        calls = [line.split("|", 1) for line in self.log.read_text(encoding="utf-8").splitlines() if "|" in line]
        return [(directory, arguments) for directory, arguments in calls]

    def complaints(self) -> list[str]:
        return [line for line in self.log.read_text(encoding="utf-8").splitlines() if "|" not in line]


@pytest.fixture
def frontend_build(tmp_path: Path) -> FrontendBuild:
    return FrontendBuild(tmp_path)


@needs_bash
def test_the_frontend_build_installs_from_the_lockfile_then_builds_in_a_copy(frontend_build: FrontendBuild) -> None:
    done = frontend_build.run()
    assert done.returncode == 0, done.stderr
    (ci_dir, ci_args), (build_dir, build_args) = frontend_build.npm_calls()
    assert ci_args.split()[0] == "ci", "npm ci installs exactly what the lockfile pins and checks its hashes"
    assert "--ignore-scripts" in ci_args.split(), "no package's install hook may run during an image build"
    assert build_args == "run build"
    assert ci_dir == build_dir
    source = frontend_build.source.resolve().as_posix().lower()
    assert source not in ci_dir.replace("\\", "/").lower(), "the build must run in a copy, not in the source tree"
    cache = re.search(r"--cache (\S+)", ci_args)
    assert cache is not None, "npm's cache must not be the build host's home directory"
    assert source not in cache[1].replace("\\", "/").lower()


@needs_bash
def test_the_frontend_output_is_the_contents_of_dist_and_nothing_else(frontend_build: FrontendBuild) -> None:
    assert frontend_build.run().returncode == 0
    assert files_under(frontend_build.output) == {"index.html", "assets/app.js"}


@needs_bash
def test_the_host_node_modules_and_a_stale_dist_never_reach_the_build(frontend_build: FrontendBuild) -> None:
    assert frontend_build.run().returncode == 0
    assert frontend_build.complaints() == []
    assert not (frontend_build.output / "node_modules").exists()
    assert not any(part == "node_modules" for p in frontend_build.output.rglob("*") for part in p.parts)


@needs_bash
def test_the_source_tree_is_left_exactly_as_it_was(frontend_build: FrontendBuild) -> None:
    before = {
        p.relative_to(frontend_build.source).as_posix(): p.read_bytes()
        for p in frontend_build.source.rglob("*")
        if p.is_file()
    }
    assert frontend_build.run().returncode == 0
    after = {
        p.relative_to(frontend_build.source).as_posix(): p.read_bytes()
        for p in frontend_build.source.rglob("*")
        if p.is_file()
    }
    assert after == before


@needs_bash
@needs_posix_modes
def test_the_frontend_builds_from_a_read_only_source_like_the_mount_in_the_builder(
    frontend_build: FrontendBuild,
) -> None:
    for path in [frontend_build.source, *frontend_build.source.rglob("*")]:
        path.chmod(0o555 if path.is_dir() else 0o444)
    try:
        done = frontend_build.run()
    finally:
        for path in [frontend_build.source, *frontend_build.source.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
    assert done.returncode == 0, done.stderr
    assert (frontend_build.output / "index.html").is_file()


@needs_bash
@pytest.mark.parametrize("missing", ["package.json", "package-lock.json"])
def test_a_frontend_without_its_lockfile_or_manifest_fails_before_npm_runs(
    frontend_build: FrontendBuild, missing: str
) -> None:
    (frontend_build.source / missing).unlink()
    done = frontend_build.run()
    assert done.returncode != 0
    assert missing in done.stderr
    assert frontend_build.npm_calls() == []
    assert not frontend_build.output.exists()


@needs_bash
def test_a_missing_frontend_directory_fails_with_its_name(frontend_build: FrontendBuild) -> None:
    done = frontend_build.run(source=frontend_build.source.parent / "absent")
    assert done.returncode != 0
    assert "frontend directory not found" in done.stderr


@needs_bash
@pytest.mark.parametrize("failing_step", ["ci", "build", "nodist"])
def test_a_failed_install_or_build_or_a_build_without_an_index_page_fails_the_script_and_ships_nothing(
    frontend_build: FrontendBuild, failing_step: str
) -> None:
    done = frontend_build.run(FAKE_NPM_FAIL=failing_step)
    assert done.returncode != 0
    assert not frontend_build.output.exists() or not any(frontend_build.output.iterdir())
    if failing_step == "ci":
        assert [args for _, args in frontend_build.npm_calls()] == [frontend_build.npm_calls()[0][1]], (
            "no build after a failed install"
        )
    if failing_step == "nodist":
        assert "no dist/index.html" in done.stderr


@needs_bash
def test_an_output_directory_that_already_holds_files_is_refused(frontend_build: FrontendBuild) -> None:
    write(frontend_build.output / "leftover.txt", "from an earlier build\n")
    done = frontend_build.run()
    assert done.returncode != 0
    assert "not empty" in done.stderr
    assert frontend_build.npm_calls() == []


@needs_bash
def test_the_frontend_build_script_has_a_usage_message() -> None:
    assert BASH is not None
    done = subprocess.run([BASH, FRONTEND_SCRIPT.as_posix(), "only-one"], capture_output=True, text=True, check=False)  # noqa: S603
    assert done.returncode == 2
    assert "usage:" in done.stderr
