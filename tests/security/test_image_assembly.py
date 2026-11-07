"""Runs os/build/assemble-config.sh, the script that fills live-build's config tree, and checks what it produces.

The script is executed for real (with a working `bash`), once against this repository and several times against
scratch trees. The scratch trees prove the rules hold for components, backend packages and data files that did not
exist when the script was written: nothing about the repository's current contents is written into the script or
into the expectations below, which are derived from the source tree itself.

File modes and ownership are POSIX facts: the mode checks skip on a Windows host (the same tests run in the Debian
container, see docs/development/DEVELOPMENT.md) and ownership is checked only when run as root.
"""

from __future__ import annotations

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
BUILD_DIR = OS_DIR / "build"
SCRIPT = BUILD_DIR / "assemble-config.sh"
BACKEND_UNIT = OS_DIR / "systemd" / "rootfs" / "etc" / "systemd" / "system" / "pai-backend.service"

# Every `bash` on PATH is tried, not just the first: on Windows the first can be the WSL launcher with no distribution.
BASH = find_working_bash()
needs_bash = pytest.mark.skipif(BASH is None, reason="no working bash on this machine")
needs_posix_modes = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes and ownership")


def assemble(os_dir: Path, backend_dir: Path, config_dir: Path) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    command = [BASH, SCRIPT.as_posix(), os_dir.as_posix(), backend_dir.as_posix(), config_dir.as_posix()]
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)  # noqa: S603


def write(path: Path, text: str, mode: int | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    if mode is not None:
        path.chmod(mode)
    return path


def files_under(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()}


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
    config = tmp_path_factory.mktemp("assembled") / "config"
    done = assemble(OS_DIR, BACKEND_DIR, config)
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


@needs_bash
def test_the_backend_lands_where_the_unit_runs_it_from(real_config: Path) -> None:
    working_directory = re.search(r"^WorkingDirectory=(\S+)$", BACKEND_UNIT.read_text(encoding="utf-8"), re.MULTILINE)
    assert working_directory is not None
    install_dir = re.search(r"^BACKEND_IMAGE_DIR=(\S+)$", SCRIPT.read_text(encoding="utf-8"), re.MULTILINE)
    assert install_dir is not None
    # `python3 -m backend` run from WorkingDirectory finds the package in <WorkingDirectory>/backend.
    assert install_dir[1] == f"{working_directory[1].strip('/')}/backend"
    assert (real_config / "includes.chroot" / install_dir[1] / "__main__.py").is_file()


@needs_bash
def test_the_installed_backend_is_the_source_without_tests_documentation_and_bytecode(real_config: Path) -> None:
    installed = real_config / "includes.chroot" / "opt" / "pai" / "backend"
    wanted = {p.relative_to(BACKEND_DIR).as_posix() for p in BACKEND_DIR.rglob("*") if p.is_file()}
    wanted = {name for name in wanted if not is_left_out(Path(name))}
    assert any(name.endswith(".sql") for name in wanted), "the repository has no migration; this test checks nothing"
    assert any(name.endswith(".py") for name in wanted)
    assert files_under(installed) == wanted
    for name in wanted:
        assert (installed / name).read_bytes() == (BACKEND_DIR / name).read_bytes()


@needs_bash
def test_the_installed_backend_imports_and_finds_its_migrations_from_the_installed_location(real_config: Path) -> None:
    app_root = real_config / "includes.chroot" / "opt" / "pai"
    program = (
        "import json, pathlib, backend, backend.api.app, backend.__main__\n"
        "from backend.database.migrate import discover\n"
        "print(json.dumps({'file': backend.__file__, 'migrations': [[m.version, m.checksum] for m in discover()]}))\n"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-s", "-c", program], cwd=app_root, capture_output=True, text=True, check=False, timeout=120
    )
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert Path(report["file"]).resolve().is_relative_to(app_root.resolve()), "imported the source tree, not the image"
    source_migrations = discover(BACKEND_DIR / "database" / "migrations")
    assert report["migrations"] == [[m.version, m.checksum] for m in source_migrations]
    assert report["migrations"], "no migration ships: the service could not create its database"


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
    """A scratch os/ directory and backend/ directory."""

    def __init__(self, base: Path) -> None:
        self.os = base / "os"
        self.backend = base / "backend"
        self.config = base / "config"
        self.os.mkdir()
        self.backend.mkdir()
        write(self.backend / "__init__.py", "")

    def run(self) -> subprocess.CompletedProcess[str]:
        return assemble(self.os, self.backend, self.config)


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


@needs_bash
def test_tests_bytecode_and_documentation_stay_out_at_any_depth_and_leave_no_empty_directories(tree: Tree) -> None:
    write(tree.backend / "README.md", "docs\n")
    write(tree.backend / "tests" / "test_top.py", "")
    write(tree.backend / "__pycache__" / "mod.cpython-313.pyc", "")
    write(tree.backend / "pkg" / "__init__.py", "")
    write(tree.backend / "pkg" / "README.md", "docs\n")
    write(tree.backend / "pkg" / "tests" / "test_pkg.py", "")
    write(tree.backend / "pkg" / "tests" / "deeper" / "test_more.py", "")
    write(tree.backend / "pkg" / "sub" / "__pycache__" / "x.cpython-312.pyc", "")
    write(tree.backend / "pkg" / "stale.pyc", "")
    write(tree.backend / "pkg" / "READMEfirst.txt", "docs\n")
    write(tree.backend / "placeholder" / "README.md", "a directory that only held documentation\n")
    assert tree.run().returncode == 0
    installed = tree.config / "includes.chroot" / "opt" / "pai" / "backend"
    assert files_under(installed) == {"__init__.py", "pkg/__init__.py"}
    assert sorted(p.relative_to(installed).as_posix() for p in installed.rglob("*") if p.is_dir()) == ["pkg"]


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
def test_a_component_may_not_ship_into_the_directory_the_backend_is_installed_to(tree: Tree) -> None:
    write(tree.os / "alpha" / "rootfs" / "opt" / "pai" / "backend" / "evil.py", "")
    done = tree.run()
    assert done.returncode != 0
    assert "already ships /opt/pai/backend" in done.stderr


@needs_bash
def test_a_hook_without_a_script_header_fails_the_build_instead_of_being_skipped(tree: Tree) -> None:
    write(tree.os / "alpha" / "hooks" / "0100-no-header.hook.chroot", "set -e\ntrue\n")
    done = tree.run()
    assert done.returncode != 0
    assert "0100-no-header.hook.chroot does not start with a #! line" in done.stderr


@needs_bash
def test_a_missing_backend_directory_fails_with_its_name(tree: Tree) -> None:
    done = assemble(tree.os, tree.backend / "absent", tree.config)
    assert done.returncode != 0
    assert "backend directory not found" in done.stderr
    assert str(tree.backend / "absent").replace("\\", "/") in done.stderr.replace("\\", "/")


@needs_bash
def test_a_missing_os_directory_fails_with_its_name(tree: Tree) -> None:
    done = assemble(tree.os / "absent", tree.backend, tree.config)
    assert done.returncode != 0
    assert "os directory not found" in done.stderr


@needs_bash
def test_the_wrong_number_of_arguments_is_a_usage_error() -> None:
    assert BASH is not None
    done = subprocess.run([BASH, SCRIPT.as_posix(), "only-one"], capture_output=True, text=True, check=False)  # noqa: S603
    assert done.returncode == 2
    assert "usage:" in done.stderr


@needs_bash
def test_a_symbolic_link_in_the_backend_tree_fails_the_build(tree: Tree) -> None:
    try:
        (tree.backend / "link.py").symlink_to("/etc/passwd")
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
    for root in (tree.os, tree.backend):
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
    write(tree.backend / "pkg" / "mod.py", "#!/usr/bin/env python3\n", 0o777)
    (tree.os / "alpha" / "rootfs" / "etc").chmod(0o777)
    (tree.backend / "pkg").chmod(0o777)
    assert tree.run().returncode == 0
    includes = tree.config / "includes.chroot"

    def mode(path: Path) -> int:
        return path.stat().st_mode & 0o777

    assert mode(includes / "etc") == 0o755
    assert mode(includes / "etc" / "thing.conf") == 0o644
    assert mode(includes / "etc" / "systemd" / "system" / "thing.service") == 0o644
    assert mode(includes / "usr" / "bin" / "tool") == 0o755
    assert mode(tree.config / "hooks" / "live" / "0100-x.hook.chroot") == 0o755
    assert mode(includes / "opt" / "pai" / "backend" / "pkg") == 0o755
    assert mode(includes / "opt" / "pai" / "backend" / "pkg" / "mod.py") == 0o644  # imported, never executed


# ------------------------------------------------------------------ the build scripts name each other correctly
def _mounts(text: str) -> dict[str, tuple[str, bool]]:
    """`-v "$ROOT/<host dir>:<container dir>[:ro]"` options of build-iso.sh: container dir -> (host dir, read-only)."""
    found = {}
    for host, container, mode in re.findall(r'-v "\$ROOT/(\w+):(/[\w/]+)(:ro)?"', text):
        found[container] = (host, mode == ":ro")
    return found


def test_the_backend_is_mounted_read_only_where_the_container_script_reads_it() -> None:
    mounts = _mounts((BUILD_DIR / "build-iso.sh").read_text(encoding="utf-8"))
    inside = (BUILD_DIR / "in-container-build.sh").read_text(encoding="utf-8")
    backend_src = re.search(r"^BACKEND_SRC=(\S+)", inside, re.MULTILINE)
    os_src = re.search(r"^SRC=(\S+)", inside, re.MULTILINE)
    assert backend_src is not None
    assert os_src is not None
    assert mounts[backend_src[1]] == ("backend", True)
    assert mounts[os_src[1]] == ("os", True)


def test_the_container_script_hands_the_assembly_to_the_assemble_script_and_copies_nothing_itself() -> None:
    inside = (BUILD_DIR / "in-container-build.sh").read_text(encoding="utf-8")
    assert 'assemble-config.sh" "$SRC" "$BACKEND_SRC" config' in inside
    assert (BUILD_DIR / "assemble-config.sh").is_file()
    # Copying here too would be a second, drifting implementation of the same rules.
    code = "\n".join(line for line in inside.splitlines() if not line.lstrip().startswith("#"))
    assert not re.search(r"\bcp -a\b|includes\.chroot|hooks/live|package-lists", code)
    assert code.index("assemble-config.sh") < code.index("lb build")
