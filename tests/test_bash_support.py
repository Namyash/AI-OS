"""Fast tests for the bash lookup used by the script tests (no real shell is started)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from tests import bash_support
from tests.bash_support import bash_candidates, find_working_bash


def _fake_bash(directory: Path) -> str:
    """An empty file that `shutil.which` accepts as `bash` on this platform; it is never executed.

    Returned normalised, because `shutil.which` on Windows reports the extension in the case PATHEXT spells it.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ("bash.exe" if sys.platform == "win32" else "bash")
    path.write_bytes(b"")
    path.chmod(0o755)
    return os.path.normcase(str(path))


def _found(dirs: list[Path]) -> list[str]:
    return [os.path.normcase(candidate) for candidate in bash_candidates([str(d) for d in dirs])]


def test_every_bash_on_path_is_a_candidate_in_path_order(tmp_path: Path) -> None:
    first, second = _fake_bash(tmp_path / "a"), _fake_bash(tmp_path / "b")
    assert _found([tmp_path / "a", tmp_path / "empty", tmp_path / "b"]) == [first, second]


def test_a_directory_listed_twice_gives_one_candidate(tmp_path: Path) -> None:
    only = _fake_bash(tmp_path / "a")
    assert _found([tmp_path / "a", tmp_path / "a"]) == [only]


def test_no_bash_anywhere_gives_no_candidate_and_no_bash(tmp_path: Path) -> None:
    assert list(bash_candidates([str(tmp_path)])) == []
    assert find_working_bash([str(tmp_path)]) is None


def test_a_broken_first_bash_does_not_hide_a_working_second_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The WSL-launcher case: the first `bash` on PATH fails every command, a later one works."""
    _fake_bash(tmp_path / "system32")
    working = _fake_bash(tmp_path / "git")
    monkeypatch.setattr(bash_support, "runs", lambda candidate: os.path.normcase(candidate) == working)
    found = find_working_bash([str(tmp_path / "system32"), str(tmp_path / "git")])
    assert found is not None
    assert os.path.normcase(found) == working


def test_the_first_working_bash_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first = _fake_bash(tmp_path / "a")
    _fake_bash(tmp_path / "b")
    monkeypatch.setattr(bash_support, "runs", lambda candidate: True)
    found = find_working_bash([str(tmp_path / "a"), str(tmp_path / "b")])
    assert found is not None
    assert os.path.normcase(found) == first


def test_when_every_bash_is_broken_there_is_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_bash(tmp_path / "a")
    monkeypatch.setattr(bash_support, "runs", lambda candidate: False)
    assert find_working_bash([str(tmp_path / "a")]) is None


def test_a_candidate_that_cannot_be_started_does_not_run(tmp_path: Path) -> None:
    not_executable = tmp_path / "bash"
    not_executable.write_bytes(b"")
    not_executable.chmod(0o644)
    assert bash_support.runs(str(not_executable)) is False


def test_a_real_shell_is_recognised_as_running() -> None:
    real = find_working_bash()
    if real is None:
        pytest.skip("no working bash on this machine")
    assert os.path.isfile(real)
    assert bash_support.runs(real) is True
