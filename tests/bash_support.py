"""Finds a `bash` that actually runs, for the tests that execute shell scripts.

`shutil.which("bash")` returns only the first `bash` on PATH. On Windows that can be the WSL launcher in
C:\\Windows\\System32 with no distribution behind it, which fails every command, while a working Git Bash sits
further down PATH. Taking the first match would silently skip every test that needs bash depending on which shell
pytest was started from, so every `bash` on PATH is tried in order.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator, Sequence


def bash_candidates(path_dirs: Sequence[str] | None = None) -> Iterator[str]:
    """Every distinct `bash` executable found in `path_dirs` (default: the directories of PATH), in PATH order."""
    seen: set[str] = set()
    for directory in os.get_exec_path() if path_dirs is None else path_dirs:
        candidate = shutil.which("bash", path=directory)
        if candidate is not None and os.path.normcase(candidate) not in seen:
            seen.add(os.path.normcase(candidate))
            yield candidate


def runs(candidate: str) -> bool:
    """True when `candidate -c "exit 0"` succeeds, i.e. the shell starts and executes a command."""
    try:
        probe = subprocess.run([candidate, "-c", "exit 0"], capture_output=True, check=False, timeout=60)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


def find_working_bash(path_dirs: Sequence[str] | None = None) -> str | None:
    """The first `bash` on PATH that runs, or None when there is none."""
    return next((candidate for candidate in bash_candidates(path_dirs) if runs(candidate)), None)
