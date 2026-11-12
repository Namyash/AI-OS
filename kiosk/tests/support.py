"""A launcher environment for tests: a fake backend, a fake browser, and the real launcher run as a subprocess.

The launcher runs as ``python -m kiosk`` in its own process, as it does on the image, so what is tested is the
shipped entry point: its exit status, its log, its signal handling and the files it writes.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from kiosk.tests.fake_backend import FakeBackend

REPO = Path(__file__).resolve().parents[2]
FAKE_BROWSER = Path(__file__).with_name("fake_chromium.py")
posix_only = pytest.mark.skipif(os.name != "posix", reason="starts a browser with inherited descriptors: POSIX only")

# Short bounds so a failure path takes a second or two, long enough that a healthy run never trips them.
FAST_TIMEOUTS = {
    "PAI_KIOSK_HANDOFF_TIMEOUT": "2",
    "PAI_KIOSK_REQUEST_TIMEOUT": "3",
    "PAI_KIOSK_BROWSER_TIMEOUT": "3",
    "PAI_KIOSK_RENDER_TIMEOUT": "3",
    "PAI_KIOSK_STATUS_INTERVAL": "0.3",
}


def wait_until(condition: Callable[[], Any], timeout: float = 15.0, what: str = "the condition") -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if value := condition():
            return value
        time.sleep(0.05)
    raise AssertionError(f"timed out after {timeout:g} s waiting for {what}")


@dataclass
class Run:
    """One launcher process."""

    process: subprocess.Popen[bytes]
    stderr_path: Path

    def wait(self, timeout: float = 20.0) -> int:
        return self.process.wait(timeout=timeout)

    def stop(self) -> int:
        self.process.send_signal(signal.SIGTERM)
        return self.wait()

    @property
    def log(self) -> str:
        return self.stderr_path.read_text(encoding="utf-8", errors="replace")


@dataclass
class Rig:
    root: Path
    backend: FakeBackend
    mode: str = "ok"
    after: int = 0
    extra_env: dict[str, str] = field(default_factory=dict)
    runs: list[Run] = field(default_factory=list)

    # ------------------------------------------------------------------ files
    @property
    def endpoint_file(self) -> Path:
        return self.root / "run" / "endpoint"

    @property
    def token_file(self) -> Path:
        return self.root / "run" / "token"

    @property
    def ready_file(self) -> Path:
        return self.root / "ui-run" / "ready"

    @property
    def profile_dir(self) -> Path:
        return self.root / "state" / "profile"

    @property
    def browser_log(self) -> Path:
        return self.root / "browser.log"

    def publish(self, endpoint: str | None = None, token: str | None = None) -> None:
        """What the backend does once its socket is bound."""
        self.endpoint_file.parent.mkdir(parents=True, exist_ok=True)
        self.endpoint_file.write_text(self.backend.origin if endpoint is None else endpoint, encoding="ascii")
        self.token_file.write_text(self.backend.token if token is None else token, encoding="ascii")

    def browser_wrapper(self) -> Path:
        wrapper = self.root / "fake-chromium"
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_BROWSER}" "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
        return wrapper

    # ------------------------------------------------------------------ the launcher
    def environment(self, **overrides: str) -> dict[str, str]:
        (self.root / "state").mkdir(exist_ok=True)
        (self.root / "state").chmod(0o700)
        flags = f"--fake-mode={self.mode} --fake-after={self.after} --fake-log={self.browser_log}"
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(REPO),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PAI_ENDPOINT_FILE": str(self.endpoint_file),
            "PAI_TOKEN_FILE": str(self.token_file),
            "PAI_KIOSK_READY_FILE": str(self.ready_file),
            "PAI_KIOSK_PROFILE_DIR": str(self.profile_dir),
            "PAI_KIOSK_CHROMIUM": str(self.browser_wrapper()),
            "PAI_KIOSK_CHROMIUM_FLAGS": flags,
            **FAST_TIMEOUTS,
            **self.extra_env,
            **overrides,
        }
        return env

    def launch(self, **overrides: str) -> Run:
        stderr_path = self.root / f"launcher-{len(self.runs)}.log"
        with stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                [sys.executable, "-s", "-m", "kiosk"],
                env=self.environment(**overrides),
                cwd=REPO,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
            )
        run = Run(process, stderr_path)
        self.runs.append(run)
        return run

    def launch_healthy(self, **overrides: str) -> Run:
        """Publish the backend's files, start the launcher and wait until it has reported the shell rendered."""
        self.publish()
        run = self.launch(**overrides)
        wait_until(lambda: self.ready_file.exists() or run.process.poll() is not None, what="the readiness file")
        assert self.ready_file.exists(), f"the launcher exited ({run.process.returncode}) first:\n{run.log}"
        return run

    def finish(self) -> None:
        for run in self.runs:
            if run.process.poll() is None:
                run.process.kill()
                run.process.wait()

    # ------------------------------------------------------------------ what happened
    def ready(self) -> dict[str, Any]:
        return json.loads(self.ready_file.read_text(encoding="utf-8"))

    def browser_entries(self, kind: str | None = None) -> list[dict[str, Any]]:
        if not self.browser_log.exists():
            return []
        lines = self.browser_log.read_text(encoding="utf-8").splitlines()
        entries = [json.loads(line) for line in lines]
        return [e for e in entries if kind is None or e["kind"] == kind]

    def commands(self, method: str) -> list[dict[str, Any]]:
        return [e for e in self.browser_entries("command") if e["method"] == method]
