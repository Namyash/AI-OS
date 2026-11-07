"""End to end: `python -m backend` as a real process serving real HTTP over a real socket."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from backend.core.exit_codes import EXIT_STARTUP_FAILED

REPO_ROOT = Path(__file__).resolve().parents[3]
STARTUP_TIMEOUT_SECONDS = 30

pytestmark = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="python -m backend refuses to run as root, so this test must run as an unprivileged user",
)


@dataclass
class RunningServer:
    url: str
    port: int
    token: str
    stdout_path: Path

    def headers(self, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", **extra}

    def stdout(self) -> str:
        return self.stdout_path.read_text(encoding="utf-8", errors="replace")


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _launch(
    root: Path, port: int, host: str, data_dir: Path | None = None
) -> tuple[subprocess.Popen[bytes], Path, Path, Path]:
    """Start ``python -m backend`` on ``host:port`` with state under ``root``; return the process and its files."""
    token_file = root / "run" / "token"
    stdout_path, stderr_path = root / "stdout.log", root / "stderr.log"
    environment = {
        **os.environ,
        "PAI_HOST": host,
        "PAI_PORT": str(port),
        "PAI_DATA_DIR": str(data_dir or root / "state"),
        "PAI_TOKEN_FILE": str(token_file),
        "PAI_LOG_LEVEL": "info",
    }
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        process = subprocess.Popen(  # fixed argv, no shell
            [sys.executable, "-m", "backend"], cwd=REPO_ROOT, env=environment, stdout=out, stderr=err
        )
    return process, token_file, stdout_path, stderr_path


def _stop(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _base_url(host: str, port: int) -> str:
    return f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"


@contextmanager
def running_server(root: Path, host: str = "127.0.0.1") -> Iterator[RunningServer]:
    """``python -m backend`` as a real process, yielded once an authenticated /health answers over a real socket."""
    port = _free_loopback_port()
    process, token_file, stdout_path, stderr_path = _launch(root, port, host)
    try:
        url = _base_url(host, port)
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while True:
            if process.poll() is not None:
                pytest.fail(f"server exited early ({process.returncode}): {stderr_path.read_text(errors='replace')}")
            if time.monotonic() > deadline:
                pytest.fail(f"server did not become ready: {stdout_path.read_text(errors='replace')}")
            if token_file.exists():
                token = token_file.read_text(encoding="ascii")
                try:
                    if httpx.get(f"{url}/health", headers={"Authorization": f"Bearer {token}"}).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
            time.sleep(0.2)
        yield RunningServer(url, port, token, stdout_path)
    finally:
        _stop(process)


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningServer]:
    with running_server(tmp_path_factory.mktemp("server")) as running:
        yield running


def test_health_over_a_real_socket(server: RunningServer) -> None:
    response = httpx.get(f"{server.url}/health", headers=server.headers())
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert isinstance(body["schema_version"], int) and body["schema_version"] >= 1


def test_unauthenticated_requests_are_refused_over_a_real_socket(server: RunningServer) -> None:
    response = httpx.get(f"{server.url}/health")
    assert response.status_code == 401
    assert response.json() == {"error": {"code": "unauthorized", "message": "Authentication required"}}


def test_dns_rebinding_is_refused_over_a_real_socket(server: RunningServer) -> None:
    response = httpx.get(f"{server.url}/health", headers=server.headers(Host=f"evil.example:{server.port}"))
    assert response.status_code == 400


def test_cross_origin_is_refused_over_a_real_socket(server: RunningServer) -> None:
    response = httpx.get(f"{server.url}/health", headers=server.headers(Origin="http://evil.example"))
    assert response.status_code == 403


def test_interactive_docs_are_not_served(server: RunningServer) -> None:
    assert httpx.get(f"{server.url}/docs", headers=server.headers()).status_code == 404


def test_the_server_does_not_announce_itself(server: RunningServer) -> None:
    response = httpx.get(f"{server.url}/health", headers=server.headers())
    assert "server" not in response.headers


def test_logs_are_json_lines_and_never_contain_the_token_or_request_lines(server: RunningServer) -> None:
    httpx.get(f"{server.url}/health", headers=server.headers())
    httpx.get(f"{server.url}/health", headers={"Authorization": "Bearer wrong-token-value-1234"})
    lines = [line for line in server.stdout().splitlines() if line.strip()]
    assert lines, "the server logged nothing"
    records = [json.loads(line) for line in lines]  # every line must parse
    assert any(r["message"] == "backend started" for r in records)
    assert all({"ts", "level", "logger", "message"} <= r.keys() for r in records)
    output = server.stdout()
    assert server.token not in output
    assert "wrong-token-value-1234" not in output
    assert "GET /health" not in output, "the access log must be off"
    assert "color_message" not in output


# ------------------------------------------------------------------ the listening socket
def _skip_unless_bindable(host: str) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, 0))
        except OSError:
            pytest.skip(f"this machine cannot bind {host}")


@pytest.mark.parametrize("host", ["127.0.0.2", "::1"])
def test_every_accepted_bind_address_answers_requests_made_to_it(tmp_path: Path, host: str) -> None:
    # config accepts all of 127.0.0.0/8 and ::1; the Host allowlist must follow, or the service would be up and
    # refuse every honest request (the readiness poll in running_server fails on the first 400).
    _skip_unless_bindable(host)
    with running_server(tmp_path, host) as running:
        assert httpx.get(f"{running.url}/health", headers=running.headers()).status_code == 200


def test_a_taken_port_stops_the_service_before_any_token_is_published(tmp_path: Path) -> None:
    port = _free_loopback_port()
    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows: without it uvicorn's SO_REUSEADDR could share the port
        squatter.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    with squatter:
        squatter.bind(("127.0.0.1", port))
        squatter.listen()
        process, token_file, stdout_path, _stderr_path = _launch(tmp_path, port, "127.0.0.1")
        try:
            returncode = process.wait(timeout=STARTUP_TIMEOUT_SECONDS)
        finally:
            _stop(process)
    assert returncode == EXIT_STARTUP_FAILED
    assert not token_file.exists(), "a token must not exist for an instance that does not hold the port"
    assert "backend started" not in stdout_path.read_text(encoding="utf-8", errors="replace")


def test_a_failed_startup_exits_with_the_startup_failure_status_and_publishes_no_token(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where the data directory's parent should be")
    process, token_file, stdout_path, _stderr_path = _launch(
        tmp_path, _free_loopback_port(), "127.0.0.1", blocker / "data"
    )
    try:
        returncode = process.wait(timeout=STARTUP_TIMEOUT_SECONDS)
    finally:
        _stop(process)
    assert returncode == EXIT_STARTUP_FAILED
    assert not token_file.exists()
    assert "refusing to start" in stdout_path.read_text(encoding="utf-8", errors="replace")
