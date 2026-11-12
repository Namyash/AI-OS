"""`python -m backend`: refuses root, rejects bad configuration, and starts uvicorn with the hardened options."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from backend import __main__ as entrypoint
from backend.core.config import Settings
from backend.core.exit_codes import EXIT_CONFIG, EXIT_REFUSED_ROOT, EXIT_STARTUP_FAILED


class FakeListener:
    """The pre-bound socket, recording what the entrypoint does with it."""

    def __init__(self, events: list[str]) -> None:
        self.events = events

    def listen(self, backlog: int) -> None:
        self.events.append(f"listen:{backlog}")


class UvicornSpy:
    """Stands in for uvicorn's Config and Server so the options the entrypoint passes, and the order in which it
    binds, listens and serves, can be inspected without opening a socket."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.configs: list[tuple[object, dict[str, object]]] = []
        self.served_sockets: list[object] = []
        self.started = True  # what the pretend server reports once run() returns
        self.bind_exit_status: int | None = None  # set to make binding fail the way uvicorn's does
        self.listener = FakeListener(self.events)

    def config(self, app: object, **options: object) -> SimpleNamespace:
        self.configs.append((app, options))
        return SimpleNamespace(backlog=2048, bind_socket=self._bind)

    def _bind(self) -> FakeListener:
        self.events.append("bind")
        if self.bind_exit_status is not None:
            raise SystemExit(self.bind_exit_status)  # what uvicorn does when the address is taken
        return self.listener

    def server(self, _config: object) -> SimpleNamespace:
        spy = self

        def run(sockets: list[object]) -> None:
            spy.events.append("run")
            spy.served_sockets.extend(sockets)

        return SimpleNamespace(run=run, started=self.started)


@pytest.fixture
def uvicorn_spy(monkeypatch: pytest.MonkeyPatch) -> UvicornSpy:
    spy = UvicornSpy()
    monkeypatch.setattr(entrypoint.uvicorn, "Config", spy.config)
    monkeypatch.setattr(entrypoint.uvicorn, "Server", spy.server)
    return spy


@pytest.fixture
def configured_logging(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    levels: list[str] = []
    monkeypatch.setattr(entrypoint, "configure_logging", levels.append)
    return levels


def _pretend_euid(monkeypatch: pytest.MonkeyPatch, euid: int) -> None:
    # raising=False: os.geteuid does not exist on Windows, and the entrypoint must cope with that too.
    monkeypatch.setattr(os, "geteuid", lambda: euid, raising=False)


def _environment(tmp_path: Path, **extra: str) -> dict[str, str]:
    return {
        "PAI_DATA_DIR": str(tmp_path / "state"),
        "PAI_TOKEN_FILE": str(tmp_path / "run" / "token"),
        "PAI_ENDPOINT_FILE": str(tmp_path / "run" / "endpoint"),
        "PAI_STATIC_DIR": str(tmp_path / "ui"),
        **extra,
    }


# ------------------------------------------------------------------ root refusal
def test_refuses_to_run_as_root(
    monkeypatch: pytest.MonkeyPatch,
    uvicorn_spy: UvicornSpy,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _pretend_euid(monkeypatch, 0)
    assert entrypoint.main(_environment(tmp_path)) == EXIT_REFUSED_ROOT
    assert "refusing to run as root" in capsys.readouterr().err
    assert uvicorn_spy.configs == []
    assert not (tmp_path / "state").exists(), "nothing may be created before the root check"


def test_there_is_no_override_for_the_root_refusal(
    monkeypatch: pytest.MonkeyPatch, uvicorn_spy: UvicornSpy, tmp_path: Path
) -> None:
    _pretend_euid(monkeypatch, 0)
    environment = _environment(tmp_path, PAI_ALLOW_ROOT="1", PAI_FORCE="yes", ALLOW_ROOT="1")
    assert entrypoint.main(environment) == EXIT_REFUSED_ROOT
    assert uvicorn_spy.configs == []


def test_the_root_check_is_skipped_only_where_the_platform_has_no_euid(
    monkeypatch: pytest.MonkeyPatch, uvicorn_spy: UvicornSpy, configured_logging: list[str], tmp_path: Path
) -> None:
    monkeypatch.delattr(os, "geteuid", raising=False)
    assert entrypoint.main(_environment(tmp_path)) == 0
    assert len(uvicorn_spy.configs) == 1


# ------------------------------------------------------------------ configuration errors
def test_invalid_configuration_exits_with_a_message_naming_the_variable(
    monkeypatch: pytest.MonkeyPatch,
    uvicorn_spy: UvicornSpy,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _pretend_euid(monkeypatch, 1000)
    assert entrypoint.main(_environment(tmp_path, PAI_HOST="0.0.0.0")) == EXIT_CONFIG  # noqa: S104
    assert "PAI_HOST" in capsys.readouterr().err
    assert uvicorn_spy.configs == []


# ------------------------------------------------------------------ the uvicorn invocation
def test_uvicorn_is_started_with_the_hardened_options(
    monkeypatch: pytest.MonkeyPatch, uvicorn_spy: UvicornSpy, configured_logging: list[str], tmp_path: Path
) -> None:
    _pretend_euid(monkeypatch, 1000)
    environment = _environment(tmp_path, PAI_HOST="::1", PAI_PORT="9001", PAI_LOG_LEVEL="warning")
    assert entrypoint.main(environment) == 0

    ((app, options),) = uvicorn_spy.configs
    assert isinstance(app, FastAPI)
    assert options == {
        "host": "::1",
        "port": 9001,
        "workers": 1,
        "reload": False,
        "lifespan": "on",
        "ws": "none",
        "server_header": False,
        "proxy_headers": False,
        "access_log": False,
        "log_config": None,
        "log_level": "warning",
    }
    assert configured_logging == ["warning"]


def test_the_app_it_serves_is_built_from_the_loaded_settings(
    monkeypatch: pytest.MonkeyPatch, uvicorn_spy: UvicornSpy, configured_logging: list[str], tmp_path: Path
) -> None:
    _pretend_euid(monkeypatch, 1000)
    built: list[Settings] = []
    real_create_app = entrypoint.create_app
    monkeypatch.setattr(
        entrypoint, "create_app", lambda settings: (built.append(settings), real_create_app(settings))[1]
    )
    entrypoint.main(_environment(tmp_path, PAI_PORT="9002"))
    assert [s.port for s in built] == [9002]


# ------------------------------------------------------------------ the listening socket and the exit status
def test_the_port_is_bound_and_listening_before_the_application_starts(
    monkeypatch: pytest.MonkeyPatch, uvicorn_spy: UvicornSpy, configured_logging: list[str], tmp_path: Path
) -> None:
    # Startup publishes the token, so the listener must already be ours when it runs.
    _pretend_euid(monkeypatch, 1000)
    assert entrypoint.main(_environment(tmp_path)) == 0
    assert uvicorn_spy.events == ["bind", "listen:2048", "run"]
    assert uvicorn_spy.served_sockets == [uvicorn_spy.listener]


def test_a_server_that_never_started_is_not_a_clean_exit(
    monkeypatch: pytest.MonkeyPatch, uvicorn_spy: UvicornSpy, configured_logging: list[str], tmp_path: Path
) -> None:
    _pretend_euid(monkeypatch, 1000)
    uvicorn_spy.started = False  # for example the lifespan startup raised
    assert entrypoint.main(_environment(tmp_path)) == EXIT_STARTUP_FAILED


def test_a_port_that_cannot_be_bound_is_a_startup_failure_and_nothing_is_served(
    monkeypatch: pytest.MonkeyPatch, uvicorn_spy: UvicornSpy, configured_logging: list[str], tmp_path: Path
) -> None:
    _pretend_euid(monkeypatch, 1000)
    uvicorn_spy.bind_exit_status = 1  # uvicorn 0.32 (Debian trixie) exits 1 here, newer versions 3
    assert entrypoint.main(_environment(tmp_path)) == EXIT_STARTUP_FAILED
    assert uvicorn_spy.events == ["bind"], "the application must not start when the port is not ours"
