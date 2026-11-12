"""Settings: the backend's own variables and defaults are honoured, bad values are named, nothing waits unbounded."""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

import pytest

from kiosk import config
from kiosk.config import Settings, load_settings
from kiosk.errors import EXIT_CONFIG, ConfigError

REPO = Path(__file__).resolve().parents[2]
BACKEND_CONFIG = REPO / "backend" / "core" / "config.py"
BACKEND_EXIT_CODES = REPO / "backend" / "core" / "exit_codes.py"


def explicit(tmp_path: Path, **overrides: str) -> dict[str, str]:
    """A complete, valid environment (absolute paths of this host), so a test can change one thing."""
    base = {
        "PAI_ENDPOINT_FILE": str(tmp_path / "endpoint"),
        "PAI_TOKEN_FILE": str(tmp_path / "token"),
        "PAI_KIOSK_READY_FILE": str(tmp_path / "ready"),
        "PAI_KIOSK_PROFILE_DIR": str(tmp_path / "profile"),
    }
    return {**base, **overrides}


def backend_constant(name: str) -> str:
    """A ``NAME = Path("...")`` constant of the backend's settings module, read without importing the backend."""
    for node in ast.parse(BACKEND_CONFIG.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            call = node.value
            assert isinstance(call, ast.Call)
            argument = call.args[0]
            assert isinstance(argument, ast.Constant)
            return str(argument.value)
    raise AssertionError(f"{name} is not defined in {BACKEND_CONFIG}")


def test_the_endpoint_and_token_defaults_are_the_backends_own() -> None:
    # The launcher reads what the backend publishes: one default, in the backend, and the launcher must agree with it.
    assert config.DEFAULT_ENDPOINT_FILE.as_posix() == backend_constant("DEFAULT_ENDPOINT_FILE")
    assert config.DEFAULT_TOKEN_FILE.as_posix() == backend_constant("DEFAULT_TOKEN_FILE")


def test_the_config_exit_status_is_the_backends() -> None:
    backend_value = re.search(r"^EXIT_CONFIG = (\d+)", BACKEND_EXIT_CODES.read_text(encoding="utf-8"), re.MULTILINE)
    assert backend_value is not None
    assert int(backend_value[1]) == EXIT_CONFIG


@pytest.mark.skipif(os.name != "posix", reason="the defaults are POSIX paths: not absolute on this platform")
def test_every_default_is_valid_on_the_image() -> None:
    settings = load_settings({})
    assert settings.chromium == config.DEFAULT_CHROMIUM
    assert settings.chromium_flags == ()
    assert settings.handoff_timeout == config.DEFAULT_HANDOFF_TIMEOUT
    assert settings.status_interval == config.DEFAULT_STATUS_INTERVAL


def test_explicit_values_are_used(tmp_path: Path) -> None:
    environ = explicit(
        tmp_path,
        PAI_KIOSK_CHROMIUM="/opt/browser/chrome",
        PAI_KIOSK_CHROMIUM_FLAGS="--one --two='a b'",
        PAI_KIOSK_HANDOFF_TIMEOUT="12.5",
        PAI_KIOSK_REQUEST_TIMEOUT="3",
        PAI_KIOSK_BROWSER_TIMEOUT="4",
        PAI_KIOSK_RENDER_TIMEOUT="5",
        PAI_KIOSK_STATUS_INTERVAL="0.5",
        PAI_PORT="9999",  # a backend variable: not the launcher's business
        PAI_SNAPSHOT="20251101T000000Z",  # an ISO build input
    )
    settings = load_settings(environ)
    assert settings == Settings(
        endpoint_file=tmp_path / "endpoint",
        token_file=tmp_path / "token",
        ready_file=tmp_path / "ready",
        profile_dir=tmp_path / "profile",
        chromium="/opt/browser/chrome",
        chromium_flags=("--one", "--two=a b"),
        handoff_timeout=12.5,
        request_timeout=3.0,
        browser_timeout=4.0,
        render_timeout=5.0,
        status_interval=0.5,
    )


@pytest.mark.parametrize(
    "variable",
    ["PAI_ENDPOINT_FILE", "PAI_TOKEN_FILE", "PAI_KIOSK_READY_FILE", "PAI_KIOSK_PROFILE_DIR"],
)
def test_a_relative_path_is_refused_by_name(tmp_path: Path, variable: str) -> None:
    with pytest.raises(ConfigError, match=rf"{variable}: must be an absolute path"):
        load_settings(explicit(tmp_path, **{variable: "relative/path"}))


@pytest.mark.parametrize(
    "variable",
    [
        "PAI_KIOSK_HANDOFF_TIMEOUT",
        "PAI_KIOSK_REQUEST_TIMEOUT",
        "PAI_KIOSK_BROWSER_TIMEOUT",
        "PAI_KIOSK_RENDER_TIMEOUT",
        "PAI_KIOSK_STATUS_INTERVAL",
    ],
)
@pytest.mark.parametrize("bad", ["abc", "", "0", "-1", "nan", "inf", "-inf", "3601", "1e9"])
def test_a_timeout_that_is_not_a_bounded_positive_number_is_refused_by_name(
    tmp_path: Path, variable: str, bad: str
) -> None:
    with pytest.raises(ConfigError, match=rf"{variable}: "):
        load_settings(explicit(tmp_path, **{variable: bad}))


def test_every_problem_is_reported_at_once(tmp_path: Path) -> None:
    environ = explicit(
        tmp_path,
        PAI_TOKEN_FILE="relative",  # noqa: S106 - a path, not a credential
        PAI_KIOSK_CHROMIUM=" ",
        PAI_KIOSK_CHROMIUM_FLAGS="--unbalanced='quote",
        PAI_KIOSK_RENDER_TIMEOUT="0",
    )
    with pytest.raises(ConfigError) as caught:
        load_settings(environ)
    message = str(caught.value)
    for variable in ("PAI_TOKEN_FILE", "PAI_KIOSK_CHROMIUM:", "PAI_KIOSK_CHROMIUM_FLAGS", "PAI_KIOSK_RENDER_TIMEOUT"):
        assert variable in message
    assert caught.value.exit_code == EXIT_CONFIG


def test_settings_cannot_be_changed_after_they_are_loaded(tmp_path: Path) -> None:
    settings = load_settings(explicit(tmp_path))
    with pytest.raises(AttributeError):
        settings.chromium = "other"  # type: ignore[misc]
