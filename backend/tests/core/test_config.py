"""Settings: defaults live in one place, hosts are loopback-only, and bad values fail loudly at load time."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.core.config import (
    DATA_DIR_MODE,
    DATABASE_FILENAME,
    DEFAULT_DATA_DIR,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TOKEN_FILE,
    ConfigError,
    Settings,
    load_settings,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="the default paths are Linux deployment paths")
not_posix = pytest.mark.skipif(os.name == "posix", reason="covers hosts where the Linux default paths are not absolute")


def _environment(tmp_path: Path, **extra: str) -> dict[str, str]:
    """Valid paths for this platform, so a test about one variable does not depend on the Linux defaults."""
    return {"PAI_DATA_DIR": str(tmp_path / "data"), "PAI_TOKEN_FILE": str(tmp_path / "run" / "token"), **extra}


def test_defaults_come_from_one_place() -> None:
    fields = Settings.model_fields
    assert fields["host"].default == DEFAULT_HOST == "127.0.0.1"
    assert fields["port"].default == DEFAULT_PORT
    assert fields["data_dir"].default == DEFAULT_DATA_DIR
    assert fields["token_file"].default == DEFAULT_TOKEN_FILE
    assert fields["log_level"].default == "info"


@posix_only
def test_unset_variables_give_the_linux_deployment_defaults() -> None:
    settings = load_settings({})
    assert settings == Settings()
    assert (settings.host, settings.port) == (DEFAULT_HOST, DEFAULT_PORT)
    assert (settings.data_dir, settings.token_file) == (DEFAULT_DATA_DIR, DEFAULT_TOKEN_FILE)
    assert settings.log_level == "info"


@not_posix
def test_linux_default_paths_are_refused_not_resolved_under_the_drive_root() -> None:
    # Path("/var/lib/pai") has no drive on Windows: left unchecked it would become a directory under the root of
    # whichever drive is current.
    with pytest.raises(ConfigError) as caught:
        load_settings({})
    assert "PAI_DATA_DIR" in str(caught.value)
    assert "PAI_TOKEN_FILE" in str(caught.value)


def test_a_default_is_validated_like_an_explicit_value() -> None:
    class Misconfigured(Settings):
        data_dir: Path = Path("relative/default")

    with pytest.raises(ValidationError, match="absolute"):
        Misconfigured()


def test_the_data_directory_is_private_to_the_service_account() -> None:
    assert DATA_DIR_MODE == 0o700


def test_database_path_is_derived_from_data_dir(tmp_path: Path) -> None:
    settings = load_settings(_environment(tmp_path))
    assert settings.database_path == tmp_path / "data" / DATABASE_FILENAME


def test_every_field_is_read_from_its_environment_variable(tmp_path: Path) -> None:
    settings = load_settings(
        {
            "PAI_HOST": "::1",
            "PAI_PORT": "9000",
            "PAI_DATA_DIR": str(tmp_path / "data"),
            "PAI_TOKEN_FILE": str(tmp_path / "run" / "token"),
            "PAI_LOG_LEVEL": "DEBUG",
        }
    )
    assert settings.host == "::1"
    assert settings.port == 9000
    assert settings.data_dir == tmp_path / "data"
    assert settings.token_file == tmp_path / "run" / "token"
    assert settings.log_level == "debug"


def test_unrelated_and_build_time_variables_are_ignored(tmp_path: Path) -> None:
    # The ISO build inputs share the PAI_ prefix, so an unknown PAI_ variable must not be an error.
    environment = _environment(tmp_path)
    noisy = {**environment, "PAI_DISTRIBUTION": "trixie", "PAI_ARCH": "amd64", "PATH": "/usr/bin"}
    assert load_settings(noisy) == load_settings(environment)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"])
def test_loopback_hosts_are_accepted(tmp_path: Path, host: str) -> None:
    assert load_settings(_environment(tmp_path, PAI_HOST=host)).host == host


@pytest.mark.parametrize(
    "host",
    [
        "0.0.0.0",  # noqa: S104 - the point of the test: all-interfaces must be refused
        "::",
        "192.168.1.10",
        "10.0.0.1",
        "8.8.8.8",
        "localhost",  # a name is resolved outside this check, so only literals are accepted
        "example.com",
        "::ffff:127.0.0.1",
        "::1%lo",
        "127.0.0.1 ",
        "",
    ],
)
def test_non_loopback_hosts_are_rejected_at_load_time(host: str) -> None:
    with pytest.raises(ConfigError, match="PAI_HOST"):
        load_settings({"PAI_HOST": host})


def test_direct_construction_is_validated_too() -> None:
    with pytest.raises(ValidationError):
        Settings(host="0.0.0.0")  # noqa: S104


@pytest.mark.parametrize("port", ["0", "80", "1023", "65536", "-1", "abc", "", "80.5"])
def test_invalid_ports_are_rejected(port: str) -> None:
    with pytest.raises(ConfigError, match="PAI_PORT"):
        load_settings({"PAI_PORT": port})


@pytest.mark.parametrize("variable", ["PAI_DATA_DIR", "PAI_TOKEN_FILE"])
@pytest.mark.parametrize("value", ["relative/path", "", "."])
def test_relative_paths_are_rejected(tmp_path: Path, variable: str, value: str) -> None:
    with pytest.raises(ConfigError, match=f"{variable}: must be an absolute path"):
        load_settings({**_environment(tmp_path), variable: value})


@pytest.mark.parametrize("level", ["verbose", "", "10", "trace"])
def test_unknown_log_levels_are_rejected(level: str) -> None:
    with pytest.raises(ConfigError, match="PAI_LOG_LEVEL"):
        load_settings({"PAI_LOG_LEVEL": level})


def test_every_problem_is_reported_and_names_its_variable() -> None:
    with pytest.raises(ConfigError) as caught:
        load_settings({"PAI_HOST": "0.0.0.0", "PAI_PORT": "80"})  # noqa: S104
    message = str(caught.value)
    assert message.startswith("Invalid configuration: ")
    assert "PAI_HOST" in message
    assert "PAI_PORT" in message


def test_settings_are_immutable(tmp_path: Path) -> None:
    settings = load_settings(_environment(tmp_path))
    with pytest.raises(ValidationError):
        settings.host = "127.0.0.2"  # type: ignore[misc]


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(unknown="x")  # type: ignore[call-arg]
