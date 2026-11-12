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
    DEFAULT_ENDPOINT_FILE,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_SESSION_TTL,
    DEFAULT_STATIC_DIR,
    DEFAULT_TOKEN_FILE,
    MAX_SESSION_TTL,
    MIN_SESSION_TTL,
    ConfigError,
    Settings,
    host_literal,
    load_settings,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_UNIT = REPO_ROOT / "os" / "systemd" / "rootfs" / "etc" / "systemd" / "system" / "pai-backend.service"

posix_only = pytest.mark.skipif(os.name != "posix", reason="the default paths are Linux deployment paths")
not_posix = pytest.mark.skipif(os.name == "posix", reason="covers hosts where the Linux default paths are not absolute")


def _environment(tmp_path: Path, **extra: str) -> dict[str, str]:
    """Valid paths for this platform, so a test about one variable does not depend on the Linux defaults."""
    return {
        "PAI_DATA_DIR": str(tmp_path / "data"),
        "PAI_TOKEN_FILE": str(tmp_path / "run" / "token"),
        "PAI_ENDPOINT_FILE": str(tmp_path / "run" / "endpoint"),
        "PAI_STATIC_DIR": str(tmp_path / "ui"),
        **extra,
    }


def test_defaults_come_from_one_place() -> None:
    fields = Settings.model_fields
    assert fields["host"].default == DEFAULT_HOST == "127.0.0.1"
    assert fields["port"].default == DEFAULT_PORT
    assert fields["data_dir"].default == DEFAULT_DATA_DIR
    assert fields["token_file"].default == DEFAULT_TOKEN_FILE
    assert fields["endpoint_file"].default == DEFAULT_ENDPOINT_FILE == Path("/run/pai/endpoint")
    assert fields["static_dir"].default == DEFAULT_STATIC_DIR == Path("/opt/pai/frontend")
    assert fields["session_ttl"].default == DEFAULT_SESSION_TTL == 12 * 60 * 60
    assert fields["log_level"].default == "info"


@posix_only
def test_unset_variables_give_the_linux_deployment_defaults() -> None:
    settings = load_settings({})
    assert settings == Settings()
    assert (settings.host, settings.port) == (DEFAULT_HOST, DEFAULT_PORT)
    assert (settings.data_dir, settings.token_file) == (DEFAULT_DATA_DIR, DEFAULT_TOKEN_FILE)
    assert (settings.endpoint_file, settings.static_dir) == (DEFAULT_ENDPOINT_FILE, DEFAULT_STATIC_DIR)
    assert settings.session_ttl == DEFAULT_SESSION_TTL
    assert settings.log_level == "info"


@not_posix
def test_linux_default_paths_are_refused_not_resolved_under_the_drive_root() -> None:
    # Path("/var/lib/pai") has no drive on Windows: left unchecked it would become a directory under the root of
    # whichever drive is current.
    with pytest.raises(ConfigError) as caught:
        load_settings({})
    for variable in ("PAI_DATA_DIR", "PAI_TOKEN_FILE", "PAI_ENDPOINT_FILE", "PAI_STATIC_DIR"):
        assert variable in str(caught.value)


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
            "PAI_ENDPOINT_FILE": str(tmp_path / "run" / "where"),
            "PAI_STATIC_DIR": str(tmp_path / "www"),
            "PAI_SESSION_TTL": "7200",
            "PAI_LOG_LEVEL": "DEBUG",
        }
    )
    assert settings.host == "::1"
    assert settings.port == 9000
    assert settings.data_dir == tmp_path / "data"
    assert settings.token_file == tmp_path / "run" / "token"
    assert settings.endpoint_file == tmp_path / "run" / "where"
    assert settings.static_dir == tmp_path / "www"
    assert settings.session_ttl == 7200
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


@pytest.mark.parametrize("variable", ["PAI_DATA_DIR", "PAI_TOKEN_FILE", "PAI_ENDPOINT_FILE", "PAI_STATIC_DIR"])
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


# ------------------------------------------------------------------ the endpoint file and the UI directory
def test_the_endpoint_file_must_not_be_the_token_file(tmp_path: Path) -> None:
    # Both are published by replacing the file at the path: one would overwrite the other.
    same = str(tmp_path / "run" / "token")
    with pytest.raises(ConfigError, match="PAI_ENDPOINT_FILE: must not be the same file as PAI_TOKEN_FILE"):
        load_settings(_environment(tmp_path, PAI_ENDPOINT_FILE=same))


@pytest.mark.parametrize("variable", ["token_file", "data_dir"])
@pytest.mark.parametrize("where", ["itself", "parent", "root"])
def test_the_ui_directory_may_not_contain_the_token_or_the_data(tmp_path: Path, variable: str, where: str) -> None:
    # Everything under the UI directory is served to the browser, whose page scripts must never see either.
    environment = _environment(tmp_path)
    secret = Path(environment[f"PAI_{variable.upper()}"])
    served = {"itself": secret, "parent": secret.parent, "root": Path(secret.anchor)}[where]
    # A directory that holds both names the first of them; one that is only one of them names that one.
    named = f"PAI_{variable.upper()}" if where == "itself" else "PAI_(TOKEN_FILE|DATA_DIR)"
    with pytest.raises(ConfigError, match=f"PAI_STATIC_DIR: must not be, or contain, {named}"):
        load_settings({**environment, "PAI_STATIC_DIR": str(served)})


def test_the_ui_directory_may_sit_next_to_or_inside_the_data(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    for allowed in (tmp_path / "www", Path(environment["PAI_DATA_DIR"]) / "ui", tmp_path / "run" / "ui"):
        assert load_settings({**environment, "PAI_STATIC_DIR": str(allowed)}).static_dir == allowed


@pytest.mark.skipif(os.name == "nt", reason="creating symbolic links needs a privilege on Windows")
def test_a_symbolic_link_does_not_hide_the_token_from_the_ui_check(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    link = tmp_path / "innocent-looking"
    Path(environment["PAI_TOKEN_FILE"]).parent.mkdir(parents=True)
    link.symlink_to(Path(environment["PAI_TOKEN_FILE"]).parent)
    with pytest.raises(ConfigError, match="PAI_STATIC_DIR"):
        load_settings({**environment, "PAI_STATIC_DIR": str(link)})


@pytest.mark.parametrize("ttl", [str(MIN_SESSION_TTL), "3600", str(DEFAULT_SESSION_TTL), str(MAX_SESSION_TTL)])
def test_session_lifetimes_inside_the_range_are_accepted(tmp_path: Path, ttl: str) -> None:
    assert load_settings(_environment(tmp_path, PAI_SESSION_TTL=ttl)).session_ttl == int(ttl)


@pytest.mark.parametrize("ttl", ["0", "59", "-1", str(MAX_SESSION_TTL + 1), "abc", "", "1.5", "12h", "nan"])
def test_session_lifetimes_outside_the_range_or_not_whole_seconds_are_rejected(tmp_path: Path, ttl: str) -> None:
    with pytest.raises(ConfigError, match="PAI_SESSION_TTL"):
        load_settings(_environment(tmp_path, PAI_SESSION_TTL=ttl))


@pytest.mark.parametrize(
    ("host", "port", "url"),
    [
        ("127.0.0.1", 8765, "http://127.0.0.1:8765"),
        ("127.0.0.2", 9000, "http://127.0.0.2:9000"),
        ("::1", 8765, "http://[::1]:8765"),
        ("0:0:0:0:0:0:0:1", 1024, "http://[::1]:1024"),
    ],
)
def test_the_endpoint_url_is_the_origin_the_service_listens_on(tmp_path: Path, host: str, port: int, url: str) -> None:
    assert load_settings(_environment(tmp_path, PAI_HOST=host, PAI_PORT=str(port))).endpoint_url == url


def test_ipv6_host_literals_are_bracketed_for_urls_and_host_headers() -> None:
    assert host_literal("127.0.0.1") == "127.0.0.1"
    assert host_literal("::1") == "[::1]"


# ------------------------------------------------------------------ the unit that runs the service
def _unit_settings() -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in BACKEND_UNIT.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and not line.startswith(("#", "[")):
            values.setdefault(key.strip(), []).append(value.strip())
    return values


def test_the_defaults_agree_with_the_unit_that_runs_the_service() -> None:
    unit = _unit_settings()
    # The endpoint is published next to the token, in the runtime directory the unit creates for the group.
    assert DEFAULT_ENDPOINT_FILE.parent == DEFAULT_TOKEN_FILE.parent
    assert DEFAULT_ENDPOINT_FILE.parent.as_posix() == f"/run/{unit['RuntimeDirectory'][0]}"
    # The UI is read from the installed code; ProtectSystem=strict makes the file system read-only, not hidden.
    assert DEFAULT_STATIC_DIR.is_relative_to(Path(unit["WorkingDirectory"][0]))
    assert unit["ProtectSystem"] == ["strict"]
    # ... and nothing makes the UI directory writable.
    writable = [path for line in unit.get("ReadWritePaths", []) for path in line.split()]
    assert not any(DEFAULT_STATIC_DIR.is_relative_to(Path(path)) for path in writable)
