"""Starting the browser: its command line, its environment, its private profile, and the descriptors it inherits."""

from __future__ import annotations

import json
import os
import signal
import stat
import sys
import time
from pathlib import Path

import pytest

from kiosk.chromium import (
    BLANK_APP_URL,
    COMMAND_FD,
    DEFAULT_FLAGS,
    PASSTHROUGH_ENV,
    REPLY_FD,
    BrowserProcess,
    build_command,
    build_environment,
    prepare_profile,
    resolve_executable,
    spawn,
)
from kiosk.config import load_settings
from kiosk.errors import ConfigError, KioskError
from kiosk.tests.support import posix_only


def settings_for(tmp_path: Path, **extra: str):
    environ = {
        "PAI_ENDPOINT_FILE": str(tmp_path / "endpoint"),
        "PAI_TOKEN_FILE": str(tmp_path / "token"),
        "PAI_KIOSK_READY_FILE": str(tmp_path / "ready"),
        "PAI_KIOSK_PROFILE_DIR": str(tmp_path / "profile"),
        **extra,
    }
    return load_settings(environ)


# ------------------------------------------------------------------------------------------ the command line
def test_the_command_line_has_the_pipe_the_profile_the_app_window_and_the_fixed_flags(tmp_path: Path) -> None:
    command = build_command(settings_for(tmp_path), "/usr/bin/chromium")
    assert command[0] == "/usr/bin/chromium"
    assert "--remote-debugging-pipe" in command
    assert f"--user-data-dir={tmp_path / 'profile'}" in command
    assert f"--app={BLANK_APP_URL}" in command
    assert set(DEFAULT_FLAGS) <= set(command)


def test_the_security_relevant_flags_are_in_the_defaults() -> None:
    for flag in (
        "--kiosk",
        "--ozone-platform=wayland",
        "--disable-gpu",
        "--no-first-run",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-component-update",
    ):
        assert flag in DEFAULT_FLAGS


def test_nothing_the_browser_must_not_have_is_on_the_command_line(tmp_path: Path) -> None:
    command = " ".join(build_command(settings_for(tmp_path), "/usr/bin/chromium"))
    assert "--no-sandbox" not in command  # the browser's own sandbox stays on
    assert "--remote-debugging-port" not in command  # the pipe is the only channel: no listening port
    assert "--remote-debugging-address" not in command
    assert "--remote-allow-origins" not in command


def test_the_blank_window_is_a_data_url_because_about_blank_opens_a_normal_browser_window() -> None:
    # Measured on Debian's Chromium: --app=about:blank is treated as "no app" and opens a tabbed window with the
    # new-tab page; any other app URL gives an app window with no browser chrome.
    assert BLANK_APP_URL.startswith("data:text/html,")
    assert "about:blank" not in BLANK_APP_URL
    assert "<" not in BLANK_APP_URL  # percent-encoded: safe as one command-line argument


def test_flags_the_operator_configured_come_last_so_they_win(tmp_path: Path) -> None:
    command = build_command(
        settings_for(tmp_path, PAI_KIOSK_CHROMIUM_FLAGS="--ozone-platform=x11 --extra"), "/b/chromium"
    )
    assert command[-2:] == ["--ozone-platform=x11", "--extra"]
    assert command.index("--ozone-platform=wayland") < command.index("--ozone-platform=x11")


def test_the_command_line_holds_nothing_derived_from_a_secret(tmp_path: Path) -> None:
    # The builder takes no token and no session id at all: there is nothing to leak. The signature is the proof.
    assert build_command.__code__.co_varnames[: build_command.__code__.co_argcount] == ("settings", "executable")


def test_an_executable_that_does_not_exist_is_a_configuration_error() -> None:
    with pytest.raises(ConfigError, match="PAI_KIOSK_CHROMIUM: executable not found: definitely-not-a-browser"):
        resolve_executable("definitely-not-a-browser")


@pytest.mark.skipif(os.name != "posix", reason="an executable is found by its mode bits: POSIX")
def test_an_executable_given_by_path_is_resolved_to_itself(tmp_path: Path) -> None:
    program = tmp_path / "browser"
    program.write_text("#!/bin/sh\n", encoding="utf-8")
    program.chmod(0o755)
    found = resolve_executable(str(program))
    assert Path(found).resolve() == program.resolve()


# ------------------------------------------------------------------------------------------ the environment
def test_only_the_listed_variables_and_the_private_profile_paths_reach_the_browser(tmp_path: Path) -> None:
    parent = {
        "PATH": "/usr/bin",
        "XDG_RUNTIME_DIR": "/run/user/995",
        "WAYLAND_DISPLAY": "wayland-0",
        "LANG": "C.UTF-8",
        "PAI_TOKEN_FILE": "/run/pai/token",
        "PAI_DECOY_SECRET": "decoy-secret-value-0123456789",
        "AWS_SECRET_ACCESS_KEY": "decoy-key-0123456789",
        "LD_PRELOAD": "/tmp/evil.so",  # noqa: S108 - a decoy value, never opened
        "HOME": "/root",
    }
    environment = build_environment(parent, settings_for(tmp_path))
    profile = str(tmp_path / "profile")
    assert environment == {
        "PATH": "/usr/bin",
        "XDG_RUNTIME_DIR": "/run/user/995",
        "WAYLAND_DISPLAY": "wayland-0",
        "LANG": "C.UTF-8",
        "HOME": profile,
        "XDG_CONFIG_HOME": str(Path(profile) / ".config"),
        "XDG_CACHE_HOME": str(Path(profile) / ".cache"),
    }


def test_a_variable_is_passed_only_when_the_launcher_has_it(tmp_path: Path) -> None:
    environment = build_environment({}, settings_for(tmp_path))
    assert set(environment) == {"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"}


def test_nothing_in_the_allow_list_can_carry_a_service_secret() -> None:
    assert not [name for name in PASSTHROUGH_ENV if name.startswith("PAI_")]
    assert "LD_PRELOAD" not in PASSTHROUGH_ENV
    assert "LD_LIBRARY_PATH" not in PASSTHROUGH_ENV


# ------------------------------------------------------------------------------------------ the profile
@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes and ownership")
class TestProfile:
    def test_a_new_profile_is_a_private_empty_directory(self, tmp_path: Path) -> None:
        profile = tmp_path / "state" / "profile"
        prepare_profile(profile)
        assert profile.is_dir()
        assert stat.S_IMODE(profile.stat().st_mode) == 0o700
        assert list(profile.iterdir()) == []

    def test_the_mode_does_not_depend_on_the_umask(self, tmp_path: Path) -> None:
        previous = os.umask(0o000)
        try:
            prepare_profile(tmp_path / "profile")
        finally:
            os.umask(previous)
        assert stat.S_IMODE((tmp_path / "profile").stat().st_mode) == 0o700

    def test_what_an_earlier_run_left_is_gone(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        prepare_profile(profile)
        (profile / "Default").mkdir()
        (profile / "Default" / "Cookies").write_text("stale session", encoding="utf-8")
        (profile / "SingletonLock").symlink_to("host-123")
        prepare_profile(profile)
        assert list(profile.iterdir()) == []

    def test_a_directory_that_is_not_closed_to_others_is_not_deleted(self, tmp_path: Path) -> None:
        precious = tmp_path / "precious"
        precious.mkdir()
        precious.chmod(0o755)
        (precious / "keep").write_text("data", encoding="utf-8")
        with pytest.raises(ConfigError, match="refusing to clear"):
            prepare_profile(precious)
        assert (precious / "keep").read_text(encoding="utf-8") == "data"

    @pytest.mark.parametrize("mode", [0o750, 0o770, 0o707, 0o701])
    def test_any_group_or_world_access_is_refused(self, tmp_path: Path, mode: int) -> None:
        directory = tmp_path / "shared"
        directory.mkdir()
        directory.chmod(mode)
        with pytest.raises(ConfigError, match="refusing to clear"):
            prepare_profile(directory)

    def test_a_file_or_a_link_in_its_place_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "elsewhere"
        target.mkdir(mode=0o700)
        link = tmp_path / "profile"
        link.symlink_to(target)
        with pytest.raises(ConfigError, match="not a directory of its own"):
            prepare_profile(link)
        link.unlink()
        link.write_text("a file", encoding="utf-8")
        with pytest.raises(ConfigError, match="not a directory of its own"):
            prepare_profile(link)
        assert target.is_dir()

    @pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to give it another owner")
    def test_a_directory_of_another_user_is_not_deleted(self, tmp_path: Path) -> None:
        directory = tmp_path / "theirs"
        directory.mkdir(mode=0o700)
        os.chown(directory, 4242, 4242)
        with pytest.raises(ConfigError, match="refusing to clear"):
            prepare_profile(directory)


# ------------------------------------------------------------------------------------------ the spawn
CHILD_REPORT = r"""
import json, os, signal, sys
reply = os.fdopen(4, "w")
commands = os.fdopen(3, "r")
line = commands.readline()
json.dump({"echo": line.strip().upper(), "argv": sys.argv[1:], "environ": dict(os.environ),
           "fds": sorted(int(n) for n in os.listdir("/proc/self/fd")), "pgid_is_pid": os.getpgrp() == os.getpid(),
           "stdin_is_null": os.fstat(0).st_rdev == os.stat(os.devnull).st_rdev}, reply)
reply.close()
"""


def is_running(pid: int) -> bool:
    """Alive and not a zombie (a killed process nobody has reaped yet still answers ``kill(pid, 0)``)."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
    except (FileNotFoundError, ProcessLookupError):
        return False
    return fields[0] != "Z"


def read_all(descriptor: int) -> bytes:
    chunks = []
    while chunk := os.read(descriptor, 65536):
        chunks.append(chunk)
    return b"".join(chunks)


@posix_only
class TestSpawn:
    def test_the_child_gets_the_pipe_on_descriptors_3_and_4_and_exactly_what_it_was_given(self) -> None:
        command = [sys.executable, "-c", CHILD_REPORT, "--flag=one", "two"]
        environment = {"PATH": os.environ["PATH"], "ONLY": "this"}
        browser = spawn(command, environment)
        try:
            os.write(browser.command_fd, b"hello\n")
            os.close(browser.command_fd)
            report = json.loads(read_all(browser.reply_fd))
            assert COMMAND_FD == 3 and REPLY_FD == 4
            assert report["echo"] == "HELLO"
            assert report["argv"] == ["--flag=one", "two"]
            assert {k: v for k, v in report["environ"].items() if k in environment} == environment
            assert set(report["environ"]) - {"LC_CTYPE"} <= set(environment)  # nothing inherited from the parent
            assert report["pgid_is_pid"] is True
            assert report["stdin_is_null"] is True
            # 0-2 standard, 3 and 4 the pipe, and the one the listing itself holds open; nothing else was inherited
            assert set(report["fds"]) - {5} == {0, 1, 2, 3, 4}
        finally:
            os.close(browser.reply_fd)
            browser.stop()

    def test_no_variable_of_the_launcher_reaches_the_child(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PAI_DECOY_SECRET", "decoy-secret-value-0123456789")
        browser = spawn([sys.executable, "-c", CHILD_REPORT], {"PATH": os.environ["PATH"]})
        try:
            os.write(browser.command_fd, b"x\n")
            report = json.loads(read_all(browser.reply_fd))
            assert "PAI_DECOY_SECRET" not in report["environ"]
        finally:
            os.close(browser.command_fd)
            os.close(browser.reply_fd)
            browser.stop()

    def test_the_launchers_own_pipe_ends_may_be_numbered_3_and_4_without_confusing_the_child(self) -> None:
        # Free descriptors 3 and 4 so the pipes spawn() creates are numbered exactly what the child must receive.
        import fcntl

        saved = {}
        for descriptor in (3, 4):
            try:
                # parked well above 4, so closing 3 and 4 below cannot make the copy of one land on the other
                saved[descriptor] = fcntl.fcntl(descriptor, fcntl.F_DUPFD, 10)
                os.close(descriptor)
            except OSError:
                pass
        try:
            browser = spawn([sys.executable, "-c", CHILD_REPORT], {"PATH": os.environ["PATH"]})
            try:
                os.write(browser.command_fd, b"swap\n")
                assert json.loads(read_all(browser.reply_fd))["echo"] == "SWAP"
            finally:
                os.close(browser.command_fd)
                os.close(browser.reply_fd)
                browser.stop()
        finally:
            for descriptor, duplicate in saved.items():
                os.dup2(duplicate, descriptor)
                os.close(duplicate)

    def test_default_signal_dispositions_are_restored_for_the_child(self) -> None:
        # Python ignores SIGPIPE; a program started from it would inherit that unless the spawn resets it.
        script = "grep -E '^SigIgn' /proc/self/status >&4"
        browser = spawn(["/bin/sh", "-c", script], {"PATH": os.environ["PATH"]})
        try:
            ignored = int(read_all(browser.reply_fd).split()[1], 16)
        finally:
            os.close(browser.command_fd)
            os.close(browser.reply_fd)
            browser.stop()
        assert not ignored & (1 << (signal.SIGPIPE - 1))

    def test_a_program_that_cannot_be_started_is_a_clean_error_and_leaks_no_descriptors(self, tmp_path: Path) -> None:
        before = len(os.listdir("/proc/self/fd"))
        with pytest.raises(KioskError, match="cannot start the browser"):
            spawn([str(tmp_path / "missing")], {})
        assert len(os.listdir("/proc/self/fd")) == before

    def test_exit_status_is_reported_once_and_a_signal_is_a_negative_status(self) -> None:
        browser = spawn(["/bin/sh", "-c", "exit 3"], {})
        status = None
        deadline = time.monotonic() + 5
        while status is None and time.monotonic() < deadline:
            status = browser.poll()
            time.sleep(0.02)
        assert status == 3
        assert browser.poll() == 3
        os.close(browser.command_fd)
        os.close(browser.reply_fd)

        victim = spawn(["/bin/sh", "-c", "kill -KILL $$"], {})
        deadline = time.monotonic() + 5
        while victim.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert victim.returncode == -signal.SIGKILL
        os.close(victim.command_fd)
        os.close(victim.reply_fd)

    def test_stop_ends_the_browser_and_the_processes_it_started(self, tmp_path: Path) -> None:
        marker = tmp_path / "helper.pid"
        browser = spawn(["/bin/sh", "-c", f"sleep 60 & echo $! > {marker}; wait"], {"PATH": os.environ["PATH"]})
        try:
            deadline = time.monotonic() + 5
            while not (marker.exists() and marker.read_text().strip()) and time.monotonic() < deadline:
                time.sleep(0.02)
            helper = int(marker.read_text().strip())
            assert is_running(helper)
            browser.stop(grace=2)
            assert browser.returncode is not None
            deadline = time.monotonic() + 5
            while is_running(helper) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not is_running(helper)
        finally:
            os.close(browser.command_fd)
            os.close(browser.reply_fd)

    def test_stop_kills_a_browser_that_ignores_the_polite_request(self) -> None:
        script = "trap '' TERM; echo ready >&4; while :; do sleep 0.1; done"
        browser = spawn(["/bin/sh", "-c", script], {"PATH": os.environ["PATH"]})
        try:
            assert os.read(browser.reply_fd, 16).startswith(b"ready")
            started = time.monotonic()
            browser.stop(grace=0.5)
            assert browser.returncode == -signal.SIGKILL
            assert time.monotonic() - started < 5
        finally:
            os.close(browser.command_fd)
            os.close(browser.reply_fd)

    def test_stopping_a_browser_that_already_exited_is_harmless(self) -> None:
        browser = spawn(["/bin/sh", "-c", "exit 0"], {})
        try:
            deadline = time.monotonic() + 5
            while browser.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            browser.stop()
            assert browser.returncode == 0
        finally:
            os.close(browser.command_fd)
            os.close(browser.reply_fd)


def test_a_process_that_someone_else_reaped_is_reported_as_gone() -> None:
    gone = BrowserProcess(pid=2**22 + 7, command_fd=-1, reply_fd=-1)  # no such child of this process
    if os.name == "posix":
        assert gone.poll() == -1
