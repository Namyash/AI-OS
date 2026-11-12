"""The command runner: list argv only, explicit environment, secrets on stdin only, redacted errors, timeouts."""

from __future__ import annotations

import io
import os
import sys

import pytest

from installer.errors import CommandError, CommandTimeout
from installer.log import REDACTED, register_secret
from installer.runner import BASE_ENVIRONMENT, Commander, CommandResult, SubprocessRunner, build_environment
from installer.secret import Secret
from installer.tests.fakes import FakeSystem

posix_only = pytest.mark.skipif(
    os.name != "posix", reason="process groups and the environment of a bare process: POSIX only"
)
SECRET = "hunter2-hunter2-hunter2"  # noqa: S105 - a test value


class Recording:
    def __init__(self, result: CommandResult) -> None:
        self.result = result
        self.seen: list[tuple[list[str], float, bytes | None, dict[str, str] | None]] = []

    def run(self, argv, *, timeout, stdin=None, extra_env=None):
        self.seen.append((list(argv), timeout, stdin, extra_env))
        return self.result


@pytest.mark.parametrize("argv", ["ls -l", "", [], ["ls", 5], ["ls", "a\0b"], None])
def test_only_a_list_of_strings_is_a_command(argv: object) -> None:
    runner = Recording(CommandResult(0))
    with pytest.raises(TypeError):
        Commander(runner).run(argv, timeout=1)  # type: ignore[arg-type]
    assert runner.seen == []


def test_a_shell_metacharacter_in_an_argument_is_just_data() -> None:
    runner = Recording(CommandResult(0))
    Commander(runner).run(["echo", "a; rm -rf /", "$(id)"], timeout=1)
    assert runner.seen[0][0] == ["echo", "a; rm -rf /", "$(id)"]


def test_a_secret_stdin_is_passed_as_exact_bytes_and_never_logged(log_buffer: io.StringIO) -> None:
    register_secret(SECRET)
    runner = Recording(CommandResult(0))
    Commander(runner).run(["cryptsetup", "open"], timeout=5, stdin=Secret(SECRET))
    assert runner.seen[0][2] == SECRET.encode()
    assert SECRET not in log_buffer.getvalue()
    assert f"stdin: {len(SECRET)} bytes" in log_buffer.getvalue()


def test_a_failure_raises_with_redacted_output_and_the_argv() -> None:
    register_secret(SECRET)
    runner = Recording(CommandResult(2, "", f"bad key {SECRET}\n"))
    with pytest.raises(CommandError) as caught:
        Commander(runner).run(["cryptsetup", "open"], timeout=5)
    assert "exit 2" in str(caught.value) and SECRET not in str(caught.value) and REDACTED in str(caught.value)
    assert caught.value.argv == ("cryptsetup", "open") and caught.value.returncode == 2


def test_check_false_returns_the_raw_result() -> None:
    result = Commander(Recording(CommandResult(3, "out", "err"))).run(["x"], timeout=1, check=False)
    assert (result.returncode, result.stdout, result.stderr) == (3, "out", "err")


def test_only_whitelisted_environment_variables_can_be_added() -> None:
    assert build_environment({"DEBIAN_FRONTEND": "noninteractive"}) == {
        **BASE_ENVIRONMENT,
        "DEBIAN_FRONTEND": "noninteractive",
    }
    for name in ("PASSPHRASE", "LUKS_KEY", "PATH_EXTRA", "HOME"):
        with pytest.raises(ValueError, match="not allowed"):
            build_environment({name: "x"})
    with pytest.raises(ValueError):
        Commander(Recording(CommandResult(0))).run(["x"], timeout=1, extra_env={"SECRET": SECRET})


def test_the_fake_system_is_a_valid_runner() -> None:
    system = FakeSystem()
    with pytest.raises(AssertionError, match="does not know"):
        Commander(system).run(["no-such-tool"], timeout=1)


@posix_only
def test_the_real_runner_gives_the_child_only_the_built_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAI_SECRET_FOR_TEST", SECRET)
    result = SubprocessRunner().run(["env"], timeout=10)
    lines = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert SECRET not in result.stdout
    assert set(lines) <= set(BASE_ENVIRONMENT) | {"PWD", "SHLVL", "_", "OLDPWD"}
    assert lines["PATH"] == BASE_ENVIRONMENT["PATH"]


def test_the_real_runner_feeds_stdin_exactly_and_captures_output() -> None:
    code = "import sys; data = sys.stdin.buffer.read(); sys.stdout.write(str(len(data))); sys.stderr.write('e')"
    result = SubprocessRunner().run([sys.executable, "-c", code], timeout=30, stdin=b"abc\ndef")
    assert (result.returncode, result.stdout, result.stderr) == (0, "7", "e")


def test_without_stdin_the_child_gets_end_of_file_not_the_terminal() -> None:
    code = "import sys; sys.stdout.write(repr(sys.stdin.read()))"
    assert SubprocessRunner().run([sys.executable, "-c", code], timeout=30).stdout == "''"


def test_a_missing_program_is_reported_as_exit_127() -> None:
    result = SubprocessRunner().run(["definitely-not-installed-tool-xyz"], timeout=5)
    assert result.returncode == 127 and "not found" in result.stderr


def test_a_command_that_exceeds_its_timeout_is_killed() -> None:
    with pytest.raises(CommandTimeout, match="timed out"):
        SubprocessRunner().run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
