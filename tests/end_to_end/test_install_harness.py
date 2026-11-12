"""Fast tests (no Docker, no QEMU) for the host side of the install test: configuration, the `docker run` commands, the
streaming of an interactive console (against a stand-in guest that asks for a passphrase), and the session's lifecycle
(Docker itself replaced by recorders)."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.end_to_end import boot_harness, install_harness
from tests.end_to_end.boot_harness import BootConfig, BootEnvironmentError, ConfigError, StreamOutcome, stream_container
from tests.end_to_end.install_console import FirstOf, PromptTyper, Scrubber, UnlockFailedWatcher
from tests.end_to_end.install_harness import (
    CONTAINER_PREFIX,
    ENV_BOOT_TIMEOUT,
    ENV_DISK_GIB,
    ENV_ECHO,
    ENV_INSTALL_TIMEOUT,
    ENV_KDF_ITER_TIME,
    ENV_KDF_MEMORY,
    ENV_NEGATIVE_TIMEOUT,
    ENV_SETTLE,
    ENV_UEFI,
    InstallConfig,
    InstallSession,
    boot_disk_step_args,
    install_step_args,
    save_log,
    step_command,
)
from tests.end_to_end.install_plan import Secret
from tests.end_to_end.selfcheck_output import required_checks

# ---- configuration ---------------------------------------------------------------------------------------------------


def test_defaults_allow_tens_of_minutes_and_build_on_the_boot_tests_defaults() -> None:
    config = InstallConfig.from_env({})
    assert config.boot == BootConfig()
    assert config.install_timeout_s >= 3600  # copying a root filesystem through an encrypted volume under emulation
    assert config.boot_timeout_s >= boot_harness.DEFAULT_TIMEOUT_S
    assert config.negative_timeout_s > config.settle_s
    assert config.disk_gib >= 16  # the engine's own minimum
    assert (config.uefi, config.echo) == ("auto", False)


def test_every_variable_is_read() -> None:
    config = InstallConfig.from_env(
        {
            "PAI_QEMU_MEMORY": "4096",
            "PAI_QEMU_CPUS": "4",
            ENV_INSTALL_TIMEOUT: "100",
            ENV_BOOT_TIMEOUT: "200.5",
            ENV_NEGATIVE_TIMEOUT: "300",
            ENV_SETTLE: "7",
            ENV_DISK_GIB: "32",
            ENV_UEFI: "OFF",
            ENV_ECHO: "1",
            ENV_KDF_MEMORY: "1000",
            ENV_KDF_ITER_TIME: "50",
        }
    )
    assert (config.boot.memory_mib, config.boot.cpus) == (4096, 4)
    assert (config.install_timeout_s, config.boot_timeout_s, config.negative_timeout_s, config.settle_s) == (
        100,
        200.5,
        300,
        7,
    )
    assert (config.disk_gib, config.uefi, config.echo) == (32, "off", True)
    assert (config.kdf_memory_kib, config.kdf_iter_time_ms) == (1000, 50)


def test_blank_variables_mean_the_default() -> None:
    blank = {name: " " for name in (ENV_INSTALL_TIMEOUT, ENV_BOOT_TIMEOUT, ENV_DISK_GIB, ENV_UEFI, ENV_ECHO)}
    assert InstallConfig.from_env(blank) == InstallConfig.from_env({})


@pytest.mark.parametrize(
    "name",
    [
        ENV_INSTALL_TIMEOUT,
        ENV_BOOT_TIMEOUT,
        ENV_NEGATIVE_TIMEOUT,
        ENV_SETTLE,
        ENV_DISK_GIB,
        ENV_KDF_MEMORY,
        ENV_KDF_ITER_TIME,
    ],
)
@pytest.mark.parametrize("bad", ["abc", "0", "-1", "nan", "inf"])
def test_an_unusable_number_is_rejected_naming_the_variable(name: str, bad: str) -> None:
    with pytest.raises(ConfigError, match=name):
        InstallConfig.from_env({name: bad})


@pytest.mark.parametrize("name", [ENV_DISK_GIB, ENV_KDF_MEMORY, ENV_KDF_ITER_TIME])
def test_a_fractional_size_is_rejected(name: str) -> None:
    with pytest.raises(ConfigError, match="whole number"):
        InstallConfig.from_env({name: "2.5"})


def test_an_unknown_uefi_mode_is_rejected() -> None:
    with pytest.raises(ConfigError, match=ENV_UEFI):
        InstallConfig.from_env({ENV_UEFI: "maybe"})


def test_a_bad_extra_kernel_word_list_is_rejected_by_the_boot_configuration() -> None:
    with pytest.raises(ConfigError, match="PAI_BOOT_EXTRA_ARGS"):
        InstallConfig.from_env({"PAI_BOOT_EXTRA_ARGS": "a\nb"})


# ---- docker commands -------------------------------------------------------------------------------------------------


def command(**kwargs: object) -> list[str]:
    return step_command("pai-instharness-x", "img:tag", "pai-instharness-vol-1", ["step"], **kwargs)  # type: ignore[arg-type]


def test_a_step_is_as_isolated_as_the_boot_test_container() -> None:
    argv = command()
    assert argv[:2] == ["docker", "run"]
    assert argv[argv.index("--name") + 1] == "pai-instharness-x"
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--read-only" in argv and "no-new-privileges" in argv
    assert "--privileged" not in argv


def test_standard_input_is_attached_only_to_steps_that_type() -> None:
    assert "-i" not in command()
    assert "-i" in command(interactive=True)


def test_the_volume_is_mounted_writable_and_the_harness_and_iso_read_only() -> None:
    mounts = [argv for argv in command(iso=Path("/data/boot.iso")) if argv.startswith("type=")]
    volume = next(m for m in mounts if m.startswith("type=volume"))
    assert volume == "type=volume,source=pai-instharness-vol-1,target=/disks"
    binds = [m for m in mounts if m.startswith("type=bind")]
    assert len(binds) == 2 and all(m.endswith(",readonly") for m in binds)


def test_a_step_without_an_iso_mounts_none() -> None:
    assert len([m for m in command() if m.startswith("type=bind")]) == 1


def test_a_comma_in_the_iso_path_is_refused() -> None:
    with pytest.raises(ConfigError, match="comma"):
        command(iso=Path("/data/a,b.iso"))


def test_the_script_and_its_arguments_follow_the_image_tag() -> None:
    argv = command()
    assert argv[argv.index("img:tag") + 1 :] == ["python3", "/harness/container_install.py", "step"]


def test_the_install_step_hands_over_memory_cpus_and_extra_words_as_single_arguments() -> None:
    args = install_step_args(BootConfig(memory_mib=1234, cpus=5, extra_kernel_args="-x loglevel=7"))
    assert args[:2] == ["install", "/iso/boot.iso"]
    assert args[args.index("--memory-mib") + 1] == "1234"
    assert args[args.index("--cpus") + 1] == "5"
    assert "--extra-kernel-args=-x loglevel=7" in args
    assert not [a for a in install_step_args(BootConfig()) if a.startswith("--extra-kernel-args")]


def test_the_boot_step_names_the_firmware() -> None:
    assert boot_disk_step_args(BootConfig(), "uefi")[:3] == ["boot-disk", "--firmware", "uefi"]


# ---- streaming an interactive console --------------------------------------------------------------------------------

# A stand-in guest: noise, then the unlock prompt (no newline), then it reads what is typed. The right passphrase
# "boots"
# it (self-check lines, exit 0); a wrong one gets "No key available" and another prompt, three times, after which it
# waits
# for kill_container, like a machine stuck in the initramfs. With ECHO set it prints what was typed, like a bad console.
GUEST = """
import os, sys, time
sentinel, expected, names, echo = sys.argv[1], sys.argv[2], sys.argv[3].split(","), sys.argv[4] == "1"
out = sys.stdout.buffer
def say(text):
    out.write(text.encode()); out.flush()
say("[    0.1] Linux version\\r\\n")
for attempt in range(3):
    say("Please unlock disk cryptroot: ")
    typed = sys.stdin.readline().rstrip("\\n")
    if echo:
        say(typed + "\\r\\n")
    if typed == expected:
        for name in names:
            say("PAI-SELFCHECK|%s|PASS|ok\\r\\n" % name)
        say("PAI-SELFCHECK|RESULT|PASS|%d/%d\\r\\n" % (len(names), len(names)))
        sys.exit(0)
    say("No key available with this passphrase.\\r\\n")
while not os.path.exists(sentinel):
    time.sleep(0.05)
"""


class Guest:
    """Replaces `docker run` of a boot step with the stand-in guest and records the containers that were killed."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, expected: str, echo: bool = False) -> None:
        self.sentinel = tmp_path / "killed"
        self.killed: list[str] = []
        names = ",".join(required_checks(installed=True))
        self.argv = [sys.executable, "-u", "-c", GUEST, str(self.sentinel), expected, names, "1" if echo else "0"]
        monkeypatch.setattr(boot_harness, "kill_container", self._kill)

    def _kill(self, name: str) -> None:
        self.killed.append(name)
        self.sentinel.write_text("x")


def has_result(line: str) -> bool:
    return boot_harness._has_result_line(line)


def test_the_passphrase_is_typed_at_the_prompt_and_the_boot_that_follows_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = Secret("right-right-right-1234")
    guest = Guest(tmp_path, monkeypatch, expected=secret.reveal())
    typer = PromptTyper([secret])
    scrubber = Scrubber([secret])
    outcome = stream_container(
        guest.argv,
        "pai-instharness-test",
        30,
        handler=FirstOf(typer, boot_harness.LineWatcher(has_result)),
        scrub=scrubber.scrub,
        interactive=True,
    )
    assert (typer.prompts_seen, typer.typed) == (1, 1)
    assert "PAI-SELFCHECK|RESULT|PASS|18/18" in outcome.output
    assert outcome.ended_by_itself and outcome.returncode == 0 and not outcome.timed_out
    assert scrubber.hits == 0  # this guest does not echo
    assert secret.reveal() not in outcome.output
    assert guest.killed == ["pai-instharness-test"]  # cleanup always runs


def test_a_guest_that_echoes_the_passphrase_is_scrubbed_and_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = Secret("right-right-right-1234")
    guest = Guest(tmp_path, monkeypatch, expected=secret.reveal(), echo=True)
    scrubber = Scrubber([secret])
    echoed: list[str] = []
    outcome = stream_container(
        guest.argv,
        "pai-instharness-test",
        30,
        echo=echoed.append,
        handler=FirstOf(PromptTyper([secret])),
        scrub=scrubber.scrub,
        interactive=True,
    )
    assert scrubber.hits == 1
    assert secret.reveal() not in outcome.output + "".join(echoed)  # not kept and not shown
    assert "<redacted>" in outcome.output


def test_wrong_passphrases_leave_the_guest_stuck_and_the_run_ends_when_it_falls_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guest = Guest(tmp_path, monkeypatch, expected="the-one-the-guest-wants")
    wrong = [Secret(f"wrong-wrong-wrong-{n}") for n in range(3)]
    typer = PromptTyper(wrong)
    started = time.monotonic()
    outcome = stream_container(
        guest.argv,
        "pai-instharness-test",
        60,
        handler=FirstOf(typer, UnlockFailedWatcher(typer, attempts=3, settle_s=1.0)),
        scrub=Scrubber(wrong).scrub,
        interactive=True,
        grace_s=1,
    )
    assert time.monotonic() - started < 30  # nowhere near the 60 s timeout
    assert (typer.prompts_seen, typer.typed) == (3, 3)
    assert outcome.stopped_by_handler and not outcome.timed_out and not outcome.ended_by_itself
    assert outcome.output.count("No key available") == 3
    assert "PAI-SELFCHECK" not in outcome.output
    assert guest.killed == ["pai-instharness-test"]


def test_a_bug_in_a_handler_fails_the_run_instead_of_ending_it_as_a_clean_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guest = Guest(tmp_path, monkeypatch, expected="x")

    class Broken:
        def feed(self, chunk: str, send: object) -> bool:
            raise RuntimeError("handler bug")

        def poll(self, send: object) -> bool:
            return False

    with pytest.raises(RuntimeError, match="handler bug"):
        stream_container(guest.argv, "pai-instharness-test", 30, handler=Broken(), interactive=True, grace_s=1)
    assert guest.killed == ["pai-instharness-test"]


def test_a_container_that_fails_before_its_goal_is_an_environment_error() -> None:
    outcome = StreamOutcome("docker: Error response from daemon\n", False, True, False, 125)
    with pytest.raises(BootEnvironmentError, match="status 125") as raised:
        boot_harness.require_a_real_run(outcome, "install")
    assert "Error response from daemon" in str(raised.value)


@pytest.mark.parametrize(
    "outcome",
    [
        StreamOutcome("", False, True, False, 0),  # powered off
        StreamOutcome("", False, True, True, 1),  # the goal was reached first
        StreamOutcome("", True, False, False, -9),  # killed at the timeout
    ],
)
def test_other_endings_are_not_environment_errors(outcome: StreamOutcome) -> None:
    boot_harness.require_a_real_run(outcome, "install")


# ---- the session -----------------------------------------------------------------------------------------------------


class Docker:
    """Records `docker <args>` calls of the session and answers success unless a scenario says otherwise."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[tuple[tuple[str, ...], bytes | None]] = []
        self.fail_on: dict[str, int] = {}
        monkeypatch.setattr(boot_harness, "_docker", self)

    def __call__(
        self, *args: str, input_bytes: bytes | None = None, timeout: float | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((args, input_bytes))
        code = next((rc for word, rc in self.fail_on.items() if word in args), 0)
        return subprocess.CompletedProcess(["docker", *args], code, b"", b"boom" if code else b"")

    def words(self) -> list[str]:
        return [word for args, _ in self.calls for word in args]


def config() -> InstallConfig:
    return InstallConfig.from_env({})


def test_the_volume_is_created_on_entry_and_removed_on_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    docker = Docker(monkeypatch)
    with InstallSession("img:tag", config()) as session:
        assert docker.calls[0][0] == ("volume", "create", session.volume)
        assert session.volume.startswith(f"{CONTAINER_PREFIX}-vol-")
    assert docker.calls[-1][0] == ("volume", "rm", "--force", session.volume)


def test_the_volume_is_removed_even_when_the_body_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    docker = Docker(monkeypatch)
    with pytest.raises(KeyError), InstallSession("img:tag", config()):
        raise KeyError("test")
    assert docker.calls[-1][0][:3] == ("volume", "rm", "--force")


def test_a_volume_that_cannot_be_created_is_an_environment_error_and_nothing_is_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = Docker(monkeypatch)
    docker.fail_on["create"] = 1
    with (
        pytest.raises(BootEnvironmentError, match="cannot create the Docker volume"),
        InstallSession("img:tag", config()),
    ):
        pytest.fail("not reached")
    assert [args[:2] for args, _ in docker.calls] == [("volume", "create")]


def test_a_volume_that_cannot_be_removed_is_reported_and_does_not_raise(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    docker = Docker(monkeypatch)
    with InstallSession("img:tag", config()) as session:
        docker.fail_on["rm"] = 1
    assert f"{session.volume} was not removed" in capsys.readouterr().err


def test_the_plan_reaches_the_media_step_on_stdin_and_nowhere_else(monkeypatch: pytest.MonkeyPatch) -> None:
    docker = Docker(monkeypatch)
    with InstallSession("img:tag", config()) as session:
        session.make_media()
    (media_call,) = [call for call in docker.calls if "make-media" in call[0]]
    args, stdin = media_call
    assert stdin is not None and session.passphrase.reveal().encode() in stdin
    assert session.passphrase.reveal() not in " ".join(docker.words())  # not in any argument of any docker call
    assert "-i" in args and "--disk-gib" in args
    assert args[args.index("--disk-gib") + 1] == str(config().disk_gib)


def test_a_failing_media_step_is_an_environment_error_that_does_not_echo_the_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = Docker(monkeypatch)
    docker.fail_on["make-media"] = 2
    with (
        pytest.raises(BootEnvironmentError, match="building the plan medium failed") as raised,
        InstallSession("img:tag", config()) as session,
    ):
        session.make_media()
    assert session.passphrase.reveal() not in str(raised.value)


def test_a_media_step_that_hangs_is_killed_and_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    killed: list[str] = []
    monkeypatch.setattr(boot_harness, "kill_container", killed.append)
    docker = Docker(monkeypatch)

    def hang(*args: str, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "make-media" in args:
            raise subprocess.TimeoutExpired(["docker", *args], 1)
        return docker(*args)

    monkeypatch.setattr(boot_harness, "_docker", hang)
    with pytest.raises(BootEnvironmentError, match="did not finish"), InstallSession("img:tag", config()) as session:
        session.make_media()
    assert len(killed) == 1 and killed[0].startswith(f"{CONTAINER_PREFIX}-media-")


@pytest.mark.parametrize(("returncode", "expected"), [(0, True), (install_harness.NO_UEFI_EXIT_STATUS, False)])
def test_uefi_availability_is_what_the_probe_step_says(
    monkeypatch: pytest.MonkeyPatch, returncode: int, expected: bool
) -> None:
    docker = Docker(monkeypatch)
    docker.fail_on["probe-uefi"] = returncode
    with InstallSession("img:tag", config()) as session:
        assert session.probe_uefi() is expected


def test_a_probe_that_fails_for_another_reason_is_an_environment_error(monkeypatch: pytest.MonkeyPatch) -> None:
    docker = Docker(monkeypatch)
    docker.fail_on["probe-uefi"] = 125
    with pytest.raises(BootEnvironmentError, match="probing the image"), InstallSession("img:tag", config()) as session:
        session.probe_uefi()


class StreamRecorder:
    """Replaces stream_container in install_harness: records how a step was started and returns a canned console."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, output: str, *, returncode: int = 0, timed_out: bool = False
    ) -> None:
        self.calls: list[dict[str, object]] = []
        self.output, self.returncode, self.timed_out = output, returncode, timed_out
        monkeypatch.setattr(install_harness, "stream_container", self)

    def __call__(self, argv: list[str], name: str, timeout_s: float, **kwargs: object) -> StreamOutcome:
        self.calls.append({"argv": argv, "name": name, "timeout_s": timeout_s, **kwargs})
        return StreamOutcome(self.output, self.timed_out, not self.timed_out, False, self.returncode)


GOOD_INSTALL = "\n".join(
    [
        '{"event": "step", "name": "partition", "state": "start", "detail": ""}',
        '{"event": "step", "name": "partition", "state": "done", "detail": ""}',
        '{"event": "result", "ok": true}',
    ]
)


def test_the_install_step_boots_the_iso_with_the_install_timeout_and_judges_the_events(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(install_harness, "LOG_DIR", tmp_path)
    recorder = StreamRecorder(monkeypatch, GOOD_INSTALL)
    Docker(monkeypatch)
    with InstallSession("img:tag", config()) as session:
        result = session.install(Path("/data/live.iso"))
    (call,) = recorder.calls
    argv = call["argv"]
    assert f"source={Path('/data/live.iso')},target=/iso/boot.iso,readonly" in " ".join(argv)  # type: ignore[arg-type]
    assert str(call["name"]).startswith(f"{CONTAINER_PREFIX}-install-")
    assert call["timeout_s"] == config().install_timeout_s
    assert result.problems == []
    assert result.log == tmp_path / "pai-e2e-last-install.log"
    assert session.passphrase.reveal() not in " ".join(argv)  # type: ignore[arg-type]


def test_an_install_whose_engine_never_reported_is_not_a_pass(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(install_harness, "LOG_DIR", tmp_path)
    StreamRecorder(monkeypatch, "[ 1.0] booted\n")
    Docker(monkeypatch)
    with InstallSession("img:tag", config()) as session:
        assert any("printed no events" in problem for problem in session.install(Path("/data/live.iso")).problems)


def test_an_install_container_that_failed_to_start_is_an_environment_error(monkeypatch: pytest.MonkeyPatch) -> None:
    StreamRecorder(monkeypatch, "docker: Error response from daemon\n", returncode=125)
    Docker(monkeypatch)
    with pytest.raises(BootEnvironmentError, match="status 125"), InstallSession("img:tag", config()) as session:
        session.install(Path("/data/live.iso"))


def test_the_boot_step_types_the_passphrase_through_an_interactive_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(install_harness, "LOG_DIR", tmp_path)
    recorder = StreamRecorder(monkeypatch, "no prompt here\n")
    Docker(monkeypatch)
    with InstallSession("img:tag", config()) as session:
        result = session.boot_installed("uefi")
    (call,) = recorder.calls
    assert call["interactive"] is True
    assert call["timeout_s"] == config().boot_timeout_s
    assert "uefi" in call["argv"]  # type: ignore[operator]
    assert any("unlock prompt never appeared" in problem for problem in result.problems)
    assert result.log.name == "pai-e2e-last-installed-boot-uefi.log"


def test_the_wrong_passphrase_step_types_three_of_them_and_judges_that_nothing_came_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(install_harness, "LOG_DIR", tmp_path)
    recorder = StreamRecorder(monkeypatch, "PAI-SELFCHECK|live-root|PASS|x\n", timed_out=True)
    Docker(monkeypatch)
    with InstallSession("img:tag", config()) as session:
        result = session.boot_with_wrong_passphrases()
    (call,) = recorder.calls
    assert call["timeout_s"] == config().negative_timeout_s
    assert call["interactive"] is True
    assert any("came up although every passphrase was wrong" in problem for problem in result.problems)
    assert any("inconclusive" in problem for problem in result.problems)


# ---- logs ------------------------------------------------------------------------------------------------------------


def test_a_saved_console_cannot_replay_the_guests_escape_sequences(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(install_harness, "LOG_DIR", tmp_path)
    path = save_log("example", "ok\r\n\x1b]0;title\x07done\n")
    text = path.read_text(encoding="utf-8")
    assert "\x1b" not in text and "\x07" not in text and "\r" not in text
    assert "<ESC>" in text


def test_the_latest_log_of_a_step_replaces_the_previous_one(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(install_harness, "LOG_DIR", tmp_path)
    save_log("example", "first\n")
    assert save_log("example", "second\n").read_text(encoding="utf-8") == "second\n"
