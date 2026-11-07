"""Fast tests (no Docker) for the host side of the boot test.

Covers configuration, ISO lookup, the docker command, image building, the command line's exit codes, console
sanitising, and the streaming / timeout / cleanup logic, which runs against a stand-in process instead of a container.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

import pytest

from tests.end_to_end import boot_harness
from tests.end_to_end.boot_harness import (
    ENV_CPUS,
    ENV_ISO,
    ENV_MEMORY,
    ENV_TIMEOUT,
    BootConfig,
    BootEnvironmentError,
    BootOutcome,
    ConfigError,
    IsoNotFoundError,
    boot_iso,
    boot_problems,
    docker_run_command,
    docker_unavailable_reason,
    ensure_image,
    image_tag,
    locate_iso,
    main,
    printable_console_text,
    save_serial_log,
)
from tests.end_to_end.selfcheck_output import REQUIRED_CHECKS

# ---- BootConfig ------------------------------------------------------------------------------------------------


def test_config_defaults() -> None:
    assert BootConfig.from_env({}) == BootConfig(
        timeout_s=boot_harness.DEFAULT_TIMEOUT_S,
        memory_mib=boot_harness.DEFAULT_MEMORY_MIB,
        cpus=boot_harness.DEFAULT_CPUS,
    )


def test_config_default_timeout_is_generous_for_software_emulation() -> None:
    assert BootConfig.from_env({}).timeout_s >= 900


def test_config_reads_every_variable() -> None:
    config = BootConfig.from_env({ENV_TIMEOUT: "90.5", ENV_MEMORY: "4096", ENV_CPUS: "4"})
    assert config == BootConfig(timeout_s=90.5, memory_mib=4096, cpus=4)


def test_blank_variables_mean_default() -> None:
    assert BootConfig.from_env({ENV_TIMEOUT: "  ", ENV_MEMORY: "", ENV_CPUS: " "}) == BootConfig()


@pytest.mark.parametrize("name", [ENV_TIMEOUT, ENV_MEMORY, ENV_CPUS])
@pytest.mark.parametrize("bad", ["abc", "0", "-3", "0.5", "nan", "NaN", "inf", "-inf", "Infinity", "1e400"])
def test_unusable_values_are_rejected_with_the_variable_name(name: str, bad: str) -> None:
    with pytest.raises(ConfigError, match=name):
        BootConfig.from_env({name: bad})


@pytest.mark.parametrize("name", [ENV_MEMORY, ENV_CPUS])
@pytest.mark.parametrize("fractional", ["1.9", "2048.5"])
def test_a_fractional_memory_or_cpu_count_is_rejected_instead_of_silently_truncated(name: str, fractional: str) -> None:
    with pytest.raises(ConfigError, match=f"{name} must be a whole number"):
        BootConfig.from_env({name: fractional})


def test_a_whole_number_written_as_a_float_is_accepted() -> None:
    config = BootConfig.from_env({ENV_MEMORY: "4096.0", ENV_CPUS: "2e0"})
    assert (config.memory_mib, config.cpus) == (4096, 2)


def test_a_fractional_timeout_is_fine() -> None:
    assert BootConfig.from_env({ENV_TIMEOUT: "2.5"}).timeout_s == 2.5


# ---- locate_iso ------------------------------------------------------------------------------------------------


def _iso(directory: Path, name: str, age_s: float) -> Path:
    path = directory / name
    path.write_bytes(b"iso")
    stamp = time.time() - age_s
    os.utime(path, (stamp, stamp))
    return path


def test_explicit_iso_wins_over_dist(tmp_path: Path) -> None:
    (tmp_path / "dist").mkdir()
    _iso(tmp_path / "dist", "newest.iso", 0)
    chosen = _iso(tmp_path, "mine.iso", 500)
    assert locate_iso(tmp_path, {ENV_ISO: str(chosen)}) == chosen.resolve()


def test_newest_dist_iso_is_used_without_an_explicit_one(tmp_path: Path) -> None:
    (tmp_path / "dist").mkdir()
    _iso(tmp_path / "dist", "old.iso", 1000)
    newest = _iso(tmp_path / "dist", "new.iso", 10)
    _iso(tmp_path / "dist", "middle.iso", 500)
    (tmp_path / "dist" / "new.iso.sha256").write_text("x")
    assert locate_iso(tmp_path, {}) == newest.resolve()


def test_explicit_iso_that_does_not_exist_is_an_error_not_a_fallback(tmp_path: Path) -> None:
    (tmp_path / "dist").mkdir()
    _iso(tmp_path / "dist", "fallback.iso", 0)
    with pytest.raises(IsoNotFoundError, match="not a file"):
        locate_iso(tmp_path, {ENV_ISO: str(tmp_path / "missing.iso")})


def test_no_iso_anywhere_says_how_to_get_one(tmp_path: Path) -> None:
    with pytest.raises(IsoNotFoundError, match=ENV_ISO):
        locate_iso(tmp_path, {})


# ---- docker command ---------------------------------------------------------------------------------------------


def _argv(iso: Path | None = None, config: BootConfig | None = None) -> list[str]:
    return docker_run_command("pai-e2e-boot-test", iso or Path("/data/boot.iso"), "img:tag", config or BootConfig())


def test_container_is_isolated_and_unprivileged() -> None:
    argv = _argv()
    assert argv[:2] == ["docker", "run"]
    assert "--rm" in argv
    assert argv[argv.index("--name") + 1] == "pai-e2e-boot-test"
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--read-only" in argv
    assert "no-new-privileges" in argv
    assert "--privileged" not in argv


def test_iso_and_harness_are_mounted_read_only() -> None:
    mounts = [arg for arg in _argv() if arg.startswith("type=bind")]
    assert len(mounts) == 2
    assert all(mount.endswith(",readonly") for mount in mounts)
    assert any(f"source={Path('/data/boot.iso')}," in mount for mount in mounts)


def test_memory_and_cpus_reach_the_container_script() -> None:
    argv = _argv(config=BootConfig(memory_mib=1234, cpus=5))
    assert argv[argv.index("--memory-mib") + 1] == "1234"
    assert argv[argv.index("--cpus") + 1] == "5"


def test_a_comma_in_the_iso_path_is_refused_instead_of_breaking_the_mount_syntax() -> None:
    with pytest.raises(ConfigError, match="comma"):
        _argv(iso=Path("/data/a,b.iso"))


def _dockerfile(directory: Path, text: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "Dockerfile"
    path.write_bytes(text.encode("utf-8"))  # bytes: write_text would turn each newline into CRLF on Windows
    return path


def test_image_tag_has_the_repository_and_twelve_hex_digits() -> None:
    repository, _, digest = image_tag().partition(":")
    assert repository == boot_harness.IMAGE_REPOSITORY
    assert re.fullmatch(r"[0-9a-f]{12}", digest)


def test_image_tag_follows_the_dockerfile_content(tmp_path: Path) -> None:
    """The tag is the only trigger for a rebuild: an edit must change it, and the same text must not."""
    first = _dockerfile(tmp_path / "a", "FROM scratch\n")
    same = _dockerfile(tmp_path / "b", "FROM scratch\n")
    edited = _dockerfile(tmp_path / "c", "FROM scratch\nRUN true\n")
    assert image_tag(first) == image_tag(same)
    assert image_tag(first) != image_tag(edited)


def test_image_tag_defaults_to_the_harness_dockerfile() -> None:
    assert image_tag() == image_tag(boot_harness.DOCKERFILE)
    assert boot_harness.DOCKERFILE == boot_harness.HARNESS_DIR / "Dockerfile"


def test_the_dockerfile_pins_the_base_image_and_the_packages() -> None:
    """Threat T12: the image that runs an untrusted ISO is built from pinned inputs, not from moving tags."""
    text = boot_harness.DOCKERFILE.read_text(encoding="utf-8")
    assert re.search(r"^ARG DEBIAN_IMAGE=\S+@sha256:[0-9a-f]{64}$", text, re.MULTILINE), (
        "base image not pinned by digest"
    )
    assert re.search(r"^FROM \$\{DEBIAN_IMAGE\}$", text, re.MULTILINE), "the base image must come from the pinned ARG"
    assert re.search(r"^ARG SNAPSHOT=\d{8}T\d{6}Z$", text, re.MULTILINE), "packages not pinned to a snapshot timestamp"
    assert "snapshot.debian.org/archive/debian/${SNAPSHOT}" in text
    assert "snapshot.debian.org/archive/debian-security/${SNAPSHOT}" in text
    assert "! grep -q 'deb\\.debian\\.org'" in text, "the build must fail if the moving mirror is still configured"


# ---- image building and the docker probe (docker replaced by a script of answers) --------------------------------


class FakeDocker:
    """Stands in for boot_harness._docker: records each call and answers from a script (an exception is raised)."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, *answers: subprocess.CompletedProcess[bytes] | Exception
    ) -> None:
        self.calls: list[tuple[tuple[str, ...], bytes | None, float | None]] = []
        self._answers = list(answers)
        monkeypatch.setattr(boot_harness, "_docker", self)

    def __call__(
        self, *args: str, input_bytes: bytes | None = None, timeout: float | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((args, input_bytes, timeout))
        answer = self._answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def _done(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(["docker"], returncode, stdout, stderr)


def test_an_existing_image_is_reused_without_building(monkeypatch: pytest.MonkeyPatch) -> None:
    docker = FakeDocker(monkeypatch, _done(0))
    assert ensure_image() == image_tag()
    assert [call[0] for call in docker.calls] == [("image", "inspect", image_tag())]


def test_a_missing_image_is_built_from_the_dockerfile_sent_on_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dockerfile = _dockerfile(tmp_path, "FROM scratch\n")
    docker = FakeDocker(monkeypatch, _done(1), _done(0))
    tag = ensure_image(dockerfile=dockerfile)
    assert tag == image_tag(dockerfile)
    inspect_call, build_call = docker.calls
    assert inspect_call[0] == ("image", "inspect", tag)
    build_args, build_input, build_timeout = build_call
    assert build_args == ("build", "--tag", tag, "-")
    assert build_input == b"FROM scratch\n"
    assert build_timeout == boot_harness.IMAGE_BUILD_TIMEOUT_S


def test_an_explicit_tag_is_used_as_given(monkeypatch: pytest.MonkeyPatch) -> None:
    docker = FakeDocker(monkeypatch, _done(0))
    assert ensure_image("custom:tag") == "custom:tag"
    assert docker.calls[0][0] == ("image", "inspect", "custom:tag")


def test_a_failed_image_build_is_an_environment_error_with_the_end_of_the_log(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeDocker(monkeypatch, _done(1), _done(100, stdout=b"Step 3/9\n", stderr=b"E: Unable to locate package qemu\n"))
    with pytest.raises(BootEnvironmentError, match=r"(?s)failed.*Unable to locate package qemu"):
        ensure_image()


def test_an_image_build_that_times_out_is_an_environment_error_not_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeDocker(monkeypatch, _done(1), subprocess.TimeoutExpired("docker", boot_harness.IMAGE_BUILD_TIMEOUT_S))
    with pytest.raises(BootEnvironmentError, match="did not finish within"):
        ensure_image()


def test_no_docker_command_is_reported_as_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boot_harness.shutil, "which", lambda name: None)
    assert "not installed" in str(docker_unavailable_reason())


def test_an_unreachable_daemon_is_reported_with_docker_s_own_words(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boot_harness.shutil, "which", lambda name: "/usr/bin/docker")
    FakeDocker(monkeypatch, _done(1, stderr=b"Cannot connect to the Docker daemon"))
    assert "Cannot connect to the Docker daemon" in str(docker_unavailable_reason())


def test_a_daemon_that_does_not_answer_is_reported_as_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boot_harness.shutil, "which", lambda name: "/usr/bin/docker")
    FakeDocker(monkeypatch, subprocess.TimeoutExpired("docker", boot_harness.DOCKER_PROBE_TIMEOUT_S))
    assert "did not answer" in str(docker_unavailable_reason())


def test_a_reachable_daemon_is_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boot_harness.shutil, "which", lambda name: "/usr/bin/docker")
    FakeDocker(monkeypatch, _done(0, stdout=b"29.0.0\n"))
    assert docker_unavailable_reason() is None


# ---- console text shown to the developer comes from an untrusted guest ------------------------------------------


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("plain text\twith a tab\n", "plain text\twith a tab\n"),
        ("café ✓ ok\n", "café ✓ ok\n"),
        ("line\r\nnext\r\n", "line\nnext\n"),
        ("\x1b[6n", "<ESC>[6n"),  # cursor position query: the terminal would answer into the developer's shell
        ("\x1b]52;c;QUJD\x07", "<ESC>]52;c;QUJD<U+0007>"),  # OSC 52 sets the clipboard
        ("\x1b]0;title\x1b\\", "<ESC>]0;title<ESC>\\"),  # OSC window title
        ("\x9b6n", "<U+009B>6n"),  # the single-character C1 form of CSI
        ("over\rwrite", "over<U+000D>write"),  # a lone carriage return would overdraw the line
        ("a\x00b\x7fc", "a<U+0000>b<U+007F>c"),
        ("‮gnp.exe", "<U+202E>gnp.exe"),  # bidirectional override reorders what is displayed
    ],
)
def test_control_characters_become_visible_text(raw: str, shown: str) -> None:
    assert printable_console_text(raw) == shown


def test_no_control_or_format_character_survives_sanitising() -> None:
    everything = "".join(chr(code) for code in range(0x3000) if chr(code) not in "\n\t")
    cleaned = printable_console_text(everything)
    assert not [char for char in cleaned if unicodedata.category(char) in {"Cc", "Cf"} and char not in "\n\t"]


def test_the_command_line_echo_survives_characters_the_terminal_cannot_encode(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="")
    monkeypatch.setattr(sys, "stdout", stream)
    boot_harness._console_echo("garbled � bytes \x1b]52;c;QUJD\x07 end\r\n")
    stream.flush()
    shown = raw.getvalue().decode("cp1252")
    assert shown == "garbled ? bytes <ESC>]52;c;QUJD<U+0007> end\n"


# ---- boot_iso: streaming, timeout, cleanup (stand-in process instead of docker) ---------------------------------

FINAL_LINE = "PAI-SELFCHECK|RESULT|PASS|6/6"
STAND_IN = """
import os, sys, time
sentinel = sys.argv[1]
for line in sys.argv[2:]:
    sys.stdout.buffer.write(line.encode("utf-8", "surrogateescape") + b"\\r\\n")
    sys.stdout.flush()
if os.environ.get("STAND_IN_EXIT") == "1":
    sys.exit(int(os.environ.get("STAND_IN_CODE", "0")))
while not os.path.exists(sentinel):
    time.sleep(0.05)
"""


class StandIn:
    """Replaces `docker run` with a Python process that prints lines, then waits for kill_container to be called."""

    def __init__(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lines: list[str], *, exits: bool, exit_code: int = 0
    ) -> None:
        self.sentinel = tmp_path / "killed"
        self.killed: list[str] = []
        if exits:
            monkeypatch.setenv("STAND_IN_EXIT", "1")
            monkeypatch.setenv("STAND_IN_CODE", str(exit_code))
        monkeypatch.setattr(
            boot_harness,
            "docker_run_command",
            lambda name, iso, tag, config: [sys.executable, "-u", "-c", STAND_IN, str(self.sentinel), *lines],
        )
        monkeypatch.setattr(boot_harness, "kill_container", self._kill)

    def _kill(self, name: str) -> None:
        self.killed.append(name)
        self.sentinel.write_text("x")


def _run(tmp_path: Path, timeout_s: float, echo: object = None) -> BootOutcome:
    return boot_iso(tmp_path / "x.iso", BootConfig(timeout_s=timeout_s), tag="img:tag", echo=echo)  # type: ignore[arg-type]


def test_output_is_collected_and_a_self_exit_means_the_guest_powered_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stand_in = StandIn(tmp_path, monkeypatch, ["boot line", "last line"], exits=True)
    outcome = _run(tmp_path, 30)
    assert outcome.output.splitlines() == ["boot line", "last line"]
    assert outcome.powered_off is True
    assert outcome.timed_out is False
    assert len(stand_in.killed) == 1  # cleanup always runs, and only for the container this run named
    assert stand_in.killed[0].startswith(boot_harness.CONTAINER_PREFIX)


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("docker: Error response from daemon: Mounts denied", 125),
        ("[pai-e2e] ERROR: xorriso could not list /iso/boot.iso: Permission denied", 2),
    ],
)
def test_a_container_that_fails_before_any_verdict_is_an_environment_error_not_a_selfcheck_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, line: str, code: int
) -> None:
    stand_in = StandIn(tmp_path, monkeypatch, [line], exits=True, exit_code=code)
    with pytest.raises(BootEnvironmentError, match=f"status {code}") as raised:
        _run(tmp_path, 30)
    assert line in str(raised.value)  # the reader is told what actually went wrong
    assert len(stand_in.killed) == 1  # cleanup still ran


def test_a_nonzero_exit_after_the_verdict_still_returns_the_console(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    StandIn(tmp_path, monkeypatch, ["noise", FINAL_LINE], exits=True, exit_code=1)
    outcome = _run(tmp_path, 30)
    assert FINAL_LINE in outcome.output
    assert outcome.powered_off is False  # the container did not end cleanly, but the verdict was printed


def test_a_hung_guest_ends_at_the_timeout_and_the_container_is_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stand_in = StandIn(tmp_path, monkeypatch, ["booting..."], exits=False)
    started = time.monotonic()
    outcome = _run(tmp_path, 1.5)
    assert time.monotonic() - started < 20
    assert outcome.timed_out is True
    assert outcome.powered_off is False
    assert "booting..." in outcome.output
    assert len(stand_in.killed) == 1


def test_the_run_stops_after_the_result_line_even_if_the_guest_never_powers_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(boot_harness, "POWEROFF_GRACE_S", 1)
    stand_in = StandIn(tmp_path, monkeypatch, ["noise", FINAL_LINE], exits=False)
    started = time.monotonic()
    outcome = _run(tmp_path, 600)
    assert time.monotonic() - started < 30  # nowhere near the 600 s timeout
    assert outcome.timed_out is False
    assert outcome.powered_off is False
    assert FINAL_LINE in outcome.output
    assert len(stand_in.killed) == 1


def test_a_check_line_alone_does_not_end_the_run_early(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boot_harness, "POWEROFF_GRACE_S", 1)
    stand_in = StandIn(tmp_path, monkeypatch, ["PAI-SELFCHECK|nft-default-drop|PASS|ok"], exits=False)
    outcome = _run(tmp_path, 2.5)
    assert outcome.timed_out is True
    assert len(stand_in.killed) == 1


def test_lines_are_echoed_as_they_arrive_and_bad_bytes_do_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    StandIn(tmp_path, monkeypatch, ["one", "caf\udce9 two"], exits=True)
    echoed: list[str] = []
    outcome = _run(tmp_path, 30, echo=echoed.append)
    assert [line.strip() for line in echoed] == ["one", "caf� two"]
    assert "two" in outcome.output


def test_a_failing_echo_stops_the_echo_but_not_the_collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A closed pipe (`| head`) must not kill the reader thread and with it the rest of the console."""
    StandIn(tmp_path, monkeypatch, ["one", "two", FINAL_LINE], exits=True)
    shown: list[str] = []

    def broken_echo(line: str) -> None:
        shown.append(line)
        raise BrokenPipeError("pipe closed")

    outcome = _run(tmp_path, 30, echo=broken_echo)
    assert len(shown) == 1  # not retried after it failed
    assert [line.strip() for line in outcome.output.splitlines()] == ["one", "two", FINAL_LINE]
    assert "BrokenPipeError: pipe closed" in outcome.echo_error
    assert outcome.powered_off is True
    assert boot_problems(outcome)  # still judged on the complete output (here: required checks are missing)


def test_a_console_line_the_terminal_cannot_encode_does_not_lose_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cp1252 case: a redirected stdout on Windows cannot print U+FFFD, and the echo used to die on it."""
    StandIn(tmp_path, monkeypatch, ["garbled \udcff\udcfe bytes", FINAL_LINE], exits=True)

    def cp1252_echo(line: str) -> None:
        line.encode("cp1252")

    outcome = _run(tmp_path, 30, echo=cp1252_echo)
    assert FINAL_LINE in outcome.output
    assert "UnicodeEncodeError" in outcome.echo_error


def test_a_working_echo_leaves_no_echo_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    StandIn(tmp_path, monkeypatch, ["one"], exits=True)
    assert _run(tmp_path, 30, echo=lambda line: None).echo_error == ""


def test_the_container_is_removed_even_when_the_wait_is_interrupted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stand_in = StandIn(tmp_path, monkeypatch, ["x"], exits=False)

    def interrupt(_self: object, timeout: float | None = None) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(boot_harness.threading.Thread, "join", interrupt)
    with pytest.raises(KeyboardInterrupt):
        _run(tmp_path, 30)
    assert len(stand_in.killed) == 1


# ---- verdict and log helpers ------------------------------------------------------------------------------------

CLEAN_RUN = "\n".join(
    [
        *(f"PAI-SELFCHECK|{name}|PASS|ok" for name in REQUIRED_CHECKS),
        f"PAI-SELFCHECK|RESULT|PASS|{len(REQUIRED_CHECKS)}/{len(REQUIRED_CHECKS)}",
    ]
)


def test_a_clean_run_has_no_problems() -> None:
    assert boot_problems(BootOutcome(CLEAN_RUN, timed_out=False, powered_off=True)) == []


def test_a_pass_that_lacks_a_required_check_is_not_a_clean_run() -> None:
    thin = "PAI-SELFCHECK|units-active|PASS|ok\nPAI-SELFCHECK|RESULT|PASS|1/1"
    problems = boot_problems(BootOutcome(thin, timed_out=False, powered_off=True))
    assert any("required check(s) missing" in problem for problem in problems)


def test_a_timeout_is_reported_first_and_missing_output_is_still_a_failure() -> None:
    problems = boot_problems(BootOutcome("Booting...", timed_out=True, powered_off=False))
    assert "timed out" in problems[0]
    assert any("no PAI-SELFCHECK output" in problem for problem in problems)


def test_a_boot_that_ended_without_the_result_line_is_a_failure() -> None:
    outcome = BootOutcome("PAI-SELFCHECK|units-active|PASS|ok", timed_out=False, powered_off=True)
    assert any("no final RESULT line" in problem for problem in boot_problems(outcome))


def test_the_saved_console_log_replaces_the_previous_boots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boot_harness, "SERIAL_LOG", tmp_path / "last.log")
    assert save_serial_log(BootOutcome("first", timed_out=False, powered_off=True)) == tmp_path / "last.log"
    save_serial_log(BootOutcome("second", timed_out=False, powered_off=True))
    assert (tmp_path / "last.log").read_text(encoding="utf-8") == "second"


def test_the_saved_console_log_cannot_replay_the_guests_escape_sequences(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(boot_harness, "SERIAL_LOG", tmp_path / "last.log")
    save_serial_log(BootOutcome("ok\r\n\x1b]52;c;QUJD\x07\r\n", timed_out=False, powered_off=True))
    saved = (tmp_path / "last.log").read_bytes()
    assert b"\x1b" not in saved
    assert b"\x07" not in saved
    assert saved == b"ok\n<ESC>]52;c;QUJD<U+0007>\n"


# ---- main: the exit status tells a failed self-check (1) from a boot that could not happen (2) -------------------

PROBLEM_RUN = "PAI-SELFCHECK|nft-default-drop|FAIL|no filter base chain on hook: forward"


def _cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    outcome: BootOutcome | None = None,
    docker_reason: str | None = None,
    image_error: Exception | None = None,
    boot_error: Exception | None = None,
) -> list[str]:
    """Replace everything main() touches outside this process; returns its argument list."""
    for name in (ENV_ISO, ENV_TIMEOUT, ENV_MEMORY, ENV_CPUS):
        monkeypatch.delenv(name, raising=False)
    iso = tmp_path / "boot.iso"
    iso.write_bytes(b"iso")
    monkeypatch.setattr(boot_harness, "SERIAL_LOG", tmp_path / "last.log")
    monkeypatch.setattr(boot_harness, "docker_unavailable_reason", lambda: docker_reason)

    def fake_image() -> str:
        if image_error is not None:
            raise image_error
        return "img:tag"

    def fake_boot(iso_path: Path, config: BootConfig, *, tag: str, echo: object = None) -> BootOutcome:
        if boot_error is not None:
            raise boot_error
        return outcome or BootOutcome(CLEAN_RUN, timed_out=False, powered_off=True)

    monkeypatch.setattr(boot_harness, "ensure_image", fake_image)
    monkeypatch.setattr(boot_harness, "boot_iso", fake_boot)
    return ["--iso", str(iso)]


def test_a_passing_boot_exits_zero_and_says_where_the_console_log_is(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(_cli(monkeypatch, tmp_path)) == 0
    err = capsys.readouterr().err
    assert "self-check PASSED" in err
    assert str(tmp_path / "last.log") in err


def test_a_failing_selfcheck_exits_one_and_lists_the_problems(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outcome = BootOutcome(PROBLEM_RUN, timed_out=False, powered_off=True)
    assert main(_cli(monkeypatch, tmp_path, outcome=outcome)) == 1
    err = capsys.readouterr().err
    assert "FAIL: nft-default-drop FAILED: no filter base chain on hook: forward" in err
    assert "self-check did NOT pass" in err


def test_no_docker_exits_two_not_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = _cli(monkeypatch, tmp_path, docker_reason="the docker command is not installed or not on PATH")
    assert main(argv) == 2
    assert "cannot boot: the docker command is not installed" in capsys.readouterr().err


def test_a_failed_image_build_exits_two_not_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = _cli(monkeypatch, tmp_path, image_error=BootEnvironmentError("building the QEMU image failed: E: nope"))
    assert main(argv) == 2
    assert "cannot boot: building the QEMU image failed: E: nope" in capsys.readouterr().err


def test_a_container_that_failed_exits_two_not_one_and_saves_no_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = _cli(monkeypatch, tmp_path, boot_error=BootEnvironmentError("the boot container exited with status 125"))
    assert main(argv) == 2
    assert "cannot boot: the boot container exited with status 125" in capsys.readouterr().err
    assert not (tmp_path / "last.log").exists()  # no console was produced, so there is nothing to save


def test_an_unusable_environment_variable_exits_two_naming_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = _cli(monkeypatch, tmp_path)
    monkeypatch.setenv(ENV_TIMEOUT, "nan")
    assert main(argv) == 2
    assert ENV_TIMEOUT in capsys.readouterr().err


def test_a_missing_iso_exits_two(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _cli(monkeypatch, tmp_path)
    assert main(["--iso", str(tmp_path / "nowhere.iso")]) == 2
    assert "not a file" in capsys.readouterr().err


def test_a_stopped_echo_is_reported_without_changing_the_verdict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outcome = BootOutcome(CLEAN_RUN, timed_out=False, powered_off=True, echo_error="BrokenPipeError: closed")
    assert main(_cli(monkeypatch, tmp_path, outcome=outcome)) == 0
    err = capsys.readouterr().err
    assert "console echo stopped (BrokenPipeError: closed)" in err
    assert "self-check PASSED" in err
