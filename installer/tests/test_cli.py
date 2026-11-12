"""The command line: exit statuses, events on stdout only, the passphrase from stdin, root check, bounded inputs."""
# ruff: noqa: S106

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from installer.cli import main
from installer.errors import EXIT_CONFIG, EXIT_FAILURE, EXIT_NOPERM, EXIT_OK
from installer.plan import MAX_PLAN_BYTES
from installer.tests.fakes import FakeSystem
from installer.tests.support import PASSPHRASE, RECOVERY_FILE, SECRETS, fixed_random, plan_document

REPO = Path(__file__).resolve().parents[2]


class Outcome:
    def __init__(self, code: int, out: str, err: str, system: FakeSystem) -> None:
        self.code, self.out, self.err, self.system = code, out, err, system

    @property
    def events(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.out.splitlines()]


def invoke(
    tmp_path: Path, document: object | str, stdin: str = "", *, euid: int = 0, system: FakeSystem | None = None
) -> Outcome:
    system = system or FakeSystem.live_machine()
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["--plan", str(plan_file)],
        runner=system,
        host=system,
        stdin=io.StringIO(stdin),
        stdout=out,
        stderr=err,
        geteuid=lambda: euid,
        random_bytes=fixed_random,
    )
    return Outcome(code, out.getvalue(), err.getvalue(), system)


def test_a_full_success_exits_zero_with_only_json_lines_on_stdout(tmp_path: Path) -> None:
    outcome = invoke(tmp_path, plan_document())
    assert outcome.code == EXIT_OK
    assert outcome.events[-1] == {"event": "result", "ok": True, "error": ""}
    assert all(event["event"] in {"step", "result"} for event in outcome.events)
    assert "run: wipefs" in outcome.err, "the log goes to stderr, not stdout"
    assert all(secret not in outcome.out + outcome.err for secret in SECRETS)


def test_a_failed_step_exits_one_with_a_failed_result(tmp_path: Path) -> None:
    system = FakeSystem.live_machine()
    system.fail_on("mkfs.ext4")
    outcome = invoke(tmp_path, plan_document(), system=system)
    assert outcome.code == EXIT_FAILURE
    assert outcome.events[-1]["ok"] is False and "mkfs" in outcome.events[-1]["error"]
    assert system.mappings == {} and system.mounted_paths() == []


def test_a_refused_target_exits_one_and_runs_nothing(tmp_path: Path) -> None:
    outcome = invoke(tmp_path, plan_document(target={"path": "/dev/sdb"}))
    assert outcome.code == EXIT_FAILURE and outcome.system.calls == []
    assert "live medium" in outcome.events[-1]["error"]


def test_the_passphrase_is_read_from_stdin_without_its_trailing_newline(tmp_path: Path) -> None:
    outcome = invoke(tmp_path, plan_document(passphrase_source="stdin", passphrase=...), stdin="stdin passphrase ok\n")
    assert outcome.code == EXIT_OK
    (call,) = [c for c in outcome.system.calls if c.argv[:2] == ["cryptsetup", "luksFormat"]]
    assert call.stdin == b"stdin passphrase ok"


def test_a_windows_line_ending_is_stripped_too_and_nothing_else(tmp_path: Path) -> None:
    outcome = invoke(
        tmp_path, plan_document(passphrase_source="stdin", passphrase=...), stdin="pass phrase  with spaces \r\n"
    )
    assert outcome.code == EXIT_OK
    (call,) = [c for c in outcome.system.calls if c.argv[:2] == ["cryptsetup", "luksFormat"]]
    assert call.stdin == b"pass phrase  with spaces "


@pytest.mark.parametrize(
    "stdin", ["", "\n", "short\n", "aaaaaaaaaaaaaaaa\n", "two\n\nlines of text here\n", "x" * 5000]
)
def test_a_bad_stdin_passphrase_is_a_config_error_that_never_echoes_it(tmp_path: Path, stdin: str) -> None:
    outcome = invoke(tmp_path, plan_document(passphrase_source="stdin", passphrase=...), stdin=stdin)
    assert outcome.code == EXIT_CONFIG and outcome.system.calls == []
    assert outcome.events[-1]["ok"] is False and "passphrase" in outcome.events[-1]["error"]
    assert stdin.strip() == "" or stdin.strip() not in outcome.out + outcome.err


def test_an_invalid_plan_exits_78_before_anything_runs_and_never_echoes_the_passphrase(tmp_path: Path) -> None:
    outcome = invoke(tmp_path, plan_document(confirm_wipe=False, hostname="-"))
    assert outcome.code == EXIT_CONFIG and outcome.system.calls == [] and outcome.system.secret_files == {}
    assert "confirm_wipe" in outcome.events[-1]["error"] and PASSPHRASE not in outcome.out + outcome.err
    assert len(outcome.events) == 1, "only the result event"


def test_not_being_root_exits_77_without_reading_the_plan(tmp_path: Path) -> None:
    outcome = invoke(tmp_path, plan_document(), euid=1000)
    assert outcome.code == EXIT_NOPERM and outcome.system.calls == []
    assert outcome.events == [{"event": "result", "ok": False, "error": "the installer must run as root"}]


def test_a_missing_plan_file_is_a_config_error(tmp_path: Path) -> None:
    out = io.StringIO()
    code = main(["--plan", str(tmp_path / "absent.json")], stdout=out, stderr=io.StringIO(), geteuid=lambda: 0)
    assert code == EXIT_CONFIG and "cannot read the plan file" in json.loads(out.getvalue())["error"]


def test_an_oversized_or_non_utf8_plan_is_refused(tmp_path: Path) -> None:
    big = invoke(tmp_path, " " * (MAX_PLAN_BYTES + 1) + json.dumps(plan_document()))
    assert big.code == EXIT_CONFIG and "larger than" in big.events[-1]["error"]
    (tmp_path / "plan.json").write_bytes(b"\xff\xfe\x00bad")
    out = io.StringIO()
    code = main(["--plan", str(tmp_path / "plan.json")], stdout=out, stderr=io.StringIO(), geteuid=lambda: 0)
    assert code == EXIT_CONFIG and "UTF-8" in json.loads(out.getvalue())["error"]


def test_broken_json_is_a_config_error_without_echoing_the_content(tmp_path: Path) -> None:
    outcome = invoke(tmp_path, '{"passphrase": "' + PASSPHRASE + '" nope')
    assert outcome.code == EXIT_CONFIG and PASSPHRASE not in outcome.out + outcome.err


def test_the_plan_flag_is_required() -> None:
    with pytest.raises(SystemExit) as caught:
        main([], stderr=io.StringIO())
    assert caught.value.code == 2


def test_signal_handlers_are_restored_after_a_run(tmp_path: Path) -> None:
    import signal

    before = signal.getsignal(signal.SIGTERM)
    invoke(tmp_path, plan_document())
    assert signal.getsignal(signal.SIGTERM) == before


def test_the_module_entry_point_reports_a_result_event_and_never_touches_a_disk(tmp_path: Path) -> None:
    """Run as ``python -m installer`` for real: a plan naming no real disk is refused, whatever the privileges."""
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(plan_document(target={"by_id": "pai-test-no-such-disk"}, recovery_key_file=str(tmp_path / "key")))
    )
    done = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-m", "installer", "--plan", str(plan)],
        cwd=REPO, capture_output=True, text=True, timeout=60, check=False, env={"PYTHONPATH": str(REPO), "PATH": ""},
    )  # fmt: skip
    assert done.returncode in {EXIT_NOPERM, EXIT_FAILURE}, done.stderr
    last = json.loads(done.stdout.splitlines()[-1])
    assert last["event"] == "result" and last["ok"] is False
    assert not (tmp_path / "key").exists()
    assert RECOVERY_FILE not in done.stdout
