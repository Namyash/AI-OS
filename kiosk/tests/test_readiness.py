"""The readiness contract with the frontend, the page probe's answer, and the readiness file."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from kiosk import readiness
from kiosk.errors import KioskError
from kiosk.readiness import (
    MAX_STATUS_CHARS,
    READY_FILE_MODE,
    PageProbe,
    ReadyFile,
    ReadyReport,
    clear_ready_file,
    parse_probe,
    probe_expression,
    write_ready_file,
)

REPO = Path(__file__).resolve().parents[2]
FRONTEND_SRC = REPO / "frontend" / "src"


# ------------------------------------------------------------------------------ the contract with the frontend
def test_the_selectors_name_things_the_frontend_still_renders() -> None:
    """The launcher reads the page through two selectors; a frontend change that breaks them must fail here."""
    app = (FRONTEND_SRC / "App.tsx").read_text(encoding="utf-8")
    status_bar = (FRONTEND_SRC / "components" / "StatusBar.tsx").read_text(encoding="utf-8")
    index = (REPO / "frontend" / "index.html").read_text(encoding="utf-8")

    assert 'id="root"' in index, "SHELL_SELECTOR starts at #root"
    assert re.search(r'className="app-shell"', app), "App no longer renders .app-shell"
    assert re.search(r'aria-label="System status"', status_bar), "the status bar region lost its accessible name"
    assert 'role="status"' in status_bar, "the status lines are no longer live regions"
    assert status_bar.index('aria-label="System status"') < status_bar.index('role="status"')

    assert readiness.SHELL_SELECTOR == "#root .app-shell"
    assert readiness.STATUS_SELECTOR == '.app-shell section[aria-label="System status"] [role="status"]'
    assert "<section" in status_bar, "the status region is no longer a <section>, which STATUS_SELECTOR names"


def test_the_probe_expression_carries_both_selectors_quoted_and_changes_nothing() -> None:
    expression = probe_expression()
    assert json.dumps(readiness.SHELL_SELECTOR) in expression
    assert json.dumps(readiness.STATUS_SELECTOR) in expression
    assert expression.lstrip().startswith("(() =>") and expression.rstrip().endswith("})()")
    assert "JSON.stringify" in expression
    # read only: no assignment to the page, no navigation, no network
    for forbidden in (
        "innerHTML",
        "location.href",
        "location =",
        "fetch(",
        "XMLHttpRequest",
        "document.write",
        ".click(",
    ):
        assert forbidden not in expression
    assert MAX_STATUS_CHARS == 200  # the documented bound; the page is told the same number
    assert f".slice(0, {MAX_STATUS_CHARS})" in expression


# ------------------------------------------------------------------------------ the probe's answer
def answer(**fields: object) -> str:
    base: dict[str, object] = {
        "origin": "http://127.0.0.1:8765",
        "complete": True,
        "shell": True,
        "status": "Backend connected",
    }
    return json.dumps({**base, **fields})


def test_a_complete_answer_is_parsed() -> None:
    probe = parse_probe(answer(status="Backend connected Version 0.0.1"))
    assert probe == PageProbe("http://127.0.0.1:8765", True, True, "Backend connected Version 0.0.1")


def test_an_absent_status_line_is_none_and_an_empty_one_too() -> None:
    assert parse_probe(answer(status=None)).status_text is None
    assert parse_probe(answer(status="")).status_text is None


def test_the_status_line_is_one_clean_bounded_line() -> None:
    probe = parse_probe(answer(status="  Backend\n\tconnected \u00a0 Version   1  " + "x" * 1000))
    assert probe.status_text is not None
    assert probe.status_text.startswith("Backend connected Version 1 xxx")
    assert len(probe.status_text) <= 200, "the status line is bounded by the documented 200 characters"
    assert "\n" not in probe.status_text


@pytest.mark.parametrize(
    "value",
    [
        None,
        12,
        {"origin": "x"},
        "not json",
        "[]",
        "null",
        "123",
        answer(origin=5),
        answer(origin=None),
        answer(complete="yes"),
        answer(shell=1),  # noqa: S604 - the page probe has a JSON field named shell; no subprocess here
        answer(shell=None),
        answer(status=7),
        json.dumps({"origin": "http://127.0.0.1:1", "complete": True}),
    ],
)
def test_anything_but_the_documented_answer_is_refused(value: object) -> None:
    with pytest.raises(KioskError):
        parse_probe(value)


# ------------------------------------------------------------------------------ the report
def test_a_page_that_cannot_be_examined_is_not_ready() -> None:
    report = ReadyReport.from_probe(None)
    assert (report.state, report.shell_rendered, report.status_bar) == ("not-ready", False, None)


def test_a_page_without_the_shell_is_not_ready_but_keeps_what_it_said() -> None:
    report = ReadyReport.from_probe(PageProbe("http://127.0.0.1:8765", True, False, "something"))
    assert (report.state, report.shell_rendered, report.status_bar) == ("not-ready", False, "something")


def test_a_page_with_the_shell_is_ready() -> None:
    report = ReadyReport.from_probe(PageProbe("http://127.0.0.1:8765", True, True, "Backend connected"))
    assert (report.state, report.shell_rendered, report.status_bar) == ("ready", True, "Backend connected")


def test_two_reports_with_the_same_facts_are_the_same_whatever_their_time(tmp_path: Path) -> None:
    first = write_ready_file(tmp_path / "ready", ReadyReport.from_probe(PageProbe("o", True, True, "a")))
    second = ReadyReport.from_probe(PageProbe("o", True, True, "a"))
    other = ReadyReport.from_probe(PageProbe("o", True, True, "b"))
    assert first.same_facts(second)
    assert not first.same_facts(other)


# ------------------------------------------------------------------------------ the file
def test_the_file_holds_exactly_the_documented_keys_and_no_secret(tmp_path: Path) -> None:
    path = tmp_path / "run" / "pai-ui" / "ready"  # the directory is created when it does not exist yet
    written = write_ready_file(
        path, ReadyReport.from_probe(PageProbe("http://127.0.0.1:8765", True, True, "Backend connected"))
    )
    content = json.loads(path.read_text(encoding="utf-8"))
    assert content == {
        "version": 1,
        "state": "ready",
        "shell_rendered": True,
        "status_bar": "Backend connected",
        "updated": written.updated,
    }
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", content["updated"])
    assert list(path.parent.iterdir()) == [path], "a temporary file was left behind"


def test_the_file_is_replaced_atomically_and_never_half_written(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    path.write_text("old content that is not JSON", encoding="utf-8")
    write_ready_file(path, ReadyReport.from_probe(None))
    assert json.loads(path.read_text(encoding="utf-8"))["state"] == "not-ready"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_the_file_is_readable_by_the_self_check_account_and_writable_only_by_its_owner(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    write_ready_file(path, ReadyReport.from_probe(None))
    assert (path.stat().st_mode & 0o777) == READY_FILE_MODE == 0o644


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_the_mode_does_not_depend_on_the_umask(tmp_path: Path) -> None:
    previous = os.umask(0o077)  # the service runs with UMask=0077
    try:
        path = tmp_path / "ready"
        write_ready_file(path, ReadyReport.from_probe(None))
    finally:
        os.umask(previous)
    assert (path.stat().st_mode & 0o777) == 0o644


def test_clearing_removes_a_stale_file_and_a_missing_one_is_fine(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    path.write_text("{}", encoding="utf-8")
    clear_ready_file(path)
    assert not path.exists()
    clear_ready_file(path)


# ------------------------------------------------------------------------------ one run's file
READY_PAGE = PageProbe("http://127.0.0.1:8765", True, True, "Backend connected")
BROKEN_PAGE = PageProbe("http://127.0.0.1:8765", True, False, None)


def state_of(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["state"]


def test_a_new_run_removes_the_file_an_earlier_run_left(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    path.write_text('{"state":"ready"}', encoding="utf-8")
    ReadyFile(path)
    assert not path.exists()


def test_the_file_is_written_when_the_facts_change_and_not_otherwise(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    ready = ReadyFile(path)
    ready.publish(READY_PAGE)
    first = path.read_text(encoding="utf-8")
    path.write_text("marker", encoding="utf-8")  # a rewrite would replace this
    ready.publish(READY_PAGE)
    assert path.read_text(encoding="utf-8") == "marker"
    ready.publish(PageProbe("http://127.0.0.1:8765", True, True, "Backend unreachable"))
    assert json.loads(path.read_text(encoding="utf-8"))["status_bar"] == "Backend unreachable"
    assert first != path.read_text(encoding="utf-8")


def test_leaving_after_ready_turns_the_file_into_not_ready(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    ready = ReadyFile(path)
    ready.publish(READY_PAGE)
    ready.retire()
    content = json.loads(path.read_text(encoding="utf-8"))
    assert (content["state"], content["shell_rendered"], content["status_bar"]) == ("not-ready", False, None)


def test_leaving_after_not_ready_keeps_the_record_of_why(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    ready = ReadyFile(path)
    ready.publish(PageProbe("http://127.0.0.1:8765", True, False, "half drawn"))
    before = path.read_text(encoding="utf-8")
    ready.retire()
    assert path.read_text(encoding="utf-8") == before


def test_leaving_without_ever_having_written_leaves_nothing(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    ReadyFile(path).retire()
    assert not path.exists()


def test_a_page_that_stops_being_examinable_after_ready_is_not_ready(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    ready = ReadyFile(path)
    ready.publish(READY_PAGE)
    ready.publish(None)
    assert state_of(path) == "not-ready"
    ready.publish(READY_PAGE)
    assert state_of(path) == "ready"
