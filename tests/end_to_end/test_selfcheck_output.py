"""Fast tests (no Docker) for reading the self-check verdict from serial console output.

The serial_*.log fixtures in tests/end_to_end/fixtures are excerpts of the console log of one real boot of the ISO
under QEMU through the real harness (then the self-check printed `RESULT|PASS|12/12`): kernel and systemd noise, status
lines with ANSI colours and carriage returns, the login prompt with terminal-reset sequences in front of the first
check line, and the journald console prefix on every self-check line. The backend's bearer token is never printed by
the script, and a test below keeps it out of the files.

The excerpts were then brought up to the 16 checks the script runs now (the kiosk, the process-state scan and the
account check were added): the four new check lines, the kiosk unit in the status stream (and no getty on tty1, which
the kiosk owns), the later check timestamps (the self-check now waits for the kiosk) and the harness's new memory
default are composed by hand in the script's own wording around the real captured lines. They are to be replaced by an
excerpt of a real boot of an image that has the kiosk (see "The serial-log fixtures" in
docs/development/BOOT_TESTING.md).

* serial_all_pass.log is the excerpt as it is.
* serial_one_failure.log is the same excerpt with one check line replaced by a failure (no-external-listeners, in the
  script's own wording from a boot whose systemd-resolved listened on the LLMNR port) and the summary changed to 15/16.
* serial_no_result.log is the same excerpt cut after the backend-health line, as if the console had been cut.
* serial_garbage.log is boot noise from a kernel and systemd with no self-check in it.

The harness writes control characters as visible markers, and so do the files: `<ESC>` is the escape character and
`<U+000D>` a carriage return; `load` turns them back. The tests also re-create CRLF line endings. The files stay plain,
diff-friendly text.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.end_to_end.selfcheck_output import (
    INSTALLED_ONLY_CHECKS,
    REQUIRED_CHECKS,
    CheckResult,
    parse_selfcheck,
    required_checks,
    selfcheck_problems,
)

FIXTURES = Path(__file__).parent / "fixtures"


_MARKER = re.compile(r"<U\+([0-9A-F]{4,6})>")


def load(name: str, *, crlf: bool = True) -> str:
    """A fixture as the serial console printed it: markers turned back into characters, optionally with CRLF lines."""
    text = (FIXTURES / name).read_text(encoding="utf-8").replace("<ESC>", "\x1b")
    text = _MARKER.sub(lambda marker: chr(int(marker[1], 16)), text)
    return text.replace("\n", "\r\n") if crlf else text


def line(name: str, status: str, detail: str) -> str:
    return f"PAI-SELFCHECK|{name}|{status}|{detail}"


ALL_PASS = "\n".join(
    [
        line("nft-default-drop", "PASS", "filter base chains with policy drop: input=1, forward=1, output=1"),
        line("modules-blocked", "PASS", "blocked and not loaded: x"),
        line("RESULT", "PASS", "2/2"),
    ]
)


def judge(text: str, required: tuple[str, ...] = ()) -> list[str]:
    """selfcheck_problems for text with made-up check names: by default no particular check is required."""
    return selfcheck_problems(parse_selfcheck(text), required)


def complete_run(**overrides: str) -> str:
    """Every required check passing, then a RESULT line; `overrides` maps a check name to a replacement line."""
    lines = [overrides.get(name) or line(name, "PASS", "ok") for name in REQUIRED_CHECKS]
    return "\n".join([*lines, line("RESULT", "PASS", f"{len(REQUIRED_CHECKS)}/{len(REQUIRED_CHECKS)}")])


# ---- parse_selfcheck ---------------------------------------------------------------------------------------------


def test_clean_lines_are_parsed_in_order() -> None:
    assert parse_selfcheck(ALL_PASS) == [
        CheckResult("nft-default-drop", True, "filter base chains with policy drop: input=1, forward=1, output=1"),
        CheckResult("modules-blocked", True, "blocked and not loaded: x"),
        CheckResult("RESULT", True, "2/2"),
    ]


def test_a_fail_status_is_not_a_pass() -> None:
    results = parse_selfcheck(line("sysctl-live", "FAIL", "kernel.sysrq: configured '0', live '16'"))
    assert results == [CheckResult("sysctl-live", False, "kernel.sysrq: configured '0', live '16'")]


def test_carriage_returns_are_not_part_of_the_detail() -> None:
    results = parse_selfcheck(ALL_PASS.replace("\n", "\r\n") + "\r\n")
    assert [result.detail for result in results][-1] == "2/2"


def test_a_journald_console_prefix_is_ignored() -> None:
    prefixed = "[   97.649615] security-selfcheck.sh[1060]: " + line("live-root", "PASS", "examining the live /proc")
    assert parse_selfcheck(prefixed) == [CheckResult("live-root", True, "examining the live /proc")]


def test_ansi_escapes_around_and_inside_a_line_are_removed() -> None:
    noisy = f"\x1b[0m\x1b[1;39m{line('units-active', 'PASS', 'active')}\x1b[0m\x1b[K"
    assert parse_selfcheck(noisy) == [CheckResult("units-active", True, "active")]


def test_kernel_messages_between_lines_do_not_hide_the_check_lines() -> None:
    text = "\n".join(
        [
            line("a", "PASS", "one"),
            "[  101.000001] random: crng init done",
            '[  101.000002] audit: type=1400 audit(1.2:3): apparmor="STATUS"',
            line("b", "FAIL", "two"),
        ]
    )
    assert [(r.name, r.passed) for r in parse_selfcheck(text)] == [("a", True), ("b", False)]


def test_a_line_cut_in_two_by_a_kernel_message_is_not_invented() -> None:
    cut = "PAI-SELFCHECK|sysctl-li[  102.5] usb 1-1: new device\nve|PASS|3 settings"
    assert parse_selfcheck(cut) == []


def test_a_truncated_final_line_is_not_a_result() -> None:
    assert parse_selfcheck("PAI-SELFCHECK|RESULT|PA") == []
    assert parse_selfcheck("PAI-SELFCHECK|RESULT|PASS") == []


def test_text_without_any_check_line_gives_nothing() -> None:
    assert parse_selfcheck("") == []
    assert parse_selfcheck("Linux version 6.12\nBooting...\n\x00\x01\x02 PAI-SELFCHECK without pipes\n") == []


def test_the_kernel_command_line_and_unit_description_are_not_check_lines() -> None:
    noise = (
        "Command line: boot=live components console=ttyS0 pai.selfcheck=1\n"
        "Starting pai-selfcheck.service - self-check...\n"
    )
    assert parse_selfcheck(noise) == []


def test_a_detail_may_contain_spaces_quotes_and_colons() -> None:
    result = parse_selfcheck(line("sysctl-live", "FAIL", "net.x: configured '0', live '1'; y: not readable"))[0]
    assert result.detail == "net.x: configured '0', live '1'; y: not readable"


# ---- selfcheck_problems ------------------------------------------------------------------------------------------


def test_a_complete_all_pass_run_has_no_problems() -> None:
    assert judge(ALL_PASS) == []


def test_no_output_at_all_is_a_problem() -> None:
    assert selfcheck_problems([]) != []


def test_a_boot_that_never_prints_the_result_line_is_a_failure_even_if_every_check_passed() -> None:
    results = parse_selfcheck("\n".join(ALL_PASS.splitlines()[:2]))
    problems = selfcheck_problems(results, required=())
    assert any("no final RESULT line" in problem for problem in problems)


def test_a_failing_check_is_reported_with_its_detail() -> None:
    text = ALL_PASS.replace(
        line("modules-blocked", "PASS", "blocked and not loaded: x"), line("modules-blocked", "FAIL", "x is loaded")
    )
    text = text.replace(line("RESULT", "PASS", "2/2"), line("RESULT", "FAIL", "1/2"))
    assert judge(text) == ["modules-blocked FAILED: x is loaded"]


def test_a_result_line_that_says_pass_cannot_hide_a_failed_check() -> None:
    text = ALL_PASS.replace(
        line("modules-blocked", "PASS", "blocked and not loaded: x"), line("modules-blocked", "FAIL", "x is loaded")
    )
    assert any("RESULT says PASS" in problem for problem in judge(text))


def test_lost_check_lines_are_detected_by_the_counts_in_the_summary() -> None:
    text = "\n".join([line("a", "PASS", "ok"), line("RESULT", "PASS", "3/3")])
    problems = judge(text)
    assert any("RESULT reports 3/3 but 1/1 check lines were seen" in problem for problem in problems)


def test_a_summary_without_counts_is_a_problem() -> None:
    text = "\n".join([line("a", "PASS", "ok"), line("RESULT", "PASS", "all good")])
    assert any("no <passed>/<total> counts" in problem for problem in judge(text))


def test_a_fail_summary_over_passing_checks_is_a_problem() -> None:
    text = "\n".join([line("a", "PASS", "ok"), line("RESULT", "FAIL", "1/1")])
    assert any("RESULT says FAIL" in problem for problem in judge(text))


def test_identical_repeated_lines_are_harmless() -> None:
    doubled = "\n".join([ALL_PASS, ALL_PASS])
    assert judge(doubled) == []


def test_conflicting_repeats_are_a_problem() -> None:
    text = "\n".join([line("a", "PASS", "ok"), line("a", "FAIL", "broken"), line("RESULT", "FAIL", "0/1")])
    problems = judge(text)
    assert any("conflicting results for check a" in problem for problem in problems)


def test_two_different_summaries_are_a_problem() -> None:
    text = "\n".join([line("a", "PASS", "ok"), line("RESULT", "PASS", "1/1"), line("RESULT", "FAIL", "0/1")])
    assert any("conflicting RESULT lines" in problem for problem in judge(text))


# ---- required checks ---------------------------------------------------------------------------------------------


def test_a_run_that_reports_every_required_check_is_accepted() -> None:
    assert selfcheck_problems(parse_selfcheck(complete_run())) == []


def test_a_pass_of_zero_checks_is_not_a_pass() -> None:
    zero = line("RESULT", "PASS", "0/0")
    assert any("no check lines" in problem for problem in selfcheck_problems(parse_selfcheck(zero)))
    assert any("no check lines" in problem for problem in judge(zero))  # also when nothing is required


def test_an_unrelated_check_with_a_matching_summary_is_not_a_pass() -> None:
    text = "\n".join([line("something-else", "PASS", "ok"), line("RESULT", "PASS", "1/1")])
    found = selfcheck_problems(parse_selfcheck(text))
    assert len(found) == 1
    assert found[0].startswith("required check(s) missing from the output: " + ", ".join(REQUIRED_CHECKS))


def test_every_missing_required_check_is_named() -> None:
    kept = [name for name in REQUIRED_CHECKS if name not in {"nft-default-drop", "no-external-listeners"}]
    text = "\n".join([*(line(name, "PASS", "ok") for name in kept), line("RESULT", "PASS", f"{len(kept)}/{len(kept)}")])
    (found,) = selfcheck_problems(parse_selfcheck(text))
    assert "nft-default-drop, no-external-listeners (" in found


def test_a_required_check_that_failed_is_reported_as_failed_not_as_missing() -> None:
    failing = line("modules-blocked", "FAIL", "x is loaded")
    n = len(REQUIRED_CHECKS)
    text = complete_run(**{"modules-blocked": failing}).replace(f"|PASS|{n}/{n}", f"|FAIL|{n - 1}/{n}")
    assert selfcheck_problems(parse_selfcheck(text)) == ["modules-blocked FAILED: x is loaded"]


def test_checks_beyond_the_required_ones_are_judged_like_the_others() -> None:
    n = len(REQUIRED_CHECKS) + 1
    extra_ok = complete_run().replace(
        line("RESULT", "PASS", f"{n - 1}/{n - 1}"),
        f"{line('extra', 'PASS', 'ok')}\n" + line("RESULT", "PASS", f"{n}/{n}"),
    )
    assert selfcheck_problems(parse_selfcheck(extra_ok)) == []
    extra_bad = extra_ok.replace(line("extra", "PASS", "ok"), line("extra", "FAIL", "bad")).replace(
        f"|PASS|{n}/{n}", f"|FAIL|{n - 1}/{n}"
    )
    assert selfcheck_problems(parse_selfcheck(extra_bad)) == ["extra FAILED: bad"]


def test_the_required_checks_can_be_overridden() -> None:
    text = "\n".join([line("a", "PASS", "ok"), line("RESULT", "PASS", "1/1")])
    assert judge(text, required=("a",)) == []
    assert any("missing" in problem and "b" in problem for problem in judge(text, required=("a", "b")))


def test_the_required_checks_have_no_duplicates() -> None:
    assert len(set(REQUIRED_CHECKS)) == len(REQUIRED_CHECKS)


# ---- captured-style serial logs ----------------------------------------------------------------------------------


@pytest.mark.parametrize("crlf", [True, False], ids=["crlf", "lf"])
def test_a_real_all_pass_log_is_accepted(crlf: bool) -> None:
    results = parse_selfcheck(load("serial_all_pass.log", crlf=crlf))
    assert selfcheck_problems(results) == []
    assert [result.name for result in results if result.name != "RESULT"] == list(REQUIRED_CHECKS)
    assert results[-1] == CheckResult("RESULT", True, f"{len(results) - 1}/{len(results) - 1}")


def test_the_real_log_fixtures_carry_the_serial_noise_the_parser_has_to_cope_with() -> None:
    text = load("serial_all_pass.log", crlf=False)
    assert "\x1b[0;32m" in text  # status colours
    assert "\r" in text  # carriage returns the console added itself
    assert "\x07" in text  # a terminal-reset sequence ending in BEL, right in front of the first check line
    assert "[    0.000000] Linux version" in text  # kernel messages
    assert len(parse_selfcheck(text)) == len(REQUIRED_CHECKS) + 1


def test_a_real_log_with_one_failing_check_names_that_check() -> None:
    results = parse_selfcheck(load("serial_one_failure.log"))
    problems = selfcheck_problems(results)
    assert len(problems) == 1
    assert problems[0].startswith("no-external-listeners FAILED: listening beyond loopback")
    assert results[-1] == CheckResult("RESULT", False, f"{len(REQUIRED_CHECKS) - 1}/{len(REQUIRED_CHECKS)}")


def test_a_real_log_cut_off_before_the_result_line_is_a_failure() -> None:
    results = parse_selfcheck(load("serial_no_result.log"))
    assert results, "the fixture is meant to contain some check lines"
    problems = selfcheck_problems(results)
    assert any("no final RESULT line" in problem for problem in problems)
    assert any("required check(s) missing" in problem and "backend-sandbox-exposure" in problem for problem in problems)


def test_a_boot_log_without_the_selfcheck_is_a_failure_not_a_pass() -> None:
    text = load("serial_garbage.log")
    assert parse_selfcheck(text) == []
    assert selfcheck_problems(parse_selfcheck(text)) != []


def test_no_fixture_holds_a_bearer_token() -> None:
    """The script never prints the backend's token; a console log that did would not belong in the repository."""
    for fixture in FIXTURES.glob("serial_*.log"):
        text = fixture.read_text(encoding="utf-8")
        assert "Bearer" not in text, fixture.name
        for mention in re.finditer(r"token", text, re.IGNORECASE):
            around = text[max(0, mention.start() - 40) : mention.end() + 20]
            # Only the script's own wording ("published its token file", "bearer token or a session cookie",
            # "the bearer token is in none of them") and
            # kernel/systemd text about other tokens.
            assert re.search(
                r"token file|bearer token (?:is in none|or a session cookie)|MPTCP token|ask-password", around
            ), f"{fixture.name}: {around!r}"


# ---- installed systems: the required set depends on what was booted --------------------------------------------------


def installed_run(**overrides: str) -> str:
    """Every required check of an installed system passing, then a RESULT line; `overrides` as in complete_run."""
    names = required_checks(installed=True)
    lines = [overrides.get(name) or line(name, "PASS", "ok") for name in names]
    return "\n".join([*lines, line("RESULT", "PASS", f"{len(names)}/{len(names)}")])


def test_a_live_boot_requires_the_sixteen_and_an_installed_one_adds_exactly_the_installed_only_checks() -> None:
    assert required_checks(installed=False) == REQUIRED_CHECKS
    assert required_checks(installed=True) == (*REQUIRED_CHECKS, *INSTALLED_ONLY_CHECKS)
    assert len(REQUIRED_CHECKS) == 16
    assert len(required_checks(installed=True)) == 18


def test_the_installed_only_checks_are_new_names_without_duplicates() -> None:
    assert len(set(INSTALLED_ONLY_CHECKS)) == len(INSTALLED_ONLY_CHECKS)
    assert not set(INSTALLED_ONLY_CHECKS) & set(REQUIRED_CHECKS)


def test_a_complete_installed_run_passes_only_when_judged_as_installed() -> None:
    results = parse_selfcheck(installed_run())
    assert selfcheck_problems(results, installed=True) == []
    live_view = selfcheck_problems(results)  # the same output judged as a live boot
    assert len(live_view) == 1
    assert live_view[0].startswith("installed-only check(s) reported by a live boot: root-encrypted, no-live-remnants")


def test_a_live_run_is_not_enough_for_an_installed_system_and_both_missing_checks_are_named() -> None:
    (found,) = selfcheck_problems(parse_selfcheck(complete_run()), installed=True)
    assert found.startswith("required check(s) missing from the output: root-encrypted, no-live-remnants (")


def test_an_installed_run_that_lost_one_installed_only_check_names_it() -> None:
    names = required_checks(installed=True)
    kept = [name for name in names if name != "root-encrypted"]
    text = "\n".join([*(line(name, "PASS", "ok") for name in kept), line("RESULT", "PASS", f"{len(kept)}/{len(kept)}")])
    (found,) = selfcheck_problems(parse_selfcheck(text), installed=True)
    assert "root-encrypted (" in found
    assert "no-live-remnants" not in found


@pytest.mark.parametrize("name", INSTALLED_ONLY_CHECKS)
def test_a_failing_installed_only_check_is_reported_as_failed(name: str) -> None:
    n = len(required_checks(installed=True))
    text = installed_run(**{name: line(name, "FAIL", "broken")}).replace(f"|PASS|{n}/{n}", f"|FAIL|{n - 1}/{n}")
    assert selfcheck_problems(parse_selfcheck(text), installed=True) == [f"{name} FAILED: broken"]


def test_an_installed_run_whose_summary_still_counts_sixteen_is_a_failure() -> None:
    n = len(required_checks(installed=True))
    text = installed_run().replace(f"|PASS|{n}/{n}", "|PASS|16/16")
    problems = selfcheck_problems(parse_selfcheck(text), installed=True)
    assert any("RESULT reports 16/16 but 18/18 check lines were seen" in problem for problem in problems)


def test_a_real_installed_log_is_accepted_as_installed_and_refused_as_live() -> None:
    results = parse_selfcheck(load("serial_installed_all_pass.log"))
    assert selfcheck_problems(results, installed=True) == []
    assert [result.name for result in results if result.name != "RESULT"] == list(required_checks(installed=True))
    assert results[-1] == CheckResult("RESULT", True, "18/18")
    assert selfcheck_problems(results) != []
