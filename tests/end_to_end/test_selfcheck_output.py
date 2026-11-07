"""Fast tests (no Docker) for reading the self-check verdict from serial console output.

The fixtures in tests/end_to_end/fixtures are excerpts of real serial logs of the live image under QEMU: boot noise,
systemd status lines with ANSI colours, and the journald console prefix on every self-check line. They were captured
with the shipped unit and script installed into a booted guest, because the ISO had not been rebuilt with them yet;
the all-pass capture also had a systemd-resolved drop-in (LLMNR=no) applied, see docs/development/BOOT_TESTING.md.
In the files `<ESC>` stands for the escape character, and the tests re-create CRLF line endings, so the files stay
plain, diff-friendly text.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.end_to_end.selfcheck_output import REQUIRED_CHECKS, CheckResult, parse_selfcheck, selfcheck_problems

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str, *, crlf: bool = True) -> str:
    text = (FIXTURES / name).read_text(encoding="utf-8").replace("<ESC>", "\x1b")
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
    assert results[-1] == CheckResult("RESULT", True, f"{len(results) - 1}/{len(results) - 1}")


def test_a_real_log_with_one_failing_check_names_that_check() -> None:
    results = parse_selfcheck(load("serial_one_failure.log"))
    problems = selfcheck_problems(results)
    assert len(problems) == 1
    assert problems[0].startswith("no-external-listeners FAILED: listening beyond loopback")
    assert results[-1].passed is False


def test_a_real_log_cut_off_before_the_result_line_is_a_failure() -> None:
    results = parse_selfcheck(load("serial_no_result.log"))
    assert results, "the fixture is meant to contain some check lines"
    assert any("no final RESULT line" in problem for problem in selfcheck_problems(results))


def test_a_boot_log_without_the_selfcheck_is_a_failure_not_a_pass() -> None:
    text = load("serial_garbage.log")
    assert parse_selfcheck(text) == []
    assert selfcheck_problems(parse_selfcheck(text)) != []
