"""Fast tests (no Docker) for what the install test reads from, and types into, a guest's serial console: the engine's
events, the unlock prompt, the watchers that end a run, the scrubbing of secrets and the verdicts built from them."""

from __future__ import annotations

import json
import re

import pytest

from tests.end_to_end.install_console import (
    INITRAMFS_GAVE_UP,
    PROMPT_WINDOW,
    REDACTED,
    FirstOf,
    InstallEvent,
    PromptDetector,
    PromptTyper,
    Scrubber,
    UnlockFailedWatcher,
    booted_markers,
    install_problems,
    installed_boot_problems,
    last_step,
    parse_install_events,
    wrong_passphrase_problems,
)
from tests.end_to_end.install_plan import Secret
from tests.end_to_end.selfcheck_output import required_checks

PASSPHRASE = Secret("pass-phrase-for-the-tests-0123")

# ---- engine events ---------------------------------------------------------------------------------------------------


def step(name: str, state: str, detail: str = "") -> str:
    return json.dumps({"event": "step", "name": name, "state": state, "detail": detail})


def result(ok: bool, error: str = "") -> str:
    return json.dumps({"event": "result", "ok": ok, "error": error})


GOOD_RUN = "\n".join(
    [step("partition", "start"), step("partition", "done"), step("grub", "start"), step("grub", "done"), result(True)]
)


def problems(text: str, *, timed_out: bool = False, powered_off: bool = True, echoed: bool = False) -> list[str]:
    return install_problems(
        parse_install_events(text), timed_out=timed_out, powered_off=powered_off, echoed_secret=echoed
    )


def test_events_are_read_in_order_with_their_fields() -> None:
    parsed = parse_install_events(
        step("partition", "done", "GPT, 4 partitions") + "\n" + result(False, "disk too small")
    )
    assert parsed.events == (
        InstallEvent("step", name="partition", state="done", detail="GPT, 4 partitions"),
        InstallEvent("result", ok=False, error="disk too small"),
    )
    assert parsed.malformed == 0


def test_events_are_found_between_kernel_messages_escape_sequences_and_carriage_returns() -> None:
    text = "\r\n".join(
        [
            "[  12.000001] random: crng init done",
            "\x1b[0;32m[  OK  ]\x1b[0m Started pai-install-auto.service",
            f"[  13.5] pai-install-auto[321]: {step('luks', 'start')}\x1b[K",
            "\x1b[2J" + result(True),
            "[  99.9] reboot: Power down",
        ]
    )
    parsed = parse_install_events(text)
    assert [(event.event, event.name) for event in parsed.events] == [("step", "luks"), ("result", "")]
    assert parsed.malformed == 0


def test_a_line_that_is_cut_or_not_json_is_counted_and_not_returned() -> None:
    cut = step("partition", "done")[:-5]
    parsed = parse_install_events(cut + "\n" + '{"event": nonsense}\n' + result(True))
    assert [event.event for event in parsed.events] == ["result"]
    assert parsed.malformed == 2


@pytest.mark.parametrize(
    "document",
    [
        {"event": "step", "state": "done"},  # no name
        {"event": "step", "name": "x", "state": "halfway"},  # unknown state
        {"event": "step", "name": 7, "state": "done"},
        {"event": "result"},  # no ok
        {"event": "result", "ok": "yes"},  # ok is not a boolean
        {"event": "result", "ok": True, "error": ["a"]},
        {"event": 5},
    ],
)
def test_an_event_of_the_wrong_shape_is_malformed(document: dict[str, object]) -> None:
    parsed = parse_install_events(json.dumps(document))
    assert parsed.events == ()
    assert parsed.malformed == 1


def test_an_event_kind_the_engine_adds_later_is_kept_and_not_judged() -> None:
    parsed = parse_install_events('{"event": "progress", "percent": 40}\n' + GOOD_RUN)
    assert parsed.events[0] == InstallEvent("progress")
    assert problems('{"event": "progress", "percent": 40}\n' + GOOD_RUN) == []


def test_json_lines_that_are_not_events_are_ignored() -> None:
    parsed = parse_install_events('{"hello": "world"}\n[1, 2]\nplain text\n')
    assert (parsed.events, parsed.malformed) == ((), 0)


def test_a_missing_optional_field_is_an_empty_string() -> None:
    parsed = parse_install_events('{"event": "step", "name": "x", "state": "start"}')
    assert parsed.events == (InstallEvent("step", name="x", state="start", detail=""),)


def test_the_last_step_is_named_for_a_failure_message() -> None:
    assert last_step(parse_install_events(step("a", "done") + "\n" + step("b", "start"))) == "b (start)"
    assert last_step(parse_install_events("")) == "no step was reported"


# ---- the install verdict ---------------------------------------------------------------------------------------------


def test_a_finished_successful_install_that_powered_off_has_no_problem() -> None:
    assert problems(GOOD_RUN) == []


def test_a_console_without_any_event_says_where_to_look() -> None:
    (found,) = problems("[ 1.0] booted\n")
    assert "printed no events" in found and "PAI-PLAN" in found and "pai.install=auto" in found


def test_events_without_a_result_mean_the_engine_did_not_finish() -> None:
    (found,) = problems(step("luks", "start"), powered_off=False)
    assert found == "no result event: the engine did not finish; last step: luks (start)"


def test_a_failed_result_carries_the_engines_reason_and_every_failed_step() -> None:
    text = "\n".join([step("partition", "done"), step("luks", "failed", "no space"), result(False, "luks failed")])
    assert problems(text) == ["the engine reported failure: luks failed", "step luks failed: no space"]


def test_a_failed_result_without_text_is_still_a_failure() -> None:
    assert problems(step("a", "done") + "\n" + result(False)) == ["the engine reported failure: no error text"]


def test_an_ok_result_with_a_failed_step_is_inconsistent_and_fails() -> None:
    text = "\n".join([step("a", "failed", "x"), result(True)])
    assert problems(text) == ["the result says ok but step a failed: x"]


def test_an_ok_result_with_a_step_that_never_finished_fails() -> None:
    text = "\n".join([step("a", "done"), step("b", "start"), result(True)])
    assert problems(text) == ["the result says ok but step b started and never finished"]


def test_an_ok_result_without_any_step_fails() -> None:
    assert problems(result(True)) == ["the result says ok but the engine reported no step at all"]


def test_conflicting_results_fail() -> None:
    (found,) = problems(GOOD_RUN + "\n" + result(False, "later failure"))
    assert found.startswith("conflicting result events")


def test_the_same_result_printed_twice_is_not_a_conflict() -> None:
    assert problems(GOOD_RUN + "\n" + result(True)) == []


def test_a_timeout_comes_first_and_names_the_last_step() -> None:
    found = problems(step("rsync", "start"), timed_out=True, powered_off=False)
    assert found[0] == "the install did not finish within the timeout; last step: rsync (start)"


def test_a_guest_that_did_not_power_off_after_a_result_is_a_problem() -> None:
    assert problems(GOOD_RUN, powered_off=False) == [
        "the guest did not power itself off after the install (the plan says after=poweroff)"
    ]


def test_an_engine_that_printed_the_passphrase_fails_the_install() -> None:
    (found,) = problems(GOOD_RUN, echoed=True)
    assert "passphrase appeared on the console" in found


def test_malformed_event_lines_fail_even_when_the_rest_is_fine() -> None:
    (found,) = problems(GOOD_RUN + '\n{"event": "step", "name": "x"')
    assert found.startswith("1 console line(s) began like an engine event")


# ---- the unlock prompt -----------------------------------------------------------------------------------------------

PROMPT = "Please unlock disk cryptroot: "


def test_a_prompt_without_a_newline_is_seen_at_once() -> None:
    detector = PromptDetector()
    assert detector.feed("loading...\r\n" + PROMPT) == 1


def test_a_prompt_cut_in_two_chunks_is_seen_when_it_is_complete() -> None:
    detector = PromptDetector()
    assert detector.feed("Please unlock di") == 0
    assert detector.feed("sk cryptroot") == 0
    assert detector.feed(": ") == 1


@pytest.mark.parametrize(
    "prompt",
    [
        "Please unlock disk cryptroot: ",
        "Please unlock disk luks-0123-4567:",
        "Enter passphrase for /dev/vda4: ",
        "Please enter passphrase for disk cryptroot:",
        "\x1b[1mPlease unlock disk cryptroot: \x1b[0m",
        "Please unlock disk cryptroot:\t",
    ],
)
def test_the_known_wordings_of_the_prompt_are_recognised(prompt: str) -> None:
    assert PromptDetector().feed(prompt) == 1


@pytest.mark.parametrize(
    "text",
    [
        "Please unlock disk",
        "Please unlock disk cryptroot",
        "unlock the disk: ",
        "Enter passphrase",
        "cryptsetup: starting",
    ],
)
def test_text_that_is_not_a_prompt_is_not_one(text: str) -> None:
    assert PromptDetector().feed(text) == 0


def test_the_same_prompt_is_not_counted_twice_and_the_next_one_is() -> None:
    detector = PromptDetector()
    assert detector.feed(PROMPT) == 1
    assert detector.feed("  ") == 0
    assert detector.feed("No key available with this passphrase.\r\n" + PROMPT) == 1


def test_two_prompts_in_one_chunk_are_two() -> None:
    assert PromptDetector().feed(PROMPT + "\r\nretry\r\n" + PROMPT) == 2


def test_the_detector_remembers_a_bounded_amount_of_text() -> None:
    detector = PromptDetector()
    detector.feed("x" * (PROMPT_WINDOW * 5))
    assert len(detector._buffer) <= PROMPT_WINDOW
    assert detector.feed(PROMPT) == 1


# ---- typing ----------------------------------------------------------------------------------------------------------


class Keyboard:
    def __init__(self) -> None:
        self.typed: list[str] = []

    def __call__(self, text: str) -> None:
        self.typed.append(text)


def test_the_passphrase_is_typed_at_the_prompt_with_a_newline_and_only_then() -> None:
    keyboard = Keyboard()
    typer = PromptTyper([PASSPHRASE])
    assert typer.feed("booting...\r\n", keyboard) is False
    assert keyboard.typed == []
    typer.feed(PROMPT, keyboard)
    assert keyboard.typed == [PASSPHRASE.reveal() + "\n"]
    assert (typer.prompts_seen, typer.typed) == (1, 1)


def test_passphrases_are_typed_one_per_prompt_in_order() -> None:
    keyboard = Keyboard()
    typer = PromptTyper([Secret("first-first-first"), Secret("second-second-2")])
    for _ in range(2):
        typer.feed(PROMPT, keyboard)
    assert keyboard.typed == ["first-first-first\n", "second-second-2\n"]


def test_a_prompt_after_the_last_passphrase_is_counted_and_not_answered() -> None:
    keyboard = Keyboard()
    typer = PromptTyper([PASSPHRASE])
    typer.feed(PROMPT, keyboard)
    typer.feed(PROMPT, keyboard)
    assert (typer.prompts_seen, typer.typed) == (2, 1)
    assert len(keyboard.typed) == 1


def test_the_typer_stamps_when_it_typed_and_never_ends_the_run_itself() -> None:
    now = [100.0]
    typer = PromptTyper([PASSPHRASE], clock=lambda: now[0])
    assert typer.last_typed_at is None
    assert typer.feed(PROMPT, Keyboard()) is False
    assert typer.last_typed_at == 100.0
    assert typer.poll(Keyboard()) is False


# ---- ending a run of wrong passphrases -------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def watcher(attempts: int = 2, settle_s: float = 60.0) -> tuple[PromptTyper, UnlockFailedWatcher, Clock, Keyboard]:
    clock = Clock()
    typer = PromptTyper([Secret("wrong-one-wrong-one"), Secret("wrong-two-wrong-two")], clock=clock)
    return typer, UnlockFailedWatcher(typer, attempts=attempts, settle_s=settle_s, clock=clock), clock, Keyboard()


def feed_both(typer: PromptTyper, watching: UnlockFailedWatcher, keyboard: Keyboard, text: str) -> bool:
    typer.feed(text, keyboard)
    return watching.feed(text, keyboard)


def test_the_run_goes_on_while_attempts_are_still_to_be_made_however_quiet_it_is() -> None:
    typer, watching, clock, keyboard = watcher()
    feed_both(typer, watching, keyboard, PROMPT)
    clock.now = 10_000
    assert watching.poll(keyboard) is False


def test_the_run_ends_when_the_guest_gives_up_after_the_last_attempt() -> None:
    typer, watching, _, keyboard = watcher()
    feed_both(typer, watching, keyboard, PROMPT)
    feed_both(typer, watching, keyboard, "No key available\r\n" + PROMPT)
    assert feed_both(typer, watching, keyboard, "ALERT! /dev/mapper/x does not exist. Dropping to a shell!\r\n") is True
    assert watching.poll(keyboard) is True


def test_a_give_up_message_before_the_last_attempt_does_not_end_the_run() -> None:
    typer, watching, _, keyboard = watcher()
    feed_both(typer, watching, keyboard, PROMPT)
    assert feed_both(typer, watching, keyboard, "Dropping to a shell\r\n") is False


def test_the_run_ends_when_the_guest_falls_silent_after_the_last_attempt() -> None:
    typer, watching, clock, keyboard = watcher(settle_s=60)
    feed_both(typer, watching, keyboard, PROMPT)
    feed_both(typer, watching, keyboard, PROMPT)
    clock.now = 59
    assert watching.poll(keyboard) is False
    clock.now = 61
    assert watching.poll(keyboard) is True


def test_output_restarts_the_silence() -> None:
    typer, watching, clock, keyboard = watcher(settle_s=60)
    feed_both(typer, watching, keyboard, PROMPT)
    feed_both(typer, watching, keyboard, PROMPT)
    clock.now = 50
    watching.feed("[  50.0] something\r\n", keyboard)
    clock.now = 100
    assert watching.poll(keyboard) is False
    clock.now = 111
    assert watching.poll(keyboard) is True


@pytest.mark.parametrize(
    "text", ["Gave up waiting for root file system device.", "Dropping to a shell!", "(initramfs) "]
)
def test_the_initramfs_give_up_messages_are_recognised(text: str) -> None:
    assert INITRAMFS_GAVE_UP.search(text)


def test_first_of_feeds_every_handler_and_ends_when_any_says_so() -> None:
    class Spy:
        def __init__(self, answer: bool) -> None:
            self.answer, self.fed, self.polled = answer, [], 0

        def feed(self, chunk: str, send: object) -> bool:
            self.fed.append(chunk)
            return self.answer

        def poll(self, send: object) -> bool:
            self.polled += 1
            return self.answer

    first, second = Spy(True), Spy(False)
    combined = FirstOf(first, second)
    assert combined.feed("x", Keyboard()) is True
    assert second.fed == ["x"]  # not skipped because the first already answered
    assert combined.poll(Keyboard()) is True
    assert second.polled == 1
    assert FirstOf(Spy(False), Spy(False)).feed("x", Keyboard()) is False


# ---- scrubbing -------------------------------------------------------------------------------------------------------


def test_a_known_secret_is_replaced_and_counted() -> None:
    scrubber = Scrubber([PASSPHRASE])
    text = f"echo: {PASSPHRASE.reveal()} and again {PASSPHRASE.reveal()}\n"
    clean = scrubber.scrub(text)
    assert PASSPHRASE.reveal() not in clean
    assert clean == f"echo: {REDACTED} and again {REDACTED}\n"
    assert scrubber.hits == 2


def test_text_without_a_secret_is_unchanged_and_counts_nothing() -> None:
    scrubber = Scrubber([PASSPHRASE])
    assert scrubber.scrub("nothing to see\n") == "nothing to see\n"
    assert scrubber.hits == 0


def test_a_secret_too_short_to_tell_from_ordinary_text_is_not_scrubbed() -> None:
    scrubber = Scrubber([Secret("short")])
    assert scrubber.scrub("a short text") == "a short text"
    assert scrubber.hits == 0


def test_the_longer_secret_is_replaced_before_one_it_contains() -> None:
    scrubber = Scrubber([Secret("abcdefgh"), Secret("abcdefghijkl")])
    assert scrubber.scrub("abcdefghijkl") == REDACTED
    assert scrubber.hits == 1


def test_several_secrets_are_all_replaced() -> None:
    scrubber = Scrubber([Secret("first-secret-1"), Secret("second-secret-2")])
    assert scrubber.scrub("first-secret-1 second-secret-2") == f"{REDACTED} {REDACTED}"


# ---- verdicts --------------------------------------------------------------------------------------------------------


def selfcheck_text(*, installed: bool = True, drop: str | None = None, fail: str | None = None) -> str:
    names = [name for name in required_checks(installed=installed) if name != drop]
    lines = [f"PAI-SELFCHECK|{name}|{'FAIL' if name == fail else 'PASS'}|ok" for name in names]
    failed = 1 if fail else 0
    summary = f"PAI-SELFCHECK|RESULT|{'FAIL' if failed else 'PASS'}|{len(names) - failed}/{len(names)}"
    return "\n".join([*lines, summary])


def boot_problems(text: str, **kwargs: object) -> list[str]:
    defaults = {"prompts_seen": 1, "typed": 1, "timed_out": False, "powered_off": True, "echoed_secret": False}
    return installed_boot_problems(text, **{**defaults, **kwargs})  # type: ignore[arg-type]


def test_a_clean_installed_boot_has_no_problem() -> None:
    assert boot_problems("Please unlock disk x: \n" + selfcheck_text()) == []


def test_an_installed_boot_needs_all_eighteen_checks() -> None:
    (found,) = boot_problems(selfcheck_text(installed=False))
    assert found.startswith("required check(s) missing from the output: root-encrypted, no-live-remnants")
    (found,) = boot_problems(selfcheck_text(drop="no-live-remnants"))
    assert "no-live-remnants (" in found


def test_a_failing_check_on_an_installed_boot_is_named() -> None:
    assert boot_problems(selfcheck_text(fail="root-encrypted")) == ["root-encrypted FAILED: ok"]


def test_a_boot_that_never_asked_for_the_passphrase_says_so_and_still_fails_for_the_missing_selfcheck() -> None:
    found = boot_problems("[ 1.0] GRUB loading\n", prompts_seen=0, typed=0)
    assert any("unlock prompt never appeared" in problem and "console=ttyS0" in problem for problem in found)
    assert any("no PAI-SELFCHECK output" in problem for problem in found)


def test_a_prompt_that_came_back_means_the_passphrase_was_not_accepted() -> None:
    found = boot_problems(selfcheck_text(), prompts_seen=2, typed=1)
    assert any("appeared 2 times but the passphrase was typed 1" in problem for problem in found)


def test_a_timeout_a_missing_power_off_and_an_echoed_secret_are_each_reported() -> None:
    assert any("did not finish within the timeout" in p for p in boot_problems(selfcheck_text(), timed_out=True))
    assert any("did not power itself off" in p for p in boot_problems(selfcheck_text(), powered_off=False))
    assert any("passphrase appeared on the console" in p for p in boot_problems(selfcheck_text(), echoed_secret=True))


def test_no_power_off_message_is_added_on_top_of_a_timeout() -> None:
    found = boot_problems(selfcheck_text(), timed_out=True, powered_off=False)
    assert not any("did not power itself off" in problem for problem in found)


def wrong(text: str, **kwargs: object) -> list[str]:
    defaults = {"prompts_seen": 3, "typed": 3, "attempts": 3, "echoed_secret": False}
    return wrong_passphrase_problems(text, **{**defaults, **kwargs})  # type: ignore[arg-type]


def test_wrong_passphrases_that_leave_the_system_at_the_prompt_prove_it_stays_locked() -> None:
    text = "Please unlock disk x: \nNo key available with this passphrase.\n" * 3 + "Dropping to a shell\n"
    assert wrong(text) == []


@pytest.mark.parametrize(
    ("text", "marker"),
    [
        ("PAI-SELFCHECK|live-root|PASS|ok\n", "a PAI-SELFCHECK line"),
        ("paitest-host login: \r\n", "a login prompt"),
        ("[  OK  ] Reached target multi-user.target - Multi-User System.\n", "systemd reaching the multi-user target"),
    ],
)
def test_a_system_that_came_up_despite_wrong_passphrases_is_a_failure(text: str, marker: str) -> None:
    (found,) = wrong(text)
    assert found == f"the system came up although every passphrase was wrong: {marker}"


def test_a_run_that_never_saw_the_prompt_proves_nothing() -> None:
    (found,) = wrong("[ 1.0] GRUB\n", prompts_seen=0, typed=0)
    assert found.startswith("inconclusive: the disk-unlock prompt never appeared")


def test_a_run_that_ended_before_every_attempt_proves_nothing() -> None:
    (found,) = wrong("x", prompts_seen=2, typed=2)
    assert found == "inconclusive: only 2 of 3 wrong passphrases were typed before the run ended"


def test_a_wrong_passphrase_on_the_console_is_reported() -> None:
    assert any("a passphrase appeared on the console" in p for p in wrong("x", echoed_secret=True))


def test_booted_markers_see_through_escapes_and_carriage_returns() -> None:
    assert booted_markers("\x1b[0mhost login: \r\n") == ["a login prompt"]
    assert booted_markers("please login: later\n") == []  # not at the end of a line
    assert booted_markers("nothing\n") == []


def test_the_prompt_words_of_the_verdicts_match_the_ones_the_detector_knows() -> None:
    assert re.search(r"Please unlock disk", PROMPT)
