"""What the install test reads from, and types into, a guest's serial console. Pure: no Docker, no QEMU, no clock but
the one a caller injects.

Three producers write to the console and each is read here:

* the installer engine's JSON-lines events (docs/architecture/INSTALLER_DESIGN.md): `{"event": "step", ...}` lines and
  one final `{"event": "result", ...}`; `parse_install_events` and `install_problems`;
* the installed system's initramfs, which asks for the disk passphrase at an unterminated prompt; `PromptDetector`,
  `PromptTyper` and the watchers that decide when a boot is over;
* the installed system's self-check verdict, read by selfcheck_output.py.

Everything that is missing counts against the run: no events, no result, a prompt that never appeared, a self-check
that never reported. A console that is untrusted (it comes from an image under test) is only ever parsed, never
executed or printed raw. `Scrubber` removes the secrets the test knows from anything that is stored or shown.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from tests.end_to_end.install_plan import Secret
from tests.end_to_end.selfcheck_output import parse_selfcheck, selfcheck_problems, strip_terminal_escapes

# ---- the engine's events ---------------------------------------------------------------------------------------------

STEP_STATES = frozenset({"start", "done", "failed"})
_EVENT_START = re.compile(r'\{\s*"event"\s*:')


@dataclass(frozen=True)
class InstallEvent:
    """One engine event. `event` is "step" or "result" (or a kind a later engine adds, which is kept and not judged)."""

    event: str
    name: str = ""  # step: its name
    state: str = ""  # step: start, done or failed
    detail: str = ""  # step: free text the engine chose
    ok: bool | None = None  # result: whether the install finished and verified
    error: str = ""  # result: why not


@dataclass(frozen=True)
class ParsedEvents:
    events: tuple[InstallEvent, ...]
    malformed: int  # lines that began like an event but were cut, not JSON, or of the wrong shape

    @property
    def results(self) -> tuple[InstallEvent, ...]:
        return tuple(event for event in self.events if event.event == "result")

    @property
    def steps(self) -> tuple[InstallEvent, ...]:
        return tuple(event for event in self.events if event.event == "step")


def _event_from(document: object) -> InstallEvent | None:
    """The event a decoded JSON object stands for, or None when its shape is wrong."""
    if not isinstance(document, dict) or not isinstance(document.get("event"), str):
        return None
    kind = document["event"]
    text = {key: document.get(key, "") for key in ("name", "state", "detail", "error")}
    if any(value is not None and not isinstance(value, str) for value in text.values()):
        return None
    name, state, detail, error = (value or "" for value in text.values())
    if kind == "step":
        if not name or state not in STEP_STATES:
            return None
        return InstallEvent("step", name=name, state=state, detail=detail)
    if kind == "result":
        ok = document.get("ok")
        return InstallEvent("result", ok=ok, error=error) if isinstance(ok, bool) else None
    return InstallEvent(kind)


def parse_install_events(text: str) -> ParsedEvents:
    """Every engine event in `text`, in order. A serial console puts kernel messages and escape sequences around (and
    sometimes in front of) the lines, so each line is searched for the start of an event object."""
    events: list[InstallEvent] = []
    malformed = 0
    decoder = json.JSONDecoder()
    for line in strip_terminal_escapes(text).splitlines():
        start = _EVENT_START.search(line)
        if start is None:
            continue
        try:
            document, _ = decoder.raw_decode(line[start.start() :])
        except ValueError:
            malformed += 1
            continue
        if (event := _event_from(document)) is None:
            malformed += 1
        else:
            events.append(event)
    return ParsedEvents(tuple(events), malformed)


def last_step(parsed: ParsedEvents) -> str:
    """A phrase naming the engine's last reported step, for a failure message."""
    steps = parsed.steps
    return f"{steps[-1].name} ({steps[-1].state})" if steps else "no step was reported"


def install_problems(parsed: ParsedEvents, *, timed_out: bool, powered_off: bool, echoed_secret: bool) -> list[str]:
    """Why this console is not a finished, successful install followed by a power-off; empty when it is."""
    problems: list[str] = []
    if timed_out:
        problems.append(f"the install did not finish within the timeout; last step: {last_step(parsed)}")
    if not parsed.events:
        problems.append(
            "the engine printed no events: pai-install-auto.service did not run it (pai.install=auto on the kernel "
            "line, a block device labelled PAI-PLAN with plan.json, the unit enabled?) or its output was lost"
        )
    if parsed.malformed:
        problems.append(f"{parsed.malformed} console line(s) began like an engine event but could not be read as one")
    results = set(parsed.results)
    if not results:
        if parsed.events:
            problems.append(f"no result event: the engine did not finish; last step: {last_step(parsed)}")
    elif len(results) > 1:
        problems.append("conflicting result events: " + "; ".join(f"ok={r.ok} {r.error}".strip() for r in results))
    else:
        (result,) = results
        failed = [
            f"step {step.name} failed: {step.detail or 'no detail'}" for step in parsed.steps if step.state == "failed"
        ]
        if result.ok:
            problems.extend(f"the result says ok but {text}" for text in failed)
            problems.extend(_unfinished_steps(parsed))
            if not parsed.steps:
                problems.append("the result says ok but the engine reported no step at all")
        else:
            problems.append(f"the engine reported failure: {result.error or 'no error text'}")
            problems.extend(failed)
    if not powered_off and not timed_out and results:
        problems.append("the guest did not power itself off after the install (the plan says after=poweroff)")
    if echoed_secret:
        problems.append("the passphrase appeared on the console (scrubbed from the saved log): a secret was printed")
    return problems


def _unfinished_steps(parsed: ParsedEvents) -> list[str]:
    state: dict[str, str] = {}
    for step in parsed.steps:
        state[step.name] = step.state
    return [
        f"the result says ok but step {name} started and never finished" for name, s in state.items() if s == "start"
    ]


# ---- the disk-unlock prompt ------------------------------------------------------------------------------------------

# How the guest asks for a LUKS passphrase on the console: the initramfs's cryptroot script ("Please unlock disk"), the
# cryptsetup program's own prompt, and systemd-ask-password's wording. Each ends in ":" and then no newline.
UNLOCK_PROMPTS: tuple[re.Pattern[str], ...] = (
    re.compile(r"Please unlock disk \S+:[ \t]*"),
    re.compile(r"Enter passphrase for \S+:[ \t]*"),
    re.compile(r"Please enter passphrase for disk \S+:[ \t]*"),
)
PROMPT_WINDOW = 1024  # characters of console kept to find a prompt that arrives in pieces


class PromptDetector:
    """Counts passphrase prompts in console text that arrives in arbitrary chunks (a prompt has no trailing newline, so
    it is not a line; it can also be cut in two chunks)."""

    def __init__(self, patterns: Sequence[re.Pattern[str]] = UNLOCK_PROMPTS) -> None:
        self._patterns = tuple(patterns)
        self._buffer = ""

    def feed(self, chunk: str) -> int:
        """The number of prompts this chunk completed. Text up to the last prompt is dropped so none counts twice."""
        self._buffer = (self._buffer + strip_terminal_escapes(chunk).replace("\r", ""))[-PROMPT_WINDOW:]
        found = 0
        while True:
            ends = [match.end() for pattern in self._patterns if (match := pattern.search(self._buffer))]
            if not ends:
                return found
            found += 1
            self._buffer = self._buffer[min(ends) :]


# ---- reacting to the console (handlers for boot_harness.stream_container) --------------------------------------------
#
# A handler has feed(chunk, send) -> bool and poll(send) -> bool: both return True when the run has reached its goal and
# should end (after a short grace period). `send` types text on the guest's console.


class PromptTyper:
    """Types the next passphrase of `passphrases` at each prompt, in order, and counts what it saw and typed.

    A prompt beyond the last passphrase is counted and not answered: the guest asks again after a failed unlock, and
    answering with something else would be guessing. The typed text is never stored anywhere but in `send`'s argument.
    """

    def __init__(self, passphrases: Sequence[Secret], *, clock: Callable[[], float] = time.monotonic) -> None:
        self._passphrases = tuple(passphrases)
        self._detector = PromptDetector()
        self._clock = clock
        self.prompts_seen = 0
        self.typed = 0
        self.last_typed_at: float | None = None

    def feed(self, chunk: str, send: Callable[[str], None]) -> bool:
        for _ in range(self._detector.feed(chunk)):
            self.prompts_seen += 1
            if self.typed < len(self._passphrases):
                send(self._passphrases[self.typed].reveal() + "\n")
                self.typed += 1
                self.last_typed_at = self._clock()
        return False

    def poll(self, send: Callable[[str], None]) -> bool:
        return False


# What the initramfs prints when it gives up on an encrypted root: after the last attempt there is nothing more to
# wait for.
INITRAMFS_GAVE_UP = re.compile(r"Gave up waiting for root|Dropping to a shell|\(initramfs\)")


class UnlockFailedWatcher:
    """Ends a run of wrong passphrases once every one was typed and the guest either gave up or fell silent for
    `settle_s`.

    Silence is a legitimate end: after the last failed attempt the initramfs waits for a root device that will never
    appear, for minutes, before it gives up. The run must not outlast the point where nothing can change.
    """

    def __init__(
        self, typer: PromptTyper, *, attempts: int, settle_s: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._typer = typer
        self._attempts = attempts
        self._settle_s = settle_s
        self._clock = clock
        self._tail = ""
        self._last_output = clock()
        self._gave_up = False

    def feed(self, chunk: str, send: Callable[[str], None]) -> bool:
        self._last_output = self._clock()
        self._tail = (self._tail + chunk)[-PROMPT_WINDOW:]
        if self._typer.typed >= self._attempts and INITRAMFS_GAVE_UP.search(self._tail):
            self._gave_up = True
        return self._gave_up

    def poll(self, send: Callable[[str], None]) -> bool:
        if self._typer.typed < self._attempts:
            return False
        return self._gave_up or self._clock() - self._last_output >= self._settle_s


class FirstOf:
    """Feeds every handler and ends the run when any of them says so (none is skipped: each keeps its own state)."""

    def __init__(self, *handlers: object) -> None:
        self._handlers = handlers

    def feed(self, chunk: str, send: Callable[[str], None]) -> bool:
        return any([handler.feed(chunk, send) for handler in self._handlers])  # type: ignore[attr-defined]

    def poll(self, send: Callable[[str], None]) -> bool:
        return any([handler.poll(send) for handler in self._handlers])  # type: ignore[attr-defined]


# ---- secrets ---------------------------------------------------------------------------------------------------------

REDACTED = "<redacted>"
MIN_SCRUBBED_LENGTH = 8  # a shorter string would also match innocent text


class Scrubber:
    """Replaces the known secrets in text before it is stored, shown or judged, and counts how often it had to.

    The guest should never print a secret (the engine reads its passphrase from the plan, the initramfs does not echo
    what is typed), so a hit is also a finding: `hits` above zero means a secret reached the console.
    """

    def __init__(self, secrets: Iterable[Secret]) -> None:
        values = {secret.reveal() for secret in secrets if len(secret.reveal()) >= MIN_SCRUBBED_LENGTH}
        self._values = tuple(sorted(values, key=len, reverse=True))
        self.hits = 0

    def scrub(self, text: str) -> str:
        for value in self._values:
            if count := text.count(value):
                self.hits += count
                text = text.replace(value, REDACTED)
        return text


# ---- verdicts --------------------------------------------------------------------------------------------------------

_LOGIN_PROMPT = re.compile(r"(?m)^[^\n]* login: ?$")
_MULTI_USER = re.compile(r"Reached target[^\n]*Multi-User System", re.IGNORECASE)
_SELFCHECK_LINE = re.compile(r"PAI-SELFCHECK\|")


def booted_markers(text: str) -> list[str]:
    """What on the console shows that a system came up: a self-check line, a login prompt, multi-user.target reached."""
    clean = strip_terminal_escapes(text).replace("\r", "")
    markers = []
    if _SELFCHECK_LINE.search(clean):
        markers.append("a PAI-SELFCHECK line")
    if _LOGIN_PROMPT.search(clean):
        markers.append("a login prompt")
    if _MULTI_USER.search(clean):
        markers.append("systemd reaching the multi-user target")
    return markers


def wrong_passphrase_problems(
    text: str, *, prompts_seen: int, typed: int, attempts: int, echoed_secret: bool
) -> list[str]:
    """Why a run of wrong passphrases does not prove that they keep the system locked; empty when it does.

    A timeout is not a problem here: a system that stays at the unlock prompt never finishes, which is the result
    wanted. What would be: the system coming up, or the run ending before the attempts were made (nothing was tested).
    """
    problems: list[str] = []
    if markers := booted_markers(text):
        problems.append("the system came up although every passphrase was wrong: " + ", ".join(markers))
    if prompts_seen == 0:
        problems.append(
            "inconclusive: the disk-unlock prompt never appeared, so no passphrase was tried (the boot failed earlier?)"
        )
    elif typed < attempts:
        problems.append(f"inconclusive: only {typed} of {attempts} wrong passphrases were typed before the run ended")
    if echoed_secret:
        problems.append("a passphrase appeared on the console (scrubbed from the saved log): a secret was printed")
    return problems


def installed_boot_problems(
    text: str, *, prompts_seen: int, typed: int, timed_out: bool, powered_off: bool, echoed_secret: bool
) -> list[str]:
    """Why this console is not a clean boot of an installed system (unlock, then a self-check that passes all 18)."""
    problems: list[str] = []
    if timed_out:
        problems.append("the boot did not finish within the timeout (see PAI_INSTALL_BOOT_TIMEOUT)")
    if prompts_seen == 0:
        problems.append(
            "the disk-unlock prompt never appeared: GRUB, the kernel or the initramfs did not get as far as asking for "
            "the passphrase (is console=ttyS0 on the installed kernel line?)"
        )
    elif prompts_seen > typed:
        problems.append(
            f"the unlock prompt appeared {prompts_seen} times but the passphrase was typed {typed}: it was not accepted"
        )
    problems.extend(selfcheck_problems(parse_selfcheck(text), installed=True))
    if not powered_off and not timed_out:
        problems.append("the guest did not power itself off after the self-check")
    if echoed_secret:
        problems.append("the passphrase appeared on the console (scrubbed from the saved log): a secret was printed")
    return problems
