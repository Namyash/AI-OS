"""Test building blocks: a valid plan, a scenario (engine, fake system, captured output) and the leak check."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from typing import Any

from installer.context import InstallContext
from installer.engine import Engine
from installer.events import EventSink
from installer.plan import Plan, parse_plan
from installer.steps.luks import format_recovery_key
from installer.tests.fakes import FakeSystem

# Values unlike anything else in the output, so a leak is found by a plain substring search.
PASSPHRASE = "Zq7!vN3-leak-canary-passphrase"  # noqa: S105 - a test value, not a credential
RECOVERY_RAW = bytes(range(1, 33))
RECOVERY_TEXT = format_recovery_key(RECOVERY_RAW)
RECOVERY_FILE = "/run/pai-install/recovery-key"
SECRETS = (PASSPHRASE, RECOVERY_TEXT, RECOVERY_TEXT.replace("-", ""))


def plan_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "version": 1,
        "target": {"by_id": "ata-TARGET-DISK"},
        "confirm_wipe": True,
        "hostname": "pai",
        "username": "owner",
        "passphrase_source": "plan",
        "passphrase": PASSPHRASE,
        "recovery_key_file": RECOVERY_FILE,
        "kdf": {"memory_kib": 1024, "iter_time_ms": 50},
        "extra_kernel_args": "quiet loglevel=3",
        "after": "poweroff",
    }
    document.update(overrides)
    return {key: value for key, value in document.items() if value is not ...}


def make_plan(**overrides: Any) -> Plan:
    return parse_plan(plan_document(**overrides))


def fixed_random(count: int) -> bytes:
    assert count == len(RECOVERY_RAW)
    return RECOVERY_RAW


@dataclass
class Scenario:
    system: FakeSystem
    plan: Plan
    out: io.StringIO
    engine: Engine

    def run(self) -> bool:
        return self.engine.run()

    @property
    def events(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.out.getvalue().splitlines()]

    @property
    def steps(self) -> list[tuple[str, str]]:
        return [(e["name"], e["state"]) for e in self.events if e["event"] == "step"]

    @property
    def result(self) -> dict[str, Any]:
        return self.events[-1]


def scenario(system: FakeSystem | None = None, plan: Plan | None = None, **plan_overrides: Any) -> Scenario:
    system = system or FakeSystem.live_machine()
    plan = plan or make_plan(**plan_overrides)
    out = io.StringIO()
    engine = Engine(plan, system, system, EventSink(out), random_bytes=fixed_random)
    return Scenario(system, plan, out, engine)


ALLOWED_PASSPHRASE_STDIN = (("cryptsetup", "luksFormat"), ("cryptsetup", "luksAddKey"), ("cryptsetup", "open"))


def assert_no_leaks(run: Scenario, log_text: str, *extra_texts: str) -> None:
    """The passphrase and the recovery key are in no argv, no environment, no event, no log line and no other text.

    The passphrase may be on the standard input of exactly the three cryptsetup commands that need it; the recovery
    key never goes through standard input at all (it travels as a 0600 file).
    """
    assert run.system.calls, "no command ran: the leak check would prove nothing"
    for call in run.system.calls:
        for secret in SECRETS:
            assert all(secret not in part for part in call.argv), f"a secret is in argv of {call.argv[:3]}"
            assert all(secret not in f"{k}={v}" for k, v in (call.extra_env or {}).items()), (
                "a secret is in the environment"
            )
        if call.stdin is not None:
            text = call.stdin.decode("utf-8", errors="replace")
            assert RECOVERY_TEXT not in text and RECOVERY_TEXT.replace("-", "") not in text
            if PASSPHRASE in text:
                assert tuple(call.argv[:2]) in ALLOWED_PASSPHRASE_STDIN, (
                    f"the passphrase went to {call.argv[:2]} on stdin"
                )
    for text in (run.out.getvalue(), log_text, *extra_texts):
        for secret in SECRETS:
            assert secret not in text


def run_until(run: Scenario, stop_before: str) -> InstallContext:
    """Run the engine's steps up to (not including) ``stop_before`` and return the context for a step test."""
    for step in run.engine.steps():
        if step.name == stop_before:
            return run.engine.context
        step.run(run.engine.context)
    raise AssertionError(f"no step named {stop_before!r}")
