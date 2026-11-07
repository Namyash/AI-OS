"""Boots the built ISO under QEMU (software emulation) in a container and checks the in-image security self-check.

Slow (minutes) and needs Docker plus an ISO, so it is deselected by default:

    python -m pytest tests/end_to_end -m e2e

It skips, with the reason, when Docker or an ISO is missing.
Variables and how to read a failure: docs/development/BOOT_TESTING.md.
"""

from __future__ import annotations

import os

import pytest

from tests.end_to_end.boot_harness import (
    SERIAL_LOG,
    BootConfig,
    BootEnvironmentError,
    BootOutcome,
    ConfigError,
    IsoNotFoundError,
    boot_iso,
    boot_problems,
    docker_unavailable_reason,
    ensure_image,
    locate_iso,
    printable_console_text,
    save_serial_log,
)

pytestmark = pytest.mark.e2e

TAIL_LINES = 80


@pytest.fixture(scope="module")
def booted() -> BootOutcome:
    """One boot shared by every test in this module; its console output is saved to SERIAL_LOG."""
    if reason := docker_unavailable_reason():
        pytest.skip(f"cannot run the boot test: {reason}")
    try:
        iso = locate_iso()
    except IsoNotFoundError as error:
        pytest.skip(str(error))
    try:
        config = BootConfig.from_env(os.environ)
    except ConfigError as error:
        pytest.fail(str(error), pytrace=False)

    try:
        outcome = boot_iso(iso, config, tag=ensure_image())
    except BootEnvironmentError as error:
        # The environment failed (image build, docker, an unreadable ISO), not the image under test: a setup error.
        pytest.fail(f"cannot run the boot test: {error}", pytrace=False)
    print(f"console log: {save_serial_log(outcome)}")  # shown by pytest -s and in failure reports
    return outcome


def _tail(outcome: BootOutcome) -> str:
    """The last console lines, with the guest's control characters made visible: the console is untrusted."""
    return "\n".join(printable_console_text(outcome.output).splitlines()[-TAIL_LINES:])


def test_selfcheck_passes_on_the_booted_iso(booted: BootOutcome) -> None:
    problems = boot_problems(booted)
    assert not problems, "\n".join(
        ["self-check did not pass:", *problems, "", f"last {TAIL_LINES} console lines ({SERIAL_LOG}):", _tail(booted)]
    )


def test_guest_powers_itself_off_after_the_selfcheck(booted: BootOutcome) -> None:
    assert booted.powered_off, f"the guest did not power itself off; last console lines:\n{_tail(booted)}"
