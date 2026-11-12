"""Fast tests (no Docker) for the plan the install test builds and the secrets that go with it."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.end_to_end.install_plan import (
    DEFAULT_KDF_ITER_TIME_MS,
    DEFAULT_KDF_MEMORY_KIB,
    INSTALLED_KERNEL_ARGS,
    MIN_PASSPHRASE_LENGTH,
    PLAN_KEYS,
    PLAN_VOLUME_LABEL,
    TARGET_BY_ID,
    TARGET_SERIAL,
    Secret,
    build_plan,
    generate_passphrase,
    generate_wrong_passphrase,
    plan_bytes,
)

DESIGN = Path(__file__).resolve().parents[2] / "docs" / "architecture" / "INSTALLER_DESIGN.md"
GOOD = Secret("correct-horse-battery-staple")

# ---- secrets ---------------------------------------------------------------------------------------------------------


def test_a_secret_never_prints() -> None:
    secret = Secret("hunter2-hunter2-hunter2")
    for shown in (
        repr(secret),
        str(secret),
        f"{secret}",
        f"{secret!r}",
        f"{[secret]}",
        f"{ {'k': secret} }",
    ):
        assert "hunter2" not in shown
        assert "<secret>" in shown


def test_a_secret_is_read_out_only_by_asking() -> None:
    assert Secret("abc").reveal() == "abc"


def test_a_secret_in_a_failed_assertion_does_not_leak() -> None:
    value = "".join(["visible-", "if-it-leaks"])  # built here so the test's own source does not contain it
    left, right = Secret(value), Secret("other-other-other")
    with pytest.raises(AssertionError) as raised:
        assert left == right
    assert value not in str(raised.value)
    assert "other-other-other" not in str(raised.value)


def test_generated_passphrases_are_long_random_and_plain_enough_to_type_on_a_console() -> None:
    first, second = generate_passphrase().reveal(), generate_passphrase().reveal()
    assert first != second
    assert len(first) >= MIN_PASSPHRASE_LENGTH + 8
    assert re.fullmatch(r"[A-Za-z0-9_-]+", first)  # nothing a shell, a terminal or the serial console treats specially


def test_a_wrong_passphrase_has_the_shape_of_the_right_one_and_differs() -> None:
    correct = generate_passphrase()
    wrong = generate_wrong_passphrase(correct)
    assert wrong.reveal() != correct.reveal()
    assert len(wrong.reveal()) == len(correct.reveal())


# ---- the plan --------------------------------------------------------------------------------------------------------


def test_the_plan_is_an_unattended_install_onto_the_disk_named_by_its_serial() -> None:
    plan = build_plan(GOOD)
    assert plan["version"] == 1
    assert plan["target"] == {"by_id": TARGET_BY_ID}
    assert f"virtio-{TARGET_SERIAL}" == TARGET_BY_ID  # udev's by-id link for a virtio disk with that serial
    assert plan["confirm_wipe"] is True
    assert plan["passphrase_source"] == "plan"  # noqa: S105 - the plan field of that name, not a credential
    assert plan["passphrase"] == "correct-horse-battery-staple"  # noqa: S105 - a test value
    assert plan["after"] == "poweroff"


def test_the_plan_gives_the_installed_kernel_the_console_and_the_selfcheck_flag() -> None:
    assert build_plan(GOOD)["extra_kernel_args"] == INSTALLED_KERNEL_ARGS
    assert set(INSTALLED_KERNEL_ARGS.split()) == {"console=ttyS0", "pai.selfcheck=1"}


def test_the_key_derivation_cost_is_small_enough_for_software_emulation_and_can_be_set() -> None:
    kdf = build_plan(GOOD)["kdf"]
    assert kdf == {"memory_kib": DEFAULT_KDF_MEMORY_KIB, "iter_time_ms": DEFAULT_KDF_ITER_TIME_MS}
    assert DEFAULT_KDF_MEMORY_KIB <= 262144  # cryptsetup's default is about 1 GiB: far too much for an emulated unlock
    assert build_plan(GOOD, kdf_memory_kib=1234, kdf_iter_time_ms=5)["kdf"] == {"memory_kib": 1234, "iter_time_ms": 5}


def test_the_plan_holds_only_keys_the_design_defines() -> None:
    plan = build_plan(GOOD)
    assert set(plan) == PLAN_KEYS
    design = DESIGN.read_text(encoding="utf-8")
    for key in [*PLAN_KEYS, *plan["target"], *plan["kdf"]]:  # type: ignore[call-overload]
        assert f'"{key}"' in design, f"{key} is not in the plan schema of INSTALLER_DESIGN.md"


@pytest.mark.parametrize("bad", ["", "short", "a" * 40, "aaaaaaaaaaaa", "x" * (MIN_PASSPHRASE_LENGTH - 1)])
def test_a_passphrase_the_engine_would_refuse_fails_at_once_without_naming_it(bad: str) -> None:
    with pytest.raises(ValueError, match="at least") as raised:
        build_plan(Secret(bad))
    assert bad not in str(raised.value) or bad == ""


def test_the_shortest_acceptable_passphrase_is_accepted() -> None:
    assert build_plan(Secret("ab" * (MIN_PASSPHRASE_LENGTH // 2)))["passphrase"] == "ab" * (MIN_PASSPHRASE_LENGTH // 2)


def test_the_plan_bytes_are_json_that_round_trips_and_hold_the_passphrase_exactly_once() -> None:
    plan = build_plan(GOOD)
    data = plan_bytes(plan)
    assert json.loads(data) == plan
    assert data.endswith(b"\n")
    assert data.count(b"correct-horse-battery-staple") == 1


def test_the_plan_volume_label_is_a_valid_iso9660_volume_id() -> None:
    assert re.fullmatch(r"[A-Z0-9_-]{1,32}", PLAN_VOLUME_LABEL)


def test_the_designs_unattended_interface_names_the_label_and_the_file() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    assert PLAN_VOLUME_LABEL in text
    assert "plan.json" in text
