"""Plan validation: strict, complete, and never echoing the passphrase."""
# ruff: noqa: S106

from __future__ import annotations

import json
from typing import Any

import pytest

from installer.errors import PlanError
from installer.plan import KdfParams, Plan, TargetSpec, load_plan_text, parse_plan, passphrase_problem
from installer.tests.support import PASSPHRASE, plan_document


def rejected(**overrides: Any) -> str:
    with pytest.raises(PlanError) as caught:
        parse_plan(plan_document(**overrides))
    return str(caught.value)


def test_a_complete_plan_is_accepted_and_typed() -> None:
    plan = parse_plan(plan_document())
    assert plan == Plan(
        target=TargetSpec(by_id="ata-TARGET-DISK"),
        hostname="pai",
        username="owner",
        passphrase_source="plan",
        recovery_key_file="/run/pai-install/recovery-key",
        passphrase=plan.passphrase,
        kdf=KdfParams(1024, 50),
        extra_kernel_args=("quiet", "loglevel=3"),
        after="poweroff",
    )
    assert plan.passphrase is not None and plan.passphrase.reveal() == PASSPHRASE


def test_the_optional_fields_have_safe_defaults() -> None:
    plan = parse_plan(plan_document(kdf=..., extra_kernel_args=..., after=...))
    assert plan.kdf == KdfParams(None, None)
    assert plan.extra_kernel_args == ()
    assert plan.after == "none"


@pytest.mark.parametrize(
    "key", ["version", "target", "confirm_wipe", "hostname", "username", "passphrase_source", "recovery_key_file"]
)
def test_every_required_field_is_required(key: str) -> None:
    assert f"{key}: required" in rejected(**{key: ...})


def test_unknown_keys_are_rejected_at_every_level() -> None:
    assert "unknown key(s) extra" in rejected(extra=1)
    assert "target: unknown key(s) disk" in rejected(target={"by_id": "x", "disk": "y"})
    assert "kdf: unknown key(s) rounds" in rejected(kdf={"rounds": 3})


def test_the_plan_must_be_an_object() -> None:
    for document in ([], "plan", 3, None):
        with pytest.raises(PlanError, match="JSON object"):
            parse_plan(document)


@pytest.mark.parametrize("version", [0, 2, "1", 1.0, True, None])
def test_only_version_one_is_accepted(version: object) -> None:
    assert "version" in rejected(version=version)


@pytest.mark.parametrize("value", [False, None, "true", 1, 0, "yes"])
def test_confirm_wipe_must_be_literally_true(value: object) -> None:
    assert "confirm_wipe: must be true" in rejected(confirm_wipe=value)


@pytest.mark.parametrize(
    "target",
    [
        {},
        {"by_id": "a", "path": "/dev/sda"},
        {"by_id": 5},
        {"path": 5},
        "ata-x",
        None,
        {"by_id": ""},
        {"by_id": "a/b"},
        {"by_id": ".."},
        {"by_id": ".hidden"},
        {"by_id": "x" * 300},
        {"path": "/dev/"},
        {"path": "sda"},
        {"path": "/etc/passwd"},
        {"path": "/dev/../etc/passwd"},
        {"path": "/dev//sda"},
        {"path": "/dev/sda "},
        {"path": "/dev/sd\na"},
    ],
)
def test_the_target_must_name_exactly_one_valid_device(target: object) -> None:
    assert "target" in rejected(target=target)


@pytest.mark.parametrize(
    "target",
    [
        {"by_id": "usb-Vendor_Model_123:0-0:0"},
        {"path": "/dev/sda"},
        {"path": "/dev/nvme0n1"},
        {"path": "/dev/disk/by-id/x"},
    ],
)
def test_valid_target_forms_are_accepted(target: dict[str, str]) -> None:
    assert parse_plan(plan_document(target=target)).target == TargetSpec(**target)


@pytest.mark.parametrize("hostname", ["", "-a", "a-", "A", "a_b", "a.b", "x" * 64, "pai host", 5, None, "ä"])
def test_hostnames_must_be_one_valid_label(hostname: object) -> None:
    assert "hostname" in rejected(hostname=hostname)


@pytest.mark.parametrize("hostname", ["pai", "a", "x" * 63, "node-1", "9lives"])
def test_valid_hostnames(hostname: str) -> None:
    assert parse_plan(plan_document(hostname=hostname)).hostname == hostname


@pytest.mark.parametrize(
    "username", ["", "Root", "root", "1abc", "a b", "a:b", "x" * 33, "-a", "a$", "üser", 5, None, "a\n"]
)
def test_usernames_follow_linux_account_rules(username: object) -> None:
    assert "username" in rejected(username=username)


@pytest.mark.parametrize("username", ["owner", "a", "x" * 32, "ana_2-b"])
def test_valid_usernames(username: str) -> None:
    assert parse_plan(plan_document(username=username)).username == username


@pytest.mark.parametrize(
    ("value", "problem"),
    [
        ("short", "at least 12"),
        ("elevenchars", "at least 12"),
        ("a" * 12, "single character"),
        ("é" * 40, "single character"),
        ("ab" * 300, "at most 512"),
        ("has a\nnewline in it", "control characters"),
        ("tab\tin the middle of it", "control characters"),
    ],
)
def test_passphrase_rules(value: str, problem: str) -> None:
    assert problem in (passphrase_problem(value) or "")


def test_a_twelve_character_passphrase_that_varies_is_accepted() -> None:
    assert passphrase_problem("abababababab") is None
    assert passphrase_problem("x" * 11 + "y") is None


def test_the_plan_passphrase_is_validated_and_never_echoed() -> None:
    for bad in ("a" * 20, "short", "bad\nline-with-text-123"):
        message = rejected(passphrase=bad)
        assert "passphrase" in message
        assert bad not in message and bad.strip() not in message


def test_a_non_string_passphrase_is_rejected_without_echo() -> None:
    assert "passphrase: must be a string" in rejected(passphrase=123456789012345)
    assert "123456789012345" not in rejected(passphrase=123456789012345)


def test_stdin_source_forbids_a_passphrase_in_the_plan_and_never_echoes_it() -> None:
    message = rejected(passphrase_source="stdin")
    assert "must not be in the plan" in message
    assert PASSPHRASE not in message


def test_plan_source_requires_a_passphrase() -> None:
    assert "passphrase: required when passphrase_source is plan" in rejected(passphrase=...)


def test_the_stdin_source_is_accepted_without_a_passphrase_then_supplied() -> None:
    plan = parse_plan(plan_document(passphrase_source="stdin", passphrase=...))
    assert plan.passphrase is None
    supplied = plan.with_passphrase("another long passphrase")
    assert supplied.passphrase is not None and supplied.passphrase.reveal() == "another long passphrase"


def test_a_passphrase_supplied_later_is_validated_without_echo() -> None:
    plan = parse_plan(plan_document(passphrase_source="stdin", passphrase=...))
    with pytest.raises(PlanError) as caught:
        plan.with_passphrase("q" * 20)
    assert "single character" in str(caught.value) and "q" * 20 not in str(caught.value)


@pytest.mark.parametrize("source", ["file", "STDIN", "", None, 1])
def test_unknown_passphrase_sources_are_rejected(source: object) -> None:
    assert "passphrase_source: must be one of" in rejected(passphrase_source=source)


@pytest.mark.parametrize(
    "path",
    [
        "relative/key",
        "",
        "/",
        "/run//key",
        "/run/../key",
        "/run/key/",
        "/dev/key",
        "/proc/x",
        "/sys/x",
        "/run/k\ney",
        5,
        None,
    ],
)
def test_recovery_key_file_must_be_a_clean_absolute_file_path(path: object) -> None:
    assert "recovery_key_file" in rejected(recovery_key_file=path)


@pytest.mark.parametrize(
    "kdf",
    [
        {"memory_kib": 0},
        {"memory_kib": 31},
        {"memory_kib": 4_194_305},
        {"memory_kib": -1},
        {"memory_kib": "1024"},
        {"memory_kib": 1024.0},
        {"memory_kib": True},
        {"iter_time_ms": 0},
        {"iter_time_ms": 600_001},
        {"iter_time_ms": "50"},
        "fast",
        [],
    ],
)
def test_kdf_values_must_be_null_or_sane_integers(kdf: object) -> None:
    assert "kdf" in rejected(kdf=kdf)


def test_kdf_null_and_boundary_values_are_accepted() -> None:
    assert parse_plan(plan_document(kdf={"memory_kib": None, "iter_time_ms": None})).kdf == KdfParams()
    assert parse_plan(plan_document(kdf={"memory_kib": 32, "iter_time_ms": 1})).kdf == KdfParams(32, 1)
    assert parse_plan(plan_document(kdf={"memory_kib": 4_194_304, "iter_time_ms": 600_000})).kdf == KdfParams(
        4_194_304, 600_000
    )
    assert parse_plan(plan_document(kdf={"iter_time_ms": 100})).kdf == KdfParams(None, 100)


@pytest.mark.parametrize(
    "args",
    [
        'quiet "x"',
        "a'b",
        "a\\b",
        "a`b`",
        "$HOME",
        "tab\there",
        "new\nline",
        "ünï",
        "x" * 257,
        " ".join(["a"] * 33),
        5,
        None,
        ["quiet"],
    ],
)
def test_extra_kernel_args_must_be_bounded_printable_words(args: object) -> None:
    assert "extra_kernel_args" in rejected(extra_kernel_args=args)


def test_extra_kernel_args_are_split_into_words() -> None:
    assert parse_plan(plan_document(extra_kernel_args="  console=ttyS0,115200   quiet ")).extra_kernel_args == (
        "console=ttyS0,115200",
        "quiet",
    )
    assert parse_plan(plan_document(extra_kernel_args="")).extra_kernel_args == ()
    assert parse_plan(plan_document(extra_kernel_args="a=b," + "x" * 100)).extra_kernel_args


@pytest.mark.parametrize("after", ["shutdown", "halt", "", None, True])
def test_after_must_be_a_known_action(after: object) -> None:
    assert "after: must be one of" in rejected(after=after)


def test_all_problems_are_reported_together() -> None:
    message = rejected(hostname="-", username="Root", confirm_wipe=False)
    assert "hostname" in message and "username" in message and "confirm_wipe" in message


def test_plan_text_must_be_valid_json_without_echoing_content() -> None:
    with pytest.raises(PlanError) as caught:
        load_plan_text('{"passphrase": "' + PASSPHRASE + '" oops}')
    assert "not valid JSON" in str(caught.value) and PASSPHRASE not in str(caught.value)


def test_duplicate_keys_are_rejected() -> None:
    with pytest.raises(PlanError, match="appears twice"):
        load_plan_text('{"version": 1, "version": 1}')


def test_plan_text_round_trip() -> None:
    assert load_plan_text(json.dumps(plan_document())).hostname == "pai"


def test_repr_and_str_of_a_plan_never_show_the_passphrase() -> None:
    plan = parse_plan(plan_document())
    assert PASSPHRASE not in repr(plan) and PASSPHRASE not in str(plan) and PASSPHRASE not in f"{plan.passphrase}"
