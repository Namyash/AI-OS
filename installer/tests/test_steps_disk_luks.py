"""The disk and encryption steps one at a time: exact commands, what is verified, what is refused."""

from __future__ import annotations

import base64
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from installer.context import InstallContext
from installer.errors import VerificationError
from installer.host import LinuxHost
from installer.steps import disk, luks
from installer.tests.fakes import GIB, MIB, FakeSystem
from installer.tests.support import PASSPHRASE, RECOVERY_FILE, RECOVERY_RAW, RECOVERY_TEXT, run_until, scenario

BIOS = "21686148-6449-6E6F-744E-656564454649"
ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
BOOT = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
ROOT = "CA7D7CCB-63ED-4C53-861C-1742536059CC"


def test_the_partition_script_is_the_designed_layout() -> None:
    assert disk.sfdisk_script() == (
        "label: gpt\n"
        f"size=1MiB, type={BIOS}, name=bios-boot\n"
        f"size=512MiB, type={ESP}, name=esp\n"
        f"size=1024MiB, type={BOOT}, name=boot\n"
        f"type={ROOT}, name=cryptroot\n"
    )


def test_the_fixed_partitions_add_up_to_the_design() -> None:
    assert sum(spec.size_bytes or 0 for spec in disk.LAYOUT) == (1 + 512 + 1024) * MIB


def test_wipe_clears_existing_partitions_before_the_disk() -> None:
    system = FakeSystem.live_machine()
    system.add_partition("sda", 1, "8:1")
    system.add_partition("sda", 2, "8:2")
    ctx = run_until(scenario(system), "wipe")
    disk.wipe_signatures(ctx)
    assert system.argvs() == [
        ["wipefs", "--all", "--force", "/dev/sda1"],
        ["wipefs", "--all", "--force", "/dev/sda2"],
        ["wipefs", "--all", "--force", "/dev/sda"],
    ]


def test_the_table_is_written_from_a_script_on_stdin_only() -> None:
    system = FakeSystem.live_machine()
    ctx = run_until(scenario(system), "partition")
    disk.write_partition_table(ctx)
    (call,) = system.commands("sfdisk")
    assert call.argv == ["sfdisk", "--quiet", "--wipe", "always", "--wipe-partitions", "always", "/dev/sda"]
    assert call.stdin == disk.sfdisk_script().encode()


def laid_out(
    target: dict[str, str] | None = None, system: FakeSystem | None = None
) -> tuple[FakeSystem, InstallContext]:
    system = system or FakeSystem.live_machine()
    ctx = run_until(scenario(system, **({"target": target} if target else {})), "partition")
    disk.write_partition_table(ctx)
    return system, ctx


def test_verification_reads_the_table_back_and_records_the_nodes() -> None:
    system, ctx = laid_out()
    disk.verify_layout(ctx)
    assert ctx.partitions is not None
    assert (ctx.partitions.bios_boot, ctx.partitions.esp, ctx.partitions.boot, ctx.partitions.root) == (
        "/dev/sda1",
        "/dev/sda2",
        "/dev/sda3",
        "/dev/sda4",
    )
    assert system.argvs()[-1] == ["sfdisk", "--json", "/dev/sda"]


def test_a_nvme_disk_gets_p_suffixed_nodes_taken_from_the_table() -> None:
    system = FakeSystem.live_machine()
    system.add_disk("nvme0n1", devt="259:0", size_gib=64)
    _, ctx = laid_out({"path": "/dev/nvme0n1"}, system)
    disk.verify_layout(ctx)
    assert ctx.partitions is not None and ctx.partitions.root == "/dev/nvme0n1p4"


def drop_last(t: dict[str, Any]) -> None:
    t["partitions"].pop()


def wrong_type(t: dict[str, Any]) -> None:
    t["partitions"][3]["type"] = BOOT


def wrong_esp_size(t: dict[str, Any]) -> None:
    t["partitions"][1]["size"] //= 2


def misaligned(t: dict[str, Any]) -> None:
    t["partitions"][2]["start"] += 1


def short_root(t: dict[str, Any]) -> None:
    t["partitions"][3]["size"] = 10 * GIB // 512


def dos_label(t: dict[str, Any]) -> None:
    t["label"] = "dos"


def foreign_node(t: dict[str, Any]) -> None:
    t["partitions"][0]["node"] = "/dev/sdb1"


def no_sector_size(t: dict[str, Any]) -> None:
    del t["sectorsize"]


@pytest.mark.parametrize(
    "mutation", [drop_last, wrong_type, wrong_esp_size, misaligned, short_root, dos_label, foreign_node, no_sector_size]
)
def test_a_table_that_differs_from_the_design_is_refused(mutation: Callable[[dict[str, Any]], None]) -> None:
    system, ctx = laid_out()
    document = json.loads(system.run(["sfdisk", "--json", "/dev/sda"], timeout=1).stdout)
    mutation(document["partitiontable"])
    system.sfdisk_json_override = json.dumps(document)
    with pytest.raises(VerificationError):
        disk.verify_layout(ctx)
    assert ctx.partitions is None


def test_unreadable_sfdisk_output_is_refused() -> None:
    system, ctx = laid_out()
    system.sfdisk_json_override = "not json"
    with pytest.raises(VerificationError, match="read back"):
        disk.verify_layout(ctx)


def test_late_device_nodes_are_waited_for_within_a_bound() -> None:
    system = FakeSystem.live_machine()
    system.node_delay = 5.0
    _, ctx = laid_out(system=system)
    disk.verify_layout(ctx)
    assert system.clock >= 5.0


def test_device_nodes_that_never_appear_fail_the_step() -> None:
    system = FakeSystem.live_machine()
    system.node_delay = 10_000.0
    _, ctx = laid_out(system=system)
    with pytest.raises(VerificationError, match="did not appear"):
        disk.verify_layout(ctx)
    assert system.clock < 100


# ---------------------------------------------------------------------------------------------------- LUKS
def test_the_recovery_key_is_256_bits_in_groups_of_four_that_decode_back() -> None:
    assert re.fullmatch(r"([A-Z2-7]{4}-){12}[A-Z2-7]{4}", RECOVERY_TEXT)
    assert base64.b32decode(RECOVERY_TEXT.replace("-", "") + "====") == RECOVERY_RAW
    assert luks.format_recovery_key(b"\xff" * 32) != luks.format_recovery_key(b"\x00" * 32)


def test_the_recovery_key_file_is_written_first_with_the_key_and_no_newline() -> None:
    system = FakeSystem.live_machine()
    ctx = run_until(scenario(system), "prepare-recovery-key")
    luks.prepare_recovery_key(ctx, lambda n: RECOVERY_RAW)
    assert system.secret_files == {RECOVERY_FILE: (RECOVERY_TEXT, 0o600)}
    assert system.calls == []


def test_a_generator_that_returns_the_wrong_amount_of_randomness_is_refused() -> None:
    system = FakeSystem.live_machine()
    ctx = run_until(scenario(system), "prepare-recovery-key")
    with pytest.raises(VerificationError, match="256 bits"):
        luks.prepare_recovery_key(ctx, lambda n: b"short")
    assert system.secret_files == {}


def test_an_existing_recovery_key_file_is_never_overwritten_and_nothing_runs() -> None:
    system = FakeSystem.live_machine()
    system.secret_files[RECOVERY_FILE] = ("another key", 0o600)
    run = scenario(system)
    assert run.run() is False
    assert system.calls == [] and system.secret_files[RECOVERY_FILE][0] == "another key"
    assert "prepare-recovery-key" in run.result["error"]


def test_discarding_removes_only_a_file_this_run_wrote() -> None:
    system = FakeSystem.live_machine()
    system.secret_files[RECOVERY_FILE] = ("not ours", 0o600)
    ctx = scenario(system).engine.context
    luks.discard_recovery_key(ctx)  # this run never wrote it
    assert RECOVERY_FILE in system.secret_files
    ctx.recovery_key_written = True
    luks.discard_recovery_key(ctx)
    assert RECOVERY_FILE not in system.secret_files


def formatted(**overrides: Any) -> tuple[FakeSystem, InstallContext]:
    system = FakeSystem.live_machine()
    ctx = run_until(scenario(system, **overrides), "luks-format")
    return system, ctx


def test_luks_format_uses_luks2_argon2id_and_the_passphrase_on_stdin_exactly() -> None:
    system, ctx = formatted()
    luks.luks_format(ctx)
    (call,) = system.commands("cryptsetup")
    assert call.argv == [
        *[
            "cryptsetup",
            "luksFormat",
            "--type",
            "luks2",
            "--pbkdf",
            "argon2id",
            "--pbkdf-memory=1024",
            "--iter-time=50",
        ],
        *["--batch-mode", "--key-file=-", "/dev/sda4"],
    ]
    assert call.stdin == PASSPHRASE.encode(), "no newline: --key-file=- takes stdin as the key, byte for byte"


def test_kdf_overrides_are_passed_only_when_given() -> None:
    system, ctx = formatted(kdf={"memory_kib": None, "iter_time_ms": None})
    luks.luks_format(ctx)
    expected = [
        "cryptsetup",
        "luksFormat",
        "--type",
        "luks2",
        "--pbkdf",
        "argon2id",
        "--batch-mode",
        "--key-file=-",
        "/dev/sda4",
    ]
    assert system.calls[-1].argv == expected
    system, ctx = formatted(kdf={"memory_kib": 4096})
    luks.luks_format(ctx)
    argv = system.calls[-1].argv
    assert "--pbkdf-memory=4096" in argv and not any(a.startswith("--iter-time") for a in argv)


def test_the_recovery_key_goes_into_a_second_keyslot_from_its_file() -> None:
    system, ctx = formatted()
    luks.luks_format(ctx)
    luks.add_recovery_key(ctx)
    add = system.calls[-1]
    assert add.argv == [
        *["cryptsetup", "luksAddKey", "--pbkdf", "argon2id", "--pbkdf-memory=1024", "--iter-time=50", "--batch-mode"],
        *["--key-file=-", "/dev/sda4", RECOVERY_FILE],
    ]
    assert add.stdin == PASSPHRASE.encode()
    assert system.luks["/dev/sda4"].slots == [PASSPHRASE.encode(), RECOVERY_TEXT.encode()]


def test_the_luks_header_must_be_luks2_with_two_argon2id_keyslots() -> None:
    system, ctx = formatted()
    luks.luks_format(ctx)
    luks.add_recovery_key(ctx)
    assert luks.verify_luks(ctx) == "LUKS2, argon2id, 2 keyslots"
    system.luks["/dev/sda4"].kdf = "pbkdf2"
    with pytest.raises(VerificationError, match="argon2id"):
        luks.verify_luks(ctx)
    system.luks["/dev/sda4"].kdf = "argon2id"
    system.luks["/dev/sda4"].slots.pop()
    with pytest.raises(VerificationError, match="expected 2 keyslots"):
        luks.verify_luks(ctx)


def test_a_header_that_does_not_dump_as_luks2_json_is_refused() -> None:
    system, ctx = formatted()
    luks.luks_format(ctx)
    system.fail_on("cryptsetup", "luksDump", returncode=0)  # exit 0 with no output
    with pytest.raises(VerificationError, match="did not dump as LUKS2"):
        luks.verify_luks(ctx)


def test_the_volume_is_opened_with_the_passphrase_on_stdin_and_registered_for_closing() -> None:
    system, ctx = formatted()
    luks.luks_format(ctx)
    luks.open_luks(ctx)
    assert system.calls[-1].argv == ["cryptsetup", "open", "--type", "luks2", "--key-file=-", "/dev/sda4", "cryptroot"]
    assert system.calls[-1].stdin == PASSPHRASE.encode()
    assert "cryptroot" in system.mappings
    assert ctx.resources.unwind() == [] and system.mappings == {}


@pytest.mark.skipif(os.name != "posix", reason="file modes: POSIX only")
def test_the_real_host_creates_the_key_file_0600_exclusively(tmp_path: Path) -> None:
    host = LinuxHost()
    target = tmp_path / "private" / "key"
    host.write_secret_file(str(target), "ABCD-EFGH")
    assert target.read_text() == "ABCD-EFGH"
    assert (target.stat().st_mode & 0o777) == 0o600 and (target.parent.stat().st_mode & 0o777) == 0o700
    with pytest.raises(FileExistsError):
        host.write_secret_file(str(target), "other")
    assert target.read_text() == "ABCD-EFGH"
    host.remove_file(str(target))
    host.remove_file(str(target))  # already gone: no error
    assert not target.exists()


@pytest.mark.skipif(os.name != "posix", reason="symlinks: POSIX only")
def test_the_real_host_refuses_to_follow_a_planted_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep")
    link = tmp_path / "key"
    link.symlink_to(victim)
    with pytest.raises(FileExistsError):
        LinuxHost().write_secret_file(str(link), "SECRET-VALUE")
    assert victim.read_text() == "keep"
