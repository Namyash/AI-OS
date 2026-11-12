"""The engine end to end on the fake system: order, exact commands, events, rollback, and that no secret leaks."""
# ruff: noqa: S106

from __future__ import annotations

import io
import json

import pytest

from installer.errors import CommandTimeout
from installer.runner import CommandResult
from installer.tests.fakes import FakeSystem
from installer.tests.support import (
    PASSPHRASE,
    RECOVERY_FILE,
    RECOVERY_TEXT,
    assert_no_leaks,
    scenario,
)

ROOT = "/run/pai-install/target"
CHROOT = ["chroot", ROOT]
LIVE = "/run/live/rootfs/filesystem.squashfs/"

EXPECTED_COMMANDS = [
    ["wipefs", "--all", "--force", "/dev/sda"],
    ["sfdisk", "--quiet", "--wipe", "always", "--wipe-partitions", "always", "/dev/sda"],
    ["sfdisk", "--json", "/dev/sda"],
    [
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
    ],
    [
        *["cryptsetup", "luksAddKey", "--pbkdf", "argon2id", "--pbkdf-memory=1024", "--iter-time=50"],
        *["--batch-mode", "--key-file=-", "/dev/sda4", RECOVERY_FILE],
    ],
    ["cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sda4"],
    ["cryptsetup", "open", "--type", "luks2", "--key-file=-", "/dev/sda4", "cryptroot"],
    ["mkfs.vfat", "-F", "32", "-n", "PAI-ESP", "/dev/sda2"],
    ["mkfs.ext4", "-F", "-q", "-L", "pai-boot", "/dev/sda3"],
    ["mkfs.ext4", "-F", "-q", "-L", "pai-root", "/dev/mapper/cryptroot"],
    ["blkid", "--probe", "--output", "export", "/dev/sda4"],
    ["blkid", "--probe", "--output", "export", "/dev/mapper/cryptroot"],
    ["blkid", "--probe", "--output", "export", "/dev/sda3"],
    ["blkid", "--probe", "--output", "export", "/dev/sda2"],
    ["install", "-d", "-m", "0700", "/run/pai-install"],
    ["install", "-d", "-m", "0755", ROOT],
    ["mount", "-t", "ext4", "/dev/mapper/cryptroot", ROOT],
    ["install", "-d", "-m", "0755", f"{ROOT}/boot"],
    ["mount", "-t", "ext4", "/dev/sda3", f"{ROOT}/boot"],
    ["install", "-d", "-m", "0755", f"{ROOT}/boot/efi"],
    ["mount", "-t", "vfat", "-o", "umask=0077", "/dev/sda2", f"{ROOT}/boot/efi"],
    [
        *["rsync", "--archive", "--hard-links", "--acls", "--xattrs", "--numeric-ids", "--one-file-system"],
        *["--exclude=/proc/*", "--exclude=/sys/*", "--exclude=/dev/*", "--exclude=/run/*", "--exclude=/tmp/*"],
        *["--exclude=/mnt/*", "--exclude=/media/*", "--exclude=/lost+found", "--exclude=/boot/efi", LIVE, f"{ROOT}/"],
    ],
    ["sync"],
    ["install", "-D", "-m", "0644", "/dev/stdin", f"{ROOT}/etc/fstab"],
    ["install", "-D", "-m", "0644", "/dev/stdin", f"{ROOT}/etc/crypttab"],
    ["install", "-D", "-m", "0644", "/dev/stdin", f"{ROOT}/etc/hostname"],
    ["install", "-D", "-m", "0644", "/dev/stdin", f"{ROOT}/etc/hosts"],
    ["install", "-D", "-m", "0644", "/dev/stdin", f"{ROOT}/etc/default/grub.d/90-pai-installer.cfg"],
    ["mount", "-t", "proc", "proc", f"{ROOT}/proc"],
    ["mount", "--rbind", "/dev", f"{ROOT}/dev"],
    ["mount", "--make-rslave", f"{ROOT}/dev"],
    ["mount", "--rbind", "/sys", f"{ROOT}/sys"],
    ["mount", "--make-rslave", f"{ROOT}/sys"],
    ["mount", "--bind", "/run", f"{ROOT}/run"],
    ["mount", "--make-rslave", f"{ROOT}/run"],
    [*CHROOT, "userdel", "--remove", "user"],
    [
        *CHROOT,
        "dpkg-query",
        "--show",
        "--showformat",
        "${db:Status-Status}\t${Package}\n",
        "live-boot",
        "live-boot-*",
        "live-config",
        "live-config-*",
        "live-tools",
    ],
    [
        *CHROOT,
        "apt-get",
        "--yes",
        "--quiet",
        "purge",
        "live-boot",
        "live-boot-doc",
        "live-boot-initramfs-tools",
        "live-config",
        "live-config-systemd",
        "live-tools",
    ],
    [
        *CHROOT,
        "rm",
        "-rf",
        "--one-file-system",
        "--",
        "/etc/live",
        "/lib/live/config",
        "/lib/live/boot",
        "/var/lib/live",
        "/etc/sudoers.d/live",
        "/etc/systemd/system/getty@tty1.service.d/autologin.conf",
    ],
    [*CHROOT, "rmdir", "--ignore-fail-on-non-empty", "/lib/live"],
    [*CHROOT, "passwd", "--lock", "root"],
    [*CHROOT, "useradd", "--create-home", "--shell", "/bin/bash", "--user-group", "owner"],
    [*CHROOT, "passwd", "--lock", "owner"],
    [*CHROOT, "truncate", "--size", "0", "/etc/machine-id"],
    [*CHROOT, "rm", "-f", "/var/lib/dbus/machine-id"],
    [*CHROOT, "update-initramfs", "-u", "-k", "all"],
    [*CHROOT, "grub-install", "--target=i386-pc", "--recheck", "/dev/sda"],
    [
        *CHROOT,
        "grub-install",
        "--target=x86_64-efi",
        "--efi-directory=/boot/efi",
        "--removable",
        "--no-nvram",
        "--recheck",
    ],
    [*CHROOT, "update-grub"],
    ["sync"],
    ["umount", "--recursive", f"{ROOT}/run"],
    ["umount", "--recursive", f"{ROOT}/sys"],
    ["umount", "--recursive", f"{ROOT}/dev"],
    ["umount", "--recursive", f"{ROOT}/proc"],
    ["umount", "--recursive", f"{ROOT}/boot/efi"],
    ["umount", "--recursive", f"{ROOT}/boot"],
    ["umount", "--recursive", ROOT],
    ["cryptsetup", "close", "cryptroot"],
    ["systemctl", "--no-block", "poweroff"],
]


def test_the_happy_path_runs_exactly_these_commands_in_this_order(log_buffer: io.StringIO) -> None:
    run = scenario()
    assert run.run() is True, run.result
    assert run.system.argvs() == EXPECTED_COMMANDS
    assert_no_leaks(run, log_buffer.getvalue())


def test_the_happy_path_ends_clean_with_the_designed_result() -> None:
    system = FakeSystem.live_machine()
    run = scenario(system)
    assert run.run() is True
    assert system.mounts and system.mounted_paths() == [], "nothing of the installer may stay mounted"
    assert system.mappings == {} and "/dev/mapper/cryptroot" not in system.nodes
    assert [row["type"] for row in system.tables["/dev/sda"]] == [
        "21686148-6449-6E6F-744E-656564454649",
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
        "CA7D7CCB-63ED-4C53-861C-1742536059CC",
    ]
    # Two keyslots: the passphrase, and the recovery key as it is written in its file.
    assert system.luks["/dev/sda4"].slots == [PASSPHRASE.encode(), RECOVERY_TEXT.encode()]
    assert system.secret_files == {RECOVERY_FILE: (RECOVERY_TEXT, 0o600)}
    assert run.result == {"event": "result", "ok": True, "error": ""}


def test_every_step_is_reported_start_then_done_and_the_result_comes_last() -> None:
    run = scenario()
    run.run()
    names = [step.name for step in run.engine.steps()]
    assert run.steps == [item for name in names for item in ((name, "start"), (name, "done"))]
    assert run.events[-1]["event"] == "result"
    assert all(line == json.dumps(json.loads(line), separators=(",", ":")) for line in run.out.getvalue().splitlines())


def test_verification_precedes_anything_that_depends_on_it() -> None:
    run = scenario()
    run.run()
    argvs = run.system.argvs()

    def first(*prefix: str) -> int:
        return next(i for i, argv in enumerate(argvs) if argv[: len(prefix)] == list(prefix))

    assert first("sfdisk", "--json") < first("cryptsetup", "luksFormat")
    assert first("cryptsetup", "luksDump") < first("cryptsetup", "open") < first("mkfs.ext4") < first("rsync")
    assert first("rsync") < first("chroot") and first("chroot", ROOT, "grub-install") < first("umount")
    assert argvs[0] == ["wipefs", "--all", "--force", "/dev/sda"], "the first command is the first destructive one"


def test_the_passphrase_reaches_only_the_three_cryptsetup_commands_and_only_on_stdin() -> None:
    run = scenario()
    run.run()
    with_stdin = [
        (c.argv[:2], c.stdin) for c in run.system.calls if c.stdin is not None and c.argv[0] in {"cryptsetup"}
    ]
    assert with_stdin == [
        (["cryptsetup", "luksFormat"], PASSPHRASE.encode()),
        (["cryptsetup", "luksAddKey"], PASSPHRASE.encode()),
        (["cryptsetup", "open"], PASSPHRASE.encode()),
    ]
    assert all(
        c.stdin is None
        for c in run.system.calls
        if c.argv[0] in {"mount", "umount", "chroot", "rsync", "mkfs.ext4", "blkid"}
    )


def test_the_environment_is_empty_except_for_the_chroot_frontend_setting() -> None:
    run = scenario()
    run.run()
    for call in run.system.calls:
        assert call.extra_env == ({"DEBIAN_FRONTEND": "noninteractive"} if call.argv[0] == "chroot" else None)


def test_every_command_is_a_list_of_strings() -> None:
    run = scenario()
    run.run()
    assert all(
        isinstance(call.argv, list) and all(isinstance(part, str) for part in call.argv) for call in run.system.calls
    )


# --------------------------------------------------------------------------------------------- rollback
FAILURES: dict[str, list[list[str]]] = {
    "wipe": [["wipefs"]],
    "partition": [["sfdisk", "--quiet"]],
    "verify-layout": [["sfdisk", "--json"]],
    "luks-format": [["cryptsetup", "luksFormat"]],
    "luks-recovery-key": [["cryptsetup", "luksAddKey"]],
    "luks-verify": [["cryptsetup", "luksDump"]],
    "luks-open": [["cryptsetup", "open"]],
    "mkfs": [["mkfs.vfat"], ["mkfs.ext4", "-F", "-q", "-L", "pai-boot"], ["mkfs.ext4", "-F", "-q", "-L", "pai-root"]],
    "identify-filesystems": [["blkid"]],
    "mount": [
        ["mount", "-t", "ext4", "/dev/mapper/cryptroot"],
        ["mount", "-t", "ext4", "/dev/sda3"],
        ["mount", "-t", "vfat"],
    ],
    "copy-system": [["rsync"]],
    "configure-files": [["install", "-D"]],
    "chroot-mounts": [
        ["mount", "-t", "proc"],
        ["mount", "--rbind", "/dev"],
        ["mount", "--make-rslave"],
        ["mount", "--bind", "/run"],
    ],
    "remove-live-session": [["chroot", "*", "userdel"], ["chroot", "*", "apt-get"], ["chroot", "*", "rm"]],
    "accounts": [["chroot", "*", "passwd"], ["chroot", "*", "useradd"]],
    "machine-id": [["chroot", "*", "truncate"]],
    "initramfs": [["chroot", "*", "update-initramfs"]],
    "bootloader": [
        ["chroot", "*", "grub-install", "--target=i386-pc"],
        ["chroot", "*", "grub-install", "--target=x86_64-efi"],
        ["chroot", "*", "update-grub"],
    ],
    "after": [["systemctl"]],
}
CASES = [(step, patterns) for step, many in FAILURES.items() for patterns in many]


def assert_clean_after_failure(run, system: FakeSystem, step: str) -> None:
    assert system.mappings == {}, "a mapping was left open"
    assert system.mounted_paths() == [], "a mount of the target was left in place"
    if step != "after":
        assert RECOVERY_FILE not in system.secret_files, "the recovery key of a failed installation must be removed"
    else:
        assert RECOVERY_FILE in system.secret_files, "a completed installation keeps the key that opens its disk"
    assert run.result["ok"] is False and f"step {step} failed" in run.result["error"]
    started = [name for name, state in run.steps if state == "start"]
    assert started[-2:] == [step, "rollback"] or started[-1] == "rollback"
    assert ("rollback", "done") in run.steps, run.steps
    assert run.steps.index((step, "failed")) < run.steps.index(("rollback", "start"))
    later = [s.name for s in run.engine.steps()]
    assert not any(name in later[later.index(step) + 1 :] for name, _ in run.steps), "a step ran after the failure"


@pytest.mark.parametrize(("step", "pattern"), CASES, ids=[f"{s}:{'/'.join(p)}" for s, p in CASES])
def test_a_failure_in_any_step_releases_everything_and_reports_it(
    step: str, pattern: list[str], log_buffer: io.StringIO
) -> None:
    system = FakeSystem.live_machine()
    system.fail_on(*pattern, stderr=f"boom {PASSPHRASE} {RECOVERY_TEXT}")
    run = scenario(system)
    assert run.run() is False
    assert_clean_after_failure(run, system, step)
    assert_no_leaks(run, log_buffer.getvalue(), run.result["error"])


def test_a_failed_verification_rolls_back_too() -> None:
    system = FakeSystem.live_machine()
    system._chroot_update_grub = lambda root, inner: CommandResult(0)  # type: ignore[method-assign]  # grub.cfg never appears
    run = scenario(system)
    assert run.run() is False
    assert "verify-installation" in run.result["error"] and "incomplete" in run.result["error"]
    assert system.mappings == {} and system.mounted_paths() == [] and RECOVERY_FILE not in system.secret_files


def test_an_unlocked_account_in_the_result_fails_the_installation() -> None:
    system = FakeSystem.live_machine()
    system._chroot_passwd = lambda root, inner: CommandResult(0)  # type: ignore[method-assign]  # locking silently does nothing
    run = scenario(system)
    assert run.run() is False
    assert "verify-installation" in run.result["error"] and "locked password" in run.result["error"]
    assert system.mappings == {} and system.mounted_paths() == []


def test_a_failure_while_closing_still_releases_what_it_can_and_says_what_is_left() -> None:
    system = FakeSystem.live_machine()
    system.busy_mounts.add(ROOT)  # the root filesystem cannot be unmounted, so the mapping cannot be closed either
    run = scenario(system)
    assert run.run() is False
    error = run.result["error"]
    assert "step close failed" in error and "rollback incomplete" in error and ROOT in error and "cryptroot" in error
    assert ("rollback", "failed") in run.steps
    # Everything that could be released was: the chroot binds, the ESP and /boot are gone; the root and mapping are not.
    assert system.mounted_paths() == [ROOT] and "cryptroot" in system.mappings
    assert RECOVERY_FILE not in system.secret_files
    # Both failed releases were attempted again by the rollback, not skipped.
    assert len([c for c in system.calls if c.argv[:2] == ["cryptsetup", "close"]]) == 2


def test_a_failing_release_during_rollback_does_not_stop_the_other_releases() -> None:
    system = FakeSystem.live_machine()
    system.fail_on("cryptsetup", "close")  # the mapping can never be closed
    system.fail_on("chroot", "*", "update-initramfs")
    run = scenario(system)
    assert run.run() is False
    assert system.mounted_paths() == [], "the mounts are released even though the mapping close failed"
    assert "cryptroot" in system.mappings
    assert "rollback incomplete" in run.result["error"] and "cryptroot" in run.result["error"]


TAKES_EFFECT_THEN_TIMES_OUT = [
    ["cryptsetup", "open"],
    ["mount", "-t", "ext4", "/dev/mapper/cryptroot"],
    ["mount", "-t", "ext4", "/dev/sda3"],
    ["mount", "-t", "vfat"],
    ["mount", "-t", "proc"],
    ["mount", "--rbind", "/dev"],
    ["mount", "--rbind", "/sys"],
    ["mount", "--bind", "/run"],
]


@pytest.mark.parametrize("pattern", TAKES_EFFECT_THEN_TIMES_OUT, ids=lambda p: "/".join(p))
def test_a_timeout_after_a_resource_was_acquired_still_releases_it(pattern: list[str]) -> None:
    """The command did its work and then ran out of time: the undo was registered first, so nothing is left."""
    system = FakeSystem.live_machine()
    original = system.run

    def run_then_time_out(argv, **kwargs):
        result = original(argv, **kwargs)
        if FakeSystem._matches(pattern, list(argv)):
            raise CommandTimeout("timed out", argv)
        return result

    system.run = run_then_time_out  # type: ignore[method-assign]
    run = scenario(system)
    assert run.run() is False
    assert "timed out" in run.result["error"]
    assert system.mounted_paths() == [] and system.mappings == {}, (
        "something acquired before the timeout was left behind"
    )


def test_an_interrupt_rolls_back_reports_and_propagates() -> None:
    system = FakeSystem.live_machine()
    system.raise_on("rsync", error=KeyboardInterrupt("signal 15"))
    run = scenario(system)
    with pytest.raises(KeyboardInterrupt):
        run.run()
    assert system.mappings == {} and system.mounted_paths() == [] and RECOVERY_FILE not in system.secret_files
    assert run.result["ok"] is False and "step copy-system failed" in run.result["error"]


def test_an_unexpected_exception_is_a_failed_result_not_a_crash() -> None:
    system = FakeSystem.live_machine()
    system.raise_on("mkfs.vfat", error=RuntimeError(f"surprise containing {PASSPHRASE}"))
    run = scenario(system)
    assert run.run() is False
    assert "RuntimeError" in run.result["error"] and PASSPHRASE not in run.out.getvalue()
    assert system.mappings == {} and system.mounted_paths() == []


def test_the_engine_refuses_a_plan_without_its_passphrase() -> None:
    from installer.engine import Engine
    from installer.errors import InstallerError
    from installer.events import EventSink
    from installer.tests.support import make_plan

    plan = make_plan(passphrase_source="stdin", passphrase=...)
    system = FakeSystem.live_machine()
    with pytest.raises(InstallerError, match="passphrase"):
        Engine(plan, system, system, EventSink(io.StringIO()))
    assert system.calls == []


def test_a_wrong_stage_cannot_proceed_without_its_prerequisites() -> None:
    """Calling a step out of order is an internal error, not a command run with missing values."""
    from installer.errors import InstallerError
    from installer.steps import luks

    ctx = scenario().engine.context
    with pytest.raises(InstallerError, match="internal error"):
        luks.luks_format(ctx)
    assert ctx.host.calls == []  # type: ignore[attr-defined]
