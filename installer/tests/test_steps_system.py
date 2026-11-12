"""Filesystems, mounting, copying, configuration, boot loader and ending, one step at a time."""
# ruff: noqa: S108

from __future__ import annotations

import pytest

from installer.context import InstallContext
from installer.errors import CommandError, InstallerError, SafetyError, VerificationError
from installer.runner import CommandResult
from installer.steps import boot, configure, copy, filesystems, finish
from installer.tests.fakes import FakeSystem
from installer.tests.support import run_until, scenario

ROOT = "/run/pai-install/target"


def at(step: str, system: FakeSystem | None = None, **overrides: object) -> tuple[FakeSystem, InstallContext]:
    system = system or FakeSystem.live_machine()
    return system, run_until(scenario(system, **overrides), step)


# --------------------------------------------------------------------------------------------- filesystems
def test_filesystems_get_the_designed_types_and_labels() -> None:
    system, ctx = at("mkfs")
    filesystems.make_filesystems(ctx)
    assert system.argvs()[-3:] == [
        ["mkfs.vfat", "-F", "32", "-n", "PAI-ESP", "/dev/sda2"],
        ["mkfs.ext4", "-F", "-q", "-L", "pai-boot", "/dev/sda3"],
        ["mkfs.ext4", "-F", "-q", "-L", "pai-root", "/dev/mapper/cryptroot"],
    ]


def test_the_uuids_are_read_by_probing_and_checked_against_the_expected_types() -> None:
    system, ctx = at("identify-filesystems")
    filesystems.identify_filesystems(ctx)
    assert ctx.uuids is not None and len({ctx.uuids.luks, ctx.uuids.root_fs, ctx.uuids.boot_fs, ctx.uuids.esp_fs}) == 4
    assert all(call.argv[:4] == ["blkid", "--probe", "--output", "export"] for call in system.commands("blkid"))


def test_a_filesystem_of_the_wrong_type_is_refused() -> None:
    system, ctx = at("identify-filesystems")
    system.filesystems["/dev/sda3"] = ("xfs", "pai-boot", "u-1234")
    with pytest.raises(VerificationError, match="expected ext4"):
        filesystems.identify_filesystems(ctx)


def test_a_filesystem_without_a_usable_uuid_is_refused() -> None:
    system, ctx = at("identify-filesystems")
    system.filesystems["/dev/sda3"] = ("ext4", "pai-boot", "not a uuid!")
    with pytest.raises(VerificationError, match="UUID"):
        filesystems.identify_filesystems(ctx)


def test_the_tree_is_mounted_root_first_then_boot_then_the_esp() -> None:
    system, ctx = at("mount")
    filesystems.mount_target_tree(ctx)
    mounts = [argv for argv in system.argvs() if argv[0] == "mount"]
    assert mounts == [
        ["mount", "-t", "ext4", "/dev/mapper/cryptroot", ROOT],
        ["mount", "-t", "ext4", "/dev/sda3", f"{ROOT}/boot"],
        ["mount", "-t", "vfat", "-o", "umask=0077", "/dev/sda2", f"{ROOT}/boot/efi"],
    ]
    assert len(ctx.resources) == 4  # the open mapping and the three mounts


def test_unwinding_unmounts_in_reverse_order() -> None:
    system, ctx = at("mount")
    filesystems.mount_target_tree(ctx)
    before = len(system.calls)
    assert ctx.resources.unwind() == []
    umounts = [call.argv[-1] for call in system.calls[before:] if call.argv[0] == "umount"]
    assert umounts[0] == f"{ROOT}/boot/efi"
    assert system.mounted_paths() == []


def test_unmounting_something_not_mounted_runs_nothing() -> None:
    system, ctx = at("mount")
    before = len(system.calls)
    filesystems.unmount(ctx, f"{ROOT}/boot")
    assert len(system.calls) == before


def test_a_busy_mount_is_retried_then_reported() -> None:
    system, ctx = at("mount")
    filesystems.mount_target_tree(ctx)
    system.busy_mounts.add(f"{ROOT}/boot/efi")
    with pytest.raises(CommandError, match="still mounted"):
        filesystems.unmount(ctx, f"{ROOT}/boot/efi")
    assert len([c for c in system.calls if c.argv[0] == "umount"]) == 3
    assert system.clock == 2.0  # a pause between attempts, none after the last


def test_a_mount_that_frees_up_is_unmounted_on_a_retry() -> None:
    system, ctx = at("mount")
    filesystems.mount_target_tree(ctx)
    system.fail_on("umount", times=1)
    filesystems.unmount(ctx, f"{ROOT}/boot/efi")
    assert f"{ROOT}/boot/efi" not in system.mounted_paths()


# --------------------------------------------------------------------------------------------------- copy
def test_the_live_layers_are_discovered_from_the_mount_table() -> None:
    system = FakeSystem.live_machine()
    assert copy.discover_live_layers(system) == ["/run/live/rootfs/filesystem.squashfs"]


def test_every_live_squashfs_layer_is_found_in_mount_order_and_foreign_squashfs_mounts_are_not() -> None:
    system = FakeSystem.live_machine()
    system.add_mount("7:1", "/lib/live/mount/rootfs/extra.squashfs", "squashfs", "/dev/loop1")
    system.add_mount("7:2", "/snap/core/1234", "squashfs", "/dev/loop2")
    system.add_mount("7:3", "/run/live/medium/live/filesystem.squashfs", "iso9660", "x")
    assert copy.discover_live_layers(system) == [
        "/run/live/rootfs/filesystem.squashfs",
        "/lib/live/mount/rootfs/extra.squashfs",
    ]


def test_a_system_that_is_not_live_has_nothing_to_copy() -> None:
    system = FakeSystem.live_machine()
    system.mounts = [m for m in system.mounts if m[2] != "squashfs"]
    with pytest.raises(SafetyError) as caught:
        copy.discover_live_layers(system)
    assert caught.value.reason == "no-live-system"


def test_the_engine_stops_before_any_command_when_there_is_no_live_system() -> None:
    system = FakeSystem.live_machine()
    system.mounts = [m for m in system.mounts if m[2] != "squashfs"]
    run = scenario(system)
    assert run.run() is False and system.calls == [] and system.secret_files == {}
    assert "find-source" in run.result["error"]


def test_the_system_is_copied_from_the_squashfs_layer_with_everything_preserved() -> None:
    system, ctx = at("copy-system")
    filesystems.mount_target_tree(ctx)
    before = len(system.calls)
    copy.copy_system(ctx)
    (rsync,) = [c.argv for c in system.calls[before:] if c.argv[0] == "rsync"]
    assert rsync[:7] == [
        "rsync",
        "--archive",
        "--hard-links",
        "--acls",
        "--xattrs",
        "--numeric-ids",
        "--one-file-system",
    ]
    assert rsync[-2:] == ["/run/live/rootfs/filesystem.squashfs/", f"{ROOT}/"]
    excludes = {a.removeprefix("--exclude=") for a in rsync if a.startswith("--exclude=")}
    assert {"/proc/*", "/sys/*", "/dev/*", "/run/*", "/tmp/*", "/boot/efi"} <= excludes
    assert f"{ROOT}/etc/passwd" in system.files
    assert system.calls[-1].argv == ["sync"]


def test_the_live_overlay_and_the_root_are_never_a_copy_source() -> None:
    system, ctx = at("copy-system")
    filesystems.mount_target_tree(ctx)
    copy.copy_system(ctx)
    sources = [c.argv[-2] for c in system.commands("rsync")]
    assert sources == ["/run/live/rootfs/filesystem.squashfs/"]


def test_several_layers_are_copied_base_first() -> None:
    system = FakeSystem.live_machine()
    system.add_mount("7:1", "/run/live/rootfs/second.squashfs", "squashfs", "/dev/loop1")
    system.source_trees["/run/live/rootfs/second.squashfs"] = {"/usr/bin/extra": "x"}
    ctx = run_until(scenario(system), "copy-system")
    filesystems.mount_target_tree(ctx)
    copy.copy_system(ctx)
    assert [c.argv[-2] for c in system.commands("rsync")] == [
        "/run/live/rootfs/filesystem.squashfs/",
        "/run/live/rootfs/second.squashfs/",
    ]


# ------------------------------------------------------------------------------------------- configuration
def test_fstab_and_crypttab_use_uuids_without_discard_or_keyfile() -> None:
    _, ctx = at("configure-files")
    uuids = ctx.require_uuids()
    fstab = configure.render_fstab(uuids)
    assert f"UUID={uuids.root_fs} / ext4" in fstab and f"UUID={uuids.boot_fs} /boot ext4" in fstab
    assert f"UUID={uuids.esp_fs} /boot/efi vfat" in fstab
    assert "/dev/sd" not in fstab and "discard" not in fstab
    crypttab = configure.render_crypttab(uuids, "cryptroot")
    entry = [line for line in crypttab.splitlines() if not line.startswith("#")]
    assert entry == [f"cryptroot UUID={uuids.luks} none luks,initramfs"]
    assert "discard" not in crypttab


def test_the_configuration_files_are_written_into_the_target_by_install() -> None:
    system, ctx = at("configure-files")
    filesystems.mount_target_tree(ctx)
    configure.write_configuration_files(ctx)
    written = {c.argv[-1]: c.stdin.decode() for c in system.commands("install") if c.argv[1] == "-D"}
    assert set(written) == {
        f"{ROOT}/etc/fstab",
        f"{ROOT}/etc/crypttab",
        f"{ROOT}/etc/hostname",
        f"{ROOT}/etc/hosts",
        f"{ROOT}/etc/default/grub.d/90-pai-installer.cfg",
    }
    assert written[f"{ROOT}/etc/hostname"] == "pai\n"
    assert "127.0.1.1 pai\n" in written[f"{ROOT}/etc/hosts"]
    grub = written[f"{ROOT}/etc/default/grub.d/90-pai-installer.cfg"]
    assert 'GRUB_CMDLINE_LINUX="quiet loglevel=3"\n' in grub and "GRUB_TIMEOUT=2\n" in grub


def test_grub_defaults_with_no_extra_arguments() -> None:
    assert 'GRUB_CMDLINE_LINUX=""\n' in configure.render_grub_defaults(())


def test_chroot_binds_are_slave_mounts_and_all_released_afterwards() -> None:
    system, ctx = at("chroot-mounts")
    filesystems.mount_target_tree(ctx)
    before = len(system.calls)
    configure.mount_chroot_binds(ctx)
    mounts = [c.argv for c in system.calls[before:]]
    assert mounts == [
        ["mount", "-t", "proc", "proc", f"{ROOT}/proc"],
        ["mount", "--rbind", "/dev", f"{ROOT}/dev"],
        ["mount", "--make-rslave", f"{ROOT}/dev"],
        ["mount", "--rbind", "/sys", f"{ROOT}/sys"],
        ["mount", "--make-rslave", f"{ROOT}/sys"],
        ["mount", "--bind", "/run", f"{ROOT}/run"],
        ["mount", "--make-rslave", f"{ROOT}/run"],
    ]
    assert ctx.resources.unwind() == [] and system.mounted_paths() == []


def prepared_for_live_removal() -> tuple[FakeSystem, InstallContext]:
    system, ctx = at("remove-live-session")
    return system, ctx


def test_the_live_user_is_read_from_live_config_else_defaults_and_must_exist() -> None:
    system, ctx = prepared_for_live_removal()
    assert configure.discover_live_user(ctx) == "user"
    system.files[f"{ROOT}/etc/live/config.conf.d/user.conf"] = 'export LIVE_USERNAME="kiosk"\n'
    assert configure.discover_live_user(ctx) is None  # configured, but no such account
    system.files[f"{ROOT}/etc/passwd"] += "kiosk:x:1002:1002::/home/kiosk:/bin/bash\n"
    assert configure.discover_live_user(ctx) == "kiosk"
    del system.files[f"{ROOT}/etc/live/config.conf.d/user.conf"]
    assert configure.discover_live_user(ctx) == "user"  # live-config's own default


def test_an_invalid_live_user_name_in_the_image_is_refused() -> None:
    system, ctx = prepared_for_live_removal()
    system.files[f"{ROOT}/etc/live/config.conf.d/user.conf"] = 'LIVE_USERNAME="a;b"\n'
    with pytest.raises(InstallerError, match="not a valid account name"):
        configure.discover_live_user(ctx)


def test_live_removal_deletes_the_user_purges_installed_live_packages_and_removes_leftovers() -> None:
    system, ctx = prepared_for_live_removal()
    before = len(system.calls)
    configure.remove_live_session(ctx)
    argvs = [c.inner for c in system.calls[before:]]
    assert argvs[0] == ["userdel", "--remove", "user"]
    assert argvs[2] == [
        "apt-get", "--yes", "--quiet", "purge",
        "live-boot", "live-boot-doc", "live-boot-initramfs-tools", "live-config", "live-config-systemd", "live-tools",
    ]  # fmt: skip
    assert argvs[3][:5] == ["rm", "-rf", "--one-file-system", "--", "/etc/live"]
    assert "/etc/systemd/system/getty@tty1.service.d/autologin.conf" in argvs[3]
    assert not any("tty2" in part for part in argvs[3]), (
        "only an autologin drop-in is removed, not other getty settings"
    )
    assert system.installed_packages == {}


def test_nothing_is_purged_when_no_live_package_is_installed() -> None:
    system, ctx = prepared_for_live_removal()
    system.installed_packages = {"live-boot": "not-installed", "coreutils": "installed"}
    configure.remove_live_session(ctx)
    assert system.commands("apt-get") == [] and system.purged == []


def test_a_package_that_dpkg_does_not_report_installed_is_not_purged() -> None:
    system, ctx = prepared_for_live_removal()
    system.installed_packages = {
        "live-config": "installed",
        "live-config-doc": "not-installed",
        "live-tools": "config-files",
    }
    assert configure.installed_live_packages(ctx) == ["live-config", "live-tools"]


def test_a_failing_package_query_is_an_error_not_an_empty_list() -> None:
    system, ctx = prepared_for_live_removal()
    system.fail_on("chroot", "*", "dpkg-query", returncode=2)
    with pytest.raises(InstallerError, match="dpkg-query failed"):
        configure.installed_live_packages(ctx)


def test_the_live_user_may_have_the_name_the_plan_wants() -> None:
    system = FakeSystem.live_machine()
    run = scenario(system, username="user")
    assert run.run() is True
    users = [line.split(":")[0] for line in system.files[f"{ROOT}/etc/passwd"].splitlines()]
    assert users.count("user") == 1
    assert "user:!:" in system.files[f"{ROOT}/etc/shadow"]


def test_accounts_lock_root_and_create_one_locked_user_without_groups() -> None:
    system, ctx = at("accounts")
    before = len(system.calls)
    configure.create_accounts(ctx)
    assert [c.inner for c in system.calls[before:]] == [
        ["passwd", "--lock", "root"],
        ["useradd", "--create-home", "--shell", "/bin/bash", "--user-group", "owner"],
        ["passwd", "--lock", "owner"],
    ]
    assert not any("--groups" in c.argv or "-G" in c.argv or "sudo" in c.argv for c in system.calls[before:])


def finished_configuration() -> tuple[FakeSystem, InstallContext]:
    system, ctx = at("verify-installation")
    return system, ctx


def test_verification_accepts_the_finished_configuration() -> None:
    _, ctx = finished_configuration()
    assert "every account is locked" in configure.verify_accounts(ctx)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda s: s.__setitem__(f"{ROOT}/etc/shadow", s[f"{ROOT}/etc/shadow"].replace("root:!", "root:")), "root"),
        (
            lambda s: s.__setitem__(f"{ROOT}/etc/shadow", s[f"{ROOT}/etc/shadow"] + "extra::19000:0:99999:7:::\n"),
            "extra",
        ),
        (lambda s: s.__setitem__(f"{ROOT}/etc/shadow", s[f"{ROOT}/etc/shadow"] + "extra:$6$x$y:19000:::::\n"), "extra"),
        (lambda s: s.__setitem__(f"{ROOT}/etc/group", "sudo:x:27:owner\n"), "administrative group"),
        (lambda s: s.__setitem__(f"{ROOT}/etc/live/config.conf", "x"), "live-session files"),
        (
            lambda s: s.__setitem__(
                f"{ROOT}/etc/systemd/system/getty@tty1.service.d/a.conf", "ExecStart=agetty --autologin x"
            ),
            "live-session files",
        ),
        (lambda s: s.__setitem__(f"{ROOT}/etc/passwd", "root:x:0:0::/root:/bin/bash\n"), "primary user"),
    ],
)
def test_verification_refuses_any_default_credential_or_live_remnant(change, message: str) -> None:
    system, ctx = finished_configuration()
    change(system.files)
    with pytest.raises(VerificationError, match=message):
        configure.verify_accounts(ctx)


def test_a_missing_shadow_file_is_refused() -> None:
    system, ctx = finished_configuration()
    del system.files[f"{ROOT}/etc/shadow"]
    with pytest.raises(VerificationError, match="shadow"):
        configure.verify_accounts(ctx)


def test_the_machine_id_is_emptied() -> None:
    system, ctx = at("machine-id")
    assert system.files[f"{ROOT}/etc/machine-id"] != ""
    configure.reset_machine_id(ctx)
    assert system.files[f"{ROOT}/etc/machine-id"] == ""
    assert ["rm", "-f", "/var/lib/dbus/machine-id"] in [c.inner for c in system.calls]


# ----------------------------------------------------------------------------------------------- boot and end
def test_initramfs_and_both_boot_loaders_are_built_in_the_designed_order() -> None:
    system, ctx = at("initramfs")
    before = len(system.calls)
    boot.build_initramfs(ctx)
    boot.install_bootloader(ctx)
    assert [c.inner for c in system.calls[before:]] == [
        ["update-initramfs", "-u", "-k", "all"],
        ["grub-install", "--target=i386-pc", "--recheck", "/dev/sda"],
        ["grub-install", "--target=x86_64-efi", "--efi-directory=/boot/efi", "--removable", "--no-nvram", "--recheck"],
        ["update-grub"],
    ]


@pytest.mark.parametrize("missing", boot.BOOT_ARTIFACTS)
def test_every_boot_artifact_is_required(missing: str) -> None:
    system, ctx = at("verify-installation")
    del system.files[f"{ROOT}{missing}"]
    with pytest.raises(VerificationError, match="incomplete"):
        boot.verify_boot_files(ctx)


@pytest.mark.parametrize(
    ("after", "argv"),
    [("poweroff", ["systemctl", "--no-block", "poweroff"]), ("reboot", ["systemctl", "--no-block", "reboot"])],
)
def test_the_after_action_is_queued_without_waiting(after: str, argv: list[str]) -> None:
    system, ctx = at("after", after=after)
    finish.run_after_action(ctx)
    assert system.calls[-1].argv == argv


def test_after_none_runs_nothing() -> None:
    system, ctx = at("after", after="none")
    before = len(system.calls)
    finish.run_after_action(ctx)
    assert len(system.calls) == before


def test_closing_unmounts_everything_and_closes_the_mapping() -> None:
    system, ctx = at("close")
    finish.close_everything(ctx)
    assert system.mounted_paths() == [] and system.mappings == {} and "/dev/mapper/cryptroot" not in system.nodes


def test_closing_fails_loudly_when_something_stays_mounted() -> None:
    system, ctx = at("close")
    system.busy_mounts.add(f"{ROOT}/boot")
    with pytest.raises(CommandError, match="still mounted"):
        finish.close_everything(ctx)


def test_closing_notices_a_mount_under_the_work_directory_it_did_not_make() -> None:
    system, ctx = at("close")
    system.add_mount("0:77", "/run/pai-install/stray", "tmpfs", "tmpfs")
    with pytest.raises(VerificationError, match=r"still mounted under .*: /run/pai-install/stray"):
        finish.close_everything(ctx)


def test_closing_tolerates_the_mount_systemd_makes_at_the_work_directory_itself() -> None:
    """Regression (found on the real install): ReadWritePaths= makes systemd bind-mount /run/pai-install onto itself
    in the service's mount namespace. That mount is not the engine's, so it must not make a finished install report
    failure."""
    system, ctx = at("close")
    system.add_mount("0:78", "/run/pai-install", "tmpfs", "tmpfs")
    assert finish.close_everything(ctx)
    assert ctx.installation_complete


def test_a_mount_below_the_work_directory_is_still_caught_when_the_work_directory_is_itself_a_mount() -> None:
    system, ctx = at("close")
    system.add_mount("0:78", "/run/pai-install", "tmpfs", "tmpfs")
    system.add_mount("0:79", "/run/pai-install/leftover", "tmpfs", "tmpfs")
    with pytest.raises(VerificationError, match="/run/pai-install/leftover") as caught:
        finish.close_everything(ctx)
    assert caught.value.args[0].count("/run/pai-install") == 2  # the directory, once, and the leftover: not itself


def test_closing_notices_a_mapping_that_is_still_there_after_close() -> None:
    system, ctx = at("close")
    original = system._cmd_cryptsetup

    def close_that_does_nothing(call):
        return CommandResult(0) if call.argv[1] == "close" else original(call)

    system._cmd_cryptsetup = close_that_does_nothing  # type: ignore[method-assign]
    with pytest.raises(VerificationError, match="still open"):
        finish.close_everything(ctx)
