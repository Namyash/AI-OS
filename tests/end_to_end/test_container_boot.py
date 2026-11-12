"""Fast tests (no Docker, no QEMU) for the in-container boot logic: kernel/initrd discovery, the QEMU command, the
xorriso calls and main()'s error handling (xorriso and the exec of QEMU are replaced)."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.end_to_end import container_boot
from tests.end_to_end.container_boot import (
    KERNEL_ARGS,
    MAX_EXTRA_KERNEL_ARGS_LENGTH,
    BootFiles,
    BootFilesNotFoundError,
    extract_iso_file,
    list_iso_files,
    main,
    parse_iso_listing,
    qemu_command,
    select_boot_files,
    validate_extra_kernel_args,
)

BUILD_SCRIPT = Path(__file__).resolve().parents[2] / "os" / "build" / "in-container-build.sh"

# `xorriso -indev <iso> -find / -type f` on a live-build ISO prints one shell-quoted path per line.
LIVE_BUILD_LISTING = """\
'/.disk/info'
'/EFI/boot/bootx64.efi'
'/boot/grub/grub.cfg'
'/isolinux/isolinux.bin'
'/live/filesystem.packages'
'/live/filesystem.squashfs'
'/live/initrd.img'
'/live/initrd.img-6.12.115+deb13.1-amd64'
'/live/vmlinuz'
'/live/vmlinuz-6.12.115+deb13.1-amd64'
'/sha256sum.txt'
"""


def test_listing_parser_reads_quoted_paths_and_ignores_everything_else() -> None:
    output = "'/live/vmlinuz'\n\nDrive current: -indev '/iso/b.iso'\n'/odd/it'\"'\"'s here'\n'unterminated\n"
    assert parse_iso_listing(output) == ["/live/vmlinuz", "/odd/it's here"]


def test_listing_parser_on_a_real_style_listing() -> None:
    paths = parse_iso_listing(LIVE_BUILD_LISTING)
    assert "/live/filesystem.squashfs" in paths
    assert len(paths) == 11


def test_a_versioned_pair_next_to_the_squashfs_is_chosen() -> None:
    chosen = select_boot_files(parse_iso_listing(LIVE_BUILD_LISTING))
    assert chosen == BootFiles(
        kernel="/live/vmlinuz-6.12.115+deb13.1-amd64", initrd="/live/initrd.img-6.12.115+deb13.1-amd64"
    )


def test_the_highest_version_wins_by_number_not_by_text() -> None:
    paths = [
        "/live/vmlinuz-6.12.9-amd64",
        "/live/initrd.img-6.12.9-amd64",
        "/live/vmlinuz-6.12.115-amd64",
        "/live/initrd.img-6.12.115-amd64",
        "/live/filesystem.squashfs",
    ]
    assert select_boot_files(paths).kernel == "/live/vmlinuz-6.12.115-amd64"


def test_unversioned_names_are_used_when_nothing_else_exists() -> None:
    paths = ["/live/vmlinuz", "/live/initrd.img", "/live/filesystem.squashfs"]
    assert select_boot_files(paths) == BootFiles(kernel="/live/vmlinuz", initrd="/live/initrd.img")


def test_other_media_layouts_work_without_any_change() -> None:
    paths = ["/casper/vmlinuz", "/casper/initrd", "/casper/filesystem.squashfs", "/boot/grub/grub.cfg"]
    assert select_boot_files(paths) == BootFiles(kernel="/casper/vmlinuz", initrd="/casper/initrd")


def test_the_pair_beside_the_squashfs_beats_a_newer_pair_elsewhere() -> None:
    paths = [
        "/live/vmlinuz-1.0",
        "/live/initrd.img-1.0",
        "/live/filesystem.squashfs",
        "/install/vmlinuz-9.9",
        "/install/initrd.img-9.9",
    ]
    assert select_boot_files(paths).kernel == "/live/vmlinuz-1.0"


def test_without_a_squashfs_any_pair_is_acceptable() -> None:
    assert select_boot_files(["/boot/vmlinuz-5.1", "/boot/initrd.img-5.1"]).kernel == "/boot/vmlinuz-5.1"


def test_a_kernel_and_initrd_of_different_versions_are_not_a_pair() -> None:
    with pytest.raises(BootFilesNotFoundError):
        select_boot_files(["/live/vmlinuz-1.0", "/live/initrd.img-2.0", "/live/filesystem.squashfs"])


@pytest.mark.parametrize(
    "paths",
    [[], ["/live/filesystem.squashfs"], ["/live/vmlinuz"], ["/live/initrd.img"], ["/a/vmlinuz", "/b/initrd.img"]],
)
def test_no_matching_pair_is_an_error_that_names_what_was_found(paths: list[str]) -> None:
    with pytest.raises(BootFilesNotFoundError, match="no matching kernel/initrd pair"):
        select_boot_files(paths)


def _command() -> list[str]:
    return qemu_command(
        kernel=Path("/work/kernel"), initrd=Path("/work/initrd"), iso=Path("/iso/boot.iso"), memory_mib=3072, cpus=3
    )


def _option(command: list[str], flag: str) -> str:
    return command[command.index(flag) + 1]


def test_qemu_runs_in_software_with_the_serial_console_on_stdio() -> None:
    command = _command()
    assert command[0] == "qemu-system-x86_64"
    assert _option(command, "-accel") == "tcg"
    assert "-nographic" in command
    assert _option(command, "-serial") == "stdio"
    assert _option(command, "-monitor") == "none"
    assert "-no-reboot" in command


def test_extra_kernel_args_come_after_the_harness_s_own_words_and_default_to_nothing() -> None:
    assert _option(_command(), "-append") == KERNEL_ARGS
    command = qemu_command(
        kernel=Path("/work/kernel"),
        initrd=Path("/work/initrd"),
        iso=Path("/iso/boot.iso"),
        memory_mib=3072,
        cpus=3,
        extra_kernel_args="  systemd.journald.forward_to_console=1   loglevel=7 ",
    )
    assert _option(command, "-append") == f"{KERNEL_ARGS} systemd.journald.forward_to_console=1 loglevel=7"


@pytest.mark.parametrize(
    "bad", ["a\nb", "a\tb", "a\x1bb", "a\x00b", "caf\u00e9", "a" * (MAX_EXTRA_KERNEL_ARGS_LENGTH + 1)]
)
def test_extra_kernel_args_that_are_not_one_bounded_line_of_printable_ascii_are_refused(bad: str) -> None:
    with pytest.raises(ValueError, match=r"at most|printable ASCII"):
        validate_extra_kernel_args(bad)
    with pytest.raises(ValueError):
        qemu_command(
            kernel=Path("/work/kernel"),
            initrd=Path("/work/initrd"),
            iso=Path("/iso/boot.iso"),
            memory_mib=1024,
            cpus=1,
            extra_kernel_args=bad,
        )


def test_main_refuses_bad_extra_kernel_args_before_touching_the_iso(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[Path] = []
    monkeypatch.setattr(container_boot, "list_iso_files", lambda iso: called.append(iso) or [])
    with pytest.raises(SystemExit):
        main(["/iso/boot.iso", "--memory-mib", "1024", "--cpus", "1", "--extra-kernel-args=bad\nline"])
    assert called == []


def test_main_hands_extra_kernel_args_to_qemu(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container_boot, "list_iso_files", lambda iso: parse_iso_listing(LIVE_BUILD_LISTING))
    monkeypatch.setattr(container_boot, "extract_iso_file", lambda iso, path, dest: None)
    executed: list[list[str]] = []
    monkeypatch.setattr(container_boot.os, "execvp", lambda file, argv: executed.append(argv))
    main(["/iso/boot.iso", "--memory-mib", "1024", "--cpus", "1", "--extra-kernel-args=-b loglevel=7"])
    assert _option(executed[0], "-append") == f"{KERNEL_ARGS} -b loglevel=7"


def test_qemu_gets_the_requested_memory_and_cpus() -> None:
    command = _command()
    assert _option(command, "-m") == "3072"
    assert _option(command, "-smp") == "3"


def test_the_iso_is_attached_as_a_read_only_cdrom() -> None:
    drive = _option(_command(), "-drive")
    assert drive.startswith("file=/iso/boot.iso,")
    assert "media=cdrom" in drive
    assert "readonly=on" in drive


def test_the_nic_is_user_mode_and_restricted() -> None:
    command = _command()
    assert _option(command, "-netdev").split(",") == ["user", "id=net0", "restrict=on"]
    assert "netdev=net0" in _option(command, "-device")


def test_kernel_arguments_enable_the_selfcheck_and_keep_output_complete() -> None:
    words = KERNEL_ARGS.split()
    assert {"boot=live", "components", "console=ttyS0", "pai.selfcheck=1"} <= set(words)
    assert "quiet" not in words
    assert _option(_command(), "-append") == KERNEL_ARGS
    assert _option(_command(), "-kernel") == "/work/kernel"
    assert _option(_command(), "-initrd") == "/work/initrd"


def test_a_panic_or_a_missing_live_medium_reboots_at_once_so_the_run_ends_instead_of_stalling() -> None:
    """Without panic=-1 live-boot waits in an initramfs shell nobody types into, and a kernel panic halts the guest:
    the container never exits and the run lasts until the overall timeout (measured: still running after 200 s)."""
    assert "panic=-1" in KERNEL_ARGS.split()
    assert "-no-reboot" in _command()  # the reboot then ends QEMU


# Words the build passes that the harness leaves out on purpose: both only hide boot output.
LEFT_OUT_ON_PURPOSE = {"quiet", "splash"}


def test_kernel_arguments_follow_the_boot_configuration_the_image_is_built_with() -> None:
    """The harness boots with its own arguments, so they must not drift from what the build bakes into the ISO."""
    match = re.search(r'--bootappend-live\s+"([^"]+)"', BUILD_SCRIPT.read_text(encoding="utf-8"))
    assert match is not None, "--bootappend-live not found in the build script"
    image_words = set(match.group(1).split())
    missing = image_words - set(KERNEL_ARGS.split()) - LEFT_OUT_ON_PURPOSE
    assert not missing, (
        f"the build passes {sorted(missing)}, which the boot harness does not: copy it or leave it out on purpose"
    )


# ---- xorriso calls ------------------------------------------------------------------------------------------------


def _xorriso(
    monkeypatch: pytest.MonkeyPatch,
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    effect: Callable[[tuple[str, ...]], None] | None = None,
) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    def fake(*args: str) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if effect is not None:
            effect(args)
        return subprocess.CompletedProcess(["xorriso", *args], returncode, stdout, stderr)

    monkeypatch.setattr(container_boot, "_run_xorriso", fake)
    return calls


def test_the_iso_is_listed_with_a_read_only_find(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _xorriso(monkeypatch, stdout=LIVE_BUILD_LISTING)
    assert len(list_iso_files(Path("/iso/boot.iso"))) == 11
    assert calls == [("-indev", str(Path("/iso/boot.iso")), "-find", "/", "-type", "f")]


def test_a_listing_failure_names_the_iso_and_xorrisos_complaint(monkeypatch: pytest.MonkeyPatch) -> None:
    _xorriso(monkeypatch, returncode=5, stderr="libisoburn : FAILURE : Permission denied")
    with pytest.raises(RuntimeError, match=r"could not list .*boot\.iso: .*Permission denied"):
        list_iso_files(Path("/iso/boot.iso"))


def test_extraction_goes_to_the_destination_and_checks_it_arrived(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    destination = tmp_path / "kernel"
    calls = _xorriso(monkeypatch, effect=lambda args: destination.write_bytes(b"k"))
    extract_iso_file(Path("/iso/boot.iso"), "/live/vmlinuz", destination)
    assert calls == [
        ("-osirrox", "on", "-indev", str(Path("/iso/boot.iso")), "-extract", "/live/vmlinuz", str(destination))
    ]


def test_an_extraction_that_fails_is_an_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _xorriso(monkeypatch, returncode=1, stderr="no such file")
    with pytest.raises(RuntimeError, match="could not extract /live/vmlinuz: no such file"):
        extract_iso_file(Path("/iso/boot.iso"), "/live/vmlinuz", tmp_path / "kernel")


def test_an_extraction_that_exits_zero_but_leaves_no_file_is_an_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _xorriso(monkeypatch)
    with pytest.raises(RuntimeError, match="could not extract"):
        extract_iso_file(Path("/iso/boot.iso"), "/live/vmlinuz", tmp_path / "kernel")


# ---- main ---------------------------------------------------------------------------------------------------------


def test_main_extracts_what_it_found_and_hands_the_process_to_qemu(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container_boot, "list_iso_files", lambda iso: parse_iso_listing(LIVE_BUILD_LISTING))
    extracted: list[str] = []
    monkeypatch.setattr(container_boot, "extract_iso_file", lambda iso, path, dest: extracted.append(path))
    executed: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(container_boot.os, "execvp", lambda file, argv: executed.append((file, argv)))

    main(["/iso/boot.iso", "--memory-mib", "1536", "--cpus", "3"])

    assert extracted == ["/live/vmlinuz-6.12.115+deb13.1-amd64", "/live/initrd.img-6.12.115+deb13.1-amd64"]
    ((file, argv),) = executed
    assert file == argv[0] == "qemu-system-x86_64"
    assert _option(argv, "-m") == "1536"
    assert _option(argv, "-smp") == "3"
    assert _option(argv, "-append") == KERNEL_ARGS


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("xorriso could not list /iso/boot.iso: Permission denied"), BootFilesNotFoundError("no pair")],
    ids=["xorriso-failed", "no-kernel-on-the-iso"],
)
def test_main_reports_an_unbootable_iso_and_exits_two_without_starting_qemu(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], failure: Exception
) -> None:
    def fail(iso: Path) -> list[str]:
        raise failure

    monkeypatch.setattr(container_boot, "list_iso_files", fail)
    executed: list[object] = []
    monkeypatch.setattr(container_boot.os, "execvp", lambda file, argv: executed.append(file))
    assert main(["/iso/boot.iso", "--memory-mib", "1024", "--cpus", "1"]) == 2
    assert f"[pai-e2e] ERROR: {failure}" in capsys.readouterr().err
    assert executed == []


@pytest.mark.parametrize("flag", ["--memory-mib", "--cpus"])
def test_main_refuses_a_zero_memory_or_cpu_count(flag: str) -> None:
    argv = ["/iso/boot.iso", "--memory-mib", "1024", "--cpus", "1"]
    argv[argv.index(flag) + 1] = "0"
    with pytest.raises(SystemExit):
        main(argv)
