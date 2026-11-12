"""Fast tests (no Docker, no QEMU) for the in-container side of the install test: the QEMU command lines, the firmware
lookup, the plan medium and the target disk, and main()'s steps (xorriso and the exec of QEMU replaced)."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.end_to_end import container_boot, container_install
from tests.end_to_end.container_boot import KERNEL_ARGS
from tests.end_to_end.container_install import (
    INSTALL_KERNEL_ARGS,
    MAX_PLAN_BYTES,
    NO_UEFI_EXIT_STATUS,
    Firmware,
    create_sparse_disk,
    disk_boot_command,
    find_uefi_firmware,
    install_command,
    main,
    make_media,
    parse_firmware_descriptor,
    plan_drive_options,
    plan_medium_command,
    read_plan,
    target_drive_options,
)
from tests.end_to_end.install_plan import PLAN_VOLUME_LABEL, TARGET_SERIAL

BUILD_SCRIPT = Path(__file__).resolve().parents[2] / "os" / "build" / "in-container-build.sh"
SECRET = "plan-secret-that-must-never-be-echoed"  # noqa: S105 - a test marker, not a credential
PLAN = json.dumps({"version": 1, "passphrase": SECRET}).encode()


def option_values(command: list[str], flag: str) -> list[str]:
    return [command[index + 1] for index, word in enumerate(command) if word == flag]


# ---- the install boot ------------------------------------------------------------------------------------------------


def install() -> list[str]:
    return install_command(
        kernel=Path("/work/kernel"), initrd=Path("/work/initrd"), iso=Path("/iso/boot.iso"), memory_mib=3072, cpus=2
    )


def test_the_install_boot_runs_the_installer_and_not_the_selfcheck() -> None:
    words = INSTALL_KERNEL_ARGS.split()
    assert "pai.install=auto" in words
    assert "pai.selfcheck=1" not in words  # the self-check powers the machine off when it finishes: mid-install
    assert {"boot=live", "components", "console=ttyS0", "panic=-1"} <= set(words)
    assert "quiet" not in words


def test_the_install_boot_masks_the_kiosk_for_this_boot_only() -> None:
    assert "systemd.mask=pai-kiosk.service" in INSTALL_KERNEL_ARGS.split()
    assert "pai-kiosk.service" not in KERNEL_ARGS  # the plain boot test still starts it
    kiosk_unit = (
        Path(__file__).resolve().parents[2]
        / "os"
        / "kiosk"
        / "rootfs"
        / "etc"
        / "systemd"
        / "system"
        / "pai-kiosk.service"
    )
    assert kiosk_unit.is_file()


def test_the_install_arguments_follow_the_live_boot_arguments_the_image_is_built_with() -> None:
    """Derived from container_boot.KERNEL_ARGS, so they cannot drift from what the build bakes into the ISO."""
    match = re.search(r'--bootappend-live\s+"([^"]+)"', BUILD_SCRIPT.read_text(encoding="utf-8"))
    assert match is not None
    missing = set(match.group(1).split()) - set(INSTALL_KERNEL_ARGS.split()) - {"quiet", "splash"}
    assert not missing


def test_the_install_boot_passes_its_own_arguments_to_the_kernel() -> None:
    command = install()
    assert option_values(command, "-append") == [INSTALL_KERNEL_ARGS]
    assert option_values(command, "-kernel") == ["/work/kernel"]


def test_the_install_boot_attaches_the_iso_the_plan_medium_and_the_target_in_that_order() -> None:
    command = install()
    drives = option_values(command, "-drive")
    assert len(drives) == 3
    assert drives[0].startswith("file=/iso/boot.iso,") and "media=cdrom" in drives[0] and "readonly=on" in drives[0]
    assert drives[1] == plan_drive_options(container_install.PLAN_IMAGE)[1]
    assert drives[2] == target_drive_options(container_install.TARGET_IMAGE)[1]
    assert target_drive_options(container_install.TARGET_IMAGE)[3] in option_values(command, "-device")


def test_the_plan_medium_is_a_read_only_cdrom() -> None:
    (drive,) = plan_drive_options(Path("/disks/plan.iso"))[1:]
    assert drive == "file=/disks/plan.iso,media=cdrom,readonly=on,format=raw"


def test_the_target_is_a_virtio_disk_with_the_serial_the_plan_names_it_by() -> None:
    drive, flag, device = target_drive_options(Path("/disks/target.img"))[1:]
    assert flag == "-device"
    assert drive.split(",")[1:3] == ["if=none", "id=target"] and "format=raw" in drive.split(",")
    # `serial` belongs to the device: QEMU's raw driver refuses it as a -drive option (found by booting, not by
    # reading).
    assert "serial" not in drive
    assert device.split(",") == ["virtio-blk-pci", "drive=target", f"serial={TARGET_SERIAL}"]


def test_extra_kernel_words_follow_the_install_arguments() -> None:
    command = install_command(
        kernel=Path("/k"), initrd=Path("/i"), iso=Path("/x.iso"), memory_mib=1, cpus=1, extra_kernel_args="loglevel=7"
    )
    assert option_values(command, "-append") == [f"{INSTALL_KERNEL_ARGS} loglevel=7"]


def test_the_install_boot_is_as_confined_as_the_plain_boot() -> None:
    command = install()
    assert option_values(command, "-accel") == ["tcg"]
    assert option_values(command, "-netdev") == ["user,id=net0,restrict=on"]
    assert "-no-reboot" in command and "-nographic" in command


# ---- booting the installed disk --------------------------------------------------------------------------------------


def test_the_bios_boot_has_no_kernel_of_ours_and_no_firmware_files() -> None:
    command = disk_boot_command(memory_mib=3072, cpus=2, firmware=None)
    assert "-kernel" not in command and "-initrd" not in command and "-append" not in command
    assert not [word for word in command if "pflash" in word]
    assert option_values(command, "-boot") == ["order=c"]
    assert option_values(command, "-drive") == [target_drive_options(container_install.TARGET_IMAGE)[1]]
    assert target_drive_options(container_install.TARGET_IMAGE)[3] in option_values(command, "-device")


def test_the_uefi_boot_gets_the_code_read_only_and_a_writable_variable_store() -> None:
    firmware = Firmware(Path("/fw/CODE.fd"), Path("/fw/VARS.fd"))
    command = disk_boot_command(memory_mib=1, cpus=1, firmware=firmware, variables=Path("/work/VARS.fd"))
    flash = [drive for drive in option_values(command, "-drive") if "pflash" in drive]
    assert flash == [
        "if=pflash,format=raw,unit=0,readonly=on,file=/fw/CODE.fd",
        "if=pflash,format=raw,unit=1,file=/work/VARS.fd",
    ]
    assert "/fw/VARS.fd" not in " ".join(command), "the template itself must never be written to"


def test_a_uefi_boot_without_a_writable_variable_store_is_refused() -> None:
    with pytest.raises(ValueError, match="variable store"):
        disk_boot_command(memory_mib=1, cpus=1, firmware=Firmware(Path("/c"), Path("/v")))


def test_both_boots_share_the_machine_the_boot_test_uses() -> None:
    plain = container_boot.machine_options(3072, 2)
    assert disk_boot_command(memory_mib=3072, cpus=2, firmware=None)[: len(plain)] == plain


# ---- UEFI firmware lookup --------------------------------------------------------------------------------------------


def descriptor(**overrides: object) -> str:
    document: dict[str, object] = {
        "description": "UEFI firmware for x86_64",
        "interface-types": ["uefi"],
        "mapping": {
            "device": "flash",
            "mode": "split",
            "executable": {"filename": "/fw/CODE.fd", "format": "raw"},
            "nvram-template": {"filename": "/fw/VARS.fd", "format": "raw"},
        },
        "targets": [{"architecture": "x86_64", "machines": ["pc-i440fx-*", "pc-q35-*"]}],
        "features": ["acpi-s3", "verbose-dynamic"],
        "tags": [],
    }
    return json.dumps({**document, **overrides})


def test_a_plain_x86_flash_firmware_for_the_pc_machine_is_accepted() -> None:
    assert parse_firmware_descriptor(descriptor()) == Firmware(Path("/fw/CODE.fd"), Path("/fw/VARS.fd"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"features": ["secure-boot", "requires-smm"]},
        {"features": ["enrolled-keys"]},
        {"targets": [{"architecture": "x86_64", "machines": ["pc-q35-*"]}]},
        {"targets": [{"architecture": "aarch64", "machines": ["virt-*"]}]},
        {"interface-types": ["bios"]},
        {"mapping": {"device": "memory", "filename": "/fw/x.bin"}},
        {
            "mapping": {
                "device": "flash",
                "executable": {"filename": "/c", "format": "qcow2"},
                "nvram-template": {"filename": "/v", "format": "raw"},
            }
        },
    ],
    ids=["secure-boot", "enrolled-keys", "q35-only", "arm", "bios-interface", "no-flash", "qcow2"],
)
def test_a_firmware_that_cannot_boot_the_installed_disk_on_the_pc_machine_is_skipped(
    overrides: dict[str, object],
) -> None:
    assert parse_firmware_descriptor(descriptor(**overrides)) is None


@pytest.mark.parametrize("text", ["", "not json", "[]", "{}", '{"mapping": 3}', "null"])
def test_a_descriptor_that_is_not_one_is_skipped_not_a_crash(text: str) -> None:
    assert parse_firmware_descriptor(text) is None


def write_firmware(directory: Path, name: str, *, features: list[str], files: bool = True) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    code, variables = directory / f"{name}-code.fd", directory / f"{name}-vars.fd"
    if files:
        code.write_bytes(b"code")
        variables.write_bytes(b"vars")
    text = descriptor(
        features=features,
        mapping={
            "device": "flash",
            "executable": {"filename": str(code), "format": "raw"},
            "nvram-template": {"filename": str(variables), "format": "raw"},
        },
    )
    (directory / f"{name}.json").write_text(text, encoding="utf-8")


def test_the_first_usable_descriptor_in_file_name_order_wins_and_secure_boot_ones_are_passed_over(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "firmware"
    write_firmware(directory, "40-secure", features=["secure-boot"])
    write_firmware(directory, "60-plain", features=[])
    write_firmware(directory, "70-other", features=[])
    assert find_uefi_firmware([directory], []) == Firmware(
        directory / "60-plain-code.fd", directory / "60-plain-vars.fd"
    )


def test_a_descriptor_whose_files_are_missing_is_passed_over(tmp_path: Path) -> None:
    directory = tmp_path / "firmware"
    write_firmware(directory, "50-gone", features=[], files=False)
    write_firmware(directory, "60-here", features=[])
    found = find_uefi_firmware([directory], [])
    assert found is not None and found.code.name == "60-here-code.fd"


def test_the_first_directory_wins_for_a_name_both_have(tmp_path: Path) -> None:
    first, second = tmp_path / "etc", tmp_path / "usr"
    write_firmware(first, "50-same", features=[])
    write_firmware(second, "50-same", features=[])
    found = find_uefi_firmware([first, second], [])
    assert found is not None and first in found.code.parents


def test_without_descriptors_the_known_file_locations_are_tried_in_order(tmp_path: Path) -> None:
    (tmp_path / "A_CODE.fd").write_bytes(b"x")  # no matching variable store: not a pair
    (tmp_path / "B_CODE.fd").write_bytes(b"x")
    (tmp_path / "B_VARS.fd").write_bytes(b"x")
    fallbacks = [(tmp_path / "A_CODE.fd", tmp_path / "A_VARS.fd"), (tmp_path / "B_CODE.fd", tmp_path / "B_VARS.fd")]
    assert find_uefi_firmware([tmp_path / "nowhere"], fallbacks) == Firmware(
        tmp_path / "B_CODE.fd", tmp_path / "B_VARS.fd"
    )


def test_no_firmware_anywhere_is_none(tmp_path: Path) -> None:
    assert find_uefi_firmware([tmp_path / "nowhere"], [(tmp_path / "a", tmp_path / "b")]) is None


# ---- the plan medium and the target disk -----------------------------------------------------------------------------


def test_the_plan_medium_is_an_iso9660_image_with_the_plan_volume_label() -> None:
    command = plan_medium_command(Path("/work/stage"), Path("/disks/plan.iso"))
    assert command[0] == "xorriso" and command[1:3] == ["-as", "mkisofs"]
    assert command[command.index("-V") + 1] == PLAN_VOLUME_LABEL
    assert "-r" in command  # Rock Ridge: the file keeps the name plan.json
    assert command[command.index("-o") + 1] == "/disks/plan.iso"
    assert command[-1] == "/work/stage"


def test_a_plan_on_stdin_is_accepted_when_it_is_a_json_object() -> None:
    assert read_plan(PLAN) == PLAN


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "no plan"),
        (b"x" * (MAX_PLAN_BYTES + 1), "longer than"),
        (SECRET.encode(), "not JSON"),
        (b'["a"]', "not a JSON object"),
    ],
)
def test_a_bad_plan_is_refused_without_echoing_it(data: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message) as raised:
        read_plan(data)
    assert SECRET not in str(raised.value)


def test_the_target_disk_is_sparse_and_the_size_asked_for(tmp_path: Path) -> None:
    disk = tmp_path / "target.img"
    create_sparse_disk(disk, 20 * 1024**2)
    assert disk.stat().st_size == 20 * 1024**2


def test_a_recreated_disk_replaces_the_old_one(tmp_path: Path) -> None:
    disk = tmp_path / "target.img"
    disk.write_bytes(b"old content")
    create_sparse_disk(disk, 1024**2)
    assert disk.stat().st_size == 1024**2
    assert disk.read_bytes()[:11] == bytes(11)


class Xorriso:
    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, returncode: int = 0, stderr: str = ""
    ) -> None:
        self.commands: list[list[str]] = []
        self.staged: dict[str, bytes] = {}
        self.stage_mode = 0
        monkeypatch.setattr(container_install, "PLAN_IMAGE", tmp_path / "plan.iso")
        monkeypatch.setattr(container_install, "TARGET_IMAGE", tmp_path / "target.img")
        monkeypatch.setattr(container_install.subprocess, "run", self._run)
        self.returncode, self.stderr = returncode, stderr

    def _run(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        stage = Path(command[-1])
        self.staged = {path.name: path.read_bytes() for path in stage.iterdir()}
        self.stage_mode = stage.stat().st_mode & 0o777
        return subprocess.CompletedProcess(command, self.returncode, "", self.stderr)


def test_the_medium_is_built_from_a_private_stage_holding_only_plan_json_and_the_stage_is_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    xorriso = Xorriso(monkeypatch, tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    make_media(PLAN, disk_bytes=1024**2, work=work)
    assert xorriso.staged == {"plan.json": PLAN}
    if sys.platform != "win32":
        assert xorriso.stage_mode == 0o700
    assert list(work.iterdir()) == []
    assert (tmp_path / "target.img").stat().st_size == 1024**2


def test_a_failing_xorriso_is_an_error_without_the_plan_and_leaves_no_stage_and_no_disk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    Xorriso(monkeypatch, tmp_path, returncode=1, stderr="xorriso: FAILURE : cannot write")
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(RuntimeError, match="could not build the plan medium") as raised:
        make_media(PLAN, disk_bytes=1024**2, work=work)
    assert SECRET not in str(raised.value)
    assert list(work.iterdir()) == []
    assert not (tmp_path / "target.img").exists()


# ---- main ------------------------------------------------------------------------------------------------------------


def run_main(argv: list[str], monkeypatch: pytest.MonkeyPatch, *, stdin: bytes = b"") -> int:
    class Stdin:
        buffer = io.BytesIO(stdin)

    monkeypatch.setattr(sys, "stdin", Stdin)
    return main(argv)


def test_make_media_reads_the_plan_from_stdin_and_never_prints_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    Xorriso(monkeypatch, tmp_path)
    monkeypatch.setattr(container_install, "WORK_DIR", tmp_path)
    monkeypatch.setattr(container_install, "make_media", lambda plan, *, disk_bytes: seen.append((plan, disk_bytes)))
    seen: list[tuple[bytes, int]] = []
    assert run_main(["make-media", "--disk-gib", "20"], monkeypatch, stdin=PLAN) == 0
    assert seen == [(PLAN, 20 * 1024**3)]
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err


def test_a_bad_plan_on_stdin_exits_two_naming_the_problem_and_not_the_plan(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(["make-media", "--disk-gib", "20"], monkeypatch, stdin=SECRET.encode()) == 2
    captured = capsys.readouterr()
    assert "not JSON" in captured.err
    assert SECRET not in captured.out + captured.err


def test_probe_uefi_exits_with_the_status_the_host_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container_install, "find_uefi_firmware", lambda: Firmware(Path("/c"), Path("/v")))
    assert run_main(["probe-uefi"], monkeypatch) == 0
    monkeypatch.setattr(container_install, "find_uefi_firmware", lambda: None)
    assert run_main(["probe-uefi"], monkeypatch) == NO_UEFI_EXIT_STATUS


def test_the_install_step_extracts_the_boot_files_and_hands_the_process_to_qemu(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    extracted: list[str] = []
    executed: list[list[str]] = []
    monkeypatch.setattr(container_install, "WORK_DIR", tmp_path)
    monkeypatch.setattr(container_install, "list_iso_files", lambda iso: ["/live/vmlinuz", "/live/initrd.img"])
    monkeypatch.setattr(container_install, "extract_iso_file", lambda iso, path, dest: extracted.append(path))
    monkeypatch.setattr(container_install.os, "execvp", lambda file, args: executed.append(args))
    run_main(
        ["install", "/iso/boot.iso", "--memory-mib", "1024", "--cpus", "3", "--extra-kernel-args=loglevel=7"],
        monkeypatch,
    )
    assert extracted == ["/live/vmlinuz", "/live/initrd.img"]
    (command,) = executed
    assert command[0] == "qemu-system-x86_64"
    assert option_values(command, "-append") == [f"{INSTALL_KERNEL_ARGS} loglevel=7"]
    assert (option_values(command, "-m"), option_values(command, "-smp")) == (["1024"], ["3"])


def test_an_iso_without_boot_files_exits_two_without_starting_qemu(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    executed: list[list[str]] = []
    monkeypatch.setattr(container_install, "list_iso_files", lambda iso: ["/readme"])
    monkeypatch.setattr(container_install.os, "execvp", lambda file, args: executed.append(args))
    assert run_main(["install", "/iso/boot.iso", "--memory-mib", "1", "--cpus", "1"], monkeypatch) == 2
    assert executed == []
    assert "no matching kernel/initrd pair" in capsys.readouterr().err


def test_the_uefi_boot_copies_the_variable_store_before_qemu_may_write_to_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    template = tmp_path / "VARS.fd"
    template.write_bytes(b"template")
    executed: list[list[str]] = []
    monkeypatch.setattr(container_install, "WORK_DIR", tmp_path / "work")
    (tmp_path / "work").mkdir()
    monkeypatch.setattr(container_install, "find_uefi_firmware", lambda: Firmware(tmp_path / "CODE.fd", template))
    monkeypatch.setattr(container_install.os, "execvp", lambda file, args: executed.append(args))
    run_main(["boot-disk", "--firmware", "uefi", "--memory-mib", "1", "--cpus", "1"], monkeypatch)
    (command,) = executed
    writable = [drive for drive in option_values(command, "-drive") if "unit=1" in drive]
    assert writable == [f"if=pflash,format=raw,unit=1,file={(tmp_path / 'work' / 'OVMF_VARS.fd').as_posix()}"]
    assert (tmp_path / "work" / "OVMF_VARS.fd").read_bytes() == b"template"
    assert template.read_bytes() == b"template"


def test_a_uefi_boot_without_firmware_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(container_install, "find_uefi_firmware", lambda: None)
    assert run_main(["boot-disk", "--firmware", "uefi", "--memory-mib", "1", "--cpus", "1"], monkeypatch) == 2
    assert "no UEFI firmware" in capsys.readouterr().err


def test_the_bios_boot_needs_no_firmware(monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[list[str]] = []
    monkeypatch.setattr(container_install.os, "execvp", lambda file, args: executed.append(args))
    run_main(["boot-disk", "--firmware", "bios", "--memory-mib", "1", "--cpus", "1"], monkeypatch)
    assert not [word for word in executed[0] if "pflash" in word]


@pytest.mark.parametrize("flag", ["--memory-mib", "--cpus"])
def test_a_zero_memory_or_cpu_count_is_refused(flag: str, monkeypatch: pytest.MonkeyPatch) -> None:
    args = ["boot-disk", "--firmware", "bios", "--memory-mib", "1", "--cpus", "1"]
    args[args.index(flag) + 1] = "0"
    with pytest.raises(SystemExit) as raised:
        run_main(args, monkeypatch)
    assert raised.value.code == 2
