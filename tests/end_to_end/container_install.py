"""Runs INSIDE the QEMU container for the install test: builds the plan medium and the target disk, boots the live ISO
with both attached, and boots the installed disk through its own firmware.

The host side (install_harness.py) starts this file once per step, each time in a container of its own that shares one
throwaway Docker volume mounted at /disks (the sparse target disk and the plan medium live there between steps):

    make-media     reads the plan JSON on STDIN (never argv: it holds the passphrase), writes /disks/plan.iso, an
    ISO9660
                   volume labelled PAI-PLAN with plan.json in it, and creates the sparse raw target disk
                   /disks/target.img
    install ISO    boots the live ISO (the kernel and initrd are taken out of it, as boot_harness does) with the plan
                   medium and the target disk attached and pai.install=auto on the kernel line
    boot-disk      boots /disks/target.img with no kernel of ours: through SeaBIOS and the GRUB the installer wrote
                   (--firmware bios), or through OVMF and the removable EFI boot path (--firmware uefi); the serial
                   console is QEMU's stdin and stdout, which is where the host types the passphrase
    probe-uefi     exits 0 and names the firmware when the image has UEFI firmware for QEMU, 3 when it has none

The command lines are built by pure functions (importable and unit-tested without Docker or QEMU); only main() touches
the
system. Nothing here prints the plan: errors name the step that failed and never the data.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

try:  # imported by the tests as part of the package
    from tests.end_to_end import container_boot as _boot
    from tests.end_to_end import install_plan as _plan
except ImportError:  # run as a script in the container, where the harness directory is mounted flat and is sys.path[0]
    import container_boot as _boot  # type: ignore[no-redef]
    import install_plan as _plan  # type: ignore[no-redef]

KERNEL_ARGS = _boot.KERNEL_ARGS
WORK_DIR = _boot.WORK_DIR
BootFilesNotFoundError = _boot.BootFilesNotFoundError
device_options = _boot.device_options
extract_iso_file = _boot.extract_iso_file
list_iso_files = _boot.list_iso_files
machine_options = _boot.machine_options
qemu_command = _boot.qemu_command
select_boot_files = _boot.select_boot_files
validate_extra_kernel_args = _boot.validate_extra_kernel_args
PLAN_FILE_NAME = _plan.PLAN_FILE_NAME
PLAN_VOLUME_LABEL = _plan.PLAN_VOLUME_LABEL
TARGET_SERIAL = _plan.TARGET_SERIAL

DISKS_DIR = Path("/disks")
TARGET_IMAGE = DISKS_DIR / "target.img"
PLAN_IMAGE = DISKS_DIR / "plan.iso"
MAX_PLAN_BYTES = 64 * 1024  # a plan is a few hundred bytes; more on stdin is a mistake, not a plan
BYTES_PER_GIB = 1024**3
XORRISO = "xorriso"

# The live ISO's own kernel line (container_boot.KERNEL_ARGS: what the build bakes in, the serial console, panic=-1)
# without the flag that runs the self-check, which would power the machine off in the middle of the install, and with
# the
# flag that starts the installer. The kiosk is masked for this boot only: an install under software emulation has no use
# for a browser rendering a page, and the CPU time it takes slows the copy. A normal boot is not touched.
INSTALL_KERNEL_ARGS = " ".join(
    [
        *(word for word in KERNEL_ARGS.split() if word != "pai.selfcheck=1"),
        "pai.install=auto",
        "systemd.mask=pai-kiosk.service",
    ]
)

# Where QEMU installs keep their UEFI firmware descriptions (the interface QEMU itself defines for finding firmware),
# and,
# for a distribution that ships none, where Debian's ovmf package puts the code and the variable store.
FIRMWARE_DESCRIPTOR_DIRS = (Path("/etc/qemu/firmware"), Path("/usr/share/qemu/firmware"))
FIRMWARE_FALLBACKS = (
    (Path("/usr/share/OVMF/OVMF_CODE_4M.fd"), Path("/usr/share/OVMF/OVMF_VARS_4M.fd")),
    (Path("/usr/share/OVMF/OVMF_CODE.fd"), Path("/usr/share/OVMF/OVMF_VARS.fd")),
)
# `-machine pc` is the i440fx; a firmware that only supports other machine types (q35 with SMM) does not start on it.
MACHINE_FAMILY_PREFIX = "pc-i440fx-"
NO_UEFI_EXIT_STATUS = 3


@dataclass(frozen=True)
class Firmware:
    """UEFI firmware for QEMU's pflash: the read-only code and the template the writable variable store starts from."""

    code: Path
    variables_template: Path


def parse_firmware_descriptor(text: str) -> Firmware | None:
    """The firmware a QEMU firmware descriptor (JSON) offers for `-machine pc` on x86_64 without Secure Boot, or None.

    Secure Boot variants are skipped: the installer's GRUB is unsigned. Anything that is not a raw flash image is
    skipped
    too (the variable store is copied as it is).
    """
    try:
        document = json.loads(text)
        mapping = document["mapping"]
        if "uefi" not in document["interface-types"] or mapping["device"] != "flash":
            return None
        features = set(document.get("features", []))
        if features & {"secure-boot", "enrolled-keys", "requires-smm"}:
            return None
        targets = [t for t in document["targets"] if t["architecture"] == "x86_64"]
        if not any(fnmatch.fnmatch(f"{MACHINE_FAMILY_PREFIX}0", glob) for t in targets for glob in t["machines"]):
            return None
        code, variables = mapping["executable"], mapping["nvram-template"]
        if code["format"] != "raw" or variables["format"] != "raw":
            return None
        return Firmware(Path(code["filename"]), Path(variables["filename"]))
    except (ValueError, KeyError, TypeError):
        return None


def find_uefi_firmware(
    descriptor_dirs: Iterable[Path] = FIRMWARE_DESCRIPTOR_DIRS,
    fallbacks: Iterable[tuple[Path, Path]] = FIRMWARE_FALLBACKS,
) -> Firmware | None:
    """The first usable UEFI firmware: from the descriptors in file-name order (the first directory that has any wins
    over the second for a file name both have), else from the known file locations. None when the image has none."""
    descriptors: dict[str, Path] = {}
    for directory in descriptor_dirs:
        if directory.is_dir():
            for path in sorted(directory.glob("*.json")):
                descriptors.setdefault(path.name, path)
    for name in sorted(descriptors):
        try:
            firmware = parse_firmware_descriptor(descriptors[name].read_text(encoding="utf-8"))
        except OSError:
            continue
        if firmware is not None and firmware.code.is_file() and firmware.variables_template.is_file():
            return firmware
    return next(
        (Firmware(code, variables) for code, variables in fallbacks if code.is_file() and variables.is_file()), None
    )


def target_drive_options(disk: Path) -> list[str]:
    """The target disk as a virtio disk with the serial the plan names it by (/dev/disk/by-id/virtio-<serial>). The
    serial is
    a property of the device (a -drive option of that name is refused by QEMU's raw driver). Writes go through the
    host's
    page cache without waiting for the disk: the volume is thrown away after the run."""
    return [
        "-drive", f"file={disk.as_posix()},if=none,id=target,format=raw,cache=unsafe",
        "-device", f"virtio-blk-pci,drive=target,serial={TARGET_SERIAL}",
    ]  # fmt: skip


def plan_drive_options(plan_medium: Path) -> list[str]:
    """The plan medium as a read-only CD-ROM, what an ISO9660 volume on removable media looks like to the guest."""
    return ["-drive", f"file={plan_medium.as_posix()},media=cdrom,readonly=on,format=raw"]


def install_command(
    *, kernel: Path, initrd: Path, iso: Path, memory_mib: int, cpus: int, extra_kernel_args: str = ""
) -> list[str]:
    """QEMU for the install boot: the live ISO, the plan medium and the blank target disk, pai.install=auto."""
    return qemu_command(
        kernel=kernel,
        initrd=initrd,
        iso=iso,
        memory_mib=memory_mib,
        cpus=cpus,
        kernel_args=INSTALL_KERNEL_ARGS,
        extra_kernel_args=extra_kernel_args,
        extra_args=[*plan_drive_options(PLAN_IMAGE), *target_drive_options(TARGET_IMAGE)],
    )


def disk_boot_command(
    *, memory_mib: int, cpus: int, firmware: Firmware | None, variables: Path | None = None
) -> list[str]:
    """QEMU for booting the installed disk on its own: BIOS (SeaBIOS) when `firmware` is None, else UEFI from
    pflash with
    `variables`, the writable copy of the firmware's variable store. The boot device is the first disk."""
    firmware_options: list[str] = []
    if firmware is not None:
        if variables is None:
            raise ValueError("a UEFI boot needs the writable copy of the variable store")
        firmware_options = [
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={firmware.code.as_posix()}",
            "-drive", f"if=pflash,format=raw,unit=1,file={variables.as_posix()}",
        ]  # fmt: skip
    return [
        *machine_options(memory_mib, cpus),
        "-boot", "order=c",
        *target_drive_options(TARGET_IMAGE),
        *firmware_options,
        *device_options(),
    ]  # fmt: skip


def plan_medium_command(stage: Path, destination: Path) -> list[str]:
    """xorriso: an ISO9660 image of `stage` (Rock Ridge, so the file keeps its name) with the plan volume's label."""
    return [
        XORRISO,
        "-as",
        "mkisofs",
        "-quiet",
        "-V",
        PLAN_VOLUME_LABEL,
        "-r",
        "-J",
        "-o",
        destination.as_posix(),
        stage.as_posix(),
    ]


def read_plan(stream_bytes: bytes) -> bytes:
    """The plan from stdin, checked to be a JSON object of sane size. The text is never echoed, not even on an error."""
    if not stream_bytes:
        raise ValueError("no plan on stdin")
    if len(stream_bytes) > MAX_PLAN_BYTES:
        raise ValueError(f"the plan on stdin is longer than {MAX_PLAN_BYTES} bytes")
    try:
        document = json.loads(stream_bytes)
    except ValueError:
        raise ValueError("the plan on stdin is not JSON") from None
    if not isinstance(document, dict):
        raise ValueError("the plan on stdin is not a JSON object")
    return stream_bytes


def create_sparse_disk(path: Path, size_bytes: int) -> None:
    """A raw disk image of `size_bytes` that occupies space only where the guest writes (truncate leaves a hole)."""
    with path.open("wb") as disk:
        disk.truncate(size_bytes)


def make_media(plan: bytes, *, disk_bytes: int, work: Path = WORK_DIR) -> None:
    """Builds PLAN_IMAGE from `plan` and creates TARGET_IMAGE. Both are replaced when they exist."""
    stage = work / "plan-stage"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(mode=0o700)
    try:
        (stage / PLAN_FILE_NAME).write_bytes(plan)
        done = subprocess.run(  # noqa: S603
            plan_medium_command(stage, PLAN_IMAGE), capture_output=True, text=True, check=False
        )
        if done.returncode != 0:
            raise RuntimeError(f"xorriso could not build the plan medium: {done.stderr.strip()[-300:]}")
    finally:
        shutil.rmtree(stage, ignore_errors=True)  # the container's /work is a tmpfs, but nothing is left lying around
    create_sparse_disk(TARGET_IMAGE, disk_bytes)


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _extra_kernel_args(text: str) -> str:
    try:
        return validate_extra_kernel_args(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


def _exec(command: Sequence[str]) -> None:
    print(f"[pai-e2e] exec {shlex.join(command)}", flush=True)
    os.execvp(command[0], list(command))  # noqa: S606 - replaces this process: signals and the exit status are QEMU's own


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Steps of the install test that run in the QEMU container.")
    steps = parser.add_subparsers(dest="step", required=True)

    media = steps.add_parser(
        "make-media", help="build the plan medium from the plan on stdin and create the target disk"
    )
    media.add_argument("--disk-gib", type=_positive_int, required=True)

    install = steps.add_parser("install", help="boot the live ISO with the plan medium and the target disk")
    install.add_argument("iso", type=Path)
    boot = steps.add_parser("boot-disk", help="boot the installed target disk through its own firmware")
    boot.add_argument("--firmware", choices=("bios", "uefi"), required=True)
    for machine in (install, boot):
        machine.add_argument("--memory-mib", type=_positive_int, required=True)
        machine.add_argument("--cpus", type=_positive_int, required=True)
    install.add_argument("--extra-kernel-args", type=_extra_kernel_args, default="")
    steps.add_parser("probe-uefi", help="say whether the image has UEFI firmware for QEMU")
    args = parser.parse_args(argv)

    try:
        if args.step == "make-media":
            make_media(read_plan(sys.stdin.buffer.read(MAX_PLAN_BYTES + 1)), disk_bytes=args.disk_gib * BYTES_PER_GIB)
            print(
                f"[pai-e2e] plan medium {PLAN_IMAGE} (volume label {PLAN_VOLUME_LABEL}) "
                f"and target disk {TARGET_IMAGE} ready",
                flush=True,
            )
            return 0
        if args.step == "probe-uefi":
            firmware = find_uefi_firmware()
            if firmware is None:
                print("[pai-e2e] no UEFI firmware in this image", flush=True)
                return NO_UEFI_EXIT_STATUS
            print(f"[pai-e2e] UEFI firmware: {firmware.code}", flush=True)
            return 0
        if args.step == "install":
            boot_files = select_boot_files(list_iso_files(args.iso))
            kernel, initrd = WORK_DIR / "kernel", WORK_DIR / "initrd"
            extract_iso_file(args.iso, boot_files.kernel, kernel)
            extract_iso_file(args.iso, boot_files.initrd, initrd)
            print(f"[pai-e2e] kernel={boot_files.kernel} initrd={boot_files.initrd}", flush=True)
            _exec(
                install_command(
                    kernel=kernel,
                    initrd=initrd,
                    iso=args.iso,
                    memory_mib=args.memory_mib,
                    cpus=args.cpus,
                    extra_kernel_args=args.extra_kernel_args,
                )
            )
        if args.step == "boot-disk":
            firmware = find_uefi_firmware() if args.firmware == "uefi" else None
            variables = None
            if args.firmware == "uefi":
                if firmware is None:
                    raise RuntimeError("no UEFI firmware in this image")
                variables = WORK_DIR / "OVMF_VARS.fd"
                shutil.copyfile(firmware.variables_template, variables)
            _exec(disk_boot_command(memory_mib=args.memory_mib, cpus=args.cpus, firmware=firmware, variables=variables))
    except (BootFilesNotFoundError, RuntimeError, ValueError, OSError) as error:
        print(f"[pai-e2e] ERROR: {error}", file=sys.stderr, flush=True)
        return 2
    return 2  # unreachable for the exec steps: execvp does not return


if __name__ == "__main__":
    sys.exit(main())
