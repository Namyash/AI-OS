"""Runs INSIDE the QEMU container: finds the kernel and initrd on an ISO, extracts them and boots the ISO.

The host side (boot_harness.py) starts this file in a container with the ISO mounted read-only. The kernel and initrd
paths are discovered from the ISO's own file listing, so a new kernel version or a different media directory needs no
change here. The kernel arguments are the harness's own (KERNEL_ARGS) and follow the live-boot convention the build
uses; a medium that boots differently (another `boot=` value) needs its own arguments.

Pure functions (listing parsing, boot-file selection, QEMU command line) are importable and unit-tested without
Docker or QEMU; only main() touches the system.
"""

from __future__ import annotations

import argparse
import os
import posixpath
import re
import shlex
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

# boot=live components: what the image's own boot configuration passes (--bootappend-live in
# os/build/in-container-build.sh; test_container_boot.py keeps the two in step). Console on the serial port (so QEMU's
# stdio carries the guest console), no "quiet" so kernel and systemd output is complete, and the flag that makes the
# image's pai-selfcheck.service run (unit: ConditionKernelCommandLine). panic=-1: a kernel panic, or live-boot failing
# to find its medium, reboots at once and -no-reboot turns that into QEMU exiting. Without it the guest halts, or waits
# in an initramfs shell for input that never comes, and the run only ends at the overall timeout.
KERNEL_ARGS = "boot=live components console=ttyS0 pai.selfcheck=1 panic=-1"

QEMU_BINARY = "qemu-system-x86_64"
WORK_DIR = Path("/work")

_KERNEL_NAME = re.compile(r"^vmlinuz(?:-(?P<version>.+))?$")
_INITRD_NAME = re.compile(r"^initrd(?:\.img)?(?:-(?P<version>.+))?$")
_DIGITS = re.compile(r"(\d+)")


class BootFilesNotFoundError(Exception):
    """The ISO listing contains no matching kernel and initrd pair."""


@dataclass(frozen=True)
class BootFiles:
    """Absolute paths, inside the ISO, of the kernel and initrd to boot."""

    kernel: str
    initrd: str


def parse_iso_listing(output: str) -> list[str]:
    """Return the file paths in `xorriso -find / -type f` output (one shell-quoted absolute path per line)."""
    paths: list[str] = []
    for line in output.splitlines():
        try:
            words = shlex.split(line)
        except ValueError:
            continue  # not a quoted path (a diagnostic line); never a file entry
        if len(words) == 1 and words[0].startswith("/"):
            paths.append(words[0])
    return paths


def _version_key(version: str | None) -> tuple[int, tuple[tuple[int, int, str], ...]]:
    """Natural ordering of kernel version strings; an unversioned name sorts below every versioned one."""
    if version is None:
        return (0, ())
    parts = tuple(
        (0, int(token), "") if token.isdigit() else (1, 0, token) for token in _DIGITS.split(version) if token
    )
    return (1, parts)


def select_boot_files(paths: Iterable[str]) -> BootFiles:
    """Choose the kernel and initrd to boot from an ISO's file paths.

    A kernel and an initrd belong together when they share a directory and a version suffix (`vmlinuz-X` and
    `initrd.img-X`, or the unversioned `vmlinuz` and `initrd.img`). Pairs next to a squashfs image win, because
    live-boot needs the kernel to come from the same medium directory as the root filesystem; among those the
    highest version wins, and a versioned pair beats an unversioned one.
    """
    all_paths = sorted(set(paths))
    squashfs_dirs = {posixpath.dirname(path) for path in all_paths if path.endswith(".squashfs")}
    kernels: dict[tuple[str, str | None], str] = {}
    initrds: dict[tuple[str, str | None], str] = {}
    for path in all_paths:
        directory, name = posixpath.split(path)
        if kernel_match := _KERNEL_NAME.match(name):
            kernels[(directory, kernel_match["version"])] = path
        elif initrd_match := _INITRD_NAME.match(name):
            initrds[(directory, initrd_match["version"])] = path

    pairs = sorted(kernels.keys() & initrds.keys(), key=lambda key: (key[0] in squashfs_dirs, _version_key(key[1])))
    if not pairs:
        found = f"kernels={sorted(kernels.values())} initrds={sorted(initrds.values())}"
        raise BootFilesNotFoundError(f"no matching kernel/initrd pair in the ISO; {found}")
    best = pairs[-1]
    return BootFiles(kernel=kernels[best], initrd=initrds[best])


def qemu_command(
    *, kernel: Path, initrd: Path, iso: Path, memory_mib: int, cpus: int, kernel_args: str = KERNEL_ARGS
) -> list[str]:
    """QEMU command line: software emulation, serial console on stdio, ISO as a read-only CD-ROM, restricted NIC."""
    return [
        QEMU_BINARY,
        "-accel", "tcg",  # no hypervisor on the dev machine; see docs/development/BOOT_TESTING.md
        "-machine", "pc",
        "-cpu", "max",
        "-m", str(memory_mib),
        "-smp", str(cpus),
        "-nographic",
        "-monitor", "none",
        "-serial", "stdio",
        "-no-reboot",  # a guest reboot ends the run instead of looping through boots
        "-kernel", kernel.as_posix(),
        "-initrd", initrd.as_posix(),
        "-append", kernel_args,
        # live-boot searches the block devices for the squashfs; a read-only CD-ROM is what a real ISO boot looks like.
        "-drive", f"file={iso.as_posix()},media=cdrom,readonly=on,format=raw",
        # User-mode networking: the guest gets DHCP from QEMU, restrict=on cuts every route to the outside.
        "-netdev", "user,id=net0,restrict=on",
        "-device", "virtio-net-pci,netdev=net0,romfile=",
        "-device", "virtio-rng-pci",
    ]  # fmt: skip


def _run_xorriso(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["xorriso", *args], capture_output=True, text=True, check=False)  # noqa: S603, S607


def list_iso_files(iso: Path) -> list[str]:
    result = _run_xorriso("-indev", str(iso), "-find", "/", "-type", "f")
    if result.returncode != 0:
        raise RuntimeError(f"xorriso could not list {iso}: {result.stderr.strip()[-500:]}")
    return parse_iso_listing(result.stdout)


def extract_iso_file(iso: Path, iso_path: str, destination: Path) -> None:
    result = _run_xorriso("-osirrox", "on", "-indev", str(iso), "-extract", iso_path, str(destination))
    if result.returncode != 0 or not destination.is_file():
        raise RuntimeError(f"xorriso could not extract {iso_path}: {result.stderr.strip()[-500:]}")


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Boot a live ISO under QEMU (software emulation) with the serial console on stdio."
    )
    parser.add_argument("iso", type=Path)
    parser.add_argument("--memory-mib", type=_positive_int, required=True)
    parser.add_argument("--cpus", type=_positive_int, required=True)
    args = parser.parse_args(argv)

    try:
        boot_files = select_boot_files(list_iso_files(args.iso))
        kernel, initrd = WORK_DIR / "kernel", WORK_DIR / "initrd"
        extract_iso_file(args.iso, boot_files.kernel, kernel)
        extract_iso_file(args.iso, boot_files.initrd, initrd)
    except (BootFilesNotFoundError, RuntimeError) as error:
        print(f"[pai-e2e] ERROR: {error}", file=sys.stderr, flush=True)
        return 2

    print(f"[pai-e2e] kernel={boot_files.kernel} initrd={boot_files.initrd}", flush=True)
    command = qemu_command(kernel=kernel, initrd=initrd, iso=args.iso, memory_mib=args.memory_mib, cpus=args.cpus)
    print(f"[pai-e2e] exec {shlex.join(command)}", flush=True)
    os.execvp(command[0], command)  # noqa: S606 - replaces this process: signals and the exit status are QEMU's own


if __name__ == "__main__":
    sys.exit(main())
