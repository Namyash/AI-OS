"""Real-tools check of the installer's disk steps, run inside a privileged container by ``in_container.sh``.

argv: <loop device> <work directory>. Runs the engine's own step functions with the real ``SubprocessRunner`` and the
real ``LinuxHost`` against a loop device, then judges the result with the tools themselves (``cryptsetup luksDump``,
``sfdisk``, ``lsblk``, ``blkid``) rather than with the installer's own parsing. Prints one PASS or FAIL line per
check and exits non-zero if any failed.

Not covered here, by design: the chroot, initramfs and GRUB steps need a real installed system and are verified by
the QEMU install test. The partition and device-mapper nodes are made by a helper thread because a container has no
udev; the installer's wait for the nodes is exercised against that.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from installer.context import MAPPING_NAME, InstallContext
from installer.errors import SafetyError
from installer.host import LinuxHost
from installer.plan import TargetSpec, parse_plan
from installer.runner import Commander, SubprocessRunner
from installer.steps import configure, copy, disk, filesystems, finish, luks
from installer.target import resolve_target

PASSPHRASE = "integration test passphrase, not a secret"  # noqa: S105 - a test value
failed = False


def check(ok: bool, what: str) -> None:
    global failed
    print(f"{'PASS' if ok else 'FAIL'}  {what}", flush=True)
    failed = failed or not ok


def tool(*argv: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[str]:
    done = subprocess.run(  # noqa: S603 - fixed argument lists, no shell
        argv, input=stdin, capture_output=True, check=False, timeout=600
    )
    return subprocess.CompletedProcess(argv, done.returncode, done.stdout.decode(), done.stderr.decode())


class NodeMaker(threading.Thread):
    """A container has no udev: create the partition and device-mapper nodes the kernel announced in /sys."""

    def __init__(self, disk_name: str) -> None:
        super().__init__(daemon=True)
        self.disk_name = disk_name
        self.stop = threading.Event()

    def run(self) -> None:
        while not self.stop.wait(0.2):
            self.make_once()

    def make_once(self) -> None:
        base = Path("/sys/block") / self.disk_name
        for child in base.iterdir():
            if (child / "partition").exists():
                self._node(Path("/dev") / child.name, child / "dev")
        for dm in Path("/sys/block").glob("dm-*"):
            name = (dm / "dm" / "name").read_text().strip()
            Path("/dev/mapper").mkdir(exist_ok=True)
            self._node(Path("/dev/mapper") / name, dm / "dev")

    @staticmethod
    def _node(path: Path, devfile: Path) -> None:
        if path.exists() or not devfile.exists():
            return
        major, minor = devfile.read_text().strip().split(":")
        os.mknod(path, 0o660 | 0o060000, os.makedev(int(major), int(minor)))  # 0o060000: S_IFBLK


def build_source(root: Path) -> None:
    """A small synthetic system: hardlinks, a symlink, modes, ids, an xattr, an ACL, and runtime dirs to be excluded."""
    (root / "etc").mkdir(parents=True)
    (root / "usr/bin").mkdir(parents=True)
    for name in ("proc", "sys", "dev", "run", "tmp", "boot/efi"):
        (root / name).mkdir(parents=True)
    (root / "proc/should-not-copy").write_text("x")
    (root / "run/should-not-copy").write_text("x")
    (root / "boot/efi/should-not-copy").write_text("x")
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    (root / "usr/bin/tool").write_bytes(os.urandom(70_000))
    os.chmod(root / "usr/bin/tool", 0o4755)  # noqa: S103 - a setuid file to prove the mode is preserved
    os.link(root / "usr/bin/tool", root / "usr/bin/tool-hardlink")
    os.symlink("tool", root / "usr/bin/tool-link")
    (root / "etc/owned").write_text("owned by 12345")
    os.chown(root / "etc/owned", 12345, 23456)
    os.setxattr(root / "etc/owned", "user.pai-test", b"xattr-value")
    tool("setfacl", "-m", "u:4242:r--", str(root / "etc/owned"))


def main() -> int:
    loop_path, work = sys.argv[1], Path(sys.argv[2])
    loop_name = loop_path.rsplit("/", 1)[1]
    source = work / "source"
    build_source(source)
    recovery_file = str(work / "run/recovery-key")
    plan = parse_plan(
        {
            "version": 1,
            "target": {"path": loop_path},
            "confirm_wipe": True,
            "hostname": "pai-it",
            "username": "owner",
            "passphrase_source": "plan",
            "passphrase": PASSPHRASE,
            "recovery_key_file": recovery_file,
            "kdf": {"memory_kib": 8192, "iter_time_ms": 50},
            "after": "none",
        }
    )
    host = LinuxHost()
    ctx = InstallContext(plan=plan, cmd=Commander(SubprocessRunner()), host=host, work_dir="/run/pai-install-it")
    ctx.layers = [str(source)]
    nodes = NodeMaker(loop_name)
    nodes.start()
    try:
        run_steps(ctx, nodes, loop_path, source, work, recovery_file)
    finally:
        nodes.stop.set()
        leftovers = ctx.resources.unwind()
        check(leftovers == [], f"the safety net released nothing it should not have needed to ({leftovers})")
    return 1 if failed else 0


def run_steps(ctx: InstallContext, nodes: NodeMaker, loop: str, source: Path, work: Path, recovery_file: str) -> None:
    # --- target safety against the real kernel
    target = resolve_target(ctx.plan.target, ctx.host)
    ctx.target = target
    check(
        target.path == loop and target.size_bytes >= 16 * 1024**3,
        f"the real /sys describes {loop} as a whole disk of {target.size_bytes >> 30} GiB",
    )
    check(not Path(work / "run").exists(), "no recovery key file exists before the run")
    luks.prepare_recovery_key(ctx, os.urandom)
    mode = os.stat(recovery_file).st_mode & 0o777
    check(mode == 0o600, f"the recovery key file is mode {mode:o} (0600 wanted)")

    # --- partitioning
    disk.wipe_signatures(ctx)
    disk.write_partition_table(ctx)
    disk.verify_layout(ctx)  # waits for the nodes that NodeMaker creates
    check(ctx.partitions is not None, "the installer waited for the partition nodes and verified the layout")
    parts = ctx.require_partitions()
    try:
        resolve_target(TargetSpec(path=parts.root), ctx.host)
        check(False, "a partition is refused as a target")
    except SafetyError as error:
        check(error.reason == "partition", f"a real partition ({parts.root}) is refused as a target: {error.reason}")

    table = json.loads(tool("sfdisk", "--json", loop).stdout)["partitiontable"]
    sector = table["sectorsize"]
    sizes = [p["size"] * sector for p in table["partitions"]]
    check(table["label"] == "gpt" and len(table["partitions"]) == 4, "sfdisk: a GPT with 4 partitions")
    check(sizes[:3] == [1 << 20, 512 << 20, 1024 << 20], f"sfdisk: sizes 1 MiB / 512 MiB / 1 GiB ({sizes[:3]})")
    check(sizes[3] > 15 * 1024**3, f"sfdisk: the LUKS partition takes the rest ({sizes[3] >> 20} MiB)")
    types = [p["type"].upper() for p in table["partitions"]]
    check(
        types == [disk.BIOS_BOOT_GUID, disk.ESP_GUID, disk.LINUX_FILESYSTEM_GUID, disk.LINUX_LUKS_GUID],
        "sfdisk: partition types BIOS boot / ESP / Linux filesystem / Linux LUKS",
    )
    check(
        all(p["start"] * sector % (1 << 20) == 0 for p in table["partitions"]),
        "sfdisk: every partition starts on a 1 MiB boundary",
    )

    # --- LUKS2
    luks.luks_format(ctx)
    luks.add_recovery_key(ctx)
    luks.verify_luks(ctx)
    dump = tool("cryptsetup", "luksDump", parts.root).stdout
    check(re.search(r"^Version:\s+2\s*$", dump, re.MULTILINE) is not None, "luksDump: LUKS version 2")
    keyslots = [line for line in dump.splitlines() if line.strip().startswith("PBKDF:")]
    check(
        len(keyslots) == 2 and all("argon2id" in line for line in keyslots),
        f"luksDump: 2 keyslots, both argon2id ({len(keyslots)} found)",
    )
    check(
        sum(1 for line in dump.splitlines() if line.startswith("  ") and line.strip().endswith(": luks2")) == 2,
        "luksDump: exactly 2 luks2 keyslot entries",
    )

    def opens(*key_args: str, stdin: bytes | None = None) -> bool:
        return tool("cryptsetup", "open", "--test-passphrase", *key_args, parts.root, stdin=stdin).returncode == 0

    check(opens("--key-file=-", stdin=PASSPHRASE.encode()), "the passphrase opens the container (stdin, no newline)")
    check(opens(f"--key-file={recovery_file}"), "the recovery key file opens the container")
    recovery_text = Path(recovery_file).read_text()
    check(opens("--key-file=-", stdin=recovery_text.encode()), "the recovery key as typed text opens the container")
    check(not opens("--key-file=-", stdin=b"definitely the wrong passphrase"), "a wrong passphrase does not open it")
    check(not opens("--key-file=-", stdin=PASSPHRASE.encode()[:-1]), "a truncated passphrase does not open it")

    # --- open, filesystems, mount, copy
    luks.open_luks(ctx)
    check(Path(ctx.mapper_path).exists(), f"{ctx.mapper_path} exists while open (node made by the helper)")
    try:
        resolve_target(ctx.plan.target, ctx.host)
        check(False, "a disk with an open mapping is refused")
    except SafetyError as error:
        check(
            error.reason == "active-mapping",
            f"the real holders/ in /sys make an open mapping a refusal: {error.reason}",
        )
    filesystems.make_filesystems(ctx)
    filesystems.identify_filesystems(ctx)
    filesystems.mount_target_tree(ctx)
    mounts = {
        line.split()[4]: line.split(" - ")[1].split()[0]
        for line in Path("/proc/self/mountinfo").read_text().splitlines()
    }
    root = ctx.target_root
    check(
        (mounts.get(root), mounts.get(f"{root}/boot"), mounts.get(f"{root}/boot/efi")) == ("ext4", "ext4", "vfat"),
        "mountinfo: root ext4, /boot ext4, /boot/efi vfat",
    )
    labels = [
        tool("blkid", "-p", "-s", "LABEL", "-o", "value", dev).stdout.strip()
        for dev in (ctx.mapper_path, parts.boot, parts.esp)
    ]
    check(labels == ["pai-root", "pai-boot", "PAI-ESP"], f"blkid labels {labels}")
    try:
        resolve_target(TargetSpec(path=loop), ctx.host)
        check(False, "a disk with mounted filesystems is refused")
    except SafetyError as error:
        check(
            error.reason in {"mounted", "active-mapping"},
            f"mounted filesystems make the disk a refusal: {error.reason}",
        )

    copy.copy_system(ctx)
    configure.write_target_file(ctx, "/etc/hostname", "pai-it\n")
    check(Path(root, "etc/hostname").read_text() == "pai-it\n", "install -D /dev/stdin wrote a file into the target")
    tool_a, tool_b = os.stat(f"{root}/usr/bin/tool"), os.stat(f"{root}/usr/bin/tool-hardlink")
    check(tool_a.st_ino == tool_b.st_ino and tool_a.st_nlink == 2, "rsync preserved the hard link")
    check(os.readlink(f"{root}/usr/bin/tool-link") == "tool", "rsync preserved the symlink")
    check(tool_a.st_mode & 0o7777 == 0o4755, f"rsync preserved the setuid mode ({tool_a.st_mode & 0o7777:o})")
    owned = os.stat(f"{root}/etc/owned")
    check((owned.st_uid, owned.st_gid) == (12345, 23456), "rsync preserved the numeric owner and group")
    check(os.getxattr(f"{root}/etc/owned", "user.pai-test") == b"xattr-value", "rsync preserved the extended attribute")
    check("user:4242:r--" in tool("getfacl", "-c", f"{root}/etc/owned").stdout, "rsync preserved the ACL")
    check(
        Path(f"{root}/usr/bin/tool").read_bytes() == (source / "usr/bin/tool").read_bytes(), "file content is identical"
    )
    excluded = [Path(root, n, "should-not-copy").exists() for n in ("proc", "run", "boot/efi")]
    check(
        not any(excluded) and all(Path(root, n).is_dir() for n in ("proc", "sys", "dev", "run", "tmp")),
        "runtime directories exist but their contents were not copied",
    )

    # --- orderly ending
    finish.close_everything(ctx)
    check(
        not Path(ctx.mapper_path).exists() and tool("cryptsetup", "status", MAPPING_NAME).returncode == 4,
        "nothing is left mapped",
    )
    check(not any(m.startswith("/run/pai-install-it") for m in mounts_now()), "nothing is left mounted")
    check(ctx.installation_complete, "the installation is marked complete")

    # --- the data is really on the disk, openable with the recovery key alone
    check(
        tool("cryptsetup", "open", f"--key-file={recovery_file}", parts.root, "pai-it-verify").returncode == 0,
        "reopened with the recovery key file alone",
    )
    try:
        nodes.make_once()
        os.makedirs(f"{work}/verify", exist_ok=True)
        mounted = tool("mount", "-o", "ro", "/dev/mapper/pai-it-verify", f"{work}/verify").returncode == 0
        check(
            mounted and Path(work, "verify/etc/hostname").read_text() == "pai-it\n",
            "the copied data is on the disk and readable after reopening",
        )
    finally:
        tool("umount", f"{work}/verify")
        tool("cryptsetup", "close", "pai-it-verify")
    check(tool("cryptsetup", "status", "pai-it-verify").returncode == 4, "the verification mapping is closed again")
    luks.discard_recovery_key(ctx)
    check(Path(recovery_file).exists(), "a completed installation keeps its recovery key file")


def mounts_now() -> list[str]:
    return [line.split()[4] for line in Path("/proc/self/mountinfo").read_text().splitlines()]


if __name__ == "__main__":
    sys.exit(main())
