"""A fake machine for the tests: one object that is both the ``Runner`` and the ``Host``.

It keeps just enough state to behave like the real tools where the installer depends on it: a partition table that
``sfdisk`` writes and reads back, LUKS containers whose keyslots really check the passphrase bytes they are given,
mappings that cannot be closed while mounted, a mount table that ``mount`` and ``umount`` change, and a target tree
that ``rsync`` and ``install`` fill. A command it does not know fails the test, so the installer cannot run something
unexpected unnoticed. Failures are injected with ``fail_on``.
"""
# ruff: noqa: S105

from __future__ import annotations

import fnmatch
import json
import posixpath
from collections.abc import Sequence
from dataclasses import dataclass, field

from installer.runner import CommandResult

GIB = 1024**3
MIB = 1024**2
SECTOR = 512

LIVE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "user:x:1000:1000:Debian Live user,,,:/home/user:/bin/bash\n"
)
LIVE_SHADOW = (
    "root:$6$rootsalt$rootrootrootroot:19000:0:99999:7:::\n"
    "daemon:*:19000:0:99999:7:::\n"
    "user:$6$live$livelivelive:19000:0:99999:7:::\n"
)
LIVE_GROUP = "root:x:0:\nsudo:x:27:user\nuser:x:1000:\n"


@dataclass
class Call:
    argv: list[str]
    stdin: bytes | None
    extra_env: dict[str, str] | None

    @property
    def inner(self) -> list[str]:
        """The command inside a chroot, or the command itself."""
        return self.argv[2:] if self.argv[:1] == ["chroot"] else self.argv


@dataclass
class FailRule:
    pattern: list[str]  # a prefix of argv; "*" matches any one element
    returncode: int = 1
    stderr: str = "injected failure"
    raises: BaseException | None = None
    remaining: int | None = None  # None: every matching call


@dataclass
class Luks:
    kdf: str
    slots: list[bytes]


@dataclass
class FakeSystem:
    calls: list[Call] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    dirs: set[str] = field(default_factory=set)
    nodes: set[str] = field(default_factory=set)
    devts: dict[str, str] = field(default_factory=dict)
    symlinks: dict[str, str] = field(default_factory=dict)
    mounts: list[tuple[str, str, str, str]] = field(default_factory=list)  # devt, mountpoint, fstype, source
    swaps: list[str] = field(default_factory=list)
    secret_files: dict[str, tuple[str, int]] = field(default_factory=dict)
    fail_rules: list[FailRule] = field(default_factory=list)
    luks: dict[str, Luks] = field(default_factory=dict)
    mappings: dict[str, str] = field(default_factory=dict)
    filesystems: dict[str, tuple[str, str, str]] = field(default_factory=dict)  # device -> type, label, uuid
    tables: dict[str, list[dict[str, object]]] = field(default_factory=dict)
    source_trees: dict[str, dict[str, str]] = field(default_factory=dict)
    installed_packages: dict[str, str] = field(default_factory=dict)
    purged: list[str] = field(default_factory=list)
    busy_mounts: set[str] = field(default_factory=set)
    node_delay: float = 0.0
    clock: float = 0.0
    sfdisk_json_override: str | None = None
    work_dir: str = "/run/pai-install"
    _pending_nodes: dict[str, float] = field(default_factory=dict)
    _uuid_counter: int = 0

    # ------------------------------------------------------------------------------------------ machine builder
    @classmethod
    def live_machine(cls, target_gib: int = 64) -> FakeSystem:
        """A booted live ISO: a blank target disk ``sda`` (also under /dev/disk/by-id), the medium on ``sdb1``."""
        system = cls()
        system.add_disk("sda", devt="8:0", size_gib=target_gib)
        system.symlinks["/dev/disk/by-id/ata-TARGET-DISK"] = "/dev/sda"
        system.add_disk("sdb", devt="8:16", size_gib=8, partitions=[(1, "8:17")])
        system.add_disk("loop0", devt="7:0", size_gib=1)
        system.mounts += [
            ("0:21", "/", "overlay", "overlay"),
            ("8:17", "/run/live/medium", "iso9660", "/dev/sdb1"),
            ("7:0", "/run/live/rootfs/filesystem.squashfs", "squashfs", "/dev/loop0"),
            ("0:22", "/proc", "proc", "proc"),
        ]
        system.source_trees["/run/live/rootfs/filesystem.squashfs"] = {
            "/etc/passwd": LIVE_PASSWD,
            "/etc/shadow": LIVE_SHADOW,
            "/etc/group": LIVE_GROUP,
            "/etc/live/config.conf.d/user.conf": 'LIVE_USERNAME="user"\n',
            "/etc/sudoers.d/live": "user ALL=(ALL) NOPASSWD: ALL\n",
            "/etc/machine-id": "0123456789abcdef0123456789abcdef\n",
            "/etc/systemd/system/getty@tty1.service.d/autologin.conf": (
                "[Service]\nExecStart=-/sbin/agetty --autologin user\n"
            ),
            "/etc/systemd/system/getty@tty2.service.d/other.conf": "[Service]\nTTYVTDisallocate=no\n",
            "/lib/live/config/0010-hostname": "#!/bin/sh\n",
            "/usr/bin/pai": "binary\n",
        }
        system.installed_packages = {
            "live-boot": "installed",
            "live-boot-initramfs-tools": "installed",
            "live-config": "installed",
            "live-config-systemd": "installed",
            "live-boot-doc": "config-files",
            "live-tools": "installed",
        }
        return system

    def add_disk(self, name: str, *, devt: str, size_gib: int, partitions: Sequence[tuple[int, str]] = ()) -> None:
        self.files[f"/sys/block/{name}/dev"] = devt + "\n"
        self.files[f"/sys/block/{name}/size"] = f"{size_gib * GIB // SECTOR}\n"
        self.files[f"/sys/block/{name}/ro"] = "0\n"
        self.nodes.add(f"/dev/{name}")
        self.devts[f"/dev/{name}"] = devt
        for number, partition_devt in partitions:
            self.add_partition(name, number, partition_devt)

    @staticmethod
    def partition_name(disk: str, number: int) -> str:
        return f"{disk}p{number}" if disk[-1].isdigit() else f"{disk}{number}"

    def add_partition(self, disk: str, number: int, devt: str) -> str:
        name = self.partition_name(disk, number)
        self.files[f"/sys/block/{disk}/{name}/dev"] = devt + "\n"
        self.files[f"/sys/block/{disk}/{name}/partition"] = f"{number}\n"
        self.files[f"/sys/class/block/{name}/partition"] = f"{number}\n"
        self.nodes.add(f"/dev/{name}")
        self.devts[f"/dev/{name}"] = devt
        return name

    def add_holder(self, sysfs_device: str, holder: str, devt: str) -> None:
        """``holder`` (a dm device) sits on top of ``sysfs_device`` (a path below /sys/block, e.g. ``sda/sda1``)."""
        self.files[f"/sys/block/{sysfs_device}/holders/{holder}"] = ""
        self.files[f"/sys/block/{holder}/dev"] = devt + "\n"
        self.files[f"/sys/block/{holder}/dm/name"] = "something\n"
        self.nodes.add(f"/dev/{holder}")
        self.devts[f"/dev/{holder}"] = devt

    def add_mount(self, devt: str, mountpoint: str, fstype: str = "ext4", source: str = "/dev/x") -> None:
        self.mounts.append((devt, mountpoint, fstype, source))

    # ------------------------------------------------------------------------------------------ failure injection
    def fail_on(
        self, *pattern: str, returncode: int = 1, stderr: str = "injected failure", times: int | None = None
    ) -> None:
        self.fail_rules.append(FailRule(list(pattern), returncode, stderr, remaining=times))

    def raise_on(self, *pattern: str, error: BaseException) -> None:
        self.fail_rules.append(FailRule(list(pattern), raises=error))

    # ------------------------------------------------------------------------------------------ inspection
    def argvs(self) -> list[list[str]]:
        return [call.argv for call in self.calls]

    def commands(self, name: str) -> list[Call]:
        return [call for call in self.calls if call.inner and call.inner[0] == name]

    @property
    def target_root(self) -> str:
        return f"{self.work_dir}/target"

    def mounted_paths(self) -> list[str]:
        return [mountpoint for _, mountpoint, _, _ in self.mounts if mountpoint.startswith(self.work_dir)]

    # ------------------------------------------------------------------------------------------ Host
    def realpath(self, path: str) -> str:
        return self.symlinks.get(path, path)

    def exists(self, path: str) -> bool:
        path = self.symlinks.get(path, path)
        if path in self._pending_nodes and self.clock < self._pending_nodes[path]:
            return False
        if path in self.files or path in self.dirs or path in self.nodes or path in self.secret_files:
            return True
        prefix = path.rstrip("/") + "/"
        return any(key.startswith(prefix) for key in (*self.files, *self.dirs))

    def is_block_device(self, path: str) -> bool:
        return path in self.nodes

    def devt(self, path: str) -> str | None:
        return self.devts.get(path) if path in self.nodes else None

    def read_text(self, path: str) -> str:
        if path == "/proc/self/mountinfo":
            return "".join(
                f"{index + 20} 1 {devt} / {mountpoint.replace(' ', chr(92) + '040')} rw - {fstype} {source} rw\n"
                for index, (devt, mountpoint, fstype, source) in enumerate(self.mounts)
            )
        if path == "/proc/swaps":
            return "Filename\tType\tSize\tUsed\tPriority\n" + "".join(
                f"{swap}\tpartition\t1024\t0\t-2\n" for swap in self.swaps
            )
        if path in self.files:
            return self.files[path]
        raise FileNotFoundError(path)

    def listdir(self, path: str) -> list[str]:
        prefix = path.rstrip("/") + "/"
        names = {key[len(prefix) :].split("/", 1)[0] for key in (*self.files, *self.dirs) if key.startswith(prefix)}
        if not names and path not in self.dirs and path not in self.files:
            raise FileNotFoundError(path)
        return sorted(names)

    def write_secret_file(self, path: str, content: str) -> None:
        if path in self.secret_files:
            raise FileExistsError(path)
        self.secret_files[path] = (content, 0o600)

    def remove_file(self, path: str) -> None:
        self.secret_files.pop(path, None)

    def sleep(self, seconds: float) -> None:
        self.clock += seconds

    def monotonic(self) -> float:
        return self.clock

    # ------------------------------------------------------------------------------------------ Runner
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        stdin: bytes | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> CommandResult:
        assert timeout > 0, "every command needs a timeout"
        call = Call(list(argv), stdin, dict(extra_env) if extra_env else None)
        self.calls.append(call)
        for rule in self.fail_rules:
            if rule.remaining == 0 or not self._matches(rule.pattern, call.argv):
                continue
            if rule.remaining is not None:
                rule.remaining -= 1
            if rule.raises is not None:
                raise rule.raises
            return CommandResult(rule.returncode, "", rule.stderr)
        handler = getattr(self, "_cmd_" + posixpath.basename(call.argv[0]).replace(".", "_").replace("-", "_"), None)
        if handler is None:
            raise AssertionError(f"the fake system does not know the command {call.argv!r}")
        return handler(call)

    @staticmethod
    def _matches(pattern: list[str], argv: list[str]) -> bool:
        return len(argv) >= len(pattern) and all(p == "*" or p == a for p, a in zip(pattern, argv, strict=False))

    # ------------------------------------------------------------------------------------------ helpers
    def _next_uuid(self, short: bool = False) -> str:
        self._uuid_counter += 1
        n = self._uuid_counter
        return f"{n:04X}-{n:04X}" if short else f"{n:08x}-1111-4222-8333-{n:012x}"

    def _mounted_at(self, path: str) -> bool:
        return any(mountpoint == path for _, mountpoint, _, _ in self.mounts)

    def _under_unmounted_target(self, path: str) -> bool:
        return path.startswith(self.target_root + "/") and not self._mounted_at(self.target_root)

    # ------------------------------------------------------------------------------------------ commands
    def _cmd_wipefs(self, call: Call) -> CommandResult:
        device = call.argv[-1]
        if device not in self.nodes:
            return CommandResult(1, "", f"wipefs: {device}: No such file or directory")
        self.filesystems.pop(device, None)
        self.luks.pop(device, None)
        if device in self.tables:
            self.tables[device] = []
        return CommandResult(0)

    def _cmd_sfdisk(self, call: Call) -> CommandResult:
        disk = call.argv[-1]
        if "--json" in call.argv:
            if self.sfdisk_json_override is not None:
                return CommandResult(0, self.sfdisk_json_override)
            partitions = self.tables.get(disk, [])
            table = {
                "partitiontable": {
                    "label": "gpt",
                    "device": disk,
                    "unit": "sectors",
                    "sectorsize": SECTOR,
                    "partitions": partitions,
                }
            }
            return CommandResult(0, json.dumps(table))
        assert call.stdin is not None, "sfdisk must get its script on standard input"
        name = disk.rsplit("/", 1)[1]
        total = int(self.files[f"/sys/block/{name}/size"])
        for old in self.tables.get(disk, []):
            self.nodes.discard(str(old["node"]))
        rows: list[dict[str, object]] = []
        start = 2048
        for index, line in enumerate(call.stdin.decode().splitlines()[1:], start=1):
            fields = dict(part.strip().split("=", 1) for part in line.split(","))
            size = int(fields["size"].removesuffix("MiB")) * MIB // SECTOR if "size" in fields else total - start - 2048
            node = f"{disk}p{index}" if disk[-1].isdigit() else f"{disk}{index}"
            rows.append({"node": node, "start": start, "size": size, "type": fields["type"], "name": fields["name"]})
            self.nodes.add(node)
            self.devts[node] = f"{self.devts[disk].split(':')[0]}:{index}"
            self.files[f"/sys/block/{name}/{node.rsplit('/', 1)[1]}/partition"] = f"{index}\n"
            if self.node_delay:
                self._pending_nodes[node] = self.clock + self.node_delay
            start += size
        self.tables[disk] = rows
        return CommandResult(0)

    def _cmd_cryptsetup(self, call: Call) -> CommandResult:
        argv = call.argv
        action = argv[1]
        if action == "luksFormat":
            device = argv[-1]
            if device not in self.nodes:
                return CommandResult(1, "", "no such device")
            kdf = argv[argv.index("--pbkdf") + 1] if "--pbkdf" in argv else "argon2id"
            assert "--key-file=-" in argv and call.stdin is not None and "--batch-mode" in argv
            self.luks[device] = Luks(kdf=kdf, slots=[call.stdin])
            return CommandResult(0)
        if action == "luksAddKey":
            device, keyfile = argv[-2], argv[-1]
            container = self.luks.get(device)
            if container is None:
                return CommandResult(1, "", "not a LUKS device")
            if call.stdin not in container.slots:
                return CommandResult(2, "", "No key available with this passphrase.")
            new_key = self.secret_files[keyfile][0].encode() if keyfile in self.secret_files else None
            if new_key is None:
                return CommandResult(1, "", "cannot read the new key file")
            container.slots.append(new_key)
            return CommandResult(0)
        if action == "luksDump":
            container = self.luks.get(argv[-1])
            if container is None:
                return CommandResult(1, "", "not a LUKS device")
            keyslots = {str(i): {"type": "luks2", "kdf": {"type": container.kdf}} for i in range(len(container.slots))}
            return CommandResult(0, json.dumps({"keyslots": keyslots, "tokens": {}}))
        if action == "open":
            device, name = argv[-2], argv[-1]
            container = self.luks.get(device)
            if container is None:
                return CommandResult(1, "", "not a LUKS device")
            if name in self.mappings:
                return CommandResult(5, "", "Device already exists")
            if call.stdin not in container.slots:
                return CommandResult(2, "", "No key available with this passphrase.")
            self.mappings[name] = device
            self.nodes.add(f"/dev/mapper/{name}")
            self.devts[f"/dev/mapper/{name}"] = "253:0"
            return CommandResult(0)
        if action == "close":
            name = argv[-1]
            if name not in self.mappings:
                return CommandResult(4, "", "Device is not active")
            if any(source == f"/dev/mapper/{name}" for _, _, _, source in self.mounts):
                return CommandResult(5, "", f"Device {name} is still in use")
            del self.mappings[name]
            self.nodes.discard(f"/dev/mapper/{name}")
            return CommandResult(0)
        raise AssertionError(f"the fake cryptsetup does not know {argv!r}")

    def _format(self, call: Call, fs_type: str, short_uuid: bool) -> CommandResult:
        device = call.argv[-1]
        if device not in self.nodes:
            return CommandResult(1, "", f"{device}: No such file or directory")
        label = call.argv[call.argv.index("-L") + 1] if "-L" in call.argv else call.argv[call.argv.index("-n") + 1]
        self.filesystems[device] = (fs_type, label, self._next_uuid(short_uuid))
        return CommandResult(0)

    def _cmd_mkfs_vfat(self, call: Call) -> CommandResult:
        return self._format(call, "vfat", True)

    def _cmd_mkfs_ext4(self, call: Call) -> CommandResult:
        return self._format(call, "ext4", False)

    def _cmd_blkid(self, call: Call) -> CommandResult:
        device = call.argv[-1]
        if device in self.luks:
            return CommandResult(
                0, f"DEVNAME={device}\nUUID=aaaaaaaa-0000-4000-8000-{len(device):012x}\nTYPE=crypto_LUKS\n"
            )
        if device in self.filesystems:
            fs_type, _, uuid = self.filesystems[device]
            return CommandResult(0, f"DEVNAME={device}\nUUID={uuid}\nTYPE={fs_type}\n")
        return CommandResult(2, "", "")

    def _cmd_mount(self, call: Call) -> CommandResult:
        argv = call.argv[1:]
        if argv[0] == "--make-rslave":
            return CommandResult(0)
        target = argv[-1]
        if target not in self.dirs and target.startswith(self.work_dir):
            return CommandResult(32, "", f"mount point {target} does not exist")
        if argv[0] in ("--rbind", "--bind"):
            self.mounts.append(("0:99", target, "none", argv[1]))
            return CommandResult(0)
        fs_type = argv[argv.index("-t") + 1]
        source = argv[-2]
        if fs_type != "proc" and source not in self.nodes:
            return CommandResult(32, "", f"{source}: special device does not exist")
        if fs_type in ("ext4", "vfat") and source not in self.filesystems:
            return CommandResult(32, "", f"{source}: wrong fs type")
        if fs_type == "ext4" and target != self.target_root and not self._mounted_at(self.target_root):
            return CommandResult(32, "", "the root is not mounted yet")
        self.mounts.append((self.devts.get(source, "0:98"), target, fs_type, source))
        return CommandResult(0)

    def _cmd_umount(self, call: Call) -> CommandResult:
        path = call.argv[-1]
        if path in self.busy_mounts:
            return CommandResult(32, "", f"{path}: target is busy")
        before = len(self.mounts)
        self.mounts = [m for m in self.mounts if not (m[1] == path or m[1].startswith(path + "/"))]
        return CommandResult(0) if len(self.mounts) < before else CommandResult(32, "", f"{path}: not mounted")

    def _cmd_install(self, call: Call) -> CommandResult:
        argv = call.argv
        path = argv[-1]
        if self._under_unmounted_target(path):
            return CommandResult(1, "", f"{path}: root not mounted")
        if argv[1] == "-d":
            self.dirs.add(path)
            return CommandResult(0)
        assert argv[1:3] == ["-D", "-m"] and argv[4] == "/dev/stdin" and call.stdin is not None
        self.files[path] = call.stdin.decode()
        return CommandResult(0)

    def _cmd_rsync(self, call: Call) -> CommandResult:
        source, destination = call.argv[-2], call.argv[-1]
        assert source.endswith("/") and destination.endswith("/")
        if not self._mounted_at(self.target_root) or not self._mounted_at(f"{self.target_root}/boot/efi"):
            return CommandResult(11, "", "destination not mounted")
        tree = self.source_trees.get(source.rstrip("/"))
        if tree is None:
            return CommandResult(23, "", "no such source")
        for path, content in tree.items():
            self.files[self.target_root + path] = content
        self.dirs.update(f"{self.target_root}/{name}" for name in ("proc", "sys", "dev", "run", "tmp"))
        return CommandResult(0)

    def _cmd_sync(self, call: Call) -> CommandResult:
        return CommandResult(0)

    def _cmd_systemctl(self, call: Call) -> CommandResult:
        return CommandResult(0)

    def _cmd_chroot(self, call: Call) -> CommandResult:
        root, inner = call.argv[1], call.argv[2:]
        assert root == self.target_root, "chroot must enter the target tree"
        assert call.extra_env == {"DEBIAN_FRONTEND": "noninteractive"}
        if inner[0] in ("update-initramfs", "grub-install", "update-grub", "apt-get"):
            for needed in ("proc", "dev", "sys", "run"):
                if not self._mounted_at(f"{root}/{needed}"):
                    return CommandResult(1, "", f"/{needed} is not mounted in the chroot")
        handler = getattr(self, "_chroot_" + inner[0].replace("-", "_"), None)
        if handler is None:
            raise AssertionError(f"the fake chroot does not know {inner!r}")
        return handler(root, inner)

    def _users(self, root: str) -> dict[str, list[str]]:
        return {line.split(":")[0]: line.split(":") for line in self.files[f"{root}/etc/passwd"].splitlines() if line}

    def _chroot_userdel(self, root: str, inner: list[str]) -> CommandResult:
        name = inner[-1]
        for name_file in ("passwd", "shadow", "group"):
            path = f"{root}/etc/{name_file}"
            kept = []
            for line in self.files[path].splitlines():
                fields = line.split(":")
                if fields[0] == name:
                    continue
                if name_file == "group" and len(fields) > 3:
                    fields[3] = ",".join(m for m in fields[3].split(",") if m != name)
                kept.append(":".join(fields))
            self.files[path] = "\n".join(kept) + "\n"
        return CommandResult(0)

    def _chroot_passwd(self, root: str, inner: list[str]) -> CommandResult:
        assert inner[1] == "--lock"
        name = inner[2]
        path = f"{root}/etc/shadow"
        lines = []
        found = False
        for line in self.files[path].splitlines():
            fields = line.split(":")
            if fields[0] == name:
                found = True
                if not fields[1].startswith(("!", "*")):
                    fields[1] = "!" + fields[1]
            lines.append(":".join(fields))
        if not found:
            return CommandResult(1, "", f"passwd: user '{name}' does not exist")
        self.files[path] = "\n".join(lines) + "\n"
        return CommandResult(0)

    def _chroot_useradd(self, root: str, inner: list[str]) -> CommandResult:
        name = inner[-1]
        if name in self._users(root):
            return CommandResult(9, "", f"useradd: user '{name}' already exists")
        self.files[f"{root}/etc/passwd"] += f"{name}:x:1001:1001::/home/{name}:/bin/bash\n"
        self.files[f"{root}/etc/shadow"] += f"{name}:!:19000:0:99999:7:::\n"
        self.files[f"{root}/etc/group"] += f"{name}:x:1001:\n"
        return CommandResult(0)

    def _chroot_dpkg_query(self, root: str, inner: list[str]) -> CommandResult:
        patterns = inner[inner.index("--showformat") + 2 :]
        lines = [
            f"{status}\t{package}\n"
            for package, status in sorted(self.installed_packages.items())
            if any(fnmatch.fnmatchcase(package, pattern) for pattern in patterns)
        ]
        return CommandResult(0 if lines else 1, "".join(lines))

    def _chroot_apt_get(self, root: str, inner: list[str]) -> CommandResult:
        assert inner[1:4] == ["--yes", "--quiet", "purge"]
        for package in inner[4:]:
            if package not in self.installed_packages:
                return CommandResult(100, "", f"E: Unable to locate package {package}")
            del self.installed_packages[package]
            self.purged.append(package)
        return CommandResult(0)

    def _chroot_rm(self, root: str, inner: list[str]) -> CommandResult:
        paths = inner[inner.index("--") + 1 :] if "--" in inner else inner[2:]
        for path in paths:
            full = root + path
            for key in [k for k in self.files if k == full or k.startswith(full + "/")]:
                del self.files[key]
        return CommandResult(0)

    def _chroot_rmdir(self, root: str, inner: list[str]) -> CommandResult:
        return CommandResult(0)

    def _chroot_truncate(self, root: str, inner: list[str]) -> CommandResult:
        self.files[root + inner[-1]] = ""
        return CommandResult(0)

    def _chroot_update_initramfs(self, root: str, inner: list[str]) -> CommandResult:
        self.files[f"{root}/boot/initrd.img-6.12"] = "initrd"
        return CommandResult(0)

    def _chroot_grub_install(self, root: str, inner: list[str]) -> CommandResult:
        if "--target=i386-pc" in inner:
            self.files[f"{root}/boot/grub/i386-pc/core.img"] = "core"
        else:
            self.files[f"{root}/boot/efi/EFI/BOOT/BOOTX64.EFI"] = "efi"
        return CommandResult(0)

    def _chroot_update_grub(self, root: str, inner: list[str]) -> CommandResult:
        self.files[f"{root}/boot/grub/grub.cfg"] = "menuentry 'Private AI OS' {}\n"
        return CommandResult(0)
