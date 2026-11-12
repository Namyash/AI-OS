"""Safety rules 1 to 4: what may be a target, and that a refusal happens before any command runs."""
# ruff: noqa: S108

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from installer.errors import SafetyError
from installer.plan import TargetSpec
from installer.target import GIB, MIN_TARGET_BYTES, resolve_target
from installer.tests.fakes import FakeSystem
from installer.tests.support import scenario

Builder = Callable[[FakeSystem], dict[str, str]]


def refusal(system: FakeSystem, target: dict[str, str]) -> SafetyError:
    with pytest.raises(SafetyError) as caught:
        resolve_target(TargetSpec(**target), system)
    return caught.value


# Each builder changes the machine and returns the plan's target. The expected reason is the safety rule that fires.
def partition_by_id(system: FakeSystem) -> dict[str, str]:
    system.symlinks["/dev/disk/by-id/usb-X-part1"] = "/dev/sdb1"
    return {"by_id": "usb-X-part1"}


def partition_by_path(system: FakeSystem) -> dict[str, str]:
    return {"path": "/dev/sdb1"}


def mapper_by_path(system: FakeSystem) -> dict[str, str]:
    system.add_disk("dm-0", devt="253:0", size_gib=64)
    system.files["/sys/block/dm-0/dm/name"] = "vault\n"
    system.symlinks["/dev/mapper/vault"] = "/dev/dm-0"
    return {"path": "/dev/mapper/vault"}


def mapper_by_node(system: FakeSystem) -> dict[str, str]:
    system.add_disk("dm-3", devt="253:3", size_gib=64)
    return {"path": "/dev/dm-3"}


def raid_device(system: FakeSystem) -> dict[str, str]:
    system.add_disk("md0", devt="9:0", size_gib=64)
    system.files["/sys/block/md0/md/level"] = "raid1\n"
    return {"path": "/dev/md0"}


def read_only_disk(system: FakeSystem) -> dict[str, str]:
    system.add_disk("sdc", devt="8:32", size_gib=64)
    system.files["/sys/block/sdc/ro"] = "1\n"
    return {"path": "/dev/sdc"}


def live_medium_disk(system: FakeSystem) -> dict[str, str]:
    return {"path": "/dev/sdb"}  # the partition of the medium is mounted at /run/live/medium


def live_squashfs_loop(system: FakeSystem) -> dict[str, str]:
    return {"path": "/dev/loop0"}  # the loop device behind the live root filesystem


def live_medium_under_other_names(system: FakeSystem) -> dict[str, str]:
    system.add_disk("nvme0n1", devt="259:0", size_gib=64, partitions=[(1, "259:1"), (3, "259:3")])
    system.add_mount("259:3", "/run/live/medium", "ext4", "/dev/nvme0n1p3")
    return {"path": "/dev/nvme0n1"}


def live_medium_old_layout(system: FakeSystem) -> dict[str, str]:
    system.add_disk("vda", devt="252:0", size_gib=64, partitions=[(1, "252:1")])
    system.add_mount("252:1", "/lib/live/mount/medium", "vfat", "/dev/vda1")
    return {"path": "/dev/vda"}


def live_medium_without_partitions(system: FakeSystem) -> dict[str, str]:
    system.add_disk("sr0", devt="11:0", size_gib=64)
    system.add_mount("11:0", "/run/live/medium", "iso9660", "/dev/sr0")
    return {"path": "/dev/sr0"}


def mounted_partition(system: FakeSystem) -> dict[str, str]:
    system.add_disk("sdc", devt="8:32", size_gib=64, partitions=[(1, "8:33"), (2, "8:34")])
    system.add_mount("8:34", "/mnt/data with space", "ext4", "/dev/sdc2")
    return {"path": "/dev/sdc"}


def mounted_whole_disk(system: FakeSystem) -> dict[str, str]:
    system.add_disk("sdc", devt="8:32", size_gib=64)
    system.add_mount("8:32", "/srv", "ext4", "/dev/sdc")
    return {"path": "/dev/sdc"}


def swap_partition(system: FakeSystem) -> dict[str, str]:
    system.add_disk("sdc", devt="8:32", size_gib=64, partitions=[(1, "8:33")])
    system.swaps.append("/dev/disk/by-id/swapalias")
    system.symlinks["/dev/disk/by-id/swapalias"] = "/dev/sdc1"
    return {"path": "/dev/sdc"}


def active_mapping(system: FakeSystem) -> dict[str, str]:
    system.add_disk("sdc", devt="8:32", size_gib=64, partitions=[(1, "8:33")])
    system.add_holder("sdc/sdc1", "dm-5", "253:5")
    return {"path": "/dev/sdc"}


def nested_mapping_mounted(system: FakeSystem) -> dict[str, str]:
    system.add_disk("sdc", devt="8:32", size_gib=64, partitions=[(1, "8:33")])
    system.add_holder("sdc/sdc1", "dm-5", "253:5")
    system.add_holder("dm-5", "dm-6", "253:6")
    system.add_mount("253:6", "/home", "ext4", "/dev/mapper/home")
    return {"path": "/dev/sdc"}


def too_small(system: FakeSystem) -> dict[str, str]:
    system.add_disk("sdc", devt="8:32", size_gib=15)
    return {"path": "/dev/sdc"}


def one_sector_too_small(system: FakeSystem) -> dict[str, str]:
    system.add_disk("sdc", devt="8:32", size_gib=16)
    system.files["/sys/block/sdc/size"] = f"{MIN_TARGET_BYTES // 512 - 1}\n"
    return {"path": "/dev/sdc"}


def missing_by_id(system: FakeSystem) -> dict[str, str]:
    return {"by_id": "ata-NOT-ATTACHED"}


def missing_path(system: FakeSystem) -> dict[str, str]:
    return {"path": "/dev/sdz"}


def outside_dev(system: FakeSystem) -> dict[str, str]:
    system.files["/dev/disk/by-id/odd"] = ""
    system.symlinks["/dev/disk/by-id/odd"] = "/tmp/odd-disk"
    system.files["/tmp/odd-disk"] = ""
    return {"by_id": "odd"}


def not_a_block_device(system: FakeSystem) -> dict[str, str]:
    system.files["/dev/null"] = ""
    return {"path": "/dev/null"}


def unknown_to_the_kernel(system: FakeSystem) -> dict[str, str]:
    system.nodes.add("/dev/ghost")
    return {"path": "/dev/ghost"}


REFUSALS: dict[str, tuple[Builder, str]] = {
    "partition-by-id": (partition_by_id, "partition"),
    "partition-by-path": (partition_by_path, "partition"),
    "mapper-by-path": (mapper_by_path, "mapper-device"),
    "mapper-by-node": (mapper_by_node, "mapper-device"),
    "raid": (raid_device, "mapper-device"),
    "read-only": (read_only_disk, "read-only"),
    "live-medium-disk": (live_medium_disk, "live-medium"),
    "live-squashfs-loop": (live_squashfs_loop, "live-medium"),
    "live-medium-nvme": (live_medium_under_other_names, "live-medium"),
    "live-medium-old-layout": (live_medium_old_layout, "live-medium"),
    "live-medium-no-partitions": (live_medium_without_partitions, "live-medium"),
    "mounted-partition": (mounted_partition, "mounted"),
    "mounted-whole-disk": (mounted_whole_disk, "mounted"),
    "swap": (swap_partition, "swap"),
    "active-mapping": (active_mapping, "active-mapping"),
    "nested-mapping-mounted": (nested_mapping_mounted, "mounted"),
    "too-small": (too_small, "too-small"),
    "one-sector-too-small": (one_sector_too_small, "too-small"),
    "missing-by-id": (missing_by_id, "not-found"),
    "missing-path": (missing_path, "not-found"),
    "outside-dev": (outside_dev, "not-a-disk"),
    "not-a-block-device": (not_a_block_device, "not-a-block-device"),
    "unknown-to-kernel": (unknown_to_the_kernel, "not-a-disk"),
}


@pytest.mark.parametrize("name", REFUSALS)
def test_the_resolver_refuses_with_the_right_reason(name: str) -> None:
    build, reason = REFUSALS[name]
    system = FakeSystem.live_machine()
    error = refusal(system, build(system))
    assert error.reason == reason, str(error)
    assert system.calls == [], "resolving a target must not run any command"


@pytest.mark.parametrize("name", REFUSALS)
def test_a_refused_target_stops_the_engine_before_anything_runs(name: str) -> None:
    build, _ = REFUSALS[name]
    system = FakeSystem.live_machine()
    run = scenario(system, target=build(system))
    assert run.run() is False
    assert system.calls == [], "not a single command may run when the target is refused"
    assert system.secret_files == {}, "no recovery key may be written when the target is refused"
    assert run.steps[0] == ("resolve-target", "start") and ("resolve-target", "failed") in run.steps
    assert run.result["ok"] is False and "resolve-target" in run.result["error"]
    assert not any(name in {"wipe", "partition"} for name, _ in run.steps)


def test_a_clean_disk_is_accepted_by_id_and_by_path() -> None:
    system = FakeSystem.live_machine(target_gib=64)
    by_id = resolve_target(TargetSpec(by_id="ata-TARGET-DISK"), system)
    by_path = resolve_target(TargetSpec(path="/dev/sda"), system)
    assert by_id == by_path
    assert (by_id.path, by_id.name, by_id.devt, by_id.size_bytes) == ("/dev/sda", "sda", "8:0", 64 * GIB)


def test_exactly_the_minimum_size_is_accepted() -> None:
    system = FakeSystem.live_machine(target_gib=16)
    assert resolve_target(TargetSpec(path="/dev/sda"), system).size_bytes == MIN_TARGET_BYTES


def test_a_nvme_style_disk_with_unmounted_partitions_is_accepted() -> None:
    system = FakeSystem.live_machine()
    system.add_disk("nvme0n1", devt="259:0", size_gib=64, partitions=[(1, "259:1"), (2, "259:2")])
    assert resolve_target(TargetSpec(path="/dev/nvme0n1"), system).name == "nvme0n1"


def test_nothing_is_ever_chosen_automatically() -> None:
    system = FakeSystem.live_machine()
    assert refusal(system, {}).reason == "not-found"


def test_the_live_medium_is_found_from_the_mount_table_not_from_names() -> None:
    """The same disk is refused or accepted purely according to what is mounted from it."""
    system = FakeSystem.live_machine()
    system.add_disk("nvme0n1", devt="259:0", size_gib=64, partitions=[(3, "259:3")])
    assert resolve_target(TargetSpec(path="/dev/nvme0n1"), system).name == "nvme0n1"
    system.add_mount("259:3", "/run/live/medium", "iso9660", "whatever")
    assert refusal(system, {"path": "/dev/nvme0n1"}).reason == "live-medium"


class UnreadableTables(FakeSystem):
    def read_text(self, path: str) -> str:
        if path in self.broken:
            raise OSError("unreadable")
        return super().read_text(path)

    broken: tuple[str, ...] = ()


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("/proc/self/mountinfo", "mount-table-unreadable"),
        ("/proc/swaps", "swap-table-unreadable"),
        ("/sys/block/sda/size", "unreadable"),
        ("/sys/block/sda/dev", "unreadable"),
    ],
)
def test_an_unreadable_table_fails_closed(path: str, reason: str) -> None:
    system = UnreadableTables.live_machine()
    system.broken = (path,)
    assert refusal(system, {"path": "/dev/sda"}).reason == reason


def test_a_malformed_mount_table_fails_closed() -> None:
    class Malformed(FakeSystem):
        def read_text(self, path: str) -> str:
            return "garbage line without fields\n" if path == "/proc/self/mountinfo" else super().read_text(path)

    assert refusal(Malformed.live_machine(), {"path": "/dev/sda"}).reason == "mount-table-unreadable"


def test_refusal_messages_name_the_device_and_the_reason() -> None:
    system = FakeSystem.live_machine()
    message: Any = str(refusal(system, {"path": "/dev/sdb"}))
    assert "/dev/sdb" in message and "live medium" in message
