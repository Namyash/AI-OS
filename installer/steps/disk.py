"""Steps on the bare disk: clear old signatures, write the GPT layout, verify what was written.

The layout is the table of INSTALLER_DESIGN.md. The partition table is written by ``sfdisk`` from a script on its
standard input, and it is read back (``sfdisk --json``) and compared with the design before anything is formatted.
"""

from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass

from installer import timeouts
from installer.context import InstallContext, Partitions
from installer.errors import VerificationError
from installer.target import SYS_BLOCK

MIB = 1024**2

# GPT partition type GUIDs (sfdisk takes GUIDs, not gdisk's short codes).
BIOS_BOOT_GUID = "21686148-6449-6E6F-744E-656564454649"
ESP_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
LINUX_FILESYSTEM_GUID = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
LINUX_LUKS_GUID = "CA7D7CCB-63ED-4C53-861C-1742536059CC"

# Slack for what the root partition cannot use: the 1 MiB before the first partition, the backup GPT, alignment.
ROOT_SLACK_BYTES = 8 * MIB


@dataclass(frozen=True)
class PartitionSpec:
    role: str
    name: str  # the GPT partition name
    size_bytes: int | None  # None: all the space that is left
    type_guid: str


LAYOUT = (
    PartitionSpec("bios_boot", "bios-boot", 1 * MIB, BIOS_BOOT_GUID),
    PartitionSpec("esp", "esp", 512 * MIB, ESP_GUID),
    PartitionSpec("boot", "boot", 1024 * MIB, LINUX_FILESYSTEM_GUID),
    PartitionSpec("root", "cryptroot", None, LINUX_LUKS_GUID),
)


def sfdisk_script() -> str:
    """The partition table as an ``sfdisk`` script. Sizes carry units, so the sector size does not matter."""
    lines = ["label: gpt"]
    for part in LAYOUT:
        size = f"size={part.size_bytes // MIB}MiB, " if part.size_bytes is not None else ""
        lines.append(f"{size}type={part.type_guid}, name={part.name}")
    return "\n".join(lines) + "\n"


def _existing_partition_nodes(ctx: InstallContext) -> list[str]:
    name = ctx.require_target().name
    disk_dir = f"{SYS_BLOCK}/{name}"
    nodes = []
    for entry in ctx.host.listdir(disk_dir):
        if ctx.host.exists(f"{disk_dir}/{entry}/partition"):
            nodes.append(f"/dev/{entry}")
    return nodes


def wipe_signatures(ctx: InstallContext) -> str:
    """Erase filesystem, RAID and partition-table signatures on the partitions and then on the disk itself."""
    target = ctx.require_target()
    nodes = [node for node in _existing_partition_nodes(ctx) if ctx.host.exists(node)]
    for device in (*nodes, target.path):
        ctx.cmd.run(["wipefs", "--all", "--force", device], timeout=timeouts.WIPE)
    return f"cleared {len(nodes)} partition(s) and the disk's own signatures"


def write_partition_table(ctx: InstallContext) -> str:
    target = ctx.require_target()
    ctx.cmd.run(
        ["sfdisk", "--quiet", "--wipe", "always", "--wipe-partitions", "always", target.path],
        timeout=timeouts.PARTITION,
        stdin=sfdisk_script().encode("ascii"),
    )
    return "wrote a GPT with 4 partitions"


def verify_layout(ctx: InstallContext) -> str:
    """Read the table back and compare it with the design; records the partition device nodes."""
    target = ctx.require_target()
    result = ctx.cmd.run(["sfdisk", "--json", target.path], timeout=timeouts.QUICK)
    try:
        table = json.loads(result.stdout)["partitiontable"]
        label = table["label"]
        sector = int(table["sectorsize"])
        parts = table["partitions"]
        rows = [(str(p["node"]), int(p["start"]), int(p["size"]), str(p["type"]).upper()) for p in parts]
    except (ValueError, KeyError, TypeError):
        raise VerificationError("the partition table could not be read back") from None

    if label != "gpt":
        raise VerificationError(f"the partition table is {label!r}, expected gpt")
    if len(rows) != len(LAYOUT):
        raise VerificationError(f"expected {len(LAYOUT)} partitions, found {len(rows)}")
    fixed = sum(spec.size_bytes or 0 for spec in LAYOUT)
    for spec, (node, start, size, type_guid) in zip(LAYOUT, rows, strict=True):
        if posixpath.dirname(node) != "/dev" or not node.startswith(target.path):
            raise VerificationError(f"partition {spec.name!r} is reported at {node}, not on {target.path}")
        if type_guid != spec.type_guid:
            raise VerificationError(f"partition {spec.name!r} has the wrong type")
        if start * sector % MIB:
            raise VerificationError(f"partition {spec.name!r} is not aligned to 1 MiB")
        if spec.size_bytes is not None and size * sector != spec.size_bytes:
            raise VerificationError(f"partition {spec.name!r} is {size * sector} bytes, expected {spec.size_bytes}")
        if spec.size_bytes is None and size * sector < target.size_bytes - fixed - ROOT_SLACK_BYTES:
            raise VerificationError(f"partition {spec.name!r} does not take the rest of the disk")

    nodes = [row[0] for row in rows]
    _wait_for_nodes(ctx, nodes)
    ctx.partitions = Partitions(*nodes)
    return f"GPT with {len(nodes)} partitions as designed"


def _wait_for_nodes(ctx: InstallContext, nodes: list[str]) -> None:
    deadline = ctx.host.monotonic() + timeouts.DEVICE_NODES
    while True:
        missing = [node for node in nodes if not ctx.host.exists(node)]
        if not missing:
            return
        if ctx.host.monotonic() >= deadline:
            raise VerificationError(f"the device node(s) {', '.join(missing)} did not appear")
        ctx.host.sleep(0.25)
