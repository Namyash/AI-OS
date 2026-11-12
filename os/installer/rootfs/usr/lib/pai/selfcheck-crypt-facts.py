#!/usr/bin/python3
"""Collects what the boot self-check's root-encrypted check needs to know and the self-check unit cannot read.

usage: selfcheck-crypt-facts.py <facts-file>

The self-check (security-selfcheck.sh) runs in a sandbox with a private /dev, so it cannot open the block device that
holds the LUKS header. This program runs as its own small unit (pai-selfcheck-crypt.service: an unprivileged account
plus the one capability that reads a block device), writes the facts to <facts-file> and the self-check judges them.
The judgement lives in the self-check, once; this program only observes.

What it observes, all through the kernel's own account of the running system:
  * the device (major:minor) that holds the root filesystem: the mount with mount point "/" in /proc/self/mountinfo;
  * whether that device is a device-mapper device, and its mapping name and uuid (/sys/dev/block/<m:n>/dm/);
  * the block devices it is stacked on (/sys/dev/block/<m:n>/slaves/);
  * for a dm-crypt mapping on exactly one device: the header's JSON metadata, from `cryptsetup luksDump
    --dump-json-metadata`, reduced to the LUKS version and the key-derivation function of every keyslot.

The facts file is `key=value` lines of names, numbers and device paths. No key, passphrase, salt or digest is ever read
into it: the JSON metadata holds salts and digests (public by design) and is dropped after the two fields are taken.
A fact that could not be observed is written as `error=<reason>` and the self-check treats that as a failure; nothing
is guessed. The exit status is 0 whenever the facts file was written, so a machine that is not encrypted is a finding
for the self-check, not a crashed unit.

Test-only: PAI_SELFCHECK_CRYPT_ROOT is a prefix for /proc and /sys (the same convention as security-selfcheck.sh),
and `cryptsetup` is found through PATH.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

CRYPTSETUP = "cryptsetup"
CRYPTSETUP_TIMEOUT_S = 60
# The prefix device-mapper's uuid of a dm-crypt mapping carries: "CRYPT-<type>-<uuid>-<name>"
# (cryptsetup, lib/libdevmapper.c).
DM_CRYPT_UUID = re.compile(r"^CRYPT-(?P<type>[A-Z0-9]+)-")
MAJOR_MINOR = re.compile(r"^\d+:\d+$")
KDF_NAME = re.compile(r"^[a-z0-9]{1,16}$")


class FactError(Exception):
    """A fact that could not be observed; the message goes into the facts file as `error=`."""


def root_device(mountinfo: str) -> str:
    """major:minor of the filesystem mounted at "/" (the last such mount, which is the one in effect).

    A line of /proc/self/mountinfo is: id parent-id major:minor root mount-point options [optional...] - type source ...
    The mount point is escaped by the kernel (a space is \\040), and "/" has nothing to escape.
    """
    found = ""
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[4] == "/" and MAJOR_MINOR.match(fields[2]):
            found = fields[2]
    if not found:
        raise FactError("no filesystem is mounted at / in mountinfo")
    return found


def read_attribute(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def luks_keyslot_kdfs(metadata: object) -> list[str]:
    """The key-derivation function name of each keyslot in LUKS2 JSON metadata, in keyslot order.

    A keyslot without a recognisable kdf is reported as "unknown": the self-check then fails it, because a keyslot
    whose derivation cannot be read cannot be called argon2id.
    """
    if not isinstance(metadata, dict) or not isinstance(metadata.get("keyslots"), dict):
        raise FactError("the LUKS2 metadata has no keyslots")
    kdfs: list[str] = []
    for _, slot in sorted(metadata["keyslots"].items(), key=lambda item: item[0]):
        kdf = slot.get("kdf") if isinstance(slot, dict) else None
        name = kdf.get("type") if isinstance(kdf, dict) else None
        kdfs.append(name if isinstance(name, str) and KDF_NAME.match(name) else "unknown")
    return kdfs


def dump_luks_metadata(device: str) -> object:
    """The LUKS2 JSON metadata of `device`, read with luksDump (read-only; no lock directory is needed for that)."""
    command = [CRYPTSETUP, "luksDump", "--dump-json-metadata", "--disable-locks", "--", device]
    try:
        done = subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, check=False, timeout=CRYPTSETUP_TIMEOUT_S
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FactError(f"cryptsetup luksDump could not run: {type(error).__name__}") from None
    if done.returncode != 0:
        # The message names the device and a reason ("not a valid LUKS2 device"); it holds no header content.
        raise FactError(f"cryptsetup luksDump failed with status {done.returncode}: {done.stderr.strip()[:200]}")
    try:
        return json.loads(done.stdout)
    except ValueError:
        raise FactError("cryptsetup luksDump did not print JSON metadata") from None


def collect(sys_root: Path, facts: dict[str, str]) -> None:
    """Fills `facts` in order; raises FactError for the first fact that cannot be observed (the earlier ones stay)."""
    proc = sys_root / "proc"
    try:
        mountinfo = (proc / "self" / "mountinfo").read_text(encoding="utf-8")
    except OSError as error:
        raise FactError(f"cannot read mountinfo: {type(error).__name__}") from None
    device = root_device(mountinfo)
    facts["root_device"] = device
    block = sys_root / "sys" / "dev" / "block" / device
    name = read_attribute(block / "dm" / "name")
    uuid = read_attribute(block / "dm" / "uuid")
    if name is None:
        facts["root_dm"] = "none"  # not a device-mapper device: the root filesystem is not on a mapping at all
        return
    facts["root_dm"] = name
    match = DM_CRYPT_UUID.match(uuid or "")
    facts["dm_kind"] = f"CRYPT-{match['type']}" if match else "other"
    if match is None:
        return  # a mapping that is not dm-crypt (LVM, ...): there is no header to read
    try:
        slaves = sorted(entry.name for entry in (block / "slaves").iterdir())
    except OSError as error:
        raise FactError(f"cannot list the devices under the mapping: {type(error).__name__}") from None
    facts["backing_count"] = str(len(slaves))
    if len(slaves) != 1:
        raise FactError(f"the mapping sits on {len(slaves)} devices; exactly one is expected")
    facts["backing"] = f"/dev/{slaves[0]}"
    metadata = dump_luks_metadata(facts["backing"])
    kdfs = luks_keyslot_kdfs(metadata)
    facts["luks_version"] = "2"  # --dump-json-metadata exists only for LUKS2; a LUKS1 header makes luksDump fail
    facts["keyslots"] = str(len(kdfs))
    facts["kdfs"] = ",".join(kdfs)


def render(facts: dict[str, str], error: str | None) -> str:
    lines = [f"{key}={value}" for key, value in facts.items()]
    if error is not None:
        lines.append("error=" + "".join(ch if ch.isprintable() else " " for ch in error))
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} <facts-file>", file=sys.stderr)
        return 2
    sys_root = Path(os.environ.get("PAI_SELFCHECK_CRYPT_ROOT", "/"))
    facts: dict[str, str] = {}
    error: str | None = None
    try:
        collect(sys_root, facts)
    except FactError as problem:
        error = str(problem)
    text = render(facts, error)
    target = Path(argv[1])
    # Written to a name of its own and renamed, so the self-check never reads half a file.
    partial = target.with_name(target.name + ".partial")
    partial.write_text(text, encoding="utf-8")
    partial.replace(target)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
