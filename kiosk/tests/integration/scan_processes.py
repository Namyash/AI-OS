#!/usr/bin/python3
"""Test fixture: look for secrets in the command line and environment of every process, as root.

usage: scan_processes.py <secret-file-or-literal>...   (each argument names a file holding one secret per line, or is
a ``literal:<value>``). Prints one line per finding, then ``scanned N processes, M findings``; exits 1 on any finding.

/proc/<pid>/cmdline and /proc/<pid>/environ are what every local account can read for another account's process on a
default Linux system (the environ of a process of another user is readable by root only, the command line by anyone):
the design's reason for not putting a secret in either. Root reads both for every process, which is the strictest look.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def secrets_from(arguments: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for argument in arguments:
        if argument.startswith("literal:"):
            found["literal"] = argument.partition(":")[2]
            continue
        for index, line in enumerate(Path(argument).read_text(encoding="utf-8").splitlines()):
            if line.strip():
                found[f"{Path(argument).name}#{index}"] = line.strip()
    return found


def describe(pid: str) -> str:
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")[:100]
        uid = next(
            line.split()[1] for line in Path(f"/proc/{pid}/status").read_text().splitlines() if line.startswith("Uid:")
        )
    except OSError:
        return f"pid {pid}"
    return f"pid {pid} uid {uid} [{command.strip()}]"


def main() -> int:
    secrets = secrets_from(sys.argv[1:])
    if not secrets:
        print("no secret to look for: the scan would prove nothing", file=sys.stderr)
        return 2
    scanned = findings = 0
    for entry in sorted(os.listdir("/proc")):
        if not entry.isdigit() or int(entry) == os.getpid():
            continue
        scanned += 1
        for source in ("cmdline", "environ"):
            try:
                data = Path(f"/proc/{entry}/{source}").read_bytes()
            except OSError:
                continue  # the process exited, or it is a kernel thread without these files
            for name, secret in secrets.items():
                if secret.encode() in data:
                    findings += 1
                    print(f"FOUND {name} in {source} of {describe(entry)}")
    print(f"scanned {scanned} processes, {findings} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
