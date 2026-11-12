#!/usr/bin/python3
"""Test fixture: sits between the launcher and the real Chromium and writes down the DevTools conversation.

The launcher starts this program as if it were Chromium (``PAI_KIOSK_CHROMIUM``) and hands it the DevTools pipe on
descriptors 3 and 4. It starts the real browser with the same command line and a pipe of its own, and copies messages
both ways, one NUL-terminated message at a time, appending each to the file named by ``--tee-log=PATH`` (removed from
the real browser's arguments). The log is how the integration test learns the session id the launcher installed, which
nothing else records: the id exists only in the backend's memory (as a hash) and in the browser.

This is test equipment. It sees the cookie and writes it to a file: it must never be installed on an image.
"""

from __future__ import annotations

import fcntl
import json
import os
import signal
import sys
import threading
import time

REAL_BROWSER = "/usr/bin/chromium"
COMMAND_FD, REPLY_FD = 3, 4


def spawn_real(arguments: list[str]) -> tuple[int, int, int]:
    """Start the real browser with its own DevTools pipe; returns (pid, our write end, our read end)."""
    commands_read, commands_write = os.pipe()
    replies_read, replies_write = os.pipe()
    child_reads = fcntl.fcntl(commands_read, fcntl.F_DUPFD_CLOEXEC, 10)
    child_writes = fcntl.fcntl(replies_write, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(commands_read)
    os.close(replies_write)
    actions = [
        (os.POSIX_SPAWN_DUP2, child_reads, COMMAND_FD),
        (os.POSIX_SPAWN_DUP2, child_writes, REPLY_FD),
    ]
    pid = os.posix_spawn(REAL_BROWSER, [REAL_BROWSER, *arguments], dict(os.environ), file_actions=actions)
    os.close(child_reads)
    os.close(child_writes)
    return pid, commands_write, replies_read


def copy(source: int, sink: int, direction: str, log_path: str, done: threading.Event) -> None:
    buffer = b""
    try:
        while chunk := os.read(source, 65536):
            os.write(sink, chunk)
            buffer += chunk
            while b"\0" in buffer:
                raw, _, buffer = buffer.partition(b"\0")
                with open(log_path, "a", encoding="utf-8") as log:
                    log.write(json.dumps({"t": time.time(), "dir": direction, "msg": json.loads(raw)}) + "\n")
    except OSError:
        pass
    finally:
        if direction == "command":
            os.close(sink)  # the launcher closed its end: the browser must see end of input, as it would without us
        done.set()


def main() -> int:
    arguments = sys.argv[1:]
    log_path = next(a.partition("=")[2] for a in arguments if a.startswith("--tee-log="))
    arguments = [a for a in arguments if not a.startswith("--tee-log=")]
    pid, to_browser, from_browser = spawn_real(arguments)
    done = threading.Event()
    threading.Thread(target=copy, args=(COMMAND_FD, to_browser, "command", log_path, done), daemon=True).start()
    threading.Thread(target=copy, args=(from_browser, REPLY_FD, "reply", log_path, done), daemon=True).start()

    def forward(signum: int, _frame: object) -> None:
        os.kill(pid, signum)

    signal.signal(signal.SIGTERM, forward)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
