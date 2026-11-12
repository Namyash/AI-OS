"""A minimal Chrome DevTools Protocol client for the ``--remote-debugging-pipe`` transport.

Chromium started with ``--remote-debugging-pipe`` reads commands from file descriptor 3 and writes replies and events
to file descriptor 4. Each message is one JSON object followed by a NUL byte. There is no port, no HTTP and no
WebSocket: the only holder of the other ends of the two pipes is the launcher.

``CdpClient`` takes the launcher's two ends. A reader thread splits the replies; ``call`` sends one command and waits
a bounded time for its reply. Events are discarded: the launcher polls instead of subscribing, which keeps the client
free of ordering races. Commands carry secrets (the session cookie), so nothing here ever logs or formats parameters;
an error names the method and the browser's own message only.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
from typing import Any

from kiosk.errors import KioskError

READ_CHUNK = 65536
# The largest message accepted from the browser. Replies the launcher asks for are a few hundred bytes; a browser that
# sends a megabyte without a terminator is broken, and buffering it without limit would not help anyone.
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
_TERMINATOR = b"\0"


class CdpError(KioskError):
    """The browser refused a command, sent something that is not the protocol, or closed the pipe."""


class CdpTimeout(CdpError):
    """The browser did not answer a command in time."""


class CdpClient:
    def __init__(self, reader_fd: int, writer_fd: int) -> None:
        self._reader_fd = reader_fd
        self._writer_fd = writer_fd
        self._condition = threading.Condition()
        self._write_lock = threading.Lock()
        self._pending: set[int] = set()  # ids of the calls still waiting for a reply
        self._replies: dict[int, dict[str, Any]] = {}
        self._next_id = 0
        self._closed_reason: str | None = None
        self._reader = threading.Thread(target=self._read_loop, name="cdp-reader", daemon=True)
        self._reader.start()

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed_reason is not None

    # ------------------------------------------------------------------ commands
    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        timeout: float,
    ) -> dict[str, Any]:
        """Send one command and return its ``result``. ``session_id`` addresses an attached page (flat sessions)."""
        with self._condition:
            if self._closed_reason is not None:
                raise CdpError(f"{method}: {self._closed_reason}")
            self._next_id += 1
            call_id = self._next_id
            self._pending.add(call_id)
        message: dict[str, Any] = {"id": call_id, "method": method}
        if params is not None:
            message["params"] = params
        if session_id is not None:
            message["sessionId"] = session_id
        try:
            self._send(json.dumps(message, separators=(",", ":")).encode("utf-8") + _TERMINATOR, method)
            with self._condition:
                self._condition.wait_for(lambda: call_id in self._replies or self._closed_reason is not None, timeout)
                reply = self._replies.pop(call_id, None)
                reason = self._closed_reason
        finally:
            with self._condition:
                self._pending.discard(call_id)  # a reply that arrives after this is dropped, not kept for ever
        if reply is None:
            if reason is not None:
                raise CdpError(f"{method}: {reason}")
            raise CdpTimeout(f"{method}: no reply from the browser within {timeout:g} s")
        error = reply.get("error")
        if error is not None:
            detail = error.get("message") if isinstance(error, dict) else None
            raise CdpError(
                f"{method} was refused by the browser: {detail if isinstance(detail, str) else 'no reason given'}"
            )
        result = reply.get("result", {})
        if not isinstance(result, dict):
            raise CdpError(f"{method}: the browser's result is not an object")
        return result

    def _send(self, payload: bytes, method: str) -> None:
        with self._write_lock:
            view = memoryview(payload)
            try:
                while view:
                    view = view[os.write(self._writer_fd, view) :]
            except OSError:
                raise CdpError(f"{method}: the DevTools pipe to the browser is closed") from None

    # ------------------------------------------------------------------ replies
    def _read_loop(self) -> None:
        buffer = bytearray()
        reason = "the browser closed the DevTools pipe"
        try:
            while True:
                chunk = os.read(self._reader_fd, READ_CHUNK)
                if not chunk:
                    break
                buffer.extend(chunk)
                while (end := buffer.find(_TERMINATOR)) != -1:
                    raw = bytes(buffer[:end])
                    del buffer[: end + 1]
                    self._dispatch(raw)
                if len(buffer) > MAX_MESSAGE_BYTES:
                    reason = "the browser sent an oversized DevTools message"
                    break
        except CdpError as exc:
            reason = str(exc)
        except OSError:
            reason = "reading the DevTools pipe failed"
        with self._condition:
            self._closed_reason = reason
            self._condition.notify_all()

    def _dispatch(self, raw: bytes) -> None:
        try:
            message = json.loads(raw)
        except ValueError:
            raise CdpError("the browser sent a DevTools message that is not JSON") from None
        if not isinstance(message, dict):
            raise CdpError("the browser sent a DevTools message that is not an object")
        call_id = message.get("id")
        if isinstance(call_id, int) and not isinstance(call_id, bool):
            with self._condition:
                if call_id in self._pending:
                    self._replies[call_id] = message
                    self._condition.notify_all()
        # Anything else is an event, or a reply nobody waits for any more: none is kept.

    # ------------------------------------------------------------------ shutdown
    def close(self, join_timeout: float = 1.0) -> None:
        """Close the command pipe (the browser sees end of input) and let the reader finish.

        The reply pipe is closed only once the reader has stopped: closing a descriptor another thread is blocked
        reading does not wake it. The reader stops when the browser closes its end, which it does when it exits.
        """
        with self._write_lock:
            self._close_fd(self._writer_fd)
            self._writer_fd = -1
        self._reader.join(join_timeout)
        if not self._reader.is_alive():
            self._close_fd(self._reader_fd)
            self._reader_fd = -1
        with self._condition:
            if self._closed_reason is None:
                self._closed_reason = "the client was closed"
                self._condition.notify_all()

    @staticmethod
    def _close_fd(descriptor: int) -> None:
        if descriptor >= 0:
            with contextlib.suppress(OSError):  # already closed: nothing left to release
                os.close(descriptor)
