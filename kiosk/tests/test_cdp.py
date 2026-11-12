"""The DevTools pipe client: framing, replies, errors, timeouts and a pipe that closes, against an in-process peer."""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from kiosk import cdp
from kiosk.cdp import CdpClient, CdpError, CdpTimeout


@dataclass
class Peer:
    """The browser's side of the two pipes: it reads commands and writes replies, one NUL-terminated JSON each."""

    reads: int  # commands arrive here
    writes: int  # replies leave from here
    received: list[dict[str, Any]] = field(default_factory=list)
    raw: bytes = b""
    _buffer: bytes = b""

    def next_command(self, timeout: float = 5.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while b"\0" not in self._buffer:
            assert time.monotonic() < deadline, "the client sent no command"
            self._buffer += os.read(self.reads, 65536)
        raw, _, self._buffer = self._buffer.partition(b"\0")
        self.raw = raw
        message = json.loads(raw)
        self.received.append(message)
        return message

    def send(self, message: dict[str, Any] | bytes) -> None:
        payload = message if isinstance(message, bytes) else json.dumps(message).encode()
        os.write(self.writes, payload + b"\0")

    def reply(self, command: dict[str, Any], result: dict[str, Any] | None = None) -> None:
        self.send({"id": command["id"], "result": {} if result is None else result})

    def close(self) -> None:
        for descriptor in (self.reads, self.writes):
            with contextlib.suppress(OSError):
                os.close(descriptor)


Pair = tuple[CdpClient, Peer]


@pytest.fixture
def pair() -> Iterator[Pair]:
    commands_read, commands_write = os.pipe()
    replies_read, replies_write = os.pipe()
    client = CdpClient(reader_fd=replies_read, writer_fd=commands_write)
    peer = Peer(reads=commands_read, writes=replies_write)
    yield client, peer
    peer.close()
    client.close()


def call_in_thread(client: CdpClient, *args: Any, **kwargs: Any) -> tuple[threading.Thread, dict[str, Any]]:
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["result"] = client.call(*args, **kwargs)
        except Exception as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=target)
    thread.start()
    return thread, outcome


def test_a_command_is_one_compact_json_object_ending_in_a_nul_byte(pair: Pair) -> None:
    client, peer = pair
    thread, outcome = call_in_thread(client, "Storage.setCookies", {"cookies": []}, timeout=5)
    command = peer.next_command()
    assert peer.raw == b'{"id":1,"method":"Storage.setCookies","params":{"cookies":[]}}'
    assert command == {"id": 1, "method": "Storage.setCookies", "params": {"cookies": []}}
    peer.reply(command, {"ok": True})
    thread.join(5)
    assert outcome["result"] == {"ok": True}


def test_a_page_command_carries_the_flat_session_id_and_ids_are_not_reused(pair: Pair) -> None:
    client, peer = pair
    for expected_id in (1, 2):
        thread, _ = call_in_thread(
            client, "Runtime.evaluate", {"expression": "1"}, session_id="PAGE-SESSION", timeout=5
        )
        command = peer.next_command()
        assert command["sessionId"] == "PAGE-SESSION"
        assert command["id"] == expected_id
        peer.reply(command)
        thread.join(5)


def test_a_command_without_parameters_has_none(pair: Pair) -> None:
    client, peer = pair
    thread, _ = call_in_thread(client, "Target.getTargets", timeout=5)
    command = peer.next_command()
    assert "params" not in command
    assert "sessionId" not in command
    peer.reply(command)
    thread.join(5)


def test_a_reply_split_across_writes_is_reassembled(pair: Pair) -> None:
    client, peer = pair
    thread, outcome = call_in_thread(client, "Browser.getVersion", timeout=5)
    command = peer.next_command()
    payload = json.dumps({"id": command["id"], "result": {"product": "Chrome/1"}}).encode() + b"\0"
    for index in range(0, len(payload), 5):
        os.write(peer.writes, payload[index : index + 5])
        time.sleep(0.01)
    thread.join(5)
    assert outcome["result"] == {"product": "Chrome/1"}


def test_two_replies_in_one_write_are_both_delivered_whatever_the_order(pair: Pair) -> None:
    client, peer = pair
    first, first_outcome = call_in_thread(client, "A", timeout=5)
    command_a = peer.next_command()
    second, second_outcome = call_in_thread(client, "B", timeout=5)
    command_b = peer.next_command()
    both = (
        json.dumps({"id": command_b["id"], "result": {"n": "b"}})
        + "\0"
        + json.dumps({"id": command_a["id"], "result": {"n": "a"}})
    )
    os.write(peer.writes, both.encode() + b"\0")
    first.join(5)
    second.join(5)
    assert first_outcome["result"] == {"n": "a"}
    assert second_outcome["result"] == {"n": "b"}


def test_events_are_ignored_and_do_not_disturb_the_reply(pair: Pair) -> None:
    client, peer = pair
    thread, outcome = call_in_thread(client, "Page.navigate", {"url": "http://127.0.0.1:1/"}, timeout=5)
    command = peer.next_command()
    peer.send({"method": "Page.frameStartedLoading", "params": {"frameId": "F"}, "sessionId": "S"})
    peer.send({"method": "Target.targetCreated", "params": {}})
    peer.reply(command, {"frameId": "F"})
    thread.join(5)
    assert outcome["result"] == {"frameId": "F"}


def test_an_error_reply_raises_with_the_browsers_reason_and_never_the_parameters(pair: Pair) -> None:
    client, peer = pair
    secret = "SECRET-COOKIE-VALUE-0123456789"  # noqa: S105 - a test value, not a credential
    thread, outcome = call_in_thread(client, "Storage.setCookies", {"cookies": [{"value": secret}]}, timeout=5)
    command = peer.next_command()
    peer.send({"id": command["id"], "error": {"code": -32602, "message": "Invalid cookie fields"}})
    thread.join(5)
    error = outcome["error"]
    assert isinstance(error, CdpError)
    assert "Storage.setCookies" in str(error)
    assert "Invalid cookie fields" in str(error)
    assert secret not in str(error)


@pytest.mark.parametrize("error", [{"code": 1}, "text", 5, {"message": 7}])
def test_an_error_reply_of_an_unexpected_shape_still_raises(pair: Pair, error: object) -> None:
    client, peer = pair
    thread, outcome = call_in_thread(client, "X", timeout=5)
    command = peer.next_command()
    peer.send({"id": command["id"], "error": error})
    thread.join(5)
    assert isinstance(outcome["error"], CdpError)
    assert "no reason given" in str(outcome["error"])


def test_a_result_that_is_not_an_object_is_refused(pair: Pair) -> None:
    client, peer = pair
    thread, outcome = call_in_thread(client, "X", timeout=5)
    command = peer.next_command()
    peer.send({"id": command["id"], "result": [1, 2]})
    thread.join(5)
    assert isinstance(outcome["error"], CdpError)
    assert "not an object" in str(outcome["error"])


def test_a_silent_browser_times_out_within_the_bound_and_a_late_reply_does_no_harm(pair: Pair) -> None:
    client, peer = pair
    started = time.monotonic()
    with pytest.raises(CdpTimeout, match=r"no reply from the browser within 0\.4 s"):
        client.call("Browser.getVersion", timeout=0.4)
    assert 0.3 < time.monotonic() - started < 3
    late = peer.next_command()
    peer.reply(late)  # arrives after the caller gave up
    thread, outcome = call_in_thread(client, "Browser.getVersion", timeout=5)
    command = peer.next_command()
    peer.reply(command, {"fresh": True})
    thread.join(5)
    assert outcome["result"] == {"fresh": True}


def test_calls_from_several_threads_each_get_their_own_reply(pair: Pair) -> None:
    client, peer = pair
    threads = [call_in_thread(client, f"Method{n}", timeout=10) for n in range(8)]
    commands = [peer.next_command() for _ in range(8)]
    for command in reversed(commands):
        peer.reply(command, {"method": command["method"]})
    for thread, _ in threads:
        thread.join(10)
    assert sorted(outcome["result"]["method"] for _, outcome in threads) == sorted(f"Method{n}" for n in range(8))


def test_a_pipe_the_browser_closes_fails_a_waiting_call_and_every_later_one(pair: Pair) -> None:
    client, peer = pair
    thread, outcome = call_in_thread(client, "Browser.getVersion", timeout=10)
    peer.next_command()
    os.close(peer.writes)
    peer.writes = -1
    thread.join(5)
    assert isinstance(outcome["error"], CdpError)
    assert not isinstance(outcome["error"], CdpTimeout)
    assert "closed the DevTools pipe" in str(outcome["error"])
    assert client.closed
    with pytest.raises(CdpError, match="closed the DevTools pipe"):
        client.call("Again", timeout=1)


def test_writing_to_a_browser_that_stopped_reading_is_an_error_not_a_hang(pair: Pair) -> None:
    client, peer = pair
    os.close(peer.reads)
    peer.reads = -1
    with pytest.raises(CdpError, match="DevTools pipe to the browser is closed"):
        client.call("Browser.getVersion", timeout=5)


@pytest.mark.parametrize("garbage", [b"not json", b"{broken", b"\xff\xfe", b"[1,2]", b'"text"', b"123", b"null"])
def test_a_message_that_is_not_a_protocol_object_closes_the_client(pair: Pair, garbage: bytes) -> None:
    client, peer = pair
    thread, outcome = call_in_thread(client, "Browser.getVersion", timeout=10)
    peer.next_command()
    peer.send(garbage)
    thread.join(5)
    assert isinstance(outcome["error"], CdpError)
    assert "DevTools message" in str(outcome["error"])
    assert client.closed


def test_an_oversized_message_without_a_terminator_closes_the_client(
    pair: Pair, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cdp, "MAX_MESSAGE_BYTES", 1000)
    client, peer = pair
    thread, outcome = call_in_thread(client, "Browser.getVersion", timeout=10)
    peer.next_command()
    os.write(peer.writes, b"a" * 5000)
    thread.join(5)
    assert isinstance(outcome["error"], CdpError)
    assert "oversized" in str(outcome["error"])


def test_a_closed_client_refuses_further_commands_and_closing_twice_is_harmless(pair: Pair) -> None:
    client, _ = pair
    client.close()
    client.close()
    with pytest.raises(CdpError):
        client.call("Browser.getVersion", timeout=1)


def test_closing_ends_the_input_the_browser_reads_so_it_knows_to_exit(pair: Pair) -> None:
    client, peer = pair
    client.close()
    assert os.read(peer.reads, 10) == b"", "the browser should see end of input"


def test_a_reply_nobody_waits_for_is_dropped_not_kept(pair: Pair) -> None:
    client, peer = pair
    peer.send({"id": 2, "result": {"stale": True}})  # the id the next call will get, sent before it is made
    time.sleep(0.2)
    thread, outcome = call_in_thread(client, "Browser.getVersion", timeout=1)
    peer.next_command()  # the real command arrives; the early reply must not have answered it
    thread.join(5)
    assert isinstance(outcome["error"], CdpTimeout)
    assert client._replies == {}
