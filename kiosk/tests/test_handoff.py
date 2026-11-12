"""The backend side of the handoff against a real HTTP server: what is read, what is sent, what is accepted back."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import pytest

from kiosk.errors import KioskError
from kiosk.handoff import MAX_FILE_BYTES, Endpoint, Session, mint_session, parse_endpoint, wait_for_handoff
from kiosk.tests.fake_backend import TOKEN, FakeBackend


# ------------------------------------------------------------------------------------------ the endpoint file
@pytest.mark.parametrize(
    ("text", "origin"),
    [
        ("http://127.0.0.1:8765", "http://127.0.0.1:8765"),
        ("http://127.0.0.1:8765/", "http://127.0.0.1:8765"),
        ("  http://127.0.0.1:8765\n", "http://127.0.0.1:8765"),
        ("http://127.1.2.3:1024", "http://127.1.2.3:1024"),
        ("http://[::1]:8765", "http://[::1]:8765"),
        ("http://[0:0:0:0:0:0:0:1]:8765", "http://[::1]:8765"),
    ],
)
def test_a_plain_loopback_origin_is_accepted(text: str, origin: str) -> None:
    endpoint = parse_endpoint(text)
    assert endpoint.origin == origin
    assert endpoint.cookie_url == origin + "/"
    assert endpoint.session_url == origin + "/v1/session"


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "127.0.0.1:8765",
        "https://127.0.0.1:8765",
        "ftp://127.0.0.1:8765",
        "http://127.0.0.1",  # no port
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:port",
        "http://localhost:8765",  # a name resolves outside this check
        "http://0.0.0.0:8765",
        "http://192.168.1.10:8765",
        "http://8.8.8.8:8765",
        "http://[::]:8765",
        "http://[2001:db8::1]:8765",
        "http://[::ffff:127.0.0.1]:8765",  # mapped form: the backend refuses it too
        "http://[::1%25lo]:8765",
        "http://user:pass@127.0.0.1:8765",
        "http://127.0.0.1:8765@evil.example:80",
        "http://evil.example:80@127.0.0.1:8765/",
        "http://127.0.0.1:8765/path",
        "http://127.0.0.1:8765/?a=1",
        "http://127.0.0.1:8765?a=1",
        "http://127.0.0.1:8765/#frag",
        "http://127.0.0.1:8765#",
        "http://127.0.0.1:8765\nhttp://evil.example",
    ],
)
def test_anything_but_a_plain_loopback_origin_is_refused(text: str) -> None:
    # The token is sent to this address, so a doubtful endpoint is a failure, never something to repair.
    with pytest.raises(KioskError):
        parse_endpoint(text)


# ------------------------------------------------------------------------------------------ the published files
def write_files(directory: Path, endpoint: str = "http://127.0.0.1:8765", token: str = TOKEN) -> tuple[Path, Path]:
    endpoint_file, token_file = directory / "endpoint", directory / "token"
    endpoint_file.write_bytes(endpoint.encode("utf-8"))
    token_file.write_bytes(token.encode("utf-8"))  # bytes: a test may write what is not ASCII
    return endpoint_file, token_file


def test_both_files_are_read(tmp_path: Path) -> None:
    endpoint, token = wait_for_handoff(*write_files(tmp_path), timeout=1)
    assert endpoint == Endpoint("http://127.0.0.1:8765")
    assert token == TOKEN


def test_whitespace_around_the_token_is_not_part_of_it(tmp_path: Path) -> None:
    files = write_files(tmp_path, token=f"\n  {TOKEN}\r\n")
    assert wait_for_handoff(*files, timeout=1)[1] == TOKEN


def test_it_waits_for_files_the_backend_has_not_published_yet(tmp_path: Path) -> None:
    endpoint_file, token_file = tmp_path / "endpoint", tmp_path / "token"

    def publish_later() -> None:
        time.sleep(0.4)
        endpoint_file.write_text("http://127.0.0.1:8765", encoding="ascii")
        time.sleep(0.4)
        token_file.write_text(TOKEN, encoding="ascii")

    thread = threading.Thread(target=publish_later)
    thread.start()
    started = time.monotonic()
    _, token = wait_for_handoff(endpoint_file, token_file, timeout=10)
    thread.join()
    assert token == TOKEN
    assert 0.7 < time.monotonic() - started < 5


def test_the_wait_is_bounded_and_names_the_file_that_never_appeared_and_nothing_else(tmp_path: Path) -> None:
    endpoint_file, token_file = write_files(tmp_path)
    token_file.unlink()
    started = time.monotonic()
    with pytest.raises(KioskError) as caught:
        wait_for_handoff(endpoint_file, token_file, timeout=0.6)
    assert 0.5 < time.monotonic() - started < 5
    assert str(token_file) in str(caught.value)
    assert str(endpoint_file) not in str(caught.value)
    assert "0.6 s" in str(caught.value)


@pytest.mark.parametrize(
    "token", ["", "   \n", "short", "has a space in it 0123456789", "päss-0123456789abcdef", "a" * 513]
)
def test_a_token_of_the_wrong_form_fails_at_once_and_is_never_quoted(tmp_path: Path, token: str) -> None:
    files = write_files(tmp_path, token=token)
    started = time.monotonic()
    with pytest.raises(KioskError) as caught:
        wait_for_handoff(*files, timeout=30)
    assert time.monotonic() - started < 5, "a malformed file will not fix itself: waiting is pointless"
    assert token.strip() == "" or token.strip() not in str(caught.value)


def test_a_malformed_endpoint_fails_at_once(tmp_path: Path) -> None:
    files = write_files(tmp_path, endpoint="http://evil.example:8765")
    with pytest.raises(KioskError, match="loopback"):
        wait_for_handoff(*files, timeout=30)


def test_a_file_that_is_not_ascii_text_fails_at_once(tmp_path: Path) -> None:
    endpoint_file, token_file = write_files(tmp_path)
    token_file.write_bytes(b"\xff\xfe" + TOKEN.encode())
    with pytest.raises(KioskError, match="not ASCII"):
        wait_for_handoff(endpoint_file, token_file, timeout=30)


def test_a_file_that_is_far_too_large_fails_at_once(tmp_path: Path) -> None:
    endpoint_file, token_file = write_files(tmp_path)
    token_file.write_text("a" * (MAX_FILE_BYTES + 1), encoding="ascii")
    with pytest.raises(KioskError, match="larger than"):
        wait_for_handoff(endpoint_file, token_file, timeout=30)


def test_a_file_that_cannot_be_read_fails_at_once_naming_the_path(tmp_path: Path) -> None:
    endpoint_file, token_file = write_files(tmp_path)
    token_file.unlink()
    token_file.mkdir()  # reading a directory fails the way a permission problem does: with an OSError
    with pytest.raises(KioskError, match="cannot read the token file"):
        wait_for_handoff(endpoint_file, token_file, timeout=30)


# ------------------------------------------------------------------------------------------ minting a session
def mint(backend: FakeBackend, *, retry_for: float = 0.0, timeout: float = 5.0) -> Session:
    return mint_session(Endpoint(backend.origin), backend.token, timeout=timeout, retry_for=retry_for)


def test_one_post_carries_the_token_in_the_authorization_header_and_nowhere_else(backend: FakeBackend) -> None:
    session = mint(backend)

    assert len(backend.requests) == 1
    request = backend.requests[0]
    assert (request.method, request.path) == ("POST", "/v1/session")
    assert request.headers["authorization"] == f"Bearer {backend.token}"
    assert request.body == b""
    assert "cookie" not in request.headers
    assert request.headers["host"] == backend.origin.removeprefix("http://")
    # the secret is in exactly one header value, not in the URL, the other headers or the body
    elsewhere = [request.path, request.body.decode(), *(v for k, v in request.headers.items() if k != "authorization")]
    assert all(backend.token not in part for part in elsewhere)
    assert session.session_id == backend.issued[0]


def test_the_session_carries_an_expiry_derived_from_what_the_backend_said(backend: FakeBackend) -> None:
    backend.ttl = 7200
    before = time.time()
    session = mint(backend)
    after = time.time()
    assert session.expires_in == 7200
    assert before + 7200 <= session.expires_at <= after + 7200


def test_the_session_id_is_not_part_of_its_repr(backend: FakeBackend) -> None:
    session = mint(backend)
    assert session.session_id not in repr(session)
    assert session.session_id not in f"{session}"


def test_the_environments_proxy_settings_never_see_the_token(
    backend: FakeBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    with socket.socket() as sink:  # a "proxy" that would receive the request if it were used
        sink.bind(("127.0.0.1", 0))
        sink.listen(1)
        proxy = f"http://127.0.0.1:{sink.getsockname()[1]}"
        for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
            monkeypatch.setenv(name, proxy)
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.delenv("NO_PROXY", raising=False)
        session = mint(backend, timeout=3)
    assert session.session_id == backend.issued[0]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_never_followed_so_the_token_cannot_be_forwarded(backend: FakeBackend, status: int) -> None:
    # urllib's own handler resends a POST as a GET, with its headers, after 301, 302 and 303: the token would travel on.
    with FakeBackend() as elsewhere:
        backend.redirect_to = f"{elsewhere.origin}/v1/session"
        backend.redirect_status = status
        with pytest.raises(KioskError, match=f"HTTP {status}"):
            mint(backend)
        assert elsewhere.requests == []
    assert len(backend.requests) == 1


def test_a_refused_token_is_reported_without_quoting_it(backend: FakeBackend) -> None:
    backend.token = "another-token-0123456789"  # noqa: S105 - a test value, not a credential
    with pytest.raises(KioskError) as caught:
        mint_session(Endpoint(backend.origin), TOKEN, timeout=5, retry_for=0)
    assert "HTTP 401" in str(caught.value)
    assert TOKEN not in str(caught.value)


def test_a_backend_without_the_endpoint_is_reported(backend: FakeBackend) -> None:
    backend.mint_status = 404
    backend.mint_body = b"{}"
    with pytest.raises(KioskError, match=r"no /v1/session endpoint \(HTTP 404\)"):
        mint(backend)


@pytest.mark.parametrize("status", [200, 202, 204])
def test_any_success_status_but_201_is_refused(backend: FakeBackend, status: int) -> None:
    backend.mint_status = status
    backend.mint_body = b'{"session_id":"abcdefghijklmnop","expires_in":60}'
    with pytest.raises(KioskError, match=f"HTTP {status}, expected 201"):
        mint(backend)


@pytest.mark.parametrize(
    ("body", "complaint"),
    [
        (b"", "not JSON"),
        (b"not json at all", "not JSON"),
        (b"\xff\xfe\x00", "not JSON"),
        (b"[]", "not a JSON object"),
        (b'"text"', "not a JSON object"),
        (b"{}", "session_id"),
        (b'{"expires_in": 60}', "session_id"),
        (b'{"session_id": 12345678, "expires_in": 60}', "session_id"),
        (b'{"session_id": "short", "expires_in": 60}', "session_id"),
        (b'{"session_id": "has a space in it", "expires_in": 60}', "session_id"),
        (b'{"session_id": "semi;colon-0123456789", "expires_in": 60}', "session_id"),
        (b'{"session_id": "abcdefghijklmnop"}', "expires_in"),
        (b'{"session_id": "abcdefghijklmnop", "expires_in": "60"}', "expires_in"),
        (b'{"session_id": "abcdefghijklmnop", "expires_in": true}', "expires_in"),
        (b'{"session_id": "abcdefghijklmnop", "expires_in": null}', "expires_in"),
        (b'{"session_id": "abcdefghijklmnop", "expires_in": 0}', "expires_in"),
        (b'{"session_id": "abcdefghijklmnop", "expires_in": -5}', "expires_in"),
        (b'{"session_id": "abcdefghijklmnop", "expires_in": NaN}', "expires_in"),
        (b'{"session_id": "abcdefghijklmnop", "expires_in": Infinity}', "expires_in"),
        (b'{"session_id": "abcdefghijklmnop", "expires_in": 1e12}', "expires_in"),
    ],
)
def test_a_reply_that_is_not_exactly_the_documented_shape_is_refused(
    backend: FakeBackend, body: bytes, complaint: str
) -> None:
    backend.mint_body = body
    with pytest.raises(KioskError, match=complaint):
        mint(backend)


def test_an_unreasonably_large_reply_is_refused(backend: FakeBackend) -> None:
    backend.mint_body = b'{"session_id": "' + b"a" * 200_000 + b'", "expires_in": 60}'
    with pytest.raises(KioskError, match="unreasonably large"):
        mint(backend)


def test_a_server_error_is_final_and_not_retried(backend: FakeBackend) -> None:
    backend.fail_mint_from = 1
    with pytest.raises(KioskError, match="HTTP 500"):
        mint(backend, retry_for=5)
    assert len(backend.requests) == 1


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_a_backend_that_is_not_listening_is_reported_after_the_bound(backend: FakeBackend) -> None:
    started = time.monotonic()
    with pytest.raises(KioskError, match="cannot reach the backend") as caught:
        mint_session(Endpoint(f"http://127.0.0.1:{free_port()}"), TOKEN, timeout=2, retry_for=0.7)
    assert 0.6 < time.monotonic() - started < 6
    assert TOKEN not in str(caught.value)


def test_a_backend_that_starts_late_is_found_by_the_retries() -> None:
    port = free_port()
    late = FakeBackend()
    threading.Timer(0.8, late.start, args=(port,)).start()
    try:
        session = mint_session(Endpoint(f"http://127.0.0.1:{port}"), late.token, timeout=2, retry_for=10)
        assert session.session_id == late.issued[0]
    finally:
        time.sleep(0.1)
        late.stop()


def test_a_backend_that_accepts_but_never_answers_times_out(backend: FakeBackend) -> None:
    backend.mint_delay = 3
    started = time.monotonic()
    with pytest.raises(KioskError, match="cannot reach the backend"):
        mint(backend, timeout=0.5)
    assert time.monotonic() - started < 2.5
