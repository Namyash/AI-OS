"""POST/DELETE /v1/session, and what the guard does with the ``pai_session`` cookie they produce."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.api import sessions as sessions_module
from backend.api.app import create_app
from backend.api.errors import install_error_handlers
from backend.api.sessions import MAX_SESSIONS, SessionStore, session_router
from backend.core.config import DEFAULT_SESSION_TTL, Settings
from backend.core.logging import configure_logging
from backend.tests.api.support import PORT, client_for

ORIGIN = f"http://127.0.0.1:{PORT}"
UNAUTHORIZED = {"error": {"code": "unauthorized", "message": "Authentication required"}}
FORBIDDEN_ORIGIN = {"error": {"code": "forbidden_origin", "message": "Cross-origin requests are not allowed"}}
STATE_CHANGING_METHODS = ["POST", "PUT", "PATCH", "DELETE"]
SAFE_METHODS = ["GET", "HEAD", "OPTIONS"]

Mint = Callable[[], str]


def cookie(session_id: str, name: str = "pai_session") -> dict[str, str]:
    return {"Cookie": f"{name}={session_id}"}


@pytest.fixture
def mint(client: TestClient, auth: dict[str, str]) -> Mint:
    def _mint() -> str:
        response = client.post("/v1/session", headers=auth)
        assert response.status_code == 201
        return str(response.json()["session_id"])

    return _mint


@pytest.fixture
def session_id(mint: Mint) -> str:
    return mint()


@pytest.fixture
def echo(app: FastAPI, client: TestClient) -> None:
    """A route that accepts every method, to exercise the guard's rule for requests that could change state."""
    methods = [*SAFE_METHODS, *STATE_CHANGING_METHODS]
    app.add_api_route("/_test/echo", lambda: {"ok": True}, methods=methods, include_in_schema=False)


class Clock:
    def __init__(self) -> None:
        self.now = 5000.0


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(sessions_module, "monotonic", lambda: fake.now)
    return fake


# ------------------------------------------------------------------ POST /v1/session
def test_the_token_mints_a_session(client: TestClient, auth: dict[str, str]) -> None:
    response = client.post("/v1/session", headers=auth)
    assert response.status_code == 201
    body = response.json()
    assert sorted(body) == ["expires_in", "session_id"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", body["session_id"])  # 256 random bits
    assert body["expires_in"] == DEFAULT_SESSION_TTL == 12 * 60 * 60


def test_the_response_that_carries_the_id_is_not_cacheable_and_sets_no_cookie(
    client: TestClient, auth: dict[str, str]
) -> None:
    response = client.post("/v1/session", headers=auth)
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers  # the launcher installs the cookie; the server never sets one


def test_expires_in_is_the_configured_lifetime(settings: Settings) -> None:
    with client_for(create_app(settings.model_copy(update={"session_ttl": 120}))) as short_lived:
        token = settings.token_file.read_text(encoding="ascii")
        response = short_lived.post("/v1/session", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["expires_in"] == 120


def test_each_call_mints_a_different_session(mint: Mint) -> None:
    assert len({mint() for _ in range(5)}) == 5


def test_minting_without_credentials_is_refused(client: TestClient) -> None:
    response = client.post("/v1/session")
    assert (response.status_code, response.json()) == (401, UNAUTHORIZED)
    assert response.headers["www-authenticate"] == "Bearer"


def test_minting_with_a_wrong_token_is_refused(client: TestClient) -> None:
    assert client.post("/v1/session", headers={"Authorization": "Bearer wrong-token-value"}).status_code == 401


def test_a_session_cookie_cannot_mint_a_session(client: TestClient, session_id: str) -> None:
    # Even from the right origin, with a live session: the browser holds a cookie, never the means to make more.
    response = client.post("/v1/session", headers={**cookie(session_id), "Origin": ORIGIN})
    assert (response.status_code, response.json()) == (401, UNAUTHORIZED)
    assert response.headers["www-authenticate"] == "Bearer"


def test_a_session_cookie_without_an_origin_cannot_mint_one_either(client: TestClient, session_id: str) -> None:
    response = client.post("/v1/session", headers=cookie(session_id))
    assert (response.status_code, response.json()) == (403, FORBIDDEN_ORIGIN)


def test_a_wrong_token_with_a_valid_cookie_cannot_mint_a_session(client: TestClient, session_id: str) -> None:
    headers = {**cookie(session_id), "Authorization": "Bearer wrong-token-value", "Origin": ORIGIN}
    assert client.post("/v1/session", headers=headers).status_code == 401


def test_the_token_wins_when_a_cookie_comes_with_it(client: TestClient, auth: dict[str, str], session_id: str) -> None:
    assert client.post("/v1/session", headers={**auth, **cookie(session_id)}).status_code == 201


def test_a_rejected_mint_is_logged_by_reason_only(
    client: TestClient, session_id: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    client.post("/v1/session", headers={**cookie(session_id), "Origin": ORIGIN})
    rejections = [r for r in caplog.records if r.getMessage() == "request rejected"]
    assert [r.reason for r in rejections] == ["unauthorized"]  # type: ignore[attr-defined]


def test_the_session_routes_refuse_a_request_the_guard_did_not_authenticate() -> None:
    # Fail closed: without the guard's verdict in the request, the routes assume nothing about who is calling.
    store = SessionStore(60)
    unguarded = FastAPI()
    install_error_handlers(unguarded)
    unguarded.include_router(session_router(store))
    plain = TestClient(unguarded, base_url=f"http://127.0.0.1:{PORT}", raise_server_exceptions=False)
    assert plain.post("/v1/session").status_code == 401
    assert plain.delete("/v1/session").status_code == 401
    assert len(store) == 0


def test_the_session_endpoints_are_in_the_api_document(client: TestClient, auth: dict[str, str]) -> None:
    operations = client.get("/openapi.json", headers=auth).json()["paths"]["/v1/session"]
    assert sorted(operations) == ["delete", "post"]


# ------------------------------------------------------------------ authenticating with the cookie
def test_a_valid_cookie_authenticates(client: TestClient, session_id: str) -> None:
    response = client.get("/health", headers=cookie(session_id))
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize(
    "authorization",
    ["Bearer wrong-token-value", "Bearer ", "Bearer", "Basic dXNlcjpwYXNz", "wrong-token-value", ""],
)
def test_a_wrong_or_malformed_token_fails_even_with_a_valid_cookie(
    client: TestClient, session_id: str, authorization: str
) -> None:
    response = client.get("/health", headers={**cookie(session_id), "Authorization": authorization})
    assert (response.status_code, response.json()) == (401, UNAUTHORIZED)


def test_repeated_authorization_headers_fail_even_with_a_valid_cookie(client: TestClient, session_id: str) -> None:
    headers = [
        ("Authorization", "Bearer one"),
        ("Authorization", "Bearer two"),
        ("Cookie", f"pai_session={session_id}"),
    ]
    assert client.get("/health", headers=headers).status_code == 401


def test_a_valid_token_is_enough_whatever_the_cookie_says(client: TestClient, auth: dict[str, str]) -> None:
    for junk in ("pai_session=not-a-session", "pai_session=", ";;;", "pai_session=a; pai_session=b"):
        assert client.get("/health", headers={**auth, "Cookie": junk}).status_code == 200


@pytest.mark.parametrize(
    "header",
    [
        "",
        "pai_session=",
        "pai_session",
        "pai_session=not-a-session",
        "other={id}",
        "PAI_SESSION={id}",
        "Pai_Session={id}",
        "pai_session={id}x",
        "pai_session=x{id}",
        'pai_session="{id}"',
        "pai_session=%20{id}",
        ";;;",
        "=",
        "={id}",
        "pai_session={id}; pai_session={id}",
        "pai_session={id}; pai_session=other",
        "pai_session=other; pai_session={id}",
        "xpai_session={id}",
    ],
)
def test_cookies_that_are_not_exactly_one_valid_session_do_not_authenticate(
    client: TestClient, session_id: str, header: str
) -> None:
    response = client.get("/health", headers={"Cookie": header.format(id=session_id)})
    assert (response.status_code, response.json()) == (401, UNAUTHORIZED)


@pytest.mark.parametrize(
    "header",
    [
        "pai_session={id}",
        "a=1; pai_session={id}; b=2",
        "pai_session={id};a=1",
        "  pai_session={id}  ",
        "junk; ;pai_session={id};;",
        "x==y; pai_session={id}",
        "other=pai_session={id}; pai_session={id}",
    ],
)
def test_the_session_cookie_is_found_among_other_cookies_and_junk(
    client: TestClient, session_id: str, header: str
) -> None:
    assert client.get("/health", headers={"Cookie": header.format(id=session_id)}).status_code == 200


def test_the_cookie_may_come_in_a_header_of_its_own(client: TestClient, session_id: str) -> None:
    headers = [("Cookie", "a=1"), ("Cookie", f"pai_session={session_id}")]
    assert client.get("/health", headers=headers).status_code == 200


def test_the_cookie_in_two_headers_is_ambiguous_and_refused(client: TestClient, session_id: str) -> None:
    headers = [("Cookie", f"pai_session={session_id}"), ("Cookie", f"pai_session={session_id}")]
    assert client.get("/health", headers=headers).status_code == 401


@pytest.mark.parametrize("size", [64 * 1024, 1024 * 1024])
def test_a_huge_cookie_header_is_refused_without_an_error(client: TestClient, session_id: str, size: int) -> None:
    padding = "x" * size
    for header in (f"pai_session={session_id}; pad={padding}", f"pai_session={padding}", padding):
        assert client.get("/health", headers={"Cookie": header}).status_code == 401
    # Another header cannot be used to hide an oversized one.
    headers = [("Cookie", f"pai_session={session_id}"), ("Cookie", f"pad={padding}")]
    assert client.get("/health", headers=headers).status_code == 401


def test_a_cookie_header_of_ordinary_size_with_many_cookies_still_works(client: TestClient, session_id: str) -> None:
    crowd = "; ".join(f"c{n}={'v' * 40}" for n in range(60))
    assert client.get("/health", headers={"Cookie": f"{crowd}; pai_session={session_id}"}).status_code == 200


def test_host_is_checked_before_the_cookie(client: TestClient, session_id: str) -> None:
    response = client.get("/health", headers={**cookie(session_id), "Host": "evil.example"})
    assert response.status_code == 400


def test_origin_is_checked_before_the_cookie(client: TestClient, session_id: str) -> None:
    response = client.get("/health", headers={**cookie(session_id), "Origin": "http://evil.example"})
    assert (response.status_code, response.json()) == (403, FORBIDDEN_ORIGIN)


def test_a_bad_cookie_is_logged_by_reason_only(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    client.get("/health", headers=cookie("forged-cookie-sentinel-1"))
    rejections = [r for r in caplog.records if r.name == "backend.api.security"]
    assert [r.reason for r in rejections] == ["unauthorized"]  # type: ignore[attr-defined]
    assert "sentinel-1" not in " ".join(
        f"{r.getMessage()} {r.__dict__}" for r in caplog.records if r.name.startswith("backend")
    )


# ------------------------------------------------------------------ requests that could change state
@pytest.mark.parametrize("method", STATE_CHANGING_METHODS)
def test_a_cookie_request_that_could_change_state_needs_an_origin(
    echo: None, client: TestClient, session_id: str, method: str
) -> None:
    response = client.request(method, "/_test/echo", headers=cookie(session_id))
    assert (response.status_code, response.json()) == (403, FORBIDDEN_ORIGIN)


@pytest.mark.parametrize("method", STATE_CHANGING_METHODS)
def test_and_is_served_when_the_origin_is_its_own(echo: None, client: TestClient, session_id: str, method: str) -> None:
    assert client.request(method, "/_test/echo", headers={**cookie(session_id), "Origin": ORIGIN}).status_code == 200


@pytest.mark.parametrize(
    "origin", ["http://evil.example", "null", f"http://localhost:{PORT}", f"https://127.0.0.1:{PORT}"]
)
def test_a_cookie_request_from_another_origin_is_refused(
    echo: None, client: TestClient, session_id: str, origin: str
) -> None:
    for method in ("GET", "POST"):
        response = client.request(method, "/_test/echo", headers={**cookie(session_id), "Origin": origin})
        assert (response.status_code, response.json()) == (403, FORBIDDEN_ORIGIN)


@pytest.mark.parametrize("method", SAFE_METHODS)
def test_a_cookie_request_that_cannot_change_state_needs_no_origin(
    echo: None, client: TestClient, session_id: str, method: str
) -> None:
    assert client.request(method, "/_test/echo", headers=cookie(session_id)).status_code == 200


def test_an_unknown_method_is_treated_as_one_that_could_change_state(client: TestClient, session_id: str) -> None:
    assert client.request("PURGE", "/health", headers=cookie(session_id)).status_code == 403


@pytest.mark.parametrize("method", STATE_CHANGING_METHODS)
def test_the_token_needs_no_origin_for_any_method(
    echo: None, client: TestClient, auth: dict[str, str], method: str
) -> None:
    assert client.request(method, "/_test/echo", headers=auth).status_code == 200


def test_a_websocket_with_only_a_cookie_must_name_its_origin(
    client: TestClient, session_id: str, caplog: pytest.LogCaptureFixture
) -> None:
    # The test client's WebSocket default Host is not a loopback name, so the right one is given explicitly.
    headers = {**cookie(session_id), "host": f"127.0.0.1:{PORT}"}
    with pytest.raises(WebSocketDisconnect) as refused, client.websocket_connect("/anything", headers=headers):
        pass
    assert refused.value.code == 1008
    assert [r.reason for r in caplog.records if r.name == "backend.api.security"] == ["forbidden_origin"]  # type: ignore[attr-defined]

    with (
        pytest.raises(WebSocketDisconnect) as passed,
        client.websocket_connect("/anything", headers={**headers, "origin": ORIGIN}),
    ):
        pass
    assert passed.value.code != 1008  # the guard let it through; there is simply no such socket


# ------------------------------------------------------------------ lifetime
def test_a_session_stops_working_when_it_expires(client: TestClient, clock: Clock, session_id: str) -> None:
    # `clock` comes first: the session's deadline must be computed on the fake clock.
    assert client.get("/health", headers=cookie(session_id)).status_code == 200
    clock.now += DEFAULT_SESSION_TTL - 1
    assert client.get("/health", headers=cookie(session_id)).status_code == 200
    clock.now += 1
    assert client.get("/health", headers=cookie(session_id)).status_code == 401


def test_the_oldest_session_is_evicted_by_the_ninth(client: TestClient, mint: Mint) -> None:
    ids = [mint() for _ in range(MAX_SESSIONS + 1)]
    statuses = [client.get("/health", headers=cookie(session_id)).status_code for session_id in ids]
    assert statuses == [401, *[200] * MAX_SESSIONS]


def test_a_restart_ends_every_session(settings: Settings, start_app: Callable[..., object]) -> None:
    with start_app() as first:  # type: ignore[attr-defined]
        token = settings.token_file.read_text(encoding="ascii")
        minted = first.post("/v1/session", headers={"Authorization": f"Bearer {token}"}).json()["session_id"]
        assert first.get("/health", headers=cookie(minted)).status_code == 200
    with start_app() as second:  # type: ignore[attr-defined]
        assert second.get("/health", headers=cookie(minted)).status_code == 401


# ------------------------------------------------------------------ DELETE /v1/session
def test_a_session_revokes_itself(client: TestClient, mint: Mint) -> None:
    mine, other = mint(), mint()
    response = client.delete("/v1/session", headers={**cookie(mine), "Origin": ORIGIN})
    assert (response.status_code, response.content) == (204, b"")
    assert client.get("/health", headers=cookie(mine)).status_code == 401
    assert client.get("/health", headers=cookie(other)).status_code == 200  # only the caller's own session went


def test_revoking_a_session_that_is_already_gone_is_refused(client: TestClient, session_id: str) -> None:
    headers = {**cookie(session_id), "Origin": ORIGIN}
    assert client.delete("/v1/session", headers=headers).status_code == 204
    assert client.delete("/v1/session", headers=headers).status_code == 401


def test_revoking_by_cookie_needs_an_origin(client: TestClient, session_id: str) -> None:
    response = client.delete("/v1/session", headers=cookie(session_id))
    assert (response.status_code, response.json()) == (403, FORBIDDEN_ORIGIN)
    assert client.get("/health", headers=cookie(session_id)).status_code == 200  # still alive


def test_revoking_without_credentials_is_refused(client: TestClient) -> None:
    assert client.delete("/v1/session").status_code == 401


def test_the_token_has_no_session_so_nothing_is_revoked(client: TestClient, auth: dict[str, str], mint: Mint) -> None:
    live = mint()
    assert client.delete("/v1/session", headers=auth).status_code == 204
    assert client.delete("/v1/session", headers={**auth, **cookie(live)}).status_code == 204  # the token wins
    assert client.get("/health", headers=cookie(live)).status_code == 200


def test_revocation_sets_no_cookie(client: TestClient, session_id: str) -> None:
    response = client.delete("/v1/session", headers={**cookie(session_id), "Origin": ORIGIN})
    assert "set-cookie" not in response.headers


# ------------------------------------------------------------------ the id and the cookie never leak
def test_the_id_appears_in_no_response_but_the_one_that_mints_it(
    echo: None, client: TestClient, auth: dict[str, str]
) -> None:
    minted = client.post("/v1/session", headers=auth)
    secret = minted.json()["session_id"]
    assert secret in minted.text

    responses = [
        client.get("/health", headers=cookie(secret)),
        client.get("/openapi.json", headers=cookie(secret)),
        client.get("/does-not-exist", headers=cookie(secret)),
        client.get("/health", headers={**cookie(secret), "Origin": "http://evil.example"}),
        client.get("/health", headers={**cookie(secret), "Host": "evil.example"}),
        client.get("/health", headers={**cookie(secret), "Authorization": "Bearer wrong"}),
        client.post("/health", headers={**cookie(secret), "Origin": ORIGIN}),
        client.post("/_test/echo", headers=cookie(secret)),
        client.post("/v1/session", headers={**cookie(secret), "Origin": ORIGIN}),
        client.get("/v1/session", headers={**cookie(secret), "Origin": ORIGIN}),
        client.delete("/v1/session", headers={**cookie(secret), "Origin": ORIGIN}),
        client.get("/health", headers=cookie(secret)),  # after revocation
    ]
    assert [r.status_code for r in responses][-1] == 401
    for response in responses:
        assert secret not in response.text
        assert secret not in str(response.headers)


@pytest.fixture
def root_logging_restored() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


def test_the_id_and_the_cookie_are_in_no_log_line(
    echo: None,
    client: TestClient,
    auth: dict[str, str],
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    root_logging_restored: None,
) -> None:
    configure_logging("debug")  # the real handler: redaction included, writing to the captured stdout
    caplog.set_level(logging.DEBUG)
    capsys.readouterr()

    secret = client.post("/v1/session", headers=auth).json()["session_id"]
    forged = "forged-cookie-sentinel-2"
    for headers in (
        cookie(secret),
        cookie(forged),
        {**cookie(secret), "Origin": "http://evil.example"},
        {**cookie(secret), "Authorization": "Bearer wrong"},
    ):
        client.get("/health", headers=headers)
    client.post("/_test/echo", headers=cookie(secret))  # refused: no Origin
    client.post("/v1/session", headers={**cookie(secret), "Origin": ORIGIN})  # refused: a cookie cannot mint
    client.get("/does-not-exist", headers=cookie(secret))
    client.delete("/v1/session", headers={**cookie(secret), "Origin": ORIGIN})

    written = capsys.readouterr().out
    raw = " ".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records if r.name.startswith("backend"))
    for sentinel in (secret, forged):
        assert sentinel not in written
        assert sentinel not in raw
    assert "request rejected" in written  # the requests above did log; the check is not vacuous


def test_a_session_id_that_is_logged_by_mistake_is_masked(
    client: TestClient, auth: dict[str, str], capsys: pytest.CaptureFixture[str], root_logging_restored: None
) -> None:
    secret = client.post("/v1/session", headers=auth).json()["session_id"]
    configure_logging("info")
    capsys.readouterr()
    logging.getLogger("backend.test").info("handling %s and pai_session=%s", secret, "some-other-cookie-value")
    written = capsys.readouterr().out
    assert secret not in written
    assert "some-other-cookie-value" not in written
