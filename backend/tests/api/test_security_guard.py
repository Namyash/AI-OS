"""The boundary guard: Host allowlist, Origin check, then bearer authentication, in that order, on every route."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.api.app import create_app
from backend.core.config import load_settings
from backend.tests.api.support import PORT, client_for

UNAUTHORIZED_BODY = {"error": {"code": "unauthorized", "message": "Authentication required"}}
# Every path the app can answer, plus ones it cannot: the guard must not reveal which exist.
ALL_PATHS = ["/health", "/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect", "/nonexistent", "/"]


# ------------------------------------------------------------------ authentication
@pytest.mark.parametrize("path", ALL_PATHS)
def test_every_path_requires_a_token(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 401
    assert response.json() == UNAUTHORIZED_BODY
    assert response.headers["www-authenticate"] == "Bearer"


def test_valid_token_is_accepted(client: TestClient, auth: dict[str, str]) -> None:
    assert client.get("/health", headers=auth).status_code == 200


def test_scheme_is_case_insensitive(client: TestClient, token: str) -> None:
    assert client.get("/health", headers={"Authorization": f"bearer {token}"}).status_code == 200


@pytest.mark.parametrize(
    "header",
    [
        "Bearer wrong-token-value",
        "Bearer ",
        "Bearer",
        "Basic dXNlcjpwYXNz",
        "wrong-token-value",
        "Bearer wrong-token-value extra",
        "Bearer éè",
    ],
)
def test_wrong_or_malformed_credentials_get_the_same_uniform_response(client: TestClient, header: str) -> None:
    response = client.get("/health", headers={"Authorization": header.encode("latin-1")})
    assert response.status_code == 401
    assert response.json() == UNAUTHORIZED_BODY
    assert response.headers["www-authenticate"] == "Bearer"


def test_bare_token_without_scheme_is_refused(client: TestClient, token: str) -> None:
    assert client.get("/health", headers={"Authorization": token}).status_code == 401


def test_token_as_a_query_parameter_is_refused(client: TestClient, token: str) -> None:
    assert client.get("/health", params={"token": token, "access_token": token}).status_code == 401


def test_repeated_authorization_headers_are_refused_even_if_one_is_valid(client: TestClient, token: str) -> None:
    headers = [("Authorization", f"Bearer {token}"), ("Authorization", "Bearer other")]
    assert client.get("/health", headers=headers).status_code == 401


def test_prefix_and_extension_of_the_token_are_refused(client: TestClient, token: str) -> None:
    for presented in (token[:-1], token + "x", token[::-1]):
        assert client.get("/health", headers={"Authorization": f"Bearer {presented}"}).status_code == 401


# ------------------------------------------------------------------ Host header (DNS rebinding)
@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        f"evil.example:{PORT}",
        "127.0.0.1",  # right name, missing port
        f"127.0.0.1:{PORT + 1}",  # right name, wrong port
        f"127.0.0.1.evil.example:{PORT}",
        f"localhost.evil.example:{PORT}",
        f"evil.example:{PORT}@127.0.0.1",
        f"localhost.:{PORT}",
        f"127.0.0.2:{PORT}",  # a loopback address, but not the configured one (the fixture binds 127.0.0.1)
        f"[::1]:{PORT + 1}",
        f"0.0.0.0:{PORT}",
    ],
)
def test_rebinding_hosts_are_rejected_even_with_a_valid_token(
    client: TestClient, auth: dict[str, str], host: str
) -> None:
    response = client.get("/health", headers={**auth, "Host": host})
    assert response.status_code == 400
    assert response.json() == {"error": {"code": "invalid_host", "message": "Invalid Host header"}}


@pytest.mark.parametrize("host", [f"127.0.0.1:{PORT}", f"localhost:{PORT}", f"[::1]:{PORT}", f"LocalHost:{PORT}"])
def test_loopback_hosts_on_the_service_port_are_accepted(client: TestClient, auth: dict[str, str], host: str) -> None:
    assert client.get("/health", headers={**auth, "Host": host}).status_code == 200


@pytest.mark.parametrize("bind_host", ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"])
def test_the_configured_bind_address_is_an_accepted_host(tmp_path: Path, bind_host: str) -> None:
    # config accepts every literal in 127.0.0.0/8 and ::1; a service bound to one must answer requests made to it.
    settings = load_settings(
        {
            "PAI_HOST": bind_host,
            "PAI_PORT": str(PORT),
            "PAI_DATA_DIR": str(tmp_path / "state"),
            "PAI_TOKEN_FILE": str(tmp_path / "run" / "token"),
        }
    )
    address = f"[{bind_host}]" if ":" in bind_host else bind_host
    with client_for(create_app(settings)) as client:
        auth = {"Authorization": f"Bearer {settings.token_file.read_text(encoding='ascii')}"}
        assert client.get("/health", headers={**auth, "Host": f"{address}:{PORT}"}).status_code == 200
        # Binding one address does not accept the rest of the range: only the configured one is added.
        assert client.get("/health", headers={**auth, "Host": f"127.0.0.3:{PORT}"}).status_code == 400


def test_repeated_host_headers_are_rejected(client: TestClient, auth: dict[str, str]) -> None:
    headers = [*auth.items(), ("Host", f"127.0.0.1:{PORT}"), ("Host", "evil.example")]
    assert client.get("/health", headers=headers).status_code == 400


def test_host_is_checked_before_origin_and_authentication(client: TestClient) -> None:
    headers = {"Host": "evil.example", "Origin": "http://evil.example"}
    assert client.get("/health", headers=headers).status_code == 400


# ------------------------------------------------------------------ Origin header
@pytest.mark.parametrize(
    "origin",
    [
        "http://evil.example",
        f"http://evil.example:{PORT}",
        "null",
        "",
        f"http://127.0.0.1:{PORT + 1}",  # same host, other port
        f"https://127.0.0.1:{PORT}",  # same host and port, other scheme
        f"http://localhost:{PORT}",  # a different loopback name than the Host header: not same-origin
        f"http://127.0.0.1.evil.example:{PORT}",
        f"http://127.0.0.1:{PORT}/",
    ],
)
def test_cross_origin_requests_are_rejected_even_with_a_valid_token(
    client: TestClient, auth: dict[str, str], origin: str
) -> None:
    response = client.get("/health", headers={**auth, "Origin": origin})
    assert response.status_code == 403
    assert response.json() == {
        "error": {"code": "forbidden_origin", "message": "Cross-origin requests are not allowed"}
    }


@pytest.mark.parametrize("origin", [f"http://127.0.0.1:{PORT}", f"HTTP://127.0.0.1:{PORT}"])
def test_same_origin_requests_are_accepted(client: TestClient, auth: dict[str, str], origin: str) -> None:
    assert client.get("/health", headers={**auth, "Origin": origin}).status_code == 200


@pytest.mark.parametrize("name", ["localhost", "[::1]"])
def test_same_origin_is_judged_against_the_host_the_request_was_sent_to(
    client: TestClient, auth: dict[str, str], name: str
) -> None:
    address = f"{name}:{PORT}"
    assert client.get("/health", headers={**auth, "Host": address, "Origin": f"http://{address}"}).status_code == 200


def test_repeated_origin_headers_are_rejected(client: TestClient, auth: dict[str, str]) -> None:
    same = f"http://127.0.0.1:{PORT}"
    assert client.get("/health", headers=[*auth.items(), ("Origin", same), ("Origin", same)]).status_code == 403


def test_origin_is_checked_before_authentication(client: TestClient) -> None:
    assert client.get("/health", headers={"Origin": "http://evil.example"}).status_code == 403


def test_cross_origin_preflight_gets_no_cors_approval(client: TestClient) -> None:
    response = client.options(
        "/health", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"}
    )
    assert response.status_code == 403
    assert not any(name.startswith("access-control-") for name in response.headers)


def test_no_cors_headers_are_ever_sent(client: TestClient, auth: dict[str, str]) -> None:
    response = client.get("/health", headers={**auth, "Origin": f"http://127.0.0.1:{PORT}"})
    assert not any(name.startswith("access-control-") for name in response.headers)


# ------------------------------------------------------------------ OpenAPI and docs
def test_openapi_document_is_served_only_with_a_token(client: TestClient, auth: dict[str, str]) -> None:
    assert client.get("/openapi.json").status_code == 401
    document = client.get("/openapi.json", headers=auth)
    assert document.status_code == 200
    assert "/health" in document.json()["paths"]


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/docs/oauth2-redirect"])
def test_interactive_docs_do_not_exist_even_with_a_token(client: TestClient, auth: dict[str, str], path: str) -> None:
    assert client.get(path, headers=auth).status_code == 404


# ------------------------------------------------------------------ other protocols
def test_websocket_handshake_without_a_token_is_closed(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as refused, client.websocket_connect("/anything"):
        pass
    assert refused.value.code == 1008


# ------------------------------------------------------------------ rejected requests leave a trace
def test_a_rejected_request_is_logged_with_its_reason_and_nothing_the_client_sent(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    client.get("/health?secret=query-sentinel-1", headers={"Authorization": "Bearer wrong-token-sentinel-2"})
    client.get("/health", headers={"Host": "host-sentinel-3.example"})
    client.get("/health", headers={"Origin": "http://origin-sentinel-4.example"})
    client.get("/path-sentinel-5", headers={"Authorization": "Bearer wrong-token-sentinel-2"})

    rejections = [r for r in caplog.records if r.name == "backend.api.security"]
    assert [(r.levelname, r.reason) for r in rejections] == [  # type: ignore[attr-defined]
        ("WARNING", "unauthorized"),
        ("WARNING", "invalid_host"),
        ("WARNING", "forbidden_origin"),
        ("WARNING", "unauthorized"),
    ]
    # Only the service's own records: the test client (httpx) logs the URLs it requests.
    everything = " ".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records if r.name.startswith("backend"))
    for sentinel in ("sentinel-1", "sentinel-2", "sentinel-3", "sentinel-4", "sentinel-5"):
        assert sentinel not in everything


def test_an_accepted_request_is_not_logged_as_rejected(
    client: TestClient, auth: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    assert client.get("/health", headers=auth).status_code == 200
    assert [r for r in caplog.records if r.name == "backend.api.security"] == []
