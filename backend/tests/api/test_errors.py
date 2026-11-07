"""Every failure, including framework-generated ones, uses one body shape and leaks nothing."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from backend.core.config import Settings
from backend.core.errors import DatabaseUnavailable
from backend.tests.api.support import client_for

LEAKY_TEXT = "boom /etc/shadow C:\\secrets\\key.pem password=hunter2 Bearer abc123def456 Traceback"
LEAK_MARKERS = ["/etc/shadow", "secrets", "hunter2", "abc123def456", "Traceback", "RuntimeError", "boom"]


def assert_error(response: httpx.Response, status: int, code: str, message: str) -> None:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"error": {"code": code, "message": message}}


def assert_no_leak(response: httpx.Response) -> None:
    text = response.text
    for marker in LEAK_MARKERS:
        assert marker not in text, marker


@pytest.fixture
def failing_app(app: FastAPI) -> FastAPI:
    """The real app plus routes that fail in the ways a future endpoint could."""

    @app.get("/_test/typed")
    def typed(limit: int) -> dict[str, int]:
        return {"limit": limit}

    @app.get("/_test/crash")
    def crash() -> None:
        raise RuntimeError(LEAKY_TEXT)

    @app.get("/_test/http-error")
    def http_error() -> None:
        raise HTTPException(status_code=400, detail=LEAKY_TEXT, headers={"X-Extra": "kept"})

    @app.get("/_test/unavailable")
    def unavailable() -> None:
        raise DatabaseUnavailable(LEAKY_TEXT)

    return app


@pytest.fixture
def failing_client(failing_app: FastAPI) -> Iterator[TestClient]:
    with client_for(failing_app) as running:
        yield running


@pytest.fixture
def failing_auth(failing_client: TestClient, settings: Settings) -> dict[str, str]:
    return {"Authorization": f"Bearer {settings.token_file.read_text(encoding='ascii')}"}


def test_unknown_path_is_a_404_in_the_standard_shape(client: TestClient, auth: dict[str, str]) -> None:
    assert_error(client.get("/does-not-exist", headers=auth), 404, "not_found", "Resource not found")


def test_wrong_method_is_a_405_in_the_standard_shape_and_keeps_the_allow_header(
    client: TestClient, auth: dict[str, str]
) -> None:
    response = client.post("/health", headers=auth)
    assert_error(response, 405, "method_not_allowed", "Method not allowed")
    assert response.headers["allow"] == "GET"


def test_invalid_input_is_a_422_that_does_not_echo_the_input(
    failing_client: TestClient, failing_auth: dict[str, str]
) -> None:
    response = failing_client.get("/_test/typed", params={"limit": "not-a-number-xyz"}, headers=failing_auth)
    assert_error(response, 422, "validation_error", "The request is invalid")
    assert "not-a-number-xyz" not in response.text
    assert "limit" not in response.text


def test_a_validation_failure_is_logged_by_error_type_without_the_input_or_the_field(
    failing_client: TestClient, failing_auth: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    failing_client.get("/_test/typed", params={"limit": "not-a-number-xyz"}, headers=failing_auth)
    ((record,),) = [[r] for r in caplog.records if r.name == "backend.api.errors"]
    assert (record.levelname, record.error_types) == ("INFO", ["int_parsing"])  # type: ignore[attr-defined]
    assert "not-a-number-xyz" not in f"{record.getMessage()} {record.__dict__}"
    assert "limit" not in f"{record.getMessage()} {record.error_types}"  # type: ignore[attr-defined]


def test_missing_required_input_is_the_same_422(failing_client: TestClient, failing_auth: dict[str, str]) -> None:
    assert_error(
        failing_client.get("/_test/typed", headers=failing_auth), 422, "validation_error", "The request is invalid"
    )


def test_unexpected_exception_is_a_generic_500_with_no_exception_text(
    failing_client: TestClient, failing_auth: dict[str, str]
) -> None:
    response = failing_client.get("/_test/crash", headers=failing_auth)
    assert_error(response, 500, "internal_error", "Internal server error")
    assert_no_leak(response)


def test_application_error_text_passed_by_a_caller_never_reaches_the_body(
    failing_client: TestClient, failing_auth: dict[str, str]
) -> None:
    response = failing_client.get("/_test/unavailable", headers=failing_auth)
    assert_error(response, 503, "database_unavailable", "The database is unavailable")
    assert_no_leak(response)


def test_framework_http_errors_keep_their_status_but_not_their_detail(
    failing_client: TestClient, failing_auth: dict[str, str]
) -> None:
    response = failing_client.get("/_test/http-error", headers=failing_auth)
    assert_error(response, 400, "http_error", "Request failed")
    assert response.headers["x-extra"] == "kept"
    assert_no_leak(response)


def test_database_failure_in_health_is_a_503_that_hides_the_database_path(
    client: TestClient, auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(_path: object) -> sqlite3.Connection:
        raise sqlite3.OperationalError("unable to open database file /secret/location/pai.sqlite3")

    monkeypatch.setattr("backend.api.health.migrate.connect", refuse)
    response = client.get("/health", headers=auth)
    assert_error(response, 503, "database_unavailable", "The database is unavailable")
    assert "secret" not in response.text


def test_every_error_response_is_valid_json_with_exactly_the_documented_keys(
    client: TestClient, auth: dict[str, str]
) -> None:
    for response in (
        client.get("/health"),
        client.get("/nope", headers=auth),
        client.post("/health", headers=auth),
        client.get("/health", headers={**auth, "Host": "evil.example"}),
        client.get("/health", headers={**auth, "Origin": "http://evil.example"}),
    ):
        body = json.loads(response.text)
        assert list(body) == ["error"]
        assert sorted(body["error"]) == ["code", "message"]
