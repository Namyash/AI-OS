"""The UI shell: served from the static directory at ``/`` behind the same guard, safely, with security headers."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.api.app import create_app
from backend.api.static import CONTENT_SECURITY_POLICY
from backend.core.config import Settings
from backend.tests.api.support import PORT, client_for

ORIGIN = f"http://127.0.0.1:{PORT}"
INDEX_HTML = "<!doctype html><title>shell</title><script type=module src=/assets/app.js></script>"
OUTSIDE_CONTENT = "OUTSIDE-THE-UI-DIRECTORY"
NOT_FOUND = {"error": {"code": "not_found", "message": "Resource not found"}}
UNAUTHORIZED = {"error": {"code": "unauthorized", "message": "Authentication required"}}
SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


def cookie(session_id: str) -> dict[str, str]:
    return {"Cookie": f"pai_session={session_id}"}


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("this host does not allow creating symbolic links")


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    """A file next to the UI directory, never to be served."""
    secret = tmp_path / "outside-secret.txt"
    secret.write_text(OUTSIDE_CONTENT)
    return secret


@pytest.fixture
def ui_dir(settings: Settings, outside: Path) -> Path:
    root = settings.static_dir
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(INDEX_HTML)
    (root / "assets" / "app.js").write_text("console.log('app');")
    (root / "assets" / "app.css").write_text("body { margin: 0 }")
    return root


@pytest.fixture
def ui(settings: Settings, ui_dir: Path) -> Iterator[TestClient]:
    with client_for(create_app(settings)) as running:
        yield running


@pytest.fixture
def bearer(settings: Settings, ui: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {settings.token_file.read_text(encoding='ascii')}"}


@pytest.fixture
def session(ui: TestClient, bearer: dict[str, str]) -> dict[str, str]:
    """The headers of a browser that holds a session: only the cookie."""
    return cookie(ui.post("/v1/session", headers=bearer).json()["session_id"])


# ------------------------------------------------------------------ behind the guard
@pytest.mark.parametrize("path", ["/", "/index.html", "/assets/app.js", "/assets/", "/assets", "/nope", "/%2e%2e/x"])
def test_no_ui_path_is_reachable_without_credentials(ui: TestClient, path: str) -> None:
    for headers in ({}, cookie("not-a-session"), {"Authorization": "Bearer wrong"}):
        response = ui.get(path, headers=headers)
        assert (response.status_code, response.json()) == (401, UNAUTHORIZED)
        assert "content-security-policy" not in response.headers


def test_the_shell_itself_needs_the_cookie(ui: TestClient, session: dict[str, str]) -> None:
    assert ui.get("/").status_code == 401
    assert ui.get("/", headers=session).status_code == 200


def test_the_token_reads_the_shell_too(ui: TestClient, bearer: dict[str, str]) -> None:
    assert ui.get("/", headers=bearer).text == INDEX_HTML


def test_host_and_origin_are_checked_for_the_ui_like_for_the_api(ui: TestClient, session: dict[str, str]) -> None:
    assert ui.get("/", headers={**session, "Host": "evil.example"}).status_code == 400
    assert ui.get("/", headers={**session, "Origin": "http://evil.example"}).status_code == 403
    assert ui.get("/", headers={**session, "Origin": ORIGIN}).status_code == 200


def test_a_cookie_request_that_could_change_state_still_needs_an_origin_on_ui_paths(
    ui: TestClient, session: dict[str, str]
) -> None:
    assert ui.post("/", headers=session).status_code == 403
    assert ui.post("/", headers={**session, "Origin": ORIGIN}).status_code == 404  # then it is simply not a UI request


# ------------------------------------------------------------------ what is served
def test_the_root_is_the_index_file(ui: TestClient, session: dict[str, str]) -> None:
    response = ui.get("/", headers=session)
    assert response.status_code == 200
    assert response.text == INDEX_HTML
    assert response.headers["content-type"].startswith("text/html")
    assert ui.get("/index.html", headers=session).text == INDEX_HTML


def test_assets_are_served_with_their_types(ui: TestClient, session: dict[str, str]) -> None:
    script = ui.get("/assets/app.js", headers=session)
    assert (script.status_code, script.text) == (200, "console.log('app');")
    assert "javascript" in script.headers["content-type"]
    assert ui.get("/assets/app.css", headers=session).headers["content-type"].startswith("text/css")


def test_head_is_answered_without_a_body(ui: TestClient, session: dict[str, str]) -> None:
    response = ui.head("/", headers=session)
    assert (response.status_code, response.content) == (200, b"")
    assert response.headers["content-security-policy"] == SECURITY_HEADERS["content-security-policy"]


def test_conditional_requests_are_answered_with_304_and_the_same_headers(
    ui: TestClient, session: dict[str, str]
) -> None:
    first = ui.get("/assets/app.js", headers=session)
    again = ui.get("/assets/app.js", headers={**session, "If-None-Match": first.headers["etag"]})
    assert (again.status_code, again.content) == (304, b"")
    for name, value in SECURITY_HEADERS.items():
        assert again.headers[name] == value


# ------------------------------------------------------------------ headers
def test_the_policy_is_the_one_in_the_design() -> None:
    assert SECURITY_HEADERS["content-security-policy"] == CONTENT_SECURITY_POLICY


@pytest.mark.parametrize("path", ["/", "/index.html", "/assets/app.js", "/assets/app.css"])
def test_every_ui_response_carries_the_security_headers(ui: TestClient, session: dict[str, str], path: str) -> None:
    response = ui.get(path, headers=session)
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_html_is_never_cached_and_assets_are_left_to_their_validators(ui: TestClient, session: dict[str, str]) -> None:
    assert ui.get("/", headers=session).headers["cache-control"] == "no-store"
    assert ui.get("/index.html", headers=session).headers["cache-control"] == "no-store"
    for asset in ("/assets/app.js", "/assets/app.css"):
        assert "cache-control" not in ui.get(asset, headers=session).headers
        assert "etag" in ui.get(asset, headers=session).headers


def test_the_ui_sets_no_cookie_and_allows_no_cross_origin_use(ui: TestClient, session: dict[str, str]) -> None:
    response = ui.get("/", headers=session)
    assert "set-cookie" not in response.headers
    assert not any(name.startswith("access-control-") for name in response.headers)


# ------------------------------------------------------------------ the API keeps its paths and its errors
@pytest.mark.parametrize("path", ["/nope", "/assets/missing.js", "/assets", "/assets/", "/deep/er/path"])
def test_unknown_paths_keep_the_json_error_shape(ui: TestClient, session: dict[str, str], path: str) -> None:
    response = ui.get(path, headers=session)
    assert (response.status_code, response.json()) == (404, NOT_FOUND)
    assert response.headers["content-type"] == "application/json"


def test_a_custom_404_page_in_the_directory_is_never_served(
    ui: TestClient, ui_dir: Path, session: dict[str, str]
) -> None:
    (ui_dir / "404.html").write_text("CUSTOM-404-PAGE")
    response = ui.get("/nope", headers=session)
    assert (response.status_code, response.json()) == (404, NOT_FOUND)


def test_a_directory_without_an_index_is_a_404_and_never_a_listing(settings: Settings, ui_dir: Path) -> None:
    (ui_dir / "index.html").unlink()
    with client_for(create_app(settings)) as running:
        bearer = {"Authorization": f"Bearer {settings.token_file.read_text(encoding='ascii')}"}
        assert running.get("/", headers=bearer).json() == NOT_FOUND
        assert running.get("/assets/", headers=bearer).json() == NOT_FOUND


def test_files_cannot_shadow_the_api(ui: TestClient, ui_dir: Path, bearer: dict[str, str]) -> None:
    (ui_dir / "health").write_text("SHADOW")
    (ui_dir / "openapi.json").write_text("SHADOW")
    (ui_dir / "v1").mkdir()
    (ui_dir / "v1" / "session").write_text("SHADOW")
    assert ui.get("/health", headers=bearer).json()["status"] == "ok"
    assert "paths" in ui.get("/openapi.json", headers=bearer).json()
    response = ui.get("/v1/session", headers=bearer)  # the API route exists, for other methods
    assert (response.status_code, response.json()["error"]["code"]) == (405, "method_not_allowed")


def test_a_wrong_method_on_an_api_path_keeps_its_405_and_allow_header(ui: TestClient, bearer: dict[str, str]) -> None:
    response = ui.post("/health", headers=bearer)
    assert (response.status_code, response.headers["allow"]) == (405, "GET")


@pytest.mark.parametrize(
    ("method", "path"), [("POST", "/nope"), ("PUT", "/"), ("DELETE", "/index.html"), ("PATCH", "/x")]
)
def test_methods_other_than_get_and_head_never_reach_the_files(
    ui: TestClient, bearer: dict[str, str], method: str, path: str
) -> None:
    response = ui.request(method, path, headers=bearer)
    assert (response.status_code, response.json()) == (404, NOT_FOUND)


def test_a_websocket_to_the_ui_is_closed_not_crashed(ui: TestClient, bearer: dict[str, str]) -> None:
    headers = {**bearer, "host": f"127.0.0.1:{PORT}"}
    with pytest.raises(WebSocketDisconnect) as closed, ui.websocket_connect("/anything", headers=headers):
        pass
    assert closed.value.code == 1000


# ------------------------------------------------------------------ nothing outside the directory
def _forms_of_the_path_to(outside: Path) -> list[str]:
    absolute = quote(outside.as_posix(), safe="")  # every separator encoded, so the client keeps it as sent
    return [f"/%2f{absolute}", f"/%2f%2f{absolute}", f"/{absolute}", f"/..%2f{absolute}", f"/%5c{absolute}"]


TRAVERSALS = [
    "/%2e%2e/outside-secret.txt",
    "/%2e%2e%2foutside-secret.txt",
    "/..%2foutside-secret.txt",
    "/assets/%2e%2e/%2e%2e/outside-secret.txt",
    "/assets/..%2f..%2foutside-secret.txt",
    "/%2e%2e%5coutside-secret.txt",
    "/assets/..%5c..%5coutside-secret.txt",
    "/%252e%252e/outside-secret.txt",
    "/.%2e/outside-secret.txt",
    "/%2e./outside-secret.txt",
    "/assets/%2e%2e%2f%2e%2e%2foutside-secret.txt",
    "/....//outside-secret.txt",
]


@pytest.mark.parametrize("path", TRAVERSALS)
def test_a_path_that_climbs_out_of_the_directory_finds_nothing(
    ui: TestClient, session: dict[str, str], path: str
) -> None:
    response = ui.get(path, headers=session)
    assert (response.status_code, response.json()) == (404, NOT_FOUND)
    assert OUTSIDE_CONTENT not in response.text


def test_an_absolute_path_to_a_file_outside_finds_nothing(
    ui: TestClient, session: dict[str, str], outside: Path
) -> None:
    for path in _forms_of_the_path_to(outside):
        response = ui.get(path, headers=session)
        assert response.status_code == 404, path
        assert OUTSIDE_CONTENT not in response.text


@pytest.mark.parametrize(
    "path",
    ["/index.html%00.png", "/%00", "/assets/app.js%00", "/" + "a" * 5000, "/assets/" + "b" * 300, "/" + "%2e" * 3000],
)
def test_paths_no_file_system_can_hold_are_plain_misses_not_errors(
    ui: TestClient, session: dict[str, str], path: str
) -> None:
    response = ui.get(path, headers=session)
    assert (response.status_code, response.json()) == (404, NOT_FOUND)


def test_a_symbolic_link_out_of_the_directory_is_not_followed(
    settings: Settings, ui_dir: Path, outside: Path, tmp_path: Path
) -> None:
    _symlink(ui_dir / "escape.txt", outside)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "outside-secret.txt").write_text(OUTSIDE_CONTENT)
    _symlink(ui_dir / "escape-dir", elsewhere)
    with client_for(create_app(settings)) as running:
        bearer = {"Authorization": f"Bearer {settings.token_file.read_text(encoding='ascii')}"}
        for path in ("/escape.txt", "/escape-dir/outside-secret.txt", "/escape-dir/", "/assets/../escape.txt"):
            response = running.get(path, headers=bearer)
            assert (response.status_code, response.json()) == (404, NOT_FOUND), path
        assert running.get("/index.html", headers=bearer).status_code == 200  # the rest still works


def test_a_symbolic_link_that_stays_inside_the_directory_is_followed(settings: Settings, ui_dir: Path) -> None:
    _symlink(ui_dir / "alias.js", ui_dir / "assets" / "app.js")
    with client_for(create_app(settings)) as running:
        bearer = {"Authorization": f"Bearer {settings.token_file.read_text(encoding='ascii')}"}
        assert running.get("/alias.js", headers=bearer).text == "console.log('app');"


def test_the_ui_directory_may_itself_be_a_symbolic_link_and_still_confines_what_it_serves(
    settings: Settings, outside: Path, tmp_path: Path
) -> None:
    real = tmp_path / "release-1"
    real.mkdir()
    (real / "index.html").write_text(INDEX_HTML)
    _symlink(real / "escape.txt", outside)
    _symlink(settings.static_dir, real)  # how a deployment can switch builds: /opt/pai/frontend -> a release directory
    with client_for(create_app(settings)) as running:
        bearer = {"Authorization": f"Bearer {settings.token_file.read_text(encoding='ascii')}"}
        assert running.get("/", headers=bearer).text == INDEX_HTML
        assert running.get("/escape.txt", headers=bearer).status_code == 404


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs file permissions that bind this user")
@pytest.mark.parametrize("unreadable", ["file", "directory"])
def test_something_the_service_may_not_read_is_an_internal_error_never_a_401_or_a_broken_200(
    ui: TestClient, ui_dir: Path, session: dict[str, str], caplog: pytest.LogCaptureFixture, unreadable: str
) -> None:
    # A client would read a 401 as "this window has no valid session", which is not what is wrong.
    if unreadable == "file":
        (ui_dir / "assets" / "app.js").chmod(0)
    else:
        (ui_dir / "assets").chmod(0)
    caplog.set_level(logging.ERROR)
    try:
        response = ui.get("/assets/app.js", headers=session)
    finally:
        (ui_dir / "assets").chmod(0o755)
    assert (response.status_code, response.json()["error"]["code"]) == (500, "internal_error")
    assert "app.js" not in response.text
    assert [r.getMessage() for r in caplog.records if r.name == "backend.api.static"] == ["a UI file could not be read"]


# ------------------------------------------------------------------ no directory
def test_without_a_ui_directory_the_api_runs_alone_and_a_warning_says_so(
    settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    assert not settings.static_dir.exists()
    with caplog.at_level(logging.WARNING):
        app = create_app(settings)
    warnings = [r for r in caplog.records if r.name == "backend.api.static"]
    assert [r.levelname for r in warnings] == ["WARNING"]
    assert "UI directory not found" in warnings[0].getMessage()
    assert warnings[0].static_dir == str(settings.static_dir)  # type: ignore[attr-defined]
    assert not settings.token_file.exists()  # nothing secret exists yet, so nothing secret can be in that line

    with client_for(app) as running:
        bearer = {"Authorization": f"Bearer {settings.token_file.read_text(encoding='ascii')}"}
        assert running.get("/health", headers=bearer).status_code == 200
        assert running.get("/", headers=bearer).json() == NOT_FOUND
        assert running.get("/index.html", headers=bearer).json() == NOT_FOUND


def test_a_file_where_the_ui_directory_should_be_is_treated_as_missing(
    settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    settings.static_dir.parent.mkdir(parents=True, exist_ok=True)
    settings.static_dir.write_text("not a directory")
    with caplog.at_level(logging.WARNING):
        app = create_app(settings)
    assert any("UI directory not found" in r.getMessage() for r in caplog.records)
    with client_for(app) as running:
        bearer = {"Authorization": f"Bearer {settings.token_file.read_text(encoding='ascii')}"}
        assert running.get("/", headers=bearer).json() == NOT_FOUND


def test_a_ui_directory_does_not_cause_the_warning(
    settings: Settings, ui_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        create_app(settings)
    assert [r for r in caplog.records if r.name == "backend.api.static"] == []
