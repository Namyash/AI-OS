"""The launcher as a process: ``python -m kiosk`` against a real HTTP backend and a DevTools-pipe browser.

What is proved here is the handoff of docs/architecture/KIOSK_SESSION_DESIGN.md: the request sequence, where each
secret travelled (and where it did not), the cookie that was installed, the readiness file, and what happens on every
way the run can go wrong. The browser is a stand-in (see fake_chromium.py); the real one is exercised by the
container integration test described in docs/development/KIOSK.md.
"""

from __future__ import annotations

import json
import signal
import time

import pytest

from kiosk.errors import EXIT_CONFIG, EXIT_FAILURE
from kiosk.tests.support import Rig, posix_only, wait_until

pytestmark = posix_only


def assert_not_claiming_ready(rig: Rig) -> None:
    """After the launcher is gone the readiness file is absent or says not-ready: never a stale 'ready'."""
    if rig.ready_file.exists():
        assert rig.ready()["state"] == "not-ready"
        assert rig.ready()["shell_rendered"] is False


def secrets_of(rig: Rig) -> list[str]:
    return [rig.backend.token, *rig.backend.issued]


# ------------------------------------------------------------------------------------------ the healthy run
def test_the_handoff_happens_in_the_documented_order(rig: Rig) -> None:
    rig.launch_healthy()

    # backend: exactly one mint (token, POST) and then the page load (cookie, GET): nothing else
    assert [(r.method, r.path) for r in rig.backend.requests] == [("POST", "/v1/session"), ("GET", "/")]
    # browser: find the page, attach, install the cookie, navigate, look
    methods = [e["method"] for e in rig.browser_entries("command")]
    assert methods[:4] == ["Target.getTargets", "Target.attachToTarget", "Storage.setCookies", "Page.navigate"]
    assert "Runtime.evaluate" in methods[4:]
    # the browser was only started after the session existed
    assert rig.browser_entries("start")


def test_the_token_travels_only_in_the_authorization_header_of_the_one_post(rig: Rig) -> None:
    rig.launch_healthy()
    token = rig.backend.token

    post, load = rig.backend.requests
    assert post.headers["authorization"] == f"Bearer {token}"
    assert "cookie" not in post.headers
    assert "authorization" not in load.headers, "the page load must carry the cookie, never the bearer token"
    everything = json.dumps([[r.method, r.path, r.headers, r.body.decode()] for r in rig.backend.requests])
    assert everything.count(token) == 1
    # and the browser never saw it over the pipe either
    assert token not in rig.browser_log.read_text(encoding="utf-8")


def test_the_cookie_has_the_required_attributes_and_the_session_the_backend_issued(rig: Rig) -> None:
    before = time.time()
    rig.backend.ttl = 5400
    rig.launch_healthy()
    after = time.time()

    (command,) = rig.commands("Storage.setCookies")
    assert command["session"] is None, "cookies are a browser-level command, not sent to the page"
    (cookie,) = command["params"]["cookies"]
    assert cookie["name"] == "pai_session"
    assert cookie["value"] == rig.backend.issued[0]
    assert cookie["url"] == rig.backend.origin + "/"  # a url and no domain: the cookie is host-only on this origin
    assert "domain" not in cookie
    assert cookie["path"] == "/"
    assert cookie["httpOnly"] is True
    assert cookie["sameSite"] == "Strict"
    assert cookie["secure"] is False
    assert before + 5400 <= cookie["expires"] <= after + 5400 + 1
    assert set(cookie) == {"name", "value", "url", "path", "httpOnly", "secure", "sameSite", "expires"}


def test_the_page_is_navigated_to_the_plain_endpoint_url(rig: Rig) -> None:
    rig.launch_healthy()
    (navigate,) = rig.commands("Page.navigate")
    assert navigate["params"] == {"url": rig.backend.origin + "/"}  # no query, no fragment, no credentials
    assert navigate["session"] == "SESSION-OF-PAGE1"
    (fetch,) = rig.browser_entries("fetch")
    assert fetch["sent_cookie"] is True
    assert fetch["status"] == 200


def test_neither_secret_is_in_the_browsers_argv_or_environment(rig: Rig) -> None:
    rig.extra_env["PAI_DECOY_SECRET"] = "decoy-secret-value-0123456789"  # noqa: S105 - a test value
    rig.launch_healthy()

    (start,) = rig.browser_entries("start")
    argv, environ = json.dumps(start["argv"]), json.dumps(start["environ"])
    for secret in secrets_of(rig):
        assert secret not in argv
        assert secret not in environ
    assert "PAI_DECOY_SECRET" not in start["environ"], "variables of the launcher do not reach the browser"
    assert not [name for name in start["environ"] if name.startswith("PAI_")]
    assert "--remote-debugging-pipe" in start["argv"]
    assert "--no-sandbox" not in start["argv"]
    assert {0, 1, 2, 3, 4} <= set(start["open_fds"])
    assert not set(start["open_fds"]) - {0, 1, 2, 3, 4, 5}, "only the DevTools pipe is inherited"


def test_the_browser_starts_from_an_empty_private_profile(rig: Rig) -> None:
    rig.profile_dir.mkdir(parents=True, mode=0o700)
    (rig.profile_dir / "Cookies").write_text("a session an earlier run left behind", encoding="utf-8")
    rig.launch_healthy()
    (start,) = rig.browser_entries("start")
    assert start["user_data_dir_entries"] == []
    assert f"--user-data-dir={rig.profile_dir}" in start["argv"]


def test_neither_secret_is_ever_logged(rig: Rig) -> None:
    run = rig.launch_healthy()
    run.stop()
    log = run.log
    assert "session minted" in log, "the launcher logged nothing: this test would pass vacuously"
    for secret in secrets_of(rig):
        assert secret not in log


def test_the_readiness_file_says_the_shell_rendered_and_what_the_status_bar_says(rig: Rig) -> None:
    rig.launch_healthy()
    ready = rig.ready()
    assert set(ready) == {"version", "state", "shell_rendered", "status_bar", "updated"}
    assert ready["version"] == 1
    assert ready["state"] == "ready"
    assert ready["shell_rendered"] is True
    assert ready["status_bar"] == "Backend connected Version fake"
    for secret in secrets_of(rig):
        assert secret not in rig.ready_file.read_text(encoding="utf-8")
    assert (rig.ready_file.stat().st_mode & 0o777) == 0o644


def test_the_readiness_file_follows_the_status_bar_while_the_browser_runs(rig: Rig) -> None:
    rig.mode = "status-changes"
    rig.publish()
    rig.launch()
    first = wait_until(lambda: rig.ready_file.exists() and rig.ready(), what="the first readiness file")
    assert first["status_bar"] == "Backend connecting"
    changed = wait_until(
        lambda: rig.ready()["status_bar"] == "Backend connected Version fake" and rig.ready(), 10, "the update"
    )
    assert changed["state"] == "ready"
    assert changed["updated"] >= first["updated"]


def test_asked_to_stop_it_exits_cleanly_and_leaves_no_readiness_file_or_browser(rig: Rig) -> None:
    run = rig.launch_healthy()
    (start,) = rig.browser_entries("start")
    assert run.stop() == 0
    assert_not_claiming_ready(rig)
    assert "asked to stop" in run.log
    assert start["argv"][0].endswith("fake_chromium.py")


def test_asked_to_stop_while_still_waiting_for_the_backend_it_exits_promptly(rig: Rig) -> None:
    run = rig.launch(PAI_KIOSK_HANDOFF_TIMEOUT="60")  # nothing published
    time.sleep(0.5)
    started = time.monotonic()
    assert run.stop() == 0
    assert time.monotonic() - started < 5


def test_a_stale_readiness_file_is_removed_before_anything_else(rig: Rig) -> None:
    rig.ready_file.parent.mkdir(parents=True)
    rig.ready_file.write_text('{"state":"ready"}', encoding="utf-8")
    run = rig.launch()  # no backend files: it fails after the handoff timeout
    wait_until(lambda: not rig.ready_file.exists(), 5, "the stale file to be removed")
    assert run.wait() == EXIT_FAILURE


def test_the_session_is_renewed_before_it_expires_with_a_new_cookie(rig: Rig) -> None:
    rig.backend.ttl = 3
    rig.launch_healthy()
    wait_until(lambda: len(rig.commands("Storage.setCookies")) >= 2, 15, "a second cookie")

    first, second = (c["params"]["cookies"][0] for c in rig.commands("Storage.setCookies")[:2])
    assert len(rig.backend.posts()) >= 2
    assert first["value"] == rig.backend.issued[0]
    assert second["value"] == rig.backend.issued[1] != first["value"]
    assert second["expires"] > first["expires"]
    # the renewal used the token again, in the header only
    assert all(p.headers["authorization"] == f"Bearer {rig.backend.token}" for p in rig.backend.posts())


def test_a_session_that_expires_without_having_been_renewed_ends_the_run(rig: Rig) -> None:
    rig.backend.ttl = 2
    rig.backend.fail_mint_from = 2  # the first mint works, every renewal fails
    run = rig.launch_healthy()
    assert run.wait(timeout=20) == EXIT_FAILURE
    assert "session expired and could not be renewed" in run.log
    assert "renewal failed, will retry" in run.log, "it must keep the old session while it can"
    assert_not_claiming_ready(rig)


# ------------------------------------------------------------------------------------------ the backend side fails
def test_a_backend_that_is_down_fails_the_run_and_never_starts_the_browser(rig: Rig) -> None:
    rig.publish(endpoint="http://127.0.0.1:1")  # nothing listens there
    run = rig.launch(PAI_KIOSK_HANDOFF_TIMEOUT="1")
    assert run.wait() == EXIT_FAILURE
    assert "cannot reach the backend" in run.log
    assert rig.browser_entries() == []


def test_a_refused_token_fails_the_run_without_quoting_it_and_never_starts_the_browser(rig: Rig) -> None:
    rig.publish(token="a-stale-token-0123456789abcdef")  # noqa: S106 - a test value, not a credential
    run = rig.launch()
    assert run.wait() == EXIT_FAILURE
    assert "HTTP 401" in run.log
    assert "a-stale-token-0123456789abcdef" not in run.log
    assert rig.browser_entries() == []


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"session_id": "abcdefghijklmnop"}'])
def test_a_malformed_session_reply_fails_the_run_and_never_starts_the_browser(rig: Rig, body: bytes) -> None:
    rig.backend.mint_body = body
    rig.publish()
    run = rig.launch()
    assert run.wait() == EXIT_FAILURE
    assert "session reply" in run.log
    assert rig.browser_entries() == []


def test_files_the_backend_never_published_fail_the_run_after_the_bound(rig: Rig) -> None:
    run = rig.launch(PAI_KIOSK_HANDOFF_TIMEOUT="1")
    assert run.wait() == EXIT_FAILURE
    assert "did not publish" in run.log
    assert rig.browser_entries() == []


def test_an_endpoint_that_is_not_loopback_is_refused_before_the_token_is_sent(rig: Rig) -> None:
    rig.publish(endpoint="http://192.0.2.1:8765")
    run = rig.launch()
    assert run.wait() == EXIT_FAILURE
    assert "loopback" in run.log
    assert rig.backend.requests == []


# ------------------------------------------------------------------------------------------ the browser side fails
def test_a_browser_that_exits_at_once_fails_the_run(rig: Rig) -> None:
    rig.mode = "exit-at-start"
    rig.publish()
    run = rig.launch()
    assert run.wait() == EXIT_FAILURE
    assert "exited unexpectedly (status 3)" in run.log or "closed the DevTools pipe" in run.log
    assert not rig.ready_file.exists(), "it never reached a page: there is nothing to record"


def test_a_browser_that_dies_while_running_fails_the_run_with_its_status(rig: Rig) -> None:
    rig.mode, rig.after = "die-after-ready", 1
    rig.publish()
    run = rig.launch()
    assert run.wait() == EXIT_FAILURE
    assert "exited unexpectedly (status 7)" in run.log
    assert_not_claiming_ready(rig)
    assert rig.ready()["state"] == "not-ready", "a dead browser must not leave 'ready' behind, and says so"


def test_a_browser_that_never_opens_a_page_fails_the_run_after_the_bound(rig: Rig) -> None:
    rig.mode = "no-page"
    rig.publish()
    run = rig.launch(PAI_KIOSK_BROWSER_TIMEOUT="1")
    assert run.wait() == EXIT_FAILURE
    assert "opened no page within 1 s" in run.log


def test_a_browser_that_never_answers_fails_the_run_after_the_bound(rig: Rig) -> None:
    rig.mode = "silent"
    rig.publish()
    started = time.monotonic()
    run = rig.launch(PAI_KIOSK_BROWSER_TIMEOUT="1")
    assert run.wait() == EXIT_FAILURE
    assert "no reply from the browser within 1 s" in run.log
    assert time.monotonic() - started < 15


def test_a_browser_that_answers_with_garbage_fails_the_run(rig: Rig) -> None:
    rig.mode = "garbage"
    rig.publish()
    run = rig.launch()
    assert run.wait() == EXIT_FAILURE
    assert "not JSON" in run.log


def test_a_browser_that_closes_the_pipe_but_keeps_running_fails_the_run(rig: Rig) -> None:
    rig.mode = "close-pipe"
    rig.publish()
    run = rig.launch()
    assert run.wait() == EXIT_FAILURE
    assert "closed the DevTools pipe" in run.log


def test_a_refused_cookie_fails_the_run_without_quoting_it(rig: Rig) -> None:
    rig.mode = "cookie-error"
    rig.publish()
    run = rig.launch()
    assert run.wait() == EXIT_FAILURE
    assert "Storage.setCookies was refused by the browser: Invalid cookie fields" in run.log
    assert not any(secret in run.log for secret in secrets_of(rig))
    assert rig.commands("Page.navigate") == [], "the page must not be loaded without a session"


def test_a_navigation_the_browser_refuses_fails_the_run_with_its_reason(rig: Rig) -> None:
    rig.mode = "navigate-error"
    rig.publish()
    run = rig.launch()
    assert run.wait() == EXIT_FAILURE
    assert "net::ERR_BLOCKED_BY_ADMINISTRATOR" in run.log


# ------------------------------------------------------------------------------------------ the page does not render
def test_a_page_without_a_valid_session_is_reported_not_ready_and_fails_the_run(rig: Rig) -> None:
    rig.backend.reject_sessions = True  # the page load is answered 401: the shell never appears
    rig.publish()
    run = rig.launch(PAI_KIOSK_RENDER_TIMEOUT="1")
    wait_until(lambda: run.process.poll() is not None, 15, "the launcher to give up")
    assert run.process.returncode == EXIT_FAILURE
    assert "app shell did not render within 1 s" in run.log
    assert "the app shell is not in it" in run.log


def test_the_not_ready_record_survives_the_launcher_so_the_self_check_can_say_why(rig: Rig) -> None:
    rig.mode = "no-shell"
    rig.publish()
    run = rig.launch(PAI_KIOSK_RENDER_TIMEOUT="1")
    assert run.wait() == EXIT_FAILURE
    ready = rig.ready()
    assert (ready["state"], ready["shell_rendered"], ready["status_bar"]) == ("not-ready", False, None)


def test_a_page_on_another_origin_is_not_accepted_as_the_ui(rig: Rig) -> None:
    rig.mode = "wrong-origin"
    rig.publish()
    run = rig.launch(PAI_KIOSK_RENDER_TIMEOUT="1")
    assert run.wait() == EXIT_FAILURE
    assert "not on the backend's origin" in run.log


def test_a_shell_that_takes_a_few_looks_is_waited_for(rig: Rig) -> None:
    rig.mode, rig.after = "late-shell", 3
    rig.launch_healthy()
    assert rig.ready()["state"] == "ready"
    assert len(rig.commands("Runtime.evaluate")) >= 4


# ------------------------------------------------------------------------------------------ configuration
def test_an_invalid_setting_ends_with_the_status_that_stops_restarts(rig: Rig) -> None:
    run = rig.launch(PAI_KIOSK_RENDER_TIMEOUT="soon", PAI_KIOSK_PROFILE_DIR="relative")
    assert run.wait() == EXIT_CONFIG == 78
    assert "PAI_KIOSK_RENDER_TIMEOUT" in run.log
    assert "PAI_KIOSK_PROFILE_DIR" in run.log
    assert rig.backend.requests == []


def test_a_browser_that_is_not_installed_ends_with_the_status_that_stops_restarts(rig: Rig) -> None:
    rig.publish()
    run = rig.launch(PAI_KIOSK_CHROMIUM="definitely-not-a-browser")
    assert run.wait() == EXIT_CONFIG
    assert "executable not found: definitely-not-a-browser" in run.log
    assert rig.backend.requests == [], "no session is minted for a browser that cannot start"


def test_a_profile_directory_that_is_not_private_is_refused_and_not_deleted(rig: Rig) -> None:
    rig.profile_dir.mkdir(parents=True)
    rig.profile_dir.chmod(0o755)
    (rig.profile_dir / "keep").write_text("data", encoding="utf-8")
    rig.publish()
    run = rig.launch()
    assert run.wait() == EXIT_CONFIG
    assert "refusing to clear" in run.log
    assert (rig.profile_dir / "keep").exists()
    assert rig.browser_entries() == []


def test_a_second_signal_does_not_interrupt_the_cleanup(rig: Rig) -> None:
    run = rig.launch_healthy()
    run.process.send_signal(signal.SIGTERM)
    run.process.send_signal(signal.SIGTERM)
    run.process.send_signal(signal.SIGINT)
    assert run.wait() == 0
    assert_not_claiming_ready(rig)
