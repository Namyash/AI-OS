"""The launcher: the session handoff of docs/architecture/KIOSK_SESSION_DESIGN.md, then supervision of the browser.

Order of events (each phase has its own bound, see ``kiosk.config``):

1. Find the browser executable and clear the last run's readiness file.
2. Wait for the backend to publish its endpoint and token files; ``POST /v1/session`` with the token.
3. Start Chromium with a private, empty profile and the DevTools pipe. Nothing secret is on its command line or in its
   environment.
4. Over the pipe: find the page, install ``pai_session`` (HttpOnly, SameSite=Strict, host-only on the backend's origin,
   with an expiry derived from ``expires_in``), navigate the page to the plain origin URL.
5. Wait until the page has loaded on that origin and the app shell has rendered; write the readiness file.
6. Supervise: look at the page every ``status_interval`` seconds (the readiness file follows what the status bar says),
   renew the session before it expires, and fail when the browser dies.

``run`` never returns: it ends with ``StopRequested`` (a SIGTERM or SIGINT, exit status 0) or with a ``KioskError``
(a non-zero status). Either way the browser is stopped on the way out and the readiness file stops saying ready.
"""

from __future__ import annotations

import logging
import os
import signal
import time
from collections.abc import Mapping
from types import FrameType
from typing import Any, NoReturn

from kiosk import handoff, readiness
from kiosk.cdp import CdpClient, CdpError
from kiosk.chromium import BrowserProcess, build_command, build_environment, prepare_profile, resolve_executable, spawn
from kiosk.config import Settings, load_settings
from kiosk.errors import EXIT_FAILURE, EXIT_OK, KioskError
from kiosk.log import configure_logging, register_secret
from kiosk.readiness import PageProbe, ReadyFile

logger = logging.getLogger("kiosk")

PAGE_POLL_INTERVAL = 0.25  # seconds between two looks while waiting for the page or the shell
SUPERVISION_SLICE = 0.2  # seconds between two checks that the browser is alive
RENEW_AT_FRACTION = 0.8  # a session is replaced after this fraction of its lifetime
STOP_GRACE = 5.0  # seconds the browser gets to exit after being asked to
_PROBE_TIMEOUT_FLOOR = 5.0  # a look at a running page never waits longer than this, whatever the browser timeout


class StopRequested(BaseException):
    """Raised from the signal handler to unwind the launcher (and run its cleanup) wherever it is waiting.

    A ``BaseException``, so no ``except Exception`` in between can swallow a request to stop.
    """


class PageDriver:
    """Everything the launcher does to the running browser over the DevTools pipe."""

    def __init__(
        self, settings: Settings, endpoint: handoff.Endpoint, browser: BrowserProcess, cdp: CdpClient, ready: ReadyFile
    ) -> None:
        self._settings = settings
        self._endpoint = endpoint
        self._browser = browser
        self._cdp = cdp
        self._ready = ready
        self._page_session: str | None = None  # the DevTools session of the page, not a credential

    def _call(self, method: str, params: dict[str, Any] | None = None, *, page: bool = False) -> dict[str, Any]:
        return self._cdp.call(
            method,
            params,
            session_id=self._page_session if page else None,
            timeout=self._settings.browser_timeout,
        )

    def require_browser_alive(self) -> None:
        status = self._browser.poll()
        if status is not None:
            raise KioskError(f"the browser exited unexpectedly (status {status})")

    # ------------------------------------------------------------------ getting the UI up
    def attach_page(self) -> None:
        """Find the browser's page and attach to it. The page appears a moment after the browser starts."""
        deadline = time.monotonic() + self._settings.browser_timeout
        while True:
            self.require_browser_alive()
            targets = self._call("Target.getTargets").get("targetInfos", [])
            pages = [t for t in targets if isinstance(t, dict) and t.get("type") == "page" and "targetId" in t]
            if pages:
                break
            if time.monotonic() >= deadline:
                raise KioskError(f"the browser opened no page within {self._settings.browser_timeout:g} s")
            time.sleep(PAGE_POLL_INTERVAL)
        attached = self._call("Target.attachToTarget", {"targetId": pages[0]["targetId"], "flatten": True})
        session_id = attached.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise KioskError("the browser attached to the page but returned no DevTools session")
        self._page_session = session_id

    def install_cookie(self, session: handoff.Session) -> None:
        self._call(
            "Storage.setCookies",
            {
                "cookies": [
                    {
                        "name": handoff.COOKIE_NAME,
                        "value": session.session_id,
                        "url": self._endpoint.cookie_url,  # host-only: no Domain attribute, scoped to this origin
                        "path": "/",
                        "httpOnly": True,  # page scripts can never read it
                        "secure": False,  # the backend is plain http on loopback; a Secure cookie would not be sent
                        "sameSite": "Strict",
                        "expires": session.expires_at,
                    }
                ]
            },
        )
        logger.info("session cookie installed")

    def navigate(self) -> None:
        result = self._call("Page.navigate", {"url": self._endpoint.cookie_url}, page=True)
        error = result.get("errorText")
        if error:
            raise KioskError(f"the browser could not load {self._endpoint.origin}: {error}")

    def _look(self) -> PageProbe:
        """One look at the page: ``KioskError`` when the browser cannot be asked or answers nonsense."""
        timeout = min(self._settings.browser_timeout, max(_PROBE_TIMEOUT_FLOOR, self._settings.status_interval))
        result = self._cdp.call(
            "Runtime.evaluate",
            {"expression": readiness.probe_expression(), "returnByValue": True},
            session_id=self._page_session,
            timeout=timeout,
        )
        if "exceptionDetails" in result:
            raise KioskError("the page probe raised an exception in the page")
        value = result.get("result", {})
        return readiness.parse_probe(value.get("value") if isinstance(value, dict) else None)

    def wait_for_shell(self) -> None:
        """Wait until the document is complete on the backend's origin and the shell is in it, then publish."""
        deadline = time.monotonic() + self._settings.render_timeout
        last_problem = "the page did not load"
        while True:
            self.require_browser_alive()
            try:
                probe = self._look()
            except CdpError as exc:
                if self._cdp.closed:
                    raise
                last_problem = str(exc)  # the page is between documents: ask again
            else:
                if probe.origin != self._endpoint.origin:
                    last_problem = f"the page is on {probe.origin!r}, not on the backend's origin"
                elif not probe.document_complete:
                    last_problem = "the document is still loading"
                elif not probe.shell_rendered:
                    last_problem = "the document loaded but the app shell is not in it"
                else:
                    self._ready.publish(probe)
                    logger.info("app shell rendered; status bar: %s", probe.status_text)
                    return
            if time.monotonic() >= deadline:
                self._ready.publish(None)
                raise KioskError(
                    f"the app shell did not render within {self._settings.render_timeout:g} s: {last_problem}"
                )
            time.sleep(PAGE_POLL_INTERVAL)

    # ------------------------------------------------------------------ keeping it up
    def supervise(self, session: handoff.Session) -> NoReturn:
        """Watch the browser until it dies (``KioskError``) or the process is asked to stop (``StopRequested``)."""
        next_look = time.monotonic() + self._settings.status_interval
        renew_at = session.minted_at + RENEW_AT_FRACTION * session.expires_in
        while True:
            self.require_browser_alive()
            if time.monotonic() >= next_look:
                next_look = time.monotonic() + self._settings.status_interval
                self._refresh_status()
                if time.time() >= renew_at:
                    session, renew_at = self._renew(session, renew_at)
            time.sleep(SUPERVISION_SLICE)

    def _refresh_status(self) -> None:
        try:
            probe: PageProbe | None = self._look()
        except CdpError as exc:
            if self._cdp.closed:
                raise KioskError(f"lost the DevTools pipe to the browser: {exc}") from None
            logger.warning("cannot look at the page: %s", exc)
            probe = None
        except KioskError as exc:
            logger.warning("cannot read the page: %s", exc)
            probe = None
        self._ready.publish(probe)

    def _renew(self, session: handoff.Session, renew_at: float) -> tuple[handoff.Session, float]:
        """Replace the session before it expires; keep the old one while renewal fails, and fail once it has expired."""
        settings = self._settings
        try:
            _, token = handoff.wait_for_handoff(settings.endpoint_file, settings.token_file, 0.0)
            register_secret(token)
            fresh = handoff.mint_session(self._endpoint, token, timeout=settings.request_timeout, retry_for=0.0)
            register_secret(fresh.session_id)
            self.install_cookie(fresh)
        except KioskError as exc:
            if time.time() >= session.expires_at:
                raise KioskError(f"the session expired and could not be renewed: {exc}") from None
            logger.warning("session renewal failed, will retry: %s", exc)
            return session, renew_at
        logger.info("session renewed, valid for %.0f s", fresh.expires_in)
        return fresh, fresh.minted_at + RENEW_AT_FRACTION * fresh.expires_in


def run(settings: Settings, environ: Mapping[str, str]) -> NoReturn:
    """Hand a session to a new browser and supervise it. See the module docstring."""
    command = build_command(settings, resolve_executable(settings.chromium))
    ready = ReadyFile(settings.ready_file)  # removes the file an earlier run left
    browser: BrowserProcess | None = None
    cdp: CdpClient | None = None
    try:
        endpoint, token = handoff.wait_for_handoff(
            settings.endpoint_file, settings.token_file, settings.handoff_timeout
        )
        register_secret(token)
        logger.info("backend published its endpoint at %s", endpoint.origin)
        session = handoff.mint_session(
            endpoint, token, timeout=settings.request_timeout, retry_for=settings.handoff_timeout
        )
        register_secret(session.session_id)
        logger.info("session minted, valid for %.0f s", session.expires_in)

        prepare_profile(settings.profile_dir)
        browser = spawn(command, build_environment(environ, settings))
        logger.info("browser started (pid %d)", browser.pid)
        cdp = CdpClient(browser.reply_fd, browser.command_fd)

        page = PageDriver(settings, endpoint, browser, cdp, ready)
        page.attach_page()
        page.install_cookie(session)
        page.navigate()
        page.wait_for_shell()
        page.supervise(session)
    finally:
        ready.retire()
        if browser is not None:
            browser.stop(STOP_GRACE)
        if cdp is not None:
            cdp.close()


def main(environ: Mapping[str, str] | None = None) -> int:
    """Entry point of ``python3 -m kiosk``: returns the process exit status."""
    configure_logging()
    environment = os.environ if environ is None else environ

    def request_stop(_signal: int, _frame: FrameType | None) -> NoReturn:
        # One request is enough; a second signal must not interrupt the cleanup the first one started.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise StopRequested

    previous = {number: signal.signal(number, request_stop) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        run(load_settings(environment), environment)
    except StopRequested:
        logger.info("asked to stop")
        return EXIT_OK
    except KioskError as exc:
        logger.error("%s", exc)
        return exc.exit_code
    except Exception:  # the last line of defence: a bug must end as a logged failure, never as a raw traceback
        logger.exception("unexpected failure")
        return EXIT_FAILURE
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
