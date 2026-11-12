"""The backend side of the handoff: read what the backend publishes, then trade the bearer token for a session.

The backend writes ``/run/pai/endpoint`` and ``/run/pai/token`` once its listening socket is bound. The launcher reads
both, sends the token in the ``Authorization`` header of exactly one request, ``POST /v1/session``, and keeps only the
session id that comes back. Everything here is strict about what it accepts, because the token goes to whatever the
endpoint file names: the endpoint must be a plain loopback origin, a redirect is never followed, and a reply that is
not exactly the documented shape is a failure rather than something to repair.

No message produced here contains the token or the session id.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.client import HTTPException
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit

from kiosk.errors import KioskError

SESSION_PATH = "/v1/session"
COOKIE_NAME = "pai_session"
POLL_INTERVAL = 0.25  # seconds between two looks for the published files
RETRY_INTERVAL = 0.5  # seconds between two attempts to reach the backend
MAX_FILE_BYTES = 4096
MAX_REPLY_BYTES = 65536
# What a bearer token or a session id looks like: URL-safe characters (the backend issues secrets.token_urlsafe), a
# little wider so a different but sane encoding still passes. Anything else could not travel in a header or cookie
# unchanged, so it is refused instead of being sanitised.
_SECRET_FORMAT = re.compile(r"[A-Za-z0-9._~+/=-]{8,512}")
MAX_SESSION_LIFETIME = 366 * 24 * 3600.0


@dataclass(frozen=True)
class Endpoint:
    """The backend's origin, for example ``http://127.0.0.1:8765`` or ``http://[::1]:8765``."""

    origin: str

    @property
    def cookie_url(self) -> str:
        """The URL the session cookie is installed for: it makes the cookie host-only on this origin."""
        return f"{self.origin}/"

    @property
    def session_url(self) -> str:
        return f"{self.origin}{SESSION_PATH}"


@dataclass(frozen=True)
class Session:
    """A session the backend minted. The id is a credential: it is never part of ``repr`` or a message."""

    session_id: str = field(repr=False)
    expires_in: float
    minted_at: float  # wall-clock seconds (time.time) when the reply arrived

    @property
    def expires_at(self) -> float:
        return self.minted_at + self.expires_in


def parse_endpoint(text: str) -> Endpoint:
    """The origin the endpoint file names, or ``KioskError``. Only ``http://<loopback literal>:<port>`` is accepted."""
    candidate = text.strip()
    try:
        parts = urlsplit(candidate)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise KioskError("the endpoint file does not hold a valid URL") from None
    if parts.scheme != "http" or host is None or port is None or not 1 <= port <= 65535:
        raise KioskError("the endpoint file must hold http://<loopback address>:<port>")
    if parts.username is not None or parts.password is not None or parts.path not in ("", "/"):
        raise KioskError("the endpoint file must hold an origin only: no credentials and no path")
    if parts.query or parts.fragment or "?" in candidate or "#" in candidate:
        raise KioskError("the endpoint file must hold an origin only: no query and no fragment")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise KioskError("the endpoint host must be a literal loopback address") from None
    # The bearer token is sent to this address: never to anything that is not this machine. The same rule as the
    # backend's own host setting: 127.0.0.0/8 or exactly ::1 (no IPv4-mapped or scoped IPv6 forms).
    is_loopback = address.is_loopback if address.version == 4 else address == ipaddress.IPv6Address("::1")
    if not is_loopback:
        raise KioskError("the endpoint host must be a loopback address, refusing to send the token elsewhere")
    shown = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return Endpoint(origin=f"http://{shown}:{port}")


def _read_published(path: Path, what: str) -> str | None:
    """The text of a file the backend publishes, None while it does not exist yet, ``KioskError`` when unusable."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KioskError(f"cannot read the {what} file {path}: {exc.strerror or exc.__class__.__name__}") from None
    if len(raw) > MAX_FILE_BYTES:
        raise KioskError(f"the {what} file {path} is larger than {MAX_FILE_BYTES} bytes")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        raise KioskError(f"the {what} file {path} is not ASCII text") from None


def _parse_token(text: str) -> str:
    token = text.strip()
    if not _SECRET_FORMAT.fullmatch(token):
        raise KioskError("the token file does not hold a token of the expected form")
    return token


def wait_for_handoff(endpoint_file: Path, token_file: Path, timeout: float) -> tuple[Endpoint, str]:
    """Wait up to ``timeout`` seconds for the backend to publish both files, then return the endpoint and the token.

    A file that exists but cannot be used (unreadable, not text, malformed) fails at once: waiting would not fix it.
    """
    deadline = time.monotonic() + timeout
    while True:
        endpoint_text = _read_published(endpoint_file, "endpoint")
        token_text = _read_published(token_file, "token")
        if endpoint_text is not None and token_text is not None:
            return parse_endpoint(endpoint_text), _parse_token(token_text)
        if time.monotonic() >= deadline:
            published = ((endpoint_file, endpoint_text), (token_file, token_text))
            missing = [str(path) for path, text in published if text is None]
            raise KioskError(f"the backend did not publish {' and '.join(missing)} within {timeout:g} s")
        time.sleep(POLL_INTERVAL)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect would resend the Authorization header wherever the reply points: refuse to follow any."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def _opener() -> urllib.request.OpenerDirector:
    """No proxies (the environment's proxy settings must never see the token) and no redirects."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())


def _fail(message: str) -> NoReturn:
    raise KioskError(message)


def _parse_session(body: bytes, minted_at: float) -> Session:
    try:
        reply = json.loads(body)
    except ValueError:
        _fail("the backend's session reply is not JSON")
    if not isinstance(reply, dict):
        _fail("the backend's session reply is not a JSON object")
    session_id = reply.get("session_id")
    expires_in = reply.get("expires_in")
    if not isinstance(session_id, str) or not _SECRET_FORMAT.fullmatch(session_id):
        _fail("the backend's session reply has no usable session_id")
    if isinstance(expires_in, bool) or not isinstance(expires_in, int | float):
        _fail("the backend's session reply has no numeric expires_in")
    if not math.isfinite(expires_in) or not 0 < expires_in <= MAX_SESSION_LIFETIME:
        _fail("the backend's session reply has an expires_in outside the accepted range")
    return Session(session_id=session_id, expires_in=float(expires_in), minted_at=minted_at)


def mint_session(endpoint: Endpoint, token: str, *, timeout: float, retry_for: float) -> Session:
    """``POST /v1/session`` with the bearer token and return the session it grants.

    Failing to connect is retried for up to ``retry_for`` seconds (the backend may be restarting); an HTTP answer
    of any kind is final, because a retry would only repeat it. Each attempt waits at most ``timeout`` seconds.
    """
    deadline = time.monotonic() + retry_for
    while True:
        request = urllib.request.Request(  # noqa: S310 - the scheme is http and the host loopback: parse_endpoint
            endpoint.session_url,
            data=b"",
            method="POST",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with _opener().open(request, timeout=timeout) as response:
                status = response.status
                body = response.read(MAX_REPLY_BYTES + 1)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 401:
                raise KioskError(
                    "the backend refused the bearer token (HTTP 401): the token file is stale or the backend restarted"
                ) from None
            if exc.code == 404:
                raise KioskError(f"the backend has no {SESSION_PATH} endpoint (HTTP 404)") from None
            raise KioskError(f"the backend answered {SESSION_PATH} with HTTP {exc.code}") from None
        except (urllib.error.URLError, HTTPException, OSError) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            if time.monotonic() >= deadline:
                raise KioskError(f"cannot reach the backend at {endpoint.origin}: {reason}") from None
            time.sleep(RETRY_INTERVAL)
            continue
        minted_at = time.time()
        if status != 201:
            raise KioskError(f"the backend answered {SESSION_PATH} with HTTP {status}, expected 201")
        if len(body) > MAX_REPLY_BYTES:
            raise KioskError("the backend's session reply is unreasonably large")
        return _parse_session(body, minted_at)
