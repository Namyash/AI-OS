"""Boundary guard: the checks every request must pass before any route (or any error page) is reached.

Pure ASGI, not route dependencies, so it covers everything the app serves, including ``/openapi.json``, the UI files
and unknown paths. Checks run in a fixed order and the first failure ends the request:

1. ``Host`` must be a loopback name on the service port: ``127.0.0.1``, ``localhost``, ``[::1]`` or the literal
   address the service is bound to (defeats DNS rebinding).
2. If ``Origin`` is present it must be exactly ``http://<Host>`` (same origin); there is no CORS.
3. The request must be authenticated, by exactly one of:

   - ``Authorization: Bearer <token>`` matching the per-start token (constant-time comparison); or
   - only when the request has no ``Authorization`` header at all, a ``pai_session`` cookie naming a live session.

   Any ``Authorization`` header means the bearer token or nothing: a wrong or malformed one fails even when a valid
   cookie comes with it. A request authenticated by cookie that could change state (anything but GET, HEAD or
   OPTIONS) must also carry an ``Origin`` header; with check 2 that makes it exactly its own origin. A browser
   attaches the cookie to whatever it is told to request, so this is what stops another page from using it.

The result is left in the request's scope for the routes (``caller_from_scope``); a route that needs the token
itself, not a session, asks for it there.

A rejected request is logged as a warning with its reason code and nothing else: never a header value, the path or
the query string, so a token-guessing attempt leaves a trace without the log holding anything an attacker sent.
"""

from __future__ import annotations

import logging

from starlette.types import ASGIApp, Receive, Scope, Send

from backend.api.auth import CALLER_STATE_KEY, Caller, Credential, TokenAuthenticator
from backend.api.errors import error_response
from backend.api.sessions import SESSION_COOKIE_NAME, SessionStore
from backend.core.config import host_literal
from backend.core.errors import AppError, ForbiddenOrigin, InvalidHost, Unauthorized

logger = logging.getLogger(__name__)

LOOPBACK_HOST_NAMES = ("127.0.0.1", "localhost", "[::1]")
_WEBSOCKET_POLICY_VIOLATION = 1008
_WATCHED_HEADERS = (b"host", b"origin", b"authorization", b"cookie")
# The only methods that are known not to change state. Anything else (an unknown method, a WebSocket upgrade) is
# treated as if it could.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_COOKIE_NAME = SESSION_COOKIE_NAME.encode("ascii")
_COOKIE_WHITESPACE = b" \t"
# Browsers send far less than this in one Cookie header; a longer one is not looked into.
_MAX_COOKIE_HEADER_BYTES = 16 * 1024


def _single(values: list[bytes]) -> bytes | None:
    """The header value, or None when it is repeated (ambiguous requests are refused, not guessed at)."""
    return values[0] if len(values) == 1 else None


def _bearer_credentials(values: list[bytes]) -> bytes:
    """The credentials of a single ``Authorization: Bearer ...`` header, or ``b""`` for anything else."""
    header = _single(values)
    if header is None:
        return b""
    scheme, _, credentials = header.partition(b" ")
    return credentials.strip(b" ") if scheme.lower() == b"bearer" else b""


def _session_cookie(values: list[bytes]) -> bytes | None:
    """The value of the one ``pai_session`` cookie in the request's ``Cookie`` headers, or None.

    None also covers every case that is not clear-cut, so none of them can authenticate: the cookie appears more
    than once (another web server on this host can plant a second cookie of the same name, and which of the two
    the browser would mean is not for the server to guess), it is empty, or a header is longer than a browser
    would send. Pairs that are not ``name=value`` are skipped, and the name is case-sensitive.
    """
    found: bytes | None = None
    for header in values:
        if len(header) > _MAX_COOKIE_HEADER_BYTES:
            return None
        for pair in header.split(b";"):
            name, separator, value = pair.partition(b"=")
            if separator and name.strip(_COOKIE_WHITESPACE) == _COOKIE_NAME:
                if found is not None:
                    return None
                found = value.strip(_COOKIE_WHITESPACE)
    return found or None


def _changes_state(scope: Scope) -> bool:
    return scope["type"] != "http" or scope["method"] not in _SAFE_METHODS


def allowed_host_headers(bind_host: str, port: int) -> frozenset[str]:
    """The ``Host`` header values a service bound to the literal loopback address ``bind_host`` accepts.

    Settings accepts any literal in 127.0.0.0/8 (and ``::1``) as the bind address; a client of such a service
    addresses it by that literal, so it must be accepted along with the usual loopback names.
    """
    return frozenset(f"{name}:{port}" for name in (*LOOPBACK_HOST_NAMES, host_literal(bind_host)))


class BoundaryGuard:
    def __init__(
        self, app: ASGIApp, *, host: str, port: int, authenticator: TokenAuthenticator, sessions: SessionStore
    ) -> None:
        self._app = app
        self._allowed_hosts = allowed_host_headers(host, port)
        self._authenticator = authenticator
        self._sessions = sessions

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:  # lifespan
            await self._app(scope, receive, send)
            return
        outcome = self._check(scope)
        if isinstance(outcome, Caller):
            scope.setdefault("state", {})[CALLER_STATE_KEY] = outcome
            await self._app(scope, receive, send)
            return
        logger.warning("request rejected", extra={"reason": outcome.code})
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": _WEBSOCKET_POLICY_VIOLATION})
        else:
            await error_response(outcome)(scope, receive, send)

    def _check(self, scope: Scope) -> Caller | AppError:
        """Who the request is, or why it is refused. Host, then Origin, then credentials; the first failure wins."""
        found: dict[bytes, list[bytes]] = {name: [] for name in _WATCHED_HEADERS}
        for name, value in scope["headers"]:
            if name in found:
                found[name].append(value)

        raw_host = _single(found[b"host"])
        host = raw_host.decode("latin-1").lower() if raw_host is not None else None
        if host not in self._allowed_hosts:
            return InvalidHost()

        if found[b"origin"]:
            origin = _single(found[b"origin"])
            if origin is None or origin.decode("latin-1").lower() != f"http://{host}":
                return ForbiddenOrigin()

        caller = self._authenticate(found)
        if caller is None:
            return Unauthorized()
        if caller.credential is Credential.SESSION and _changes_state(scope) and not found[b"origin"]:
            return ForbiddenOrigin()  # only a page of this origin names itself; the rest must not ride on the cookie
        return caller

    def _authenticate(self, found: dict[bytes, list[bytes]]) -> Caller | None:
        if found[b"authorization"]:  # the bearer token or nothing: a cookie cannot rescue a wrong token
            if self._authenticator.verify(_bearer_credentials(found[b"authorization"])):
                return Caller(Credential.BEARER)
            return None
        cookie = _session_cookie(found[b"cookie"])
        key = None if cookie is None else self._sessions.authenticate(cookie)
        return None if key is None else Caller(Credential.SESSION, key)
