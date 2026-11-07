"""Boundary guard: the checks every request must pass before any route (or any error page) is reached.

Pure ASGI, not route dependencies, so it covers everything the app serves, including ``/openapi.json`` and
unknown paths. Checks run in a fixed order and the first failure ends the request:

1. ``Host`` must be a loopback name on the service port: ``127.0.0.1``, ``localhost``, ``[::1]`` or the literal
   address the service is bound to (defeats DNS rebinding).
2. If ``Origin`` is present it must be exactly ``http://<Host>`` (same origin); there is no CORS.
3. ``Authorization: Bearer <token>`` must match the per-start token (constant-time comparison).

A rejected request is logged as a warning with its reason code and nothing else: never a header value, the path or
the query string, so a token-guessing attempt leaves a trace without the log holding anything an attacker sent.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable

from starlette.types import ASGIApp, Receive, Scope, Send

from backend.api.auth import TokenAuthenticator
from backend.api.errors import error_response
from backend.core.errors import AppError, ForbiddenOrigin, InvalidHost, Unauthorized

logger = logging.getLogger(__name__)

LOOPBACK_HOST_NAMES = ("127.0.0.1", "localhost", "[::1]")
_WEBSOCKET_POLICY_VIOLATION = 1008
_WATCHED_HEADERS = (b"host", b"origin", b"authorization")


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


def allowed_host_headers(bind_host: str, port: int) -> frozenset[str]:
    """The ``Host`` header values a service bound to the literal loopback address ``bind_host`` accepts.

    Settings accepts any literal in 127.0.0.0/8 (and ``::1``) as the bind address; a client of such a service
    addresses it by that literal, so it must be accepted along with the usual loopback names.
    """
    address = ipaddress.ip_address(bind_host)
    literal = f"[{address.compressed}]" if address.version == 6 else str(address)
    return frozenset(f"{name}:{port}" for name in (*LOOPBACK_HOST_NAMES, literal))


class BoundaryGuard:
    def __init__(self, app: ASGIApp, *, host: str, port: int, authenticator: TokenAuthenticator) -> None:
        self._app = app
        self._allowed_hosts = allowed_host_headers(host, port)
        self._authenticator = authenticator

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:  # lifespan
            await self._app(scope, receive, send)
            return
        violation = self._violation(scope["headers"])
        if violation is None:
            await self._app(scope, receive, send)
            return
        logger.warning("request rejected", extra={"reason": violation.code})
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": _WEBSOCKET_POLICY_VIOLATION})
        else:
            await error_response(violation)(scope, receive, send)

    def _violation(self, headers: Iterable[tuple[bytes, bytes]]) -> AppError | None:
        found: dict[bytes, list[bytes]] = {name: [] for name in _WATCHED_HEADERS}
        for name, value in headers:
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

        if not self._authenticator.verify(_bearer_credentials(found[b"authorization"])):
            return Unauthorized()
        return None
