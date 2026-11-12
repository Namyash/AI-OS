"""Browser sessions: an in-memory store of expiring, revocable credentials, and the endpoints that mint and revoke them.

The kiosk's browser never holds the bearer token. The launcher, which does, trades it for a session id
(``POST /v1/session``) and hands that to the browser as the ``pai_session`` cookie (the server never sets a cookie).
A session id is 256 random bits; the store keeps only its SHA-256 hash, compared in constant time, so a read of the
store's memory yields nothing a client can present. Sessions live in memory only: a restart ends every one of them.
They have an absolute lifetime (``Settings.session_ttl``), at most ``MAX_SESSIONS`` are alive at once (minting another
evicts the oldest), and expired ones are dropped on every use, so the store never holds more than ``MAX_SESSIONS``
entries.

Live ids are registered with the log redaction filter (like the token) and taken out again when their session ends.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
from collections import OrderedDict
from time import monotonic

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from backend.api.auth import Caller, Credential, caller_from_scope, issue_token
from backend.core.errors import Unauthorized
from backend.core.logging import register_secret, unregister_secret

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "pai_session"
SESSION_PATH = "/v1/session"
MAX_SESSIONS = 8
# A session id is 43 characters; anything much longer is not one, so it is not even hashed.
_MAX_PRESENTED_BYTES = 128


def _digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


class SessionStore:
    """The live sessions, as ``{hash of id: deadline}`` oldest first. Safe to call from any thread."""

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._deadlines: OrderedDict[bytes, float] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    def __len__(self) -> int:
        with self._lock:
            self._drop_expired()
            return len(self._deadlines)

    def create(self) -> str:
        """Mint a session and return its id, the only time the id exists outside the client that holds it."""
        session_id = issue_token()  # the same kind of secret as the token: 256 random bits, URL-safe
        key = _digest(session_id.encode("ascii"))
        with self._lock:
            self._drop_expired()
            while len(self._deadlines) >= MAX_SESSIONS:
                self._forget(next(iter(self._deadlines)))
            self._deadlines[key] = monotonic() + self._ttl_seconds
            register_secret(session_id, owner=key.hex())
        return session_id

    def authenticate(self, presented: bytes) -> bytes | None:
        """The key of the live session whose id is ``presented``, or None.

        Every live session is compared, without stopping at the first match, so the time taken does not say
        which one matched or how much of a guess was right.
        """
        if not presented or len(presented) > _MAX_PRESENTED_BYTES:
            return None
        candidate = _digest(presented)
        match: bytes | None = None
        with self._lock:
            self._drop_expired()
            for key in self._deadlines:
                if secrets.compare_digest(key, candidate):
                    match = key
        return match

    def revoke(self, key: bytes) -> None:
        """End the session with this key (as returned by ``authenticate``). An unknown key is ignored."""
        with self._lock:
            if key in self._deadlines:
                self._forget(key)

    def _drop_expired(self) -> None:
        now = monotonic()  # does not count time the machine is suspended: a lifetime is time spent running
        for key, deadline in list(self._deadlines.items()):
            if deadline <= now:
                self._forget(key)

    def _forget(self, key: bytes) -> None:
        del self._deadlines[key]
        unregister_secret(key.hex())


class SessionCreated(BaseModel):
    session_id: str
    expires_in: int


def _caller(request: Request) -> Caller:
    caller = caller_from_scope(request.scope)
    if caller is None:  # the guard did not run for this request: refuse rather than assume
        raise Unauthorized
    return caller


def session_router(store: SessionStore) -> APIRouter:
    router = APIRouter()

    # `async def`: nothing here blocks (no I/O), so it runs on the event loop with the guard that authenticated it.
    @router.post(SESSION_PATH, status_code=201, response_model=SessionCreated)
    async def create_session(request: Request, response: Response) -> SessionCreated:
        # Minting needs the token itself: a session (a browser cookie) must not be able to create more of itself.
        if _caller(request).credential is not Credential.BEARER:
            logger.warning("request rejected", extra={"reason": Unauthorized.code})
            raise Unauthorized
        response.headers["Cache-Control"] = "no-store"
        return SessionCreated(session_id=store.create(), expires_in=store.ttl_seconds)

    @router.delete(SESSION_PATH, status_code=204, response_class=Response)
    async def revoke_session(request: Request) -> Response:
        # Revokes the session this request was authenticated by. A request authenticated by the token has no
        # session, so there is nothing to revoke: the answer is the same.
        caller = _caller(request)
        if caller.session_key is not None:
            store.revoke(caller.session_key)
        return Response(status_code=204)

    return router
