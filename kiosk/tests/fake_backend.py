"""A real HTTP server on a loopback port that plays the backend's side of the session handoff.

It follows docs/architecture/KIOSK_SESSION_DESIGN.md: ``POST /v1/session`` accepts the bearer token only and mints a
session; every other path accepts the ``pai_session`` cookie only. It records every request so a test can assert the
exact sequence and where each secret travelled. Behaviours a test needs (wrong status, garbage body, redirect, delay,
failure on the n-th mint) are options.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

TOKEN = "T" + "x" * 41 + "0"  # looks like secrets.token_urlsafe(32): 43 URL-safe characters


@dataclass
class Recorded:
    method: str
    path: str
    headers: dict[str, str]  # lower-case names
    body: bytes


@dataclass
class FakeBackend:
    token: str = TOKEN
    ttl: float = 3600
    mint_status: int = 201
    mint_body: bytes | None = None  # sent instead of the real reply when set
    mint_delay: float = 0.0
    redirect_to: str | None = None
    redirect_status: int = 302  # 301, 302 and 303 make urllib resend a POST as a GET with its headers
    fail_mint_from: int | None = None  # the n-th and later mints (1-based) answer 500
    reject_sessions: bool = False  # every cookie is refused, as if the browser had no valid session
    requests: list[Recorded] = field(default_factory=list)
    issued: list[str] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ------------------------------------------------------------------ lifecycle
    def start(self, port: int = 0) -> FakeBackend:
        backend = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                backend._handle(self)

            def do_GET(self) -> None:
                backend._handle(self)

            def log_message(self, *_args: object) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.server_address[1])

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> FakeBackend:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # ------------------------------------------------------------------ requests
    def posts(self) -> list[Recorded]:
        return [r for r in self.requests if r.method == "POST"]

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length) if length else b""
        headers = {name.lower(): value for name, value in handler.headers.items()}
        with self._lock:
            self.requests.append(Recorded(handler.command, handler.path, headers, body))
        if handler.command == "POST" and handler.path == "/v1/session":
            self._mint(handler, headers)
        else:
            self._page(handler, headers)

    def _reply(self, handler: BaseHTTPRequestHandler, status: int, body: bytes, *, location: str | None = None) -> None:
        content_type = "text/html" if status == 200 else "application/json"
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        if location is not None:
            handler.send_header("Location", location)
        handler.end_headers()
        handler.wfile.write(body)

    def _mint(self, handler: BaseHTTPRequestHandler, headers: dict[str, str]) -> None:
        if self.mint_delay:
            time.sleep(self.mint_delay)
        if headers.get("authorization") != f"Bearer {self.token}":
            self._reply(handler, 401, b'{"error":"unauthorized"}')
            return
        with self._lock:
            mints = len(self.issued) + 1
        if self.redirect_to is not None:
            self._reply(handler, self.redirect_status, b"", location=self.redirect_to)
        elif self.fail_mint_from is not None and mints >= self.fail_mint_from:
            self._reply(handler, 500, b'{"error":"internal"}')
        elif self.mint_body is not None:
            self._reply(handler, self.mint_status, self.mint_body)
        else:
            session_id = secrets.token_urlsafe(32)
            with self._lock:
                self.issued.append(session_id)
            reply: dict[str, Any] = {"session_id": session_id, "expires_in": self.ttl}
            self._reply(handler, self.mint_status, json.dumps(reply).encode())

    def _page(self, handler: BaseHTTPRequestHandler, headers: dict[str, str]) -> None:
        cookies = dict(part.strip().split("=", 1) for part in headers.get("cookie", "").split(";") if "=" in part)
        if "authorization" in headers or self.reject_sessions or cookies.get("pai_session") not in self.issued:
            self._reply(handler, 401, b'{"error":"unauthorized"}')
        else:
            self._reply(handler, 200, b"<!doctype html><title>ui</title>")
