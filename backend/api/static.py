"""The UI shell: the built frontend, served from ``Settings.static_dir`` at ``/`` behind the same guard as the API.

Starlette's ``StaticFiles`` does the serving: it normalises the path, refuses anything that resolves (symbolic links
included) to somewhere outside the directory, and handles HEAD, ETag and conditional requests. This module adds what
is specific to this service:

- the files answer only what no API route claims, so ``/health`` and the rest of the API can never be shadowed by a
  file of the same name, and a wrong method on an API path keeps its own 405 and ``Allow`` header;
- ``/`` is ``index.html`` (no directory listings, no ``404.html``, no redirects), and every other miss is the one JSON
  error body of ``errors.py``, not a page;
- every response carries the security headers, and HTML is never cached, so a new build shows on the next load;
- a path no file system can hold (a NUL byte) is a plain miss, and a file or directory the service may not read is an
  internal error (a packaging fault, logged), never the 401 Starlette answers a directory with, which a client would
  read as "no valid session", nor a 200 that breaks off half way, which is what Starlette does for a file.

There is no unauthenticated route: the guard runs before any of this, so loading the shell itself needs the cookie.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Receive, Scope, Send

from backend.core.errors import AppError

logger = logging.getLogger(__name__)

INDEX_FILE = "index.html"
# Deny by default, allow the page's own origin only for what the UI actually loads. frontend/security-headers.ts
# holds the same policy (the dev preview server sends it); tests/security/test_csp_contract.py fails if they differ.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
_HTML_MEDIA_TYPES = ("text/html", "application/xhtml+xml")
_STARLETTE_UNREADABLE_STATUS = 401  # what StaticFiles answers when the operating system refuses to look at a path


def _cannot_read() -> AppError:
    logger.error("a UI file could not be read")  # no path: it came from the client
    return AppError()


class _UiFiles(StaticFiles):
    def lookup_path(self, path: str) -> tuple[str, os.stat_result | None]:
        try:
            return super().lookup_path(path)
        except ValueError:  # a NUL byte, or (on Windows) a path on another drive: there is no such file
            return "", None

    def file_response(
        self, full_path: os.PathLike[str] | str, stat_result: os.stat_result, scope: Scope, status_code: int = 200
    ) -> Response:
        if not os.access(full_path, os.R_OK):  # FileResponse would send "200" and only then fail to open the file
            raise _cannot_read()
        return super().file_response(full_path, stat_result, scope, status_code)

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(INDEX_FILE if path == "." else path, scope)
        except HTTPException as exc:
            if exc.status_code != _STARLETTE_UNREADABLE_STATUS:
                raise
            raise _cannot_read() from exc
        response.headers.update(SECURITY_HEADERS)
        if response.headers.get("content-type", "").startswith(_HTML_MEDIA_TYPES):
            response.headers["Cache-Control"] = "no-store"
        return response


def install_static_ui(app: FastAPI, directory: Path) -> bool:
    """Serve ``directory`` for every GET and HEAD that no route of ``app`` claims.

    Returns False, after a warning, when ``directory`` does not exist: the API then runs alone, as before. The
    check is made once, at start; a directory that appears later is picked up by the next start.
    """
    if not directory.is_dir():
        logger.warning("UI directory not found; serving the API only", extra={"static_dir": str(directory)})
        return False
    files = _UiFiles(directory=directory, check_dir=False)
    unclaimed = app.router.default  # what answers a path nothing matches: the JSON 404 (and a WebSocket close)

    async def serve(scope: Scope, receive: Receive, send: Send) -> None:
        reading = scope["type"] == "http" and scope["method"] in ("GET", "HEAD")
        await (files if reading else unclaimed)(scope, receive, send)

    app.router.default = serve
    return True
