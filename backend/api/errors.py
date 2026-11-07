"""Turns every failure into the one JSON error shape: ``{"error": {"code": ..., "message": ...}}``.

Handlers never read the exception they receive beyond its type (and, for HTTP errors, status and headers),
so exception text, paths and secrets cannot leak into a response body. A validation failure is also logged,
by its fixed error-type codes only (``int_parsing``, ``missing``, ...): never the input and never a field name,
which a client can choose.
"""

from __future__ import annotations

import logging
from typing import cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from backend.core.errors import AppError, MethodNotAllowed, NotFound, ValidationFailed, error_body

logger = logging.getLogger(__name__)

# Status codes Starlette's router raises on its own, mapped to the matching application error.
_ROUTING_ERRORS: dict[int, type[AppError]] = {404: NotFound, 405: MethodNotAllowed}
_UNMAPPED_HTTP_MESSAGE = "Request failed"


def error_response(error: AppError) -> JSONResponse:
    return JSONResponse(error_body(error.code, error.message), status_code=error.status, headers=dict(error.headers))


async def _handle_app_error(_request: Request, exc: Exception) -> JSONResponse:
    return error_response(exc if isinstance(exc, AppError) else AppError())


async def _handle_http_error(_request: Request, exc: Exception) -> JSONResponse:
    http_error = cast(StarletteHTTPException, exc)
    headers = dict(http_error.headers or {})  # framework-set, e.g. Allow on a 405
    known = _ROUTING_ERRORS.get(http_error.status_code)
    if known is not None:
        return JSONResponse(error_body(known.code, known.message), status_code=known.status, headers=headers)
    body = error_body("http_error", _UNMAPPED_HTTP_MESSAGE)
    return JSONResponse(body, status_code=http_error.status_code, headers=headers)


async def _handle_validation_error(_request: Request, exc: Exception) -> JSONResponse:
    error_types = sorted({str(item["type"]) for item in cast(RequestValidationError, exc).errors()})
    logger.info("request validation failed", extra={"error_types": error_types})
    return error_response(ValidationFailed())


async def _handle_unexpected(_request: Request, _exc: Exception) -> JSONResponse:
    # The server still logs the traceback (uvicorn does, after this response is sent); the client gets nothing.
    return error_response(AppError())


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _handle_app_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(Exception, _handle_unexpected)
