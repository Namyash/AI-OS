"""Application errors: a stable machine-readable code plus an HTTP status and a fixed, client-safe message.

Messages are class constants on purpose. Nothing a caller passes in (exception text, file paths, secrets)
can reach a response body, so an error response can only ever say what the class says.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import ClassVar


def error_body(code: str, message: str) -> dict[str, dict[str, str]]:
    """The one JSON error shape every API response uses."""
    return {"error": {"code": code, "message": message}}


class AppError(Exception):
    """Base class. Used as-is it is the generic internal error: the client learns nothing but that it failed."""

    status: ClassVar[int] = 500
    code: ClassVar[str] = "internal_error"
    message: ClassVar[str] = "Internal server error"
    headers: ClassVar[Mapping[str, str]] = MappingProxyType({})


class InvalidHost(AppError):
    status = 400
    code = "invalid_host"
    message = "Invalid Host header"


class Unauthorized(AppError):
    status = 401
    code = "unauthorized"
    message = "Authentication required"
    headers = MappingProxyType({"WWW-Authenticate": "Bearer"})


class ForbiddenOrigin(AppError):
    status = 403
    code = "forbidden_origin"
    message = "Cross-origin requests are not allowed"


class NotFound(AppError):
    status = 404
    code = "not_found"
    message = "Resource not found"


class MethodNotAllowed(AppError):
    status = 405
    code = "method_not_allowed"
    message = "Method not allowed"


class ValidationFailed(AppError):
    status = 422
    code = "validation_error"
    message = "The request is invalid"


class DatabaseUnavailable(AppError):
    status = 503
    code = "database_unavailable"
    message = "The database is unavailable"
