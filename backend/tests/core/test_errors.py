"""The error hierarchy: stable unique codes, valid statuses, and messages that are fixed class constants."""

from __future__ import annotations

from backend.core.errors import AppError, error_body


def _all_errors() -> list[type[AppError]]:
    found: list[type[AppError]] = []
    pending = [AppError]
    while pending:
        current = pending.pop()
        found.append(current)
        pending.extend(current.__subclasses__())
    return found


def test_codes_are_unique_and_machine_readable() -> None:
    codes = [error.code for error in _all_errors()]
    assert len(codes) == len(set(codes))
    assert all(code.isidentifier() and code == code.lower() for code in codes)


def test_statuses_are_http_errors() -> None:
    assert all(400 <= error.status <= 599 for error in _all_errors())


def test_base_error_is_the_generic_internal_error() -> None:
    assert (AppError.status, AppError.code) == (500, "internal_error")


def test_message_is_fixed_and_ignores_constructor_arguments() -> None:
    error = AppError("/etc/shadow password=hunter2")
    assert error.message == AppError.message
    assert "hunter2" not in error.message


def test_error_body_shape() -> None:
    assert error_body("not_found", "Resource not found") == {
        "error": {"code": "not_found", "message": "Resource not found"}
    }
