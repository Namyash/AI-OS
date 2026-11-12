"""Redaction: neither the token nor a session id can reach a log line, however a message is built."""

from __future__ import annotations

import io
import logging
import time

import pytest

from kiosk.log import REDACTED, RedactionFilter, configure_logging, redact, register_secret

SECRET = "s3cr3t-value-0123456789abcdef"  # noqa: S105 - a test value, not a credential


def test_a_registered_secret_is_masked_wherever_it_appears() -> None:
    register_secret(SECRET)
    assert redact(f"before {SECRET} after {SECRET}") == f"before {REDACTED} after {REDACTED}"
    assert redact(f"embedded:x{SECRET}y") == f"embedded:x{REDACTED}y"


def test_a_secret_that_is_too_short_to_mask_safely_is_refused() -> None:
    with pytest.raises(ValueError, match="at least"):
        register_secret("short")


def test_an_unregistered_value_is_left_alone() -> None:
    assert redact("session minted, valid for 43200 s") == "session minted, valid for 43200 s"


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer abc.def-123",
        "sent header authorization=Bearer abc.def-123 to backend",
        "bearer abc.def-123",
        "Bearer   abc.def-123",
    ],
)
def test_a_bearer_credential_is_masked_even_when_it_was_never_registered(text: str) -> None:
    assert "abc.def-123" not in redact(text)


@pytest.mark.parametrize(
    "text",
    [
        "pai_session=abc123xyz",
        "Cookie: pai_session=abc123xyz; other=1",
        "token: abc123xyz",
        "PAI_TOKEN_FILE=abc123xyz",
        'session_id="abc123xyz"',
        "password = abc123xyz",
    ],
)
def test_the_value_of_a_credential_key_is_masked(text: str) -> None:
    assert "abc123xyz" not in redact(text)


def test_the_key_stays_readable_so_the_log_still_says_what_was_hidden() -> None:
    assert redact("pai_session=abc123xyz") == f"pai_session={REDACTED}"


def _log_through_a_real_handler(*messages: str) -> str:
    stream = io.StringIO()
    logger = configure_logging(stream)
    for message in messages:
        logger.error(message)
    return stream.getvalue()


def test_the_handler_masks_what_a_log_call_formats_and_what_an_exception_carries() -> None:
    register_secret(SECRET)
    stream = io.StringIO()
    logger = configure_logging(stream)
    logger.warning("value is %s", SECRET)
    try:
        raise RuntimeError(f"failure mentioning {SECRET}")
    except RuntimeError:
        logger.exception("it broke")
    output = stream.getvalue()
    assert SECRET not in output
    assert output.count(REDACTED) >= 2
    assert "it broke" in output
    assert "RuntimeError" in output


def test_a_record_that_cannot_be_scrubbed_is_replaced_not_emitted(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(_text: str) -> str:
        raise RuntimeError("redaction bug")

    monkeypatch.setattr("kiosk.log.redact", explode)
    record = logging.LogRecord("kiosk", logging.ERROR, __file__, 1, "contains a secret", (), None)
    assert RedactionFilter().filter(record) is True
    assert record.getMessage() == "log record suppressed: redaction failed"


def test_configuring_twice_does_not_duplicate_output() -> None:
    first, second = io.StringIO(), io.StringIO()
    configure_logging(first)
    configure_logging(second).error("once")
    assert first.getvalue() == ""
    assert second.getvalue().count("once") == 1


def test_the_record_does_not_leak_through_a_parent_logger() -> None:
    root_stream = io.StringIO()
    root_handler = logging.StreamHandler(root_stream)
    logging.getLogger().addHandler(root_handler)
    try:
        _log_through_a_real_handler("quiet")
    finally:
        logging.getLogger().removeHandler(root_handler)
    assert root_stream.getvalue() == ""


@pytest.mark.parametrize(
    "hostile",
    ["a" * 200_000, "token" + "=" * 100_000, "x-" * 100_000 + "token", "Bearer " + "a" * 200_000, ("key=" * 50_000)],
)
def test_redaction_time_stays_linear_on_adversarial_input(hostile: str) -> None:
    register_secret(SECRET)
    started = time.perf_counter()
    redact(hostile)
    assert time.perf_counter() - started < 2.0
