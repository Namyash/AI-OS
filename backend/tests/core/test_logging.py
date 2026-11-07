"""Structured logging: one JSON object per line on stdout, with secrets masked before anything is written."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterator

import pytest

from backend.core.logging import (
    REDACTED,
    JsonFormatter,
    RedactionFilter,
    configure_logging,
    redact_text,
    redact_value,
    register_secret,
)

Emit = Callable[..., dict[str, object]]


@pytest.fixture
def root_logging_restored() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


@pytest.fixture
def emit(capsys: pytest.CaptureFixture[str], root_logging_restored: None) -> Emit:
    """The returned function logs one record through real logging and returns its parsed JSON line."""
    logger = logging.getLogger("test.redaction")

    def _emit(message: str, *args: object, **kwargs: object) -> dict[str, object]:
        # Configured per call, not in the fixture: the handler must bind the stdout capsys has active right now.
        configure_logging("debug")
        capsys.readouterr()
        logger.info(message, *args, **kwargs)
        lines = capsys.readouterr().out.splitlines()
        assert len(lines) == 1, lines
        return json.loads(lines[0])

    return _emit


# ------------------------------------------------------------------ text redaction
@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Bearer abc.DEF-123_xyz~+/=", "abc.DEF-123_xyz"),
        ("retrying with bearer S3cr3tValue99 after failure", "S3cr3tValue99"),
        ("password=hunter2 user=sam", "hunter2"),
        ("PASSWORD: Tr0ub4dor&3", "Tr0ub4dor&3"),
        ('payload {"api_key": "AKIAEXAMPLE0001", "name": "x"}', "AKIAEXAMPLE0001"),
        ("client_secret='my quoted secret value'", "my quoted secret value"),
        ("token: abcdef123456", "abcdef123456"),
        ("X-Auth-Token=zzz999yyy", "zzz999yyy"),
        ('headers {"Authorization": "Basic dXNlcjpwYXNz"}', "dXNlcjpwYXNz"),
        ("cookie: session=abc123def456", "abc123def456"),
        ("private_key=-----BEGINKEYDATA", "-----BEGINKEYDATA"),
    ],
)
def test_secrets_in_messages_are_masked(text: str, secret: str) -> None:
    redacted = redact_text(text)
    assert secret not in redacted
    assert REDACTED in redacted


def test_non_secret_text_is_untouched() -> None:
    text = "listening on 127.0.0.1:8765 schema_version=1 user=sam applied_migrations=[1]"
    assert redact_text(text) == text


def test_redaction_keeps_the_key_and_unrelated_fields() -> None:
    assert redact_text("password=hunter2 user=sam") == f"password={REDACTED} user=sam"


def test_redaction_is_idempotent() -> None:
    once = redact_text("Authorization: Bearer abc123def456 password=x1y2z3w4")
    assert redact_text(once) == once


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
        ("Authorization: Token abcdef0123456789", "abcdef0123456789"),
        ("Proxy-Authorization: Negotiate YIIabcdef", "YIIabcdef"),
        ("Authorization: Digest username=sam, response=abc123def", "abc123def"),
        ("authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("Cookie: a=1; sessionid=zzz999yyy", "zzz999yyy"),
        ("Set-Cookie: sid=zzz999yyy; Path=/; HttpOnly", "zzz999yyy"),
        ("token: Bearer abc123def456", "abc123def456"),
        ("data=password=hunter2", "hunter2"),  # a harmless key must not hide a secret-bearing pair in its value
    ],
)
def test_the_whole_credential_is_masked_whatever_the_scheme(text: str, secret: str) -> None:
    assert secret not in redact_text(text)


def test_a_header_value_is_masked_to_the_end_of_its_line_only() -> None:
    redacted = redact_text("Authorization: Basic abc123\nHost: 127.0.0.1:8765\nCookie: a=1; b=2\nX-Other: kept")
    assert redacted == f"Authorization: {REDACTED}\nHost: 127.0.0.1:8765\nCookie: {REDACTED}\nX-Other: kept"


# Redaction runs synchronously on the event loop for every record, so its cost must stay linear in the text.
# Each input defeats a different shortcut: a long word, a word made only of sensitive names, sensitive keys with
# separators and quotes, and runs of spaces, quotes and Bearer prefixes. The old pattern needed 2-4 s for 30 KB
# of "key"; the budget is generous so a slow CI machine does not fail it, yet far below that.
REDACTION_BUDGET_SECONDS = 1.0
ADVERSARIAL_INPUTS = {
    "long word": "a" * 300_000,
    "sensitive word run": "key" * 100_000,
    "mixed sensitive run": "tokenkeypassword-secret." * 20_000,
    "many assignments": "password=x " * 40_000,
    "unterminated quotes": 'password="x ' * 40_000,
    "header lines": "Authorization: Basic abc\n" * 20_000,
    "spaces": "key" + " " * 300_000,
    "quote run": '"' * 300_000,
    "bearer prefixes": "Bearer " * 40_000,
}


@pytest.mark.parametrize("text", ADVERSARIAL_INPUTS.values(), ids=ADVERSARIAL_INPUTS.keys())
def test_redaction_time_is_linear_even_on_adversarial_input(text: str) -> None:
    started = time.perf_counter()
    redact_text(text)
    assert time.perf_counter() - started < REDACTION_BUDGET_SECONDS


def test_a_secret_is_still_found_at_the_end_of_a_very_long_record() -> None:
    assert redact_text("key" * 100_000 + " password=hunter2").endswith(f"password={REDACTED}")


# ------------------------------------------------------------------ registered secrets
def test_registered_secret_is_masked_anywhere() -> None:
    secret = "plain-secret-value-0123456789"  # noqa: S105 - test fixture, not a credential
    register_secret(secret)
    assert redact_text(f"unexpectedly logged {secret} in prose") == f"unexpectedly logged {REDACTED} in prose"


def test_registering_a_short_secret_is_refused() -> None:
    # An empty or tiny registration would mask ordinary text everywhere.
    with pytest.raises(ValueError, match="at least"):
        register_secret("")


# ------------------------------------------------------------------ structured values
def test_sensitive_keys_mask_their_whole_value() -> None:
    assert redact_value("api_key", {"nested": "x"}) == REDACTED
    assert redact_value("Authorization", "anything") == REDACTED
    assert redact_value("user_password", None) == REDACTED


def test_nested_structures_are_scrubbed_recursively() -> None:
    value = {"outer": {"password": "p1", "ok": 1}, "items": [{"token": "t1"}, "Bearer zzz111aaa"], "n": None}
    assert redact_value("data", value) == {
        "outer": {"password": REDACTED, "ok": 1},
        "items": [{"token": REDACTED}, f"Bearer {REDACTED}"],
        "n": None,
    }


def test_self_referencing_structures_cannot_recurse_forever() -> None:
    loop: dict[str, object] = {}
    loop["me"] = loop
    assert "[TRUNCATED]" in json.dumps(redact_value("data", loop))


# ------------------------------------------------------------------ end to end through the handler
def test_output_is_one_json_object_per_record(emit: Emit) -> None:
    record = emit("started on port %d", 8765, extra={"applied_migrations": [1]})
    assert record["message"] == "started on port 8765"
    assert record["level"] == "info"
    assert record["logger"] == "test.redaction"
    assert record["applied_migrations"] == [1]
    assert str(record["ts"]).endswith("+00:00")


def test_message_arguments_are_redacted_after_formatting(emit: Emit) -> None:
    record = emit("sent header %s", "Authorization: Bearer abc123def456")
    assert "abc123def456" not in json.dumps(record)


def test_extra_fields_are_redacted(emit: Emit) -> None:
    record = emit("login", extra={"password": "hunter2", "note": "token=abc999xyz", "attempt": 3})
    assert record["password"] == REDACTED
    assert record["note"] == f"token={REDACTED}"
    assert record["attempt"] == 3


def test_exception_text_is_redacted_but_keeps_the_error_type(
    capsys: pytest.CaptureFixture[str], root_logging_restored: None
) -> None:
    configure_logging("info")
    try:
        raise RuntimeError("upstream said password=hunter2")
    except RuntimeError:
        logging.getLogger("test.exc").exception("call failed")
    record = json.loads(capsys.readouterr().out)
    assert "hunter2" not in json.dumps(record)
    assert "RuntimeError" in record["exception"]


def test_core_keys_cannot_be_overridden_by_extras(emit: Emit) -> None:
    record = emit("hello", extra={"level": "spoofed", "logger": "spoofed", "ts": "spoofed"})
    assert (record["level"], record["logger"]) == ("info", "test.redaction")
    assert record["ts"] != "spoofed"


def test_uvicorn_colour_duplicate_is_not_emitted(emit: Emit) -> None:
    record = emit("Uvicorn running", extra={"color_message": "\x1b[32mUvicorn\x1b[0m"})
    assert "color_message" not in record


def test_unscrubbable_record_is_suppressed_not_emitted(emit: Emit) -> None:
    class Hostile:
        def __str__(self) -> str:
            raise RuntimeError("cannot stringify")

    record = emit("password=hunter2 about to fail", extra={"payload": Hostile()})
    assert record["message"] == "log record suppressed: redaction failed"
    assert "hunter2" not in json.dumps(record)
    assert "payload" not in record


def test_records_from_third_party_loggers_are_covered(
    capsys: pytest.CaptureFixture[str], root_logging_restored: None
) -> None:
    # The filter sits on the handler, so records propagated from any logger (uvicorn, httpx, ...) are scrubbed.
    configure_logging("info")
    logging.getLogger("uvicorn.error").info("request carried Bearer abc123def456")
    assert "abc123def456" not in capsys.readouterr().out


# ------------------------------------------------------------------ configuration
def test_configure_logging_is_idempotent_and_sets_the_level(root_logging_restored: None) -> None:
    configure_logging("warning")
    configure_logging("error")
    root = logging.getLogger()
    ours = [h for h in root.handlers if isinstance(h.formatter, JsonFormatter)]
    assert len(ours) == 1
    assert any(isinstance(f, RedactionFilter) for f in ours[0].filters)
    assert root.level == logging.ERROR


def test_configure_logging_leaves_foreign_handlers_alone(root_logging_restored: None) -> None:
    foreign = logging.NullHandler()
    logging.getLogger().addHandler(foreign)
    configure_logging("info")
    assert foreign in logging.getLogger().handlers
