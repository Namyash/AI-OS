"""Redaction and the Secret wrapper: a secret cannot reach a log line however a message is built."""

from __future__ import annotations

import io
import logging
import pickle

import pytest

from installer.log import LOGGER_NAME, REDACTED, configure_logging, redact, register_secret
from installer.secret import Secret

VALUE = "s3cr3t-value-0123456789abcdef"


def test_a_registered_secret_is_masked_wherever_it_appears() -> None:
    register_secret(VALUE)
    assert redact(f"a {VALUE} b {VALUE}") == f"a {REDACTED} b {REDACTED}"


def test_a_secret_that_is_too_short_to_mask_safely_is_refused() -> None:
    with pytest.raises(ValueError, match="at least"):
        register_secret("short")


def test_a_secret_containing_another_is_masked_whole() -> None:
    register_secret("abcdefgh")
    register_secret("abcdefghijklmnop")
    assert redact("x abcdefghijklmnop y") == f"x {REDACTED} y"


@pytest.mark.parametrize(
    "text", ["passphrase=hunter2hunter2", "Passphrase: 'two words here'", "recovery_key = AAAA-BBBB", "token: abc"]
)
def test_credential_pairs_are_masked_even_when_never_registered(text: str) -> None:
    assert REDACTED in redact(text)


def test_log_lines_are_redacted_including_args_and_exceptions(log_buffer: io.StringIO) -> None:
    register_secret(VALUE)
    logger = logging.getLogger(f"{LOGGER_NAME}.test")
    logger.info("value %s", VALUE)
    try:
        raise RuntimeError(f"failed with {VALUE}")
    except RuntimeError:
        logger.exception("boom")
    assert VALUE not in log_buffer.getvalue()
    assert REDACTED in log_buffer.getvalue()


def test_configure_logging_is_repeatable() -> None:
    configure_logging(io.StringIO())
    configure_logging(io.StringIO())
    assert len(logging.getLogger(LOGGER_NAME).handlers) == 1


def test_a_secret_never_prints_or_pickles() -> None:
    secret = Secret(VALUE)
    for text in (str(secret), repr(secret), f"{secret}", f"{secret!r}", "%s" % secret, "{}".format(secret)):  # noqa: UP031, UP032
        assert VALUE not in text
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    assert secret.reveal() == VALUE and secret.reveal_bytes() == VALUE.encode()
