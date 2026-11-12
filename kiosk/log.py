"""Logging to stderr (the journal) with secret redaction.

The launcher handles two secrets: the bearer token and the session id. Neither may reach a log line, whatever code
path formats the message (an exception text, a library's error, a future log call). The redaction follows the ideas
of ``backend/core/logging.py`` without importing it: literal secrets registered with ``register_secret`` are masked
wherever they appear, ``Bearer <credentials>`` is masked anywhere, and so is the value of a ``key=value`` pair whose
key names a credential. It runs as a handler filter, so it covers every record that reaches the handler.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import TextIO

REDACTED = "[REDACTED]"
LOGGER_NAME = "kiosk"
_MIN_SECRET_LENGTH = 8
_BEARER = re.compile(r"\b(bearer)\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
# A key can only start where a run of key characters starts (the lookbehind) and only runs that contain a credential
# word qualify (the lookahead), so a long word is scanned once and the cost stays linear in the length of the text.
_CREDENTIAL_WORDS = "token|secret|password|credential|cookie|authorization|pai_session|session_id"
_CREDENTIAL_PAIR = re.compile(
    rf"""(?<![\w.-])((?=[\w.-]*(?:{_CREDENTIAL_WORDS}))[\w.-]+)(\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)""",
    re.IGNORECASE,
)

_secrets: frozenset[str] = frozenset()


def register_secret(value: str) -> None:
    """Mask ``value`` wherever it appears in a log record from now on."""
    global _secrets  # process-wide registry; rebuilt rather than mutated, so readers need no lock
    if len(value) < _MIN_SECRET_LENGTH:
        raise ValueError(f"a registered secret must be at least {_MIN_SECRET_LENGTH} characters")
    _secrets = _secrets | {value}


def redact(text: str) -> str:
    for secret in _secrets:
        text = text.replace(secret, REDACTED)
    text = _BEARER.sub(rf"\1 {REDACTED}", text)
    return _CREDENTIAL_PAIR.sub(lambda match: f"{match[1]}{match[2]}{REDACTED}", text)


class RedactionFilter(logging.Filter):
    """Rewrites each record in place so no later handler or formatter can see the unmasked content."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.getMessage())
            record.args = None
            if record.exc_info and not record.exc_text:
                record.exc_text = logging.Formatter().formatException(record.exc_info)
            if record.exc_text:
                record.exc_text = redact(record.exc_text)
        except Exception:  # fail closed: a record that cannot be scrubbed is replaced, never emitted raw
            record.msg = "log record suppressed: redaction failed"
            record.args = None
            record.exc_info = record.exc_text = None
        return True


def configure_logging(stream: TextIO | None = None) -> logging.Logger:
    """Send the launcher's log to ``stream`` (default stderr). Safe to call again: it replaces its own handler."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr if stream is None else stream)
    handler.setFormatter(logging.Formatter("%(levelname)s kiosk: %(message)s"))
    handler.addFilter(RedactionFilter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger
