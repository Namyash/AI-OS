"""Logging to stderr (the journal) with secret redaction.

Follows ``kiosk/log.py`` without importing it. The installer handles two secrets, the passphrase and the recovery
key. Neither may reach a log line, an event or an error message, whatever code path formats it: literal secrets
registered with ``register_secret`` are masked wherever they appear, and so is the value of a ``key=value`` pair whose
key names a credential. Redaction also runs on everything the command runner captures before it is logged or raised.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import TextIO

REDACTED = "[REDACTED]"
LOGGER_NAME = "installer"
_MIN_SECRET_LENGTH = 8
_CREDENTIAL_WORDS = "token|secret|password|passphrase|credential|recovery"
_CREDENTIAL_PAIR = re.compile(
    rf"""(?<![\w.-])((?=[\w.-]*(?:{_CREDENTIAL_WORDS}))[\w.-]+)(\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)""",
    re.IGNORECASE,
)

_secrets: frozenset[str] = frozenset()


def register_secret(value: str) -> None:
    """Mask ``value`` wherever it appears from now on."""
    global _secrets  # process-wide registry; rebuilt rather than mutated, so readers need no lock
    if len(value) < _MIN_SECRET_LENGTH:
        raise ValueError(f"a registered secret must be at least {_MIN_SECRET_LENGTH} characters")
    _secrets = _secrets | {value}


def redact(text: str) -> str:
    # Longest first, so a secret that contains another registered secret is masked whole.
    for secret in sorted(_secrets, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
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
    """Send the installer's log to ``stream`` (default stderr). Safe to call again: it replaces its own handler."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr if stream is None else stream)
    handler.setFormatter(logging.Formatter("%(levelname)s installer: %(message)s"))
    handler.addFilter(RedactionFilter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger
