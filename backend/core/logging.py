"""Structured JSON logging to stdout (journald collects it) with secret redaction.

Redaction is applied by a handler filter, so it covers every record that reaches the handler, including
those from third-party loggers such as uvicorn. Three layers, from most to least precise:

1. Literal secrets registered with ``register_secret`` (the live bearer token) are masked wherever they appear.
2. ``key=value`` / ``"key": "value"`` pairs, and structured ``extra`` fields, whose key looks secret-bearing
   (see ``_SENSITIVE_WORDS``) have the value masked. The value of an ``authorization`` or ``cookie`` key is a
   whole header (``Basic <credentials>``, ``a=1; b=2``), so it is masked to the end of its line; the value of
   any other key is one quoted string, one ``Bearer <credentials>`` pair or one word.
3. ``Bearer <credentials>`` anywhere in a message is masked.

The key list is deliberately broad: an over-masked value costs a log line, a leaked one costs a credential.
Exempt a harmless name (for example a token *count*) by adding an explicit exemption here, never by weakening
the pattern.

Redaction runs synchronously, on the event loop for uvicorn's own records, so its cost must stay linear in the
length of the text. The patterns are written for that: a key can only start where a run of key characters
starts (a lookbehind, so a long word is scanned once rather than once per character), and the test for a
sensitive word is a lookahead that runs once per run. A test feeds adversarial inputs under a time budget.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime

REDACTED = "[REDACTED]"
_MIN_SECRET_LENGTH = 8
_MAX_DEPTH = 8
# Header-style keys: the value is a whole header ("Basic <credentials>", "a=1; b=2"), not a single word.
_LINE_VALUED_WORDS = ("authorization", "cookie")
_SENSITIVE_WORDS = (*_LINE_VALUED_WORDS, "token", "password", "passwd", "secret", "credential", "key")

_WORDS_PATTERN = "|".join(_SENSITIVE_WORDS)
_SENSITIVE_KEY = re.compile(_WORDS_PATTERN, re.IGNORECASE)
_LINE_VALUED_KEY = re.compile("|".join(_LINE_VALUED_WORDS), re.IGNORECASE)
# A secret-bearing key and its ':' or '=' separator, without the value. The key is a maximal run of key
# characters, optionally quoted. The lookbehind lets a match start only where a run starts; the lookahead
# accepts only runs that contain a sensitive word.
_SENSITIVE_ASSIGNMENT = re.compile(
    rf"""(?<![\w.-])["']?(?=[\w.-]*(?:{_WORDS_PATTERN}))[\w.-]+["']?\s*[:=]\s*""",
    re.IGNORECASE,
)
_WORD_VALUE = re.compile(r""""[^"]*"|'[^']*'|(?:bearer\s+)?\S+""", re.IGNORECASE)
_LINE_VALUE = re.compile(r""""[^"]*"|'[^']*'|[^\r\n]+""")
_BEARER = re.compile(r"\b(bearer)\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)

# Attributes every LogRecord has; anything else on a record came from the caller's ``extra=``.
_RECORD_ATTRIBUTES = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}
# uvicorn attaches an ANSI-coloured duplicate of its message here.
_OMITTED_EXTRAS = frozenset({"color_message"})

_secrets: frozenset[str] = frozenset()


def register_secret(value: str) -> None:
    """Mask ``value`` wherever it appears in a log record from now on."""
    global _secrets  # process-wide registry; rebuilt rather than mutated, so readers need no lock
    if len(value) < _MIN_SECRET_LENGTH:
        raise ValueError(f"a registered secret must be at least {_MIN_SECRET_LENGTH} characters")
    _secrets = _secrets | {value}


def _mask_assignments(text: str) -> str:
    """Mask the value of every secret-bearing ``key=value`` / ``key: value`` pair, keeping key and separator.

    Matching the key alone, then reading the value from where the separator ends, keeps a harmless key from
    swallowing a secret-bearing pair inside its own value (``data=password=x``): scanning resumes right after
    each separator, and only a secret-bearing key consumes the value that follows it.
    """
    parts: list[str] = []
    position = 0
    while key := _SENSITIVE_ASSIGNMENT.search(text, position):
        value_pattern = _LINE_VALUE if _LINE_VALUED_KEY.search(key[0]) else _WORD_VALUE
        value = value_pattern.match(text, key.end())
        parts.append(text[position : key.end()])
        if value is None:  # the separator ends the text or the line: no value to mask
            position = key.end()
            continue
        parts.append(REDACTED)
        position = value.end()
    parts.append(text[position:])
    return "".join(parts)


def redact_text(text: str) -> str:
    for secret in _secrets:
        text = text.replace(secret, REDACTED)
    return _BEARER.sub(rf"\1 {REDACTED}", _mask_assignments(text))


def redact_value(key: str, value: object, depth: int = 0) -> object:
    """Return a JSON-friendly copy of ``value`` that is safe to log under ``key``."""
    if _SENSITIVE_KEY.search(key):
        return REDACTED
    if depth > _MAX_DEPTH:
        return "[TRUNCATED]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, Mapping):
        return {str(k): redact_value(str(k), v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [redact_value(key, item, depth + 1) for item in value]
    return redact_text(value if isinstance(value, str) else str(value))


class RedactionFilter(logging.Filter):
    """Rewrites each record in place so no later handler or formatter can see the unmasked content."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact_text(record.getMessage())
            record.args = None
            if record.exc_info and not record.exc_text:
                record.exc_text = logging.Formatter().formatException(record.exc_info)
            if record.exc_text:
                record.exc_text = redact_text(record.exc_text)
            for name in record.__dict__.keys() - _RECORD_ATTRIBUTES:
                setattr(record, name, redact_value(name, record.__dict__[name]))
        except Exception:
            # Fail closed: a record that cannot be scrubbed is replaced, never emitted raw.
            record.msg = "log record suppressed: redaction failed"
            record.args = None
            record.exc_info = record.exc_text = None
            for name in record.__dict__.keys() - _RECORD_ATTRIBUTES:
                delattr(record, name)
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Core keys win over caller-supplied extras of the same name."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for name, value in record.__dict__.items():
            if name not in _RECORD_ATTRIBUTES and name not in _OMITTED_EXTRAS and name not in payload:
                payload[name] = value
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            payload["exception"] = record.exc_text
        return json.dumps(payload, default=str, separators=(",", ":"))


_INSTALLED_MARKER = "_pai_structured_handler"


def configure_logging(level: str) -> None:
    """Send all logging to stdout as redacted JSON lines. Safe to call again: it replaces its own handler."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, _INSTALLED_MARKER, False):
            root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())
    setattr(handler, _INSTALLED_MARKER, True)
    root.addHandler(handler)
    root.setLevel(level.upper())
