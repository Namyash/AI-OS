"""A value that refuses to be printed: the passphrase and the recovery key travel inside this wrapper."""

from __future__ import annotations

from installer.log import REDACTED


class Secret:
    """Holds a secret string. ``str``, ``repr``, f-strings and ``%`` formatting all give ``[REDACTED]``.

    Reading the value is an explicit call (``reveal``), so every place that handles it is easy to find, and an
    accidental ``f"{plan}"`` or a traceback of a dataclass holding one cannot leak it.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def reveal_bytes(self) -> bytes:
        return self._value.encode("utf-8")

    def __repr__(self) -> str:
        return f"Secret({REDACTED})"

    def __str__(self) -> str:
        return REDACTED

    def __format__(self, format_spec: str) -> str:
        return REDACTED

    def __reduce__(self) -> object:
        raise TypeError("a Secret cannot be pickled or copied by value")

    def __bool__(self) -> bool:
        return bool(self._value)
