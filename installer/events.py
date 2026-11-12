"""Progress events: one JSON object per line on stdout (the contract of INSTALLER_DESIGN.md).

``{"event": "step", "name": ..., "state": "start|done|failed", "detail": ...}`` as steps run and a final
``{"event": "result", "ok": ..., "error": ...}``. Text is redacted before it is written, so an event can never
carry a secret even if a message was built carelessly.
"""

from __future__ import annotations

import json
from typing import Literal, TextIO

from installer.log import redact

_MAX_TEXT = 2000
StepState = Literal["start", "done", "failed"]


class EventSink:
    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def step(self, name: str, state: StepState, detail: str = "") -> None:
        self._write({"event": "step", "name": name, "state": state, "detail": self._text(detail)})

    def result(self, ok: bool, error: str = "") -> None:
        self._write({"event": "result", "ok": ok, "error": self._text(error)})

    @staticmethod
    def _text(text: str) -> str:
        return redact(text)[:_MAX_TEXT]

    def _write(self, event: dict[str, object]) -> None:
        self._stream.write(json.dumps(event, separators=(",", ":")) + "\n")
        self._stream.flush()
