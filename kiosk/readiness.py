"""What "the UI is up" means, how the launcher looks at the page, and the readiness file it publishes.

The contract with the frontend is the two selectors below, read from ``frontend/src`` (``App.tsx``, ``StatusBar.tsx``):

* ``SHELL_SELECTOR``: the element ``App`` renders around everything. Present means React mounted and the shell drew.
* ``STATUS_SELECTOR``: the first live status line inside the status bar region (the backend line). Its text is
  what the user is told about the backend ("Backend connected ...", "Backend unreachable ...").

The frontend has no dedicated machine-readable marker (a ``data-`` attribute) for either, so these selectors lean on a
CSS class and an accessibility label. They live in this one place so a change on the frontend side is one edit here,
and ``docs/development/KIOSK.md`` records the gap.

The readiness file (default ``/run/pai-ui/ready``) is JSON and holds no secret: it is world-readable so the boot
self-check, which runs as another account, can read it.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from kiosk.errors import KioskError

SHELL_SELECTOR = "#root .app-shell"
STATUS_SELECTOR = '.app-shell section[aria-label="System status"] [role="status"]'
MAX_STATUS_CHARS = 200
READY_FILE_VERSION = 1
READY_FILE_MODE = 0o644
STATE_READY = "ready"
STATE_NOT_READY = "not-ready"


@dataclass(frozen=True)
class PageProbe:
    """What one look at the page found."""

    origin: str
    document_complete: bool
    shell_rendered: bool
    status_text: str | None


def probe_expression() -> str:
    """The JavaScript the launcher evaluates in the page. It returns a JSON string and changes nothing."""
    return f"""(() => {{
  const shell = document.querySelector({json.dumps(SHELL_SELECTOR)});
  const status = document.querySelector({json.dumps(STATUS_SELECTOR)});
  const text = status === null ? null : status.textContent.replace(/\\s+/g, " ").trim().slice(0, {MAX_STATUS_CHARS});
  return JSON.stringify({{
    origin: location.origin,
    complete: document.readyState === "complete",
    shell: shell !== null,
    status: text,
  }});
}})()"""


def parse_probe(value: object) -> PageProbe:
    """The probe's answer as a ``PageProbe``; ``KioskError`` when the page returned anything else."""
    if not isinstance(value, str):
        raise KioskError("the page probe did not return text")
    try:
        data = json.loads(value)
    except ValueError:
        raise KioskError("the page probe did not return JSON") from None
    if not isinstance(data, dict):
        raise KioskError("the page probe did not return an object")
    origin, complete, shell, status = data.get("origin"), data.get("complete"), data.get("shell"), data.get("status")
    if not (isinstance(origin, str) and isinstance(complete, bool) and isinstance(shell, bool)):
        raise KioskError("the page probe returned fields of the wrong type")
    if status is not None and not isinstance(status, str):
        raise KioskError("the page probe returned a status line of the wrong type")
    return PageProbe(origin, complete, shell, _clean(status) if status else None)


def _clean(text: str) -> str:
    """One line of printable text, however the page spelled it."""
    return " ".join(text.split())[:MAX_STATUS_CHARS]


@dataclass(frozen=True, kw_only=True)
class ReadyReport:
    """The content of the readiness file."""

    version: int = READY_FILE_VERSION
    state: str
    shell_rendered: bool
    status_bar: str | None
    updated: str = ""

    @classmethod
    def from_probe(cls, probe: PageProbe | None) -> ReadyReport:
        """``probe`` is None when the page could not be examined."""
        rendered = probe is not None and probe.shell_rendered
        return cls(
            state=STATE_READY if rendered else STATE_NOT_READY,
            shell_rendered=rendered,
            status_bar=probe.status_text if probe is not None else None,
        )

    def same_facts(self, other: ReadyReport) -> bool:
        return (self.state, self.shell_rendered, self.status_bar) == (
            other.state,
            other.shell_rendered,
            other.status_bar,
        )


def write_ready_file(path: Path, report: ReadyReport) -> ReadyReport:
    """Atomically replace ``path`` with ``report`` (stamped with the time) and return what was written."""
    stamped = ReadyReport(
        state=report.state,
        shell_rendered=report.shell_rendered,
        status_bar=report.status_bar,
        updated=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if os.name == "posix":  # Windows development hosts have no POSIX modes to set
                os.fchmod(handle.fileno(), READY_FILE_MODE)
            handle.write(json.dumps(asdict(stamped), separators=(",", ":")))
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return stamped


def clear_ready_file(path: Path) -> None:
    """Remove a readiness file an earlier run left: a stale ``ready`` must not outlive the process that wrote it."""
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


class ReadyFile:
    """The readiness file of one run: written when what it says changes, never left claiming "ready" after the exit."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._last: ReadyReport | None = None
        clear_ready_file(path)

    def publish(self, probe: PageProbe | None) -> None:
        """Say what ``probe`` found (None: the page cannot be examined), unless the file already says exactly that."""
        report = ReadyReport.from_probe(probe)
        if self._last is None or not self._last.same_facts(report):
            self._last = write_ready_file(self._path, report)

    def retire(self) -> None:
        """Called on the way out. A file that says ready now says not ready; a not-ready record stays, because it is
        the explanation of why the page never rendered; a run that never wrote one leaves none."""
        if self._last is not None and self._last.state == STATE_READY:
            self.publish(None)
