"""A stand-in for Chromium that speaks the DevTools pipe protocol, for the launcher's tests.

The launcher starts it exactly as it starts Chromium: a command line, an environment and two inherited descriptors.
It reads NUL-terminated JSON commands on descriptor 3 and writes replies on descriptor 4. It behaves like a page
that loads URLs for real: ``Page.navigate`` fetches the URL over HTTP with the cookies it was given, and the page
probe answers from that response, so a session the backend refuses leaves the shell unrendered.

Everything it saw is appended to the file named by ``--fake-log``: its argv and environment at start, every command,
and what each fetch got. Behaviours (``--fake-mode``) make it fail in the ways a real browser can.

    ok                  serve normally
    status-changes      the status bar says "connecting" for the first probes, then "connected"
    late-shell          no shell for the first ``--fake-after`` probes
    no-shell            the shell never renders
    wrong-origin        the page reports an origin that is not the backend's
    no-page             no page target ever appears
    exit-at-start       exit before answering anything
    die-after-ready     exit with status 7 after ``--fake-after`` probes
    silent              read commands, never reply
    garbage             answer with something that is not JSON
    close-pipe          close the reply pipe after attaching, and keep running
    navigate-error      Page.navigate answers with an errorText
    cookie-error        Storage.setCookies is refused
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

COMMAND_FD = 3
REPLY_FD = 4


def parse_options(argv: list[str]) -> dict[str, str]:
    options = {}
    for argument in argv:
        if argument.startswith("--fake-") and "=" in argument:
            name, _, value = argument[len("--fake-") :].partition("=")
            options[name] = value
    return options


class Browser:
    def __init__(self, options: dict[str, str]) -> None:
        self.mode = options.get("mode", "ok")
        self.after = int(options.get("after", "0"))
        self.log_path = options["log"]
        self.cookies: list[dict[str, Any]] = []
        self.url = "data:text/html,start"
        self.fetch_status: int | None = None
        self.probes = 0
        self.buffer = b""

    def log(self, **entry: Any) -> None:
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

    # ------------------------------------------------------------------ wire
    def read_message(self) -> dict[str, Any] | None:
        while b"\0" not in self.buffer:
            chunk = os.read(COMMAND_FD, 65536)
            if not chunk:
                return None
            self.buffer += chunk
        raw, _, self.buffer = self.buffer.partition(b"\0")
        return json.loads(raw)

    def send(self, message: dict[str, Any]) -> None:
        os.write(REPLY_FD, json.dumps(message).encode() + b"\0")

    # ------------------------------------------------------------------ commands
    def result(self, command: dict[str, Any]) -> dict[str, Any]:
        method = command["method"]
        params = command.get("params", {})
        if method == "Target.getTargets":
            if self.mode == "no-page":
                return {"targetInfos": [{"targetId": "UI1", "type": "browser_ui", "url": "chrome://omnibox/"}]}
            return {
                "targetInfos": [
                    {"targetId": "UI1", "type": "browser_ui", "url": "chrome://omnibox-popup.top-chrome/"},
                    {"targetId": "PAGE1", "type": "page", "url": self.url},
                ]
            }
        if method == "Target.attachToTarget":
            assert params["targetId"] == "PAGE1" and params["flatten"] is True
            return {"sessionId": "SESSION-OF-PAGE1"}
        if method == "Storage.setCookies":
            self.cookies = params["cookies"]
            return {}
        if method == "Page.navigate":
            return self.navigate(params["url"])
        if method == "Runtime.evaluate":
            return self.evaluate()
        return {}

    def navigate(self, url: str) -> dict[str, Any]:
        self.url = url
        cookie = "; ".join(f"{c['name']}={c['value']}" for c in self.cookies)
        request = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})  # noqa: S310 - test URL
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=5) as response:
                self.fetch_status = response.status
        except urllib.error.HTTPError as exc:
            self.fetch_status = exc.code
        self.log(kind="fetch", url=url, status=self.fetch_status, sent_cookie=bool(cookie))
        return (
            {"errorText": "net::ERR_BLOCKED_BY_ADMINISTRATOR"} if self.mode == "navigate-error" else {"frameId": "F1"}
        )

    def evaluate(self) -> dict[str, Any]:
        self.probes += 1
        rendered = self.fetch_status == 200 and self.mode != "no-shell"
        if self.mode == "late-shell":
            rendered = rendered and self.probes > self.after
        status = None
        if rendered:
            connecting = self.mode == "status-changes" and self.probes <= max(self.after, 1)
            status = "Backend connecting" if connecting else "Backend connected Version fake"
        parts = urlsplit(self.url)
        origin = "http://example.invalid" if self.mode == "wrong-origin" else f"{parts.scheme}://{parts.netloc}"
        probe = {"origin": origin, "complete": True, "shell": rendered, "status": status}
        return {"result": {"type": "string", "value": json.dumps(probe)}}

    # ------------------------------------------------------------------ main loop
    def run(self) -> int:
        self.log(
            kind="start",
            argv=sys.argv,
            environ=dict(os.environ),
            open_fds=sorted(int(name) for name in os.listdir("/proc/self/fd")),
            user_data_dir_entries=self.profile_entries(),
        )
        if self.mode == "exit-at-start":
            return 3
        while (command := self.read_message()) is not None:
            self.log(
                kind="command", method=command["method"], params=command.get("params"), session=command.get("sessionId")
            )
            if self.mode == "silent":
                continue
            if self.mode == "garbage":
                os.write(REPLY_FD, b"this is not json\0")
                continue
            if command["method"] == "Storage.setCookies" and self.mode == "cookie-error":
                self.send({"id": command["id"], "error": {"code": -32000, "message": "Invalid cookie fields"}})
                continue
            self.send({"id": command["id"], "result": self.result(command)})
            if command["method"] == "Target.attachToTarget" and self.mode == "close-pipe":
                os.close(REPLY_FD)
                time.sleep(60)
            if self.mode == "die-after-ready" and self.probes > self.after:
                return 7
        return 0

    @staticmethod
    def profile_entries() -> list[str]:
        for argument in sys.argv:
            if argument.startswith("--user-data-dir="):
                path = argument.partition("=")[2]
                return sorted(os.listdir(path)) if os.path.isdir(path) else ["<missing>"]
        return ["<no --user-data-dir>"]


if __name__ == "__main__":
    sys.exit(Browser(parse_options(sys.argv[1:])).run())
