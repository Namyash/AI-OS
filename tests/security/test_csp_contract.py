"""Contract: the backend sends exactly the Content-Security-Policy the frontend is built and tested under.

The policy is written twice because the two sides use different languages (backend/api/static.py and
frontend/security-headers.ts). A difference would mean the UI is verified under one policy and served under another.
"""

from __future__ import annotations

import re
from pathlib import Path

from backend.api.static import CONTENT_SECURITY_POLICY

FRONTEND_HEADERS = Path(__file__).resolve().parents[2] / "frontend" / "security-headers.ts"


def _frontend_policy() -> str:
    source = FRONTEND_HEADERS.read_text(encoding="utf-8")
    block = re.search(r"CONTENT_SECURITY_POLICY\s*=\s*\[(?P<items>.*?)\]\.join\('; '\)", source, re.DOTALL)
    assert block is not None, "could not find CONTENT_SECURITY_POLICY in frontend/security-headers.ts"
    directives = re.findall(r'"([^"]+)"', block["items"])
    assert directives, "the frontend policy has no directives"
    return "; ".join(directives)


def test_backend_and_frontend_send_the_same_content_security_policy() -> None:
    assert _frontend_policy() == CONTENT_SECURITY_POLICY


def test_policy_denies_by_default_and_has_no_unsafe_sources() -> None:
    directives = dict(part.split(" ", 1) if " " in part else (part, "") for part in CONTENT_SECURITY_POLICY.split("; "))
    assert directives["default-src"] == "'none'"
    for name in ("script-src", "style-src", "connect-src"):
        assert directives[name] == "'self'"
    assert "unsafe-inline" not in CONTENT_SECURITY_POLICY
    assert "unsafe-eval" not in CONTENT_SECURITY_POLICY
