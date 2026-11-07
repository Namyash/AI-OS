"""Reads the self-check verdict from a guest's serial console output.

The producer is os/security/rootfs/usr/lib/pai/security-selfcheck.sh, one line per check plus a summary:

    PAI-SELFCHECK|<name>|PASS|<detail>
    PAI-SELFCHECK|<name>|FAIL|<detail>
    PAI-SELFCHECK|RESULT|PASS|<passed>/<total>

A serial console is noisy: kernel messages, ANSI escapes and carriage returns surround (and sometimes cut into) the
lines. Parsing therefore searches for the pattern inside each line instead of expecting clean lines, and the verdict
logic trusts nothing that is missing: no summary line, a summary that disagrees with the lines seen, a run with no
check at all, or a run that lacks one of REQUIRED_CHECKS is a failure.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

RESULT_NAME = "RESULT"

# The checks a boot must report. A pass that lacks one of them proves nothing about what it guards: an ISO built
# before a check existed, or a script edited to drop one, would otherwise pass with whatever subset it still prints
# (`RESULT PASS 1/1`). They cover the firewall policy (threat model invariant 5), the host-integration modules
# (invariant 6), the kernel hardening values, the listening sockets, the core services, the guard that the
# script examined the real system, and the backend service (running, unprivileged, loopback only, refusing anonymous
# requests, answering an authenticated one, and sandboxed to within a measured exposure).
# test_selfcheck_wiring.py keeps this list equal to the CHECKS table of
# os/security/rootfs/usr/lib/pai/security-selfcheck.sh, so a check can be neither added nor dropped silently.
REQUIRED_CHECKS: tuple[str, ...] = (
    "live-root",
    "backend-active",
    "nft-default-drop",
    "modules-blocked",
    "sysctl-live",
    "no-external-listeners",
    "units-active",
    "backend-unprivileged",
    "backend-loopback-only",
    "backend-refuses-anonymous",
    "backend-health",
    "backend-sandbox-exposure",
)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
_LINE = re.compile(r"PAI-SELFCHECK\|(?P<name>[A-Za-z0-9_.:-]+)\|(?P<status>PASS|FAIL)\|(?P<detail>[^\r\n]*)")
_COUNTS = re.compile(r"^\s*(?P<passed>\d+)\s*/\s*(?P<total>\d+)\s*$")


@dataclass(frozen=True)
class CheckResult:
    """One PAI-SELFCHECK line. The summary line has name RESULT and a detail of the form `<passed>/<total>`."""

    name: str
    passed: bool
    detail: str


def parse_selfcheck(text: str) -> list[CheckResult]:
    """Every well-formed PAI-SELFCHECK line in `text`, in order. Lines that are cut or garbled are not returned."""
    clean = _ANSI_ESCAPE.sub("", text)
    return [
        CheckResult(match["name"], match["status"] == "PASS", match["detail"].strip())
        for match in _LINE.finditer(clean)
    ]


def selfcheck_problems(results: Sequence[CheckResult], required: Sequence[str] = REQUIRED_CHECKS) -> list[str]:
    """Why these results do not prove a clean self-check; an empty list means all passed and the run completed.

    `required` names the checks that must appear in the output (default: REQUIRED_CHECKS). Extra checks the image
    reports beyond them are judged like any other.
    """
    # Identical repeats (a line echoed twice on the console) are harmless; conflicting repeats are reported below.
    unique = list(dict.fromkeys(results))
    checks = [result for result in unique if result.name != RESULT_NAME]
    summaries = [result for result in unique if result.name == RESULT_NAME]

    problems: list[str] = []
    if not results:
        return ["no PAI-SELFCHECK output: the self-check did not run or its output was lost"]
    if not summaries:
        problems.append("no final RESULT line: the self-check did not finish")
    if len(summaries) > 1:
        problems.append(
            "conflicting RESULT lines: " + "; ".join(f"{'PASS' if s.passed else 'FAIL'} {s.detail}" for s in summaries)
        )

    names = [check.name for check in checks]
    if not checks:
        problems.append("no check lines: a run that checked nothing proves nothing")
    elif missing := [name for name in required if name not in names]:
        problems.append(
            f"required check(s) missing from the output: {', '.join(missing)} "
            "(the image's self-check is older than this harness expects, or its output was lost)"
        )
    problems.extend(f"conflicting results for check {name}" for name in dict.fromkeys(names) if names.count(name) > 1)
    problems.extend(f"{check.name} FAILED: {check.detail}" for check in checks if not check.passed)

    if len(summaries) == 1:
        problems.extend(_summary_problems(summaries[0], checks))
    return problems


def _summary_problems(summary: CheckResult, checks: Sequence[CheckResult]) -> list[str]:
    failed = sum(1 for check in checks if not check.passed)
    if summary.passed and failed:
        return [f"RESULT says PASS but {failed} check line(s) say FAIL"]
    counts = _COUNTS.match(summary.detail)
    if counts is None:
        return [f"RESULT has no <passed>/<total> counts: {summary.detail!r}"]
    expected_total, expected_passed = int(counts["total"]), int(counts["passed"])
    if (len(checks), len(checks) - failed) != (expected_total, expected_passed):
        return [
            f"RESULT reports {expected_passed}/{expected_total} but {len(checks) - failed}/{len(checks)} check lines "
            "were seen: some output was lost or duplicated"
        ]
    if not summary.passed and not failed:
        return ["RESULT says FAIL although every check line passed"]
    return []
