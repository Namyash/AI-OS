"""Runs the real security-selfcheck.sh against a simulated machine (tests/end_to_end/selfcheck_sim.py).

Each of the script's checks must be shown to PASS on a healthy machine and to FAIL when exactly the thing it guards
is broken, and one failing check must never stop the others. The script's test-only PAI_SELFCHECK_ROOT prefix
redirects /proc, /etc and /opt; the live-root check fails while it is set, so these runs can never be mistaken for a
real one (and its passing outcome is shown by a run without the prefix).

Every scenario is one run of the script. A run costs a few seconds on a machine where starting a process is slow, so
the scenarios of a pytest session are started together on a thread pool and each test reads its own finished run.

Module and sysctl names in the simulated machines are placeholders; the real image configuration is covered by one
scenario that feeds the repository's own nftables.conf, modprobe.d and sysctl.d through the script (with the ruleset
real `nft` printed for that nftables.conf, fixtures/nft_ruleset_shipped.json).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.end_to_end.selfcheck_output import INSTALLED_ONLY_CHECKS, REQUIRED_CHECKS, CheckResult
from tests.end_to_end.selfcheck_sim import (
    ACCEPT,
    BACKEND_UNIT,
    BASH,
    BROWSER_CHILD_PID,
    BROWSER_NAME,
    BROWSER_PID,
    CONNECTED_LABEL,
    CREDENTIAL_LENGTH,
    HEALTHY_CHAINS,
    HEALTHY_RULES,
    IMAGE_ETC,
    KIOSK_PID,
    KIOSK_UID,
    KIOSK_UNIT,
    KIOSK_USER,
    LAUNCHER_PID,
    LIVE_CMDLINE_WORD,
    LIVE_MEDIUM_MOUNT,
    LIVE_USER_FULL_NAME,
    MATCH,
    MAX_CREDENTIAL_CANDIDATES,
    REQUIRED_LUKS_KDF,
    SCRIPT,
    SERVICE_PID,
    SERVICE_UID,
    SERVICE_USER,
    SESSION_COOKIE,
    SHIPPED_NFT_RULESET,
    STATE_LISTEN,
    STATE_UNCONNECTED,
    TOKEN_BYTES,
    WILDCARD_V4,
    Reply,
    Run,
    Sim,
    chain,
    chain_regular,
    conf_with,
    health_body,
    ipv4_hex,
    ipv6_hex,
    rule,
    script_value,
    sock_row,
)

ALL_CHECKS = REQUIRED_CHECKS  # the script's order; test_selfcheck_wiring keeps it equal to the script's CHECKS table
pytestmark = pytest.mark.skipif(BASH is None, reason="no working bash on this machine")

MAX_PARALLEL_RUNS = 8  # runs of the script started together; each is mostly waiting for child processes

# The checks that need the backend probe's answer, which is only asked of a unit that is up. no-secret-in-process-state
# tests credential-shaped strings against the backend, so it reads the backend's settings the same way and fails
# with it.
BACKEND_PROBE_CHECKS = (
    "backend-active",
    "backend-loopback-only",
    "backend-refuses-anonymous",
    "backend-health",
    "no-secret-in-process-state",
)
# The checks that need the kiosk probe's answer.
KIOSK_PROBE_CHECKS = ("kiosk-active", "kiosk-ready")
BACKEND_FACT_OF = {
    "backend-active": "ready",
    "backend-loopback-only": "loopback",
    "backend-refuses-anonymous": "anonymous",
    "backend-health": "health",
}


@dataclass(frozen=True)
class Scenario:
    """One run of the script on a simulated machine, and what it must print."""

    name: str
    arrange: Callable[[Sim], None] = lambda sim: None
    # check -> text its detail must contain. Exactly these checks (plus live-root) must fail.
    failing: Mapping[str, str] = field(default_factory=dict)
    # check -> text its detail must contain, whatever its status
    details: Mapping[str, str] = field(default_factory=dict)
    verify: Callable[[Run], None] | None = None  # anything else the run must show
    env: Mapping[str, str] = field(default_factory=dict)  # extra environment of the script
    host: str = "127.0.0.1"  # where the simulated backend listens
    exact: bool = True  # False: only `details` and `verify` are judged, not the full set of statuses
    installed: bool = False  # the machine is an installed system, which also reports INSTALLED_ONLY_CHECKS


# ---- arranging a machine ---------------------------------------------------------------------------------------------


def _nft_policy(hook: str, policy: str) -> Callable[[Sim], None]:
    return lambda s: s.set_nft(*[chain(h, policy if h == hook else "drop") for h in ("input", "forward", "output")])


def _module_loaded(sim: Sim) -> None:
    sim.write(sim.root / "proc" / "modules", "ext4 1 1 - Live 0x0\nhostshare 99 0 - Live 0x0\n")


def _module_hyphenated(sim: Sim) -> None:
    sim.write(sim.root / "etc" / "modprobe.d" / "block.conf", "install host-share /bin/false\n")
    sim.write(sim.root / "proc" / "modules", "host_share 99 0 - Live 0x0\n")


def _override_not_blocking(sim: Sim) -> None:
    sim.write(sim.state / "modprobe.dry.hostshare", "insmod /lib/modules/6.12/kernel/fs/hostshare.ko \n")


def _no_install_lines(sim: Sim) -> None:
    sim.write(sim.root / "etc" / "modprobe.d" / "block.conf", "blacklist hostshare\n# install hostshare /bin/false\n")


def _unit_state(unit: str, state: str) -> Callable[[Sim], None]:
    return lambda s: s.write(s.state / f"unit.{unit}", state)


def _listener(table: str, local_hex: str, port: int, state: str) -> Callable[[Sim], None]:
    return lambda s: s.set_sockets(**{table: [sock_row(local_hex, port, state)]})


def _all_of(*steps: Callable[[Sim], None]) -> Callable[[Sim], None]:
    def arrange(sim: Sim) -> None:
        for step in steps:
            step(sim)

    return arrange


def _unit(**properties: str) -> Callable[[Sim], None]:
    return lambda s: s.set_unit(**properties)


def _process(**kwargs: object) -> Callable[[Sim], None]:
    return lambda s: s.set_process(**kwargs)  # type: ignore[arg-type]


def _analyze(verdict: str) -> Callable[[Sim], None]:
    return lambda s: s.set_analyze_report(verdict)


def _anonymous(reply: Reply) -> Callable[[Sim], None]:
    return lambda s: setattr(s.backend, "anonymous", reply)


def _authenticated(reply: Reply) -> Callable[[Sim], None]:
    return lambda s: setattr(s.backend, "authenticated", reply)


def _health_answer(body: object) -> Callable[[Sim], None]:
    """The backend answers an authenticated GET /health with 200 and this body (bytes, or an object sent as JSON)."""
    payload = body if isinstance(body, bytes) else json.dumps(body).encode()
    return _authenticated(Reply(200, payload))


def _backend_down(sim: Sim) -> None:
    sim.backend.stop()


def _unit_is_not_up(reason: str) -> dict[str, str]:
    """What fails when the unit cannot be examined: its own checks give `reason`, the probe's checks got nothing."""
    return {
        "backend-active": reason,
        "backend-unprivileged": reason,
        "no-secret-in-process-state": reason,
        **{check: f"did not report '{fact}'" for check, fact in BACKEND_FACT_OF.items() if check != "backend-active"},
    }


def _kiosk_is_not_up(reason: str) -> dict[str, str]:
    """What fails when the kiosk unit cannot be examined: both of its checks say why."""
    return dict.fromkeys(KIOSK_PROBE_CHECKS, reason)


LEAK_PID = 7001  # a process that a scenario adds to the machine
# Shaped like password hashes, made up: they must never appear in the output.
SHADOW_HASH = "$6$simsalt$simulatedhashsimulatedhashsimulatedhashsimulatedhashsimulatedhash"
OLD_STYLE_HASH = "Xy12abCDefGHi"


def _kiosk_unit(**properties: str) -> Callable[[Sim], None]:
    return lambda s: s.set_kiosk_unit(**properties)


def _ready(**fields: object) -> Callable[[Sim], None]:
    """The kiosk's readiness file says this (the default, no fields, says ready and connected)."""
    return lambda s: s.set_ready(**fields)


def _process_with(
    pid: int,
    comm: str,
    *,
    ppid: int = 1,
    uid: int = 0,
    argv: Callable[[Sim], list[str]] = lambda s: [],
    environ: Callable[[Sim], dict[str, str]] = lambda s: {},
) -> Callable[[Sim], None]:
    """Add a process to the machine; its argument list and environment may name what only the machine knows."""
    return lambda s: s.add_process(pid, ppid=ppid, comm=comm, uid=uid, argv=argv(s), environ=environ(s))


def _later(sim: Sim, *commands: str) -> None:
    """Run `commands` two seconds after the script first asks systemd about the kiosk unit."""
    sim.after_unit_is_shown(KIOSK_UNIT, 2, *commands)


def _browser_appears_later(sim: Sim) -> None:
    commands = []
    for pid in (BROWSER_PID, BROWSER_CHILD_PID):
        parked = sim.state / f"later-{pid}"
        shutil.move(sim.root / "proc" / str(pid), parked)
        commands.append(f'cp -r "{parked.as_posix()}" "{(sim.root / "proc" / str(pid)).as_posix()}"')
    _later(sim, *commands)


def _ready_appears_later(sim: Sim) -> None:
    sim.write(sim.state / "ready.later", sim.ready_report())
    sim.ready_file.unlink()
    _later(sim, f'cp "{(sim.state / "ready.later").as_posix()}" "{sim.ready_file.as_posix()}"')


def _revoked_session(sim: Sim) -> None:
    """A process holds a session id that was valid once: by the time the check asks the backend, it is not."""
    session = sim.backend.new_session()
    sim.add_process(LEAK_PID, comm="leaky", environ={"PAI_SESSION": session})
    sim.backend.sessions.discard(session)


def _unreadable_environ(sim: Sim) -> None:
    """A process whose environment cannot be read (here: a directory where the file is, which no open() accepts)."""
    sim.add_process(LEAK_PID, comm="hidden")
    (sim.root / "proc" / str(LEAK_PID) / "environ").unlink()
    (sim.root / "proc" / str(LEAK_PID) / "environ").mkdir()


def _vanishing_process(sim: Sim) -> None:
    """A process that ends between the scan reading its argument list and its environment."""
    sim.add_process(LEAK_PID, comm="gone")
    (sim.root / "proc" / str(LEAK_PID) / "environ").unlink()


JOURNAL_LINES = int(script_value("DIAGNOSTIC_JOURNAL_LINES"))
JOURNAL_LINE_LIMIT = int(script_value("DIAGNOSTIC_LINE_LIMIT"))


def _kiosk_died(sim: Sim) -> None:
    """The kiosk crashed and systemd gave up on it: failed, with an exit status, and its output is in the journal."""
    sim.set_kiosk_unit(
        ActiveState="failed", SubState="failed", Result="exit-code", ExecMainStatus="1", ExecMainCode="1", NRestarts="3"
    )
    sim.set_kiosk_unit(MainPID="0")
    sim.set_journal(
        KIOSK_UNIT,
        [
            "cage: could not open the display",
            f"the launcher was handed {sim.backend.token} by mistake",  # the worst a journal could hold: the token
            "pai-kiosk: the browser exited with status 1",
        ],
    )


def _kiosk_died_with_a_long_journal(sim: Sim) -> None:
    sim.set_kiosk_unit(ActiveState="inactive", SubState="dead", Result="exit-code")
    sim.set_journal(
        KIOSK_UNIT,
        [f"journal line {number:03d}" for number in range(1, 101)] + ["tail " + "abcd," * 100],
    )


def _verify_a_failed_kiosk_is_explained(run: Run) -> None:
    for check in KIOSK_PROBE_CHECKS:
        detail = run.results[check].detail
        assert f"systemd reports for {KIOSK_UNIT}:" in detail
        for fact in ("ActiveState=failed", "SubState=failed", "Result=exit-code", "ExecMainStatus=1", "NRestarts=3"):
            assert fact in detail, (check, fact)
        assert "cage: could not open the display / " in detail  # the journal's lines, joined
        assert "the browser exited with status 1" in detail
        assert "[masked]" in detail  # the credential-shaped string is replaced, not shown
    # (Sim.run asserts the token itself appears nowhere in the output.)


def _verify_only_the_last_journal_lines_and_each_one_cut(run: Run) -> None:
    detail = run.results["kiosk-active"].detail
    assert f"(last {JOURNAL_LINES} lines)" in detail
    assert "journal line 100" in detail
    assert f"journal line {101 - JOURNAL_LINES + 1:03d}" in detail  # the oldest of the lines kept ...
    assert f"journal line {101 - JOURNAL_LINES:03d}" not in detail  # ... and the one before it is not there
    # a long line is cut to its limit, prefix counted (commas in the filler: a solid run is masked as a credential)
    kept = ("tail " + "abcd," * 100)[:JOURNAL_LINE_LIMIT]
    assert kept in detail
    assert kept + "abcd," not in detail


def _verify_the_pid_that_went_away_is_named(run: Run) -> None:
    detail = run.results["kiosk-active"].detail
    assert "pid 999, is gone (cannot read" in detail
    assert f"systemd now reports MainPID={KIOSK_PID}" in detail
    assert "the unit restarted or died after the wait began" in detail


def _verify_the_pid_is_still_the_units(run: Run) -> None:
    assert "systemd still names that pid (ActiveState=active)" in run.results["kiosk-active"].detail


def _verify_no_diagnostics_on_a_pass(run: Run) -> None:
    for check in KIOSK_PROBE_CHECKS:
        detail = run.results[check].detail
        assert "systemd reports" not in detail
        assert "journal" not in detail


def _verify_status_is_cut(run: Run) -> None:
    detail = run.results["kiosk-ready"].detail
    assert "x" * 60 in detail
    assert "x" * 61 not in detail


def _verify_the_token_is_found_both_ways(run: Run) -> None:
    assert "a value the backend accepts as a bearer token" in run.results["no-secret-in-process-state"].detail


def _verify_only_the_token_hit(run: Run) -> None:
    # A token glued to other characters is not a credential-shaped string: only the search for the token finds it.
    assert "a value the backend accepts" not in run.results["no-secret-in-process-state"].detail


def _verify_session_is_not_printed(run: Run) -> None:
    assert run.sessions
    assert not [session for session in run.sessions if session in run.stdout]


def _verify_nothing_was_tried(run: Run) -> None:
    """Only the backend probe asked anything: no candidate was sent anywhere."""
    assert run.backend_requests == [("/health", None), ("/health", f"Bearer {run.token}")]
    assert run.backend_cookies == []


def _verify_no_hash_is_printed(run: Run) -> None:
    assert not [hash_text for hash_text in (SHADOW_HASH, OLD_STYLE_HASH, "$y$j9T$sim") if hash_text in run.stdout]


# ---- the scenarios ---------------------------------------------------------------------------------------------------


def _verify_healthy(run: Run) -> None:
    assert "PAI_SELFCHECK_ROOT" in run.results["live-root"].detail
    assert run.returncode == 1  # live-root fails by design under the prefix
    # The probe asks twice, in this order: anonymously first, then with the token the backend published. Then
    # no-secret-in-process-state tries the one credential-shaped string the machine has (it is no credential), as a
    # bearer token and as the session cookie, and the backend refuses both.
    benign = run.benign_candidate
    assert run.backend_requests == [
        ("/health", None),
        ("/health", f"Bearer {run.token}"),
        ("/health", f"Bearer {benign}"),
        ("/health", None),
    ]
    assert run.backend_cookies == [f"{SESSION_COOKIE}={benign}"]
    assert run.modprobe_calls() == ["dry hostshare"]  # a modprobe that loads a module is never run, only the dry run
    # The probe imports code from the app directory, so python starts without the per-user site directory and without
    # writing bytecode: nothing a user account left behind runs inside the self-check.
    assert "-s -B" in run.python_options()
    _verify_no_diagnostics_on_a_pass(run)  # what a failing kiosk check adds is not there when the checks pass


def _verify_wildcard_backend(run: Run) -> None:
    assert "tcp 0.0.0.0:" in run.results["backend-loopback-only"].detail


def _verify_version_is_cut(run: Run) -> None:
    detail = run.results["backend-health"].detail
    assert "9" * 64 in detail
    assert "9" * 65 not in detail


def _verify_wrong_token_is_what_was_sent(run: Run) -> None:
    assert run.backend_requests[1][1] == "Bearer " + "w" * 24  # the probe's second request: the one with the token


def _verify_nothing_was_asked(run: Run) -> None:
    assert run.backend_requests == []


def _verify_dry_run_only(run: Run) -> None:
    assert run.modprobe_calls() == ["dry hostshare"]  # a real, loading call must never happen


def _verify_every_module_checked(run: Run) -> None:
    detail = run.results["modules-blocked"].detail
    assert "second_mod is loaded" in detail
    assert "hostshare is loaded" not in detail
    assert run.modprobe_calls() == ["dry hostshare", "dry third_mod"]


def _verify_flattened(run: Run) -> None:
    detail = run.results["nft-default-drop"].detail
    assert "boom/with pipes" in detail
    assert all(ch.isprintable() for ch in detail)
    assert len(run.stdout.splitlines()) == len(ALL_CHECKS) + 1


def _verify_truncated(run: Run) -> None:
    detail = run.results["nft-default-drop"].detail
    limit = int(script_value("DETAIL_LIMIT"))
    assert detail.endswith("...")
    assert limit <= len(detail) < limit + 100


def _verify_independence(run: Run) -> None:
    assert run.results["RESULT"].detail == f"{len(ALL_CHECKS) - 7}/{len(ALL_CHECKS)}"  # live-root and six more fail


def _verify_three_problems(run: Run) -> None:
    detail = run.results["backend-unprivileged"].detail
    assert detail.startswith(f"pid {SERVICE_PID} of {BACKEND_UNIT}: ")
    assert detail.count("; ") == 2


def _verify_the_shipped_configuration(run: Run) -> None:
    count = sum(
        1
        for conf in (IMAGE_ETC / "sysctl.d").glob("*.conf")
        for raw in conf.read_text(encoding="utf-8").splitlines()
        if "=" in raw.split("#", 1)[0]
    )
    assert count > 0
    assert f"{count} settings match" in run.results["sysctl-live"].detail
    assert "vboxsf" in run.results["modules-blocked"].detail
    assert "input=1, forward=1, output=1" in run.results["nft-default-drop"].detail
    assert "3 configured base chains loaded as declared" in run.results["nft-default-drop"].detail


def _verify_installed_healthy(run: Run) -> None:
    assert [line.split("|")[1] for line in run.stdout.splitlines()] == [*ALL_CHECKS, *INSTALLED_ONLY_CHECKS, "RESULT"]
    assert "root is on dm-crypt mapping cryptroot-sim (LUKS2, on /dev/vda4); 2 keyslot(s), every one argon2id" in (
        run.results["root-encrypted"].detail
    )
    assert run.results["no-live-remnants"].detail.startswith("no live-boot or live-config package")
    assert (
        run.results["RESULT"].detail
        == f"{len(ALL_CHECKS) + len(INSTALLED_ONLY_CHECKS) - 1}/{len(ALL_CHECKS) + len(INSTALLED_ONLY_CHECKS)}"
    )


def _verify_the_installed_checks_are_independent(run: Run) -> None:
    """Both installed-only checks are in the output and only the one that was broken failed."""
    assert run.results["root-encrypted"].passed
    assert not run.results["no-live-remnants"].passed


def _verify_the_installed_checks_ran(run: Run) -> None:
    assert run.results["root-encrypted"].passed
    assert run.results["no-live-remnants"].passed


def _verify_live_root_passes(run: Run) -> None:
    assert run.results["live-root"].passed
    assert "examining the live" in run.results["live-root"].detail


def _verify_ipv6_backend(run: Run) -> None:
    assert re.search(r"listens on \[::1\]:\d+ and nowhere else", run.results["backend-loopback-only"].detail)


def _arrange_shipped_configuration(sim: Sim) -> None:
    shutil.rmtree(sim.root / "etc")
    shutil.copytree(IMAGE_ETC / "modprobe.d", sim.root / "etc" / "modprobe.d")
    shutil.copytree(IMAGE_ETC / "sysctl.d", sim.root / "etc" / "sysctl.d")
    shutil.copy(IMAGE_ETC / "nftables.conf", sim.root / "etc" / "nftables.conf")
    sim.install_accounts()  # /etc was replaced wholesale: the accounts are not the overlay's, so they go back
    sim.write(sim.state / "nft.out", SHIPPED_NFT_RULESET.read_text(encoding="utf-8"))
    shutil.rmtree(sim.root / "proc" / "sys")
    for conf in sorted((sim.root / "etc" / "sysctl.d").glob("*.conf")):
        for raw in conf.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0]
            if "=" in line:
                key, value = (part.strip() for part in line.split("=", 1))
                sim.write(sim.root / "proc" / "sys" / Path(*key.split(".")), value + "\n")


SCENARIOS: list[Scenario] = [
    Scenario("healthy-machine", verify=_verify_healthy),
    # -- live-root: fails under the prefix in every run; passes when there is no prefix ----
    Scenario(
        "live-root-passes-without-the-test-prefix",
        env={"PAI_SELFCHECK_ROOT": ""},
        exact=False,
        verify=_verify_live_root_passes,
    ),
    # -- nft-default-drop ----
    Scenario("nft-output-accept", _nft_policy("output", "accept"), {"nft-default-drop": "inet/t/output policy=accept"}),
    Scenario("nft-input-accept", _nft_policy("input", "accept"), {"nft-default-drop": "inet/t/input policy=accept"}),
    Scenario(
        "nft-forward-no-policy",
        lambda s: s.set_nft(chain("input"), chain("forward", None), chain("output")),
        {"nft-default-drop": "policy=None"},
    ),
    Scenario(
        "nft-hook-missing",
        lambda s: s.set_nft(chain("input"), chain("output")),
        {"nft-default-drop": "no filter base chain on hook: forward"},
    ),
    Scenario("nft-empty-ruleset", lambda s: s.set_nft(), {"nft-default-drop": "input, forward, output"}),
    Scenario(
        "nft-extra-chain-open",
        lambda s: s.set_nft(*HEALTHY_CHAINS, chain("input", "accept", name="extra")),
        {"nft-default-drop": "inet/t/extra policy=accept"},
    ),
    Scenario(
        "nft-unconditional-accept",
        lambda s: s.set_nft(*HEALTHY_CHAINS, rules=(rule("input", ACCEPT),)),
        {"nft-default-drop": "unconditional accept in: inet/t/input"},
    ),
    Scenario(
        "nft-unconditional-accept-behind-conditional-rules",
        lambda s: s.set_nft(*HEALTHY_CHAINS, rules=(*HEALTHY_RULES, rule("output", {"counter": {}}, ACCEPT))),
        {"nft-default-drop": "unconditional accept in: inet/t/output"},
    ),
    Scenario(
        "nft-accept-reached-by-unconditional-jump",
        lambda s: s.set_nft(
            *HEALTHY_CHAINS,
            chain_regular("allow_all"),
            rules=(rule("forward", {"jump": {"target": "allow_all"}}), rule("allow_all", ACCEPT)),
        ),
        {"nft-default-drop": "unconditional accept in: inet/t/forward via inet/t/allow_all"},
    ),
    Scenario(
        "nft-accept-reached-by-unconditional-goto",
        lambda s: s.set_nft(
            *HEALTHY_CHAINS,
            chain_regular("allow_all"),
            rules=(rule("output", {"goto": {"target": "allow_all"}}), rule("allow_all", ACCEPT)),
        ),
        {"nft-default-drop": "inet/t/output via inet/t/allow_all"},
    ),
    Scenario(
        "nft-chain-in-config-not-loaded",
        lambda s: s.set_nft(*[{**c, "table": "other"} for c in HEALTHY_CHAINS], rules=()),
        {"nft-default-drop": "inet/t/input is configured but not loaded"},
    ),
    Scenario(
        "nft-config-chain-loaded-with-another-hook",
        lambda s: s.set_nft(chain("input"), chain("forward"), chain("output"), chain("prerouting", name="input")),
        {"nft-default-drop": "inet/t/input: configured filter hook input policy drop, live filter hook prerouting"},
    ),
    Scenario(
        "nft-config-file-missing",
        lambda s: (s.root / "etc" / "nftables.conf").unlink(),
        {"nft-default-drop": "cannot read"},
    ),
    Scenario(
        "nft-config-declares-no-base-chain",
        lambda s: s.write(s.root / "etc" / "nftables.conf", "table inet t { chain input { } }\n"),
        {"nft-default-drop": "nothing to verify"},
    ),
    Scenario(
        "nft-not-json", lambda s: s.write(s.state / "nft.out", "not json"), {"nft-default-drop": "not valid JSON"}
    ),
    Scenario(
        "nft-command-fails",
        lambda s: (s.write(s.state / "nft.out", "Operation not permitted"), s.write(s.state / "nft.rc", "1")),
        {"nft-default-drop": "nft -j list ruleset failed"},
    ),
    Scenario(
        "nft-config-chain-with-accept-policy-loaded-as-drop",
        _all_of(
            lambda s: s.write(
                s.root / "etc" / "nftables.conf",
                conf_with("chain pre { type filter hook prerouting priority -300; policy accept; }"),
            ),
            lambda s: s.set_nft(*HEALTHY_CHAINS, chain("prerouting", "drop", name="pre")),
        ),
        {
            "nft-default-drop": "inet/t/pre: configured filter hook prerouting policy accept, "
            "live filter hook prerouting policy drop"
        },
    ),
    Scenario(
        "nft-accepts-that-are-conditional-or-unreachable-and-chains-declared-accept-are-no-hole",
        _all_of(
            lambda s: s.write(
                s.root / "etc" / "nftables.conf",
                conf_with(
                    "chain pre { type filter hook prerouting priority -300; policy accept; }\n"
                    "    chain post { type filter hook postrouting priority 300; }"  # no policy statement: accept
                ),
            ),
            lambda s: s.set_nft(
                *HEALTHY_CHAINS,
                chain("prerouting", "accept", name="pre"),
                chain("postrouting", "accept", name="post"),
                chain_regular("helper"),
                chain_regular("unused"),
                rules=(
                    rule(
                        "input", MATCH, {"jump": {"target": "helper"}}
                    ),  # a conditional jump into a chain that accepts
                    rule("helper", ACCEPT),
                    rule("unused", ACCEPT),  # nothing jumps here
                    rule("output", {"drop": None}),  # an unconditional verdict ends the chain: the next rule is dead
                    rule("output", ACCEPT),
                    rule("forward", {"limit": {"rate": 5, "per": "second"}}, ACCEPT),  # rate-limited, so conditional
                ),
            ),
        ),
        details={"nft-default-drop": "5 configured base chains loaded as declared"},
    ),
    # -- modules-blocked ----
    Scenario("module-loaded", _module_loaded, {"modules-blocked": "hostshare is loaded"}),
    Scenario("module-loaded-hyphen-vs-underscore", _module_hyphenated, {"modules-blocked": "host-share is loaded"}),
    Scenario(
        "module-install-override-missing",
        _override_not_blocking,
        {"modules-blocked": "would not run a blocking install command"},
        verify=_verify_dry_run_only,
    ),
    Scenario("module-no-install-lines", _no_install_lines, {"modules-blocked": "nothing to verify"}),
    Scenario(
        "module-every-blocked-module-checked-and-every-failure-reported",
        lambda s: (
            s.write(
                s.root / "etc" / "modprobe.d" / "block.conf",
                "install hostshare /bin/false\ninstall second_mod /bin/false\n",
            ),
            s.write(s.root / "etc" / "modprobe.d" / "other.conf", "install third_mod /bin/false\noptions foo bar=1\n"),
            s.write(s.root / "proc" / "modules", "second_mod 1 0 - Live 0x0\n"),
        ),
        {"modules-blocked": "second_mod is loaded"},
        verify=_verify_every_module_checked,
    ),
    Scenario(
        "module-names-and-install-commands-that-still-block",
        lambda s: (
            # a dashed name (the kernel lists it with an underscore) and a no-op /bin/true install, with a comment
            s.write(
                s.root / "etc" / "modprobe.d" / "block.conf",
                "install host-share /bin/false\ninstall hostshare /bin/true # no-op\n",
            ),
            s.write(s.state / "modprobe.dry.hostshare", "install /bin/true \n"),
        ),
        details={"modules-blocked": "blocked and not loaded: host-share hostshare"},
    ),
    # -- sysctl-live ----
    Scenario(
        "sysctl-mismatch",
        lambda s: s.sysctl("net.sim.switch", "0", live="1", conf="91-extra.conf"),
        {"sysctl-live": "net.sim.switch: configured '0', live '1'"},
    ),
    Scenario(
        "sysctl-live-missing",
        lambda s: s.sysctl("net.sim.gone", "1", live_present=False, conf="91-extra.conf"),
        {"sysctl-live": "net.sim.gone: not readable"},
    ),
    Scenario(
        "sysctl-wildcard-key",
        lambda s: s.sysctl("net.sim.*.rp", "1", live_present=False, conf="91-extra.conf"),
        {"sysctl-live": "wildcard keys are not supported"},
    ),
    Scenario(
        "sysctl-multivalue-differs",
        lambda s: s.sysctl("net.sim.triple", "4096 131072 6291456", live="4096\t131072\t1", conf="91-extra.conf"),
        {"sysctl-live": "net.sim.triple"},
    ),
    Scenario(
        "sysctl-no-settings", lambda s: shutil.rmtree(s.root / "etc" / "sysctl.d"), {"sysctl-live": "nothing to verify"}
    ),
    Scenario(
        "sysctl-optional-later-and-slash-separated-keys-are-read-like-systemd-sysctl",
        lambda s: (
            s.sysctl(
                "net.sim.optional", "1", live_present=False, conf="91-extra.conf", prefix="-"
            ),  # not in the kernel
            s.sysctl("net.sim.switch", "1", live="1", conf="99-later.conf"),  # 90-sim.conf says 0: the later file wins
            s.sysctl("net/sim/slashed", "7", conf="91-extra.conf"),
        ),
        details={"sysctl-live": "5 settings match the live kernel"},
    ),
    # -- no-external-listeners ----
    Scenario(
        "listener-tcp-wildcard",
        _listener("tcp", ipv4_hex(WILDCARD_V4), 22, STATE_LISTEN),
        {"no-external-listeners": "tcp 0.0.0.0:22"},
    ),
    Scenario(
        "listener-tcp-on-nic-address",
        _listener("tcp", ipv4_hex("10.0.2.15"), 8080, STATE_LISTEN),
        {"no-external-listeners": "tcp 10.0.2.15:8080"},
    ),
    Scenario(
        "listener-tcp6-wildcard",
        _listener("tcp6", ipv6_hex("::"), 22, STATE_LISTEN),
        {"no-external-listeners": "tcp6 [::]:22"},
    ),
    Scenario(
        "listener-udp-wildcard",
        _listener("udp", ipv4_hex(WILDCARD_V4), 5353, STATE_UNCONNECTED),
        {"no-external-listeners": "udp 0.0.0.0:5353"},
    ),
    Scenario(
        "listener-udp6-link-local",
        _listener("udp6", ipv6_hex("fe80::1"), 5353, STATE_UNCONNECTED),
        {"no-external-listeners": "udp6 [fe80::1]:5353"},
    ),
    Scenario(
        "listener-allow-is-per-table",
        _listener("udp6", ipv6_hex("fe80::1"), 68, STATE_UNCONNECTED),
        {"no-external-listeners": "udp6 [fe80::1]:68"},
    ),
    Scenario(
        "listener-allow-never-covers-a-wildcard-bind-udp",
        _listener("udp", ipv4_hex(WILDCARD_V4), 68, STATE_UNCONNECTED),
        {"no-external-listeners": "udp 0.0.0.0:68"},
    ),
    Scenario(
        "listener-allow-never-covers-a-wildcard-bind-udp6",
        _listener("udp6", ipv6_hex("::"), 546, STATE_UNCONNECTED),
        {"no-external-listeners": "udp6 [::]:546"},
    ),
    Scenario(
        "listener-allow-never-covers-a-mapped-wildcard-bind",
        _listener("udp6", ipv6_hex(f"::ffff:{WILDCARD_V4}"), 546, STATE_UNCONNECTED),
        {"no-external-listeners": "udp6 [::ffff:0:0]:546"},
    ),
    Scenario(
        "listener-allow-is-per-port",
        _listener("udp", ipv4_hex(WILDCARD_V4), 69, STATE_UNCONNECTED),
        {"no-external-listeners": "udp 0.0.0.0:69"},
    ),
    Scenario(
        "listener-net-table-unreadable-also-blinds-the-backend-loopback-check",
        lambda s: (s.root / "proc" / "net" / "tcp").unlink(),
        {"no-external-listeners": "cannot read tcp", "backend-loopback-only": "cannot read tcp"},
    ),
    Scenario(
        "listener-garbage-row-is-a-failure-of-the-checks-that-read-it-and-of-no-other",
        lambda s: s.set_sockets(tcp=["   0: ZZZZ:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000"]),
        {
            "no-external-listeners": "ValueError",
            **{
                check: "the probe crashed"
                for check in ("backend-loopback-only", "backend-refuses-anonymous", "backend-health")
            },
        },
    ),
    Scenario(
        "listener-allow-table-admits-the-dhcp-client-ports-and-says-so",
        lambda s: s.set_sockets(
            udp=[sock_row(ipv4_hex("10.0.2.15"), 68, STATE_UNCONNECTED)],
            udp6=[sock_row(ipv6_hex("fe80::5054:ff:fe12:3456"), 546, STATE_UNCONNECTED)],
        ),
        details={
            "no-external-listeners": "udp 10.0.2.15:68, udp6 [fe80::5054:ff:fe12:3456]:546",
        },
    ),
    Scenario(
        "listener-established-connections-and-missing-ipv6-tables-are-not-listeners",
        lambda s: ((s.root / "proc" / "net" / "tcp6").unlink(), (s.root / "proc" / "net" / "udp6").unlink()),
    ),
    # -- units-active ----
    Scenario(
        "unit-inactive", _unit_state("nftables.service", "inactive"), {"units-active": "nftables.service is inactive"}
    ),
    Scenario(
        "unit-failed",
        _unit_state("systemd-networkd.service", "failed"),
        {"units-active": "systemd-networkd.service is failed"},
    ),
    # -- backend-active: the unit as systemd reports it ----
    Scenario(
        "backend-unit-inactive",
        _unit(ActiveState="inactive"),
        _unit_is_not_up(f"{BACKEND_UNIT} is inactive"),
    ),
    Scenario("backend-unit-failed", _unit(ActiveState="failed"), _unit_is_not_up(f"{BACKEND_UNIT} is failed")),
    Scenario(
        "backend-unit-not-installed",
        _unit(LoadState="not-found", ActiveState="inactive"),
        _unit_is_not_up(f"{BACKEND_UNIT} is not installed"),
    ),
    Scenario(
        "backend-unit-still-activating-when-the-wait-ends",
        lambda s: s.unit_activates_after(1000),
        _unit_is_not_up(f"{BACKEND_UNIT} is activating"),
    ),
    Scenario(
        "backend-unit-reaches-active-while-the-script-waits",
        lambda s: s.unit_activates_after(2),
        env={"PAI_SELFCHECK_READY_TIMEOUT": "20"},
    ),
    Scenario("backend-ready-timeout-with-a-leading-zero-is-decimal", env={"PAI_SELFCHECK_READY_TIMEOUT": "08"}),
    Scenario(
        "backend-unit-reads-an-environment-file-the-self-check-cannot-see",
        _unit(EnvironmentFiles="/etc/default/pai-sim (ignore_errors=no)"),
        _unit_is_not_up("loads EnvironmentFile="),
    ),
    Scenario(
        "backend-systemctl-show-fails",
        lambda s: s.write(s.state / "show.rc", "1"),
        {**_unit_is_not_up(f"{BACKEND_UNIT} is unknown"), **_kiosk_is_not_up(f"{KIOSK_UNIT} is unknown")},
    ),
    Scenario(
        "backend-ready-timeout-is-not-a-number",
        env={"PAI_SELFCHECK_READY_TIMEOUT": "soon"},
        failing=_unit_is_not_up("is not a whole number of seconds"),
    ),
    # -- backend-active: the service answering ----
    Scenario(
        "backend-refuses-connections",
        _backend_down,
        {
            "backend-active": "is not ready",
            "backend-refuses-anonymous": "the backend is not ready, so it was not asked",
            "backend-health": "the backend is not ready, so it was not asked",
            "no-secret-in-process-state": "the backend gave no answer to 2 request(s)",
        },
        verify=_verify_nothing_was_asked,
    ),
    Scenario(
        "backend-refuses-connections-and-has-no-socket-in-proc-net",
        _all_of(_backend_down, lambda s: s.backend_listens_on()),
        {
            "backend-active": "is not ready",
            "backend-loopback-only": "nothing listens on",
            "backend-refuses-anonymous": "not ready",
            "backend-health": "not ready",
            "no-secret-in-process-state": "gave no answer",
        },
    ),
    Scenario(
        "backend-token-file-missing",
        lambda s: s.token_file.unlink(),
        {
            "backend-active": "token file is not ready",
            "backend-refuses-anonymous": "not ready",
            "backend-health": "not ready",
            "no-secret-in-process-state": "cannot read the token file",
        },
        verify=_verify_nothing_was_asked,
    ),
    Scenario(
        "backend-token-file-empty",
        lambda s: s.write(s.token_file, ""),
        {
            "backend-active": "the token file is empty",
            "backend-refuses-anonymous": "not ready",
            "backend-health": "not ready",
            "no-secret-in-process-state": "is empty",
        },
    ),
    Scenario(
        "backend-token-file-is-not-text",
        lambda s: s.token_file.write_bytes(b"\xff\xfe\xfd\xfc" * 8),
        {"backend-health": "cannot read the token file"},
    ),
    Scenario(
        "backend-token-file-holds-another-token",
        lambda s: s.write(s.token_file, "w" * 24 + "\n"),
        {"backend-health": "returned 401, expected 200"},
        verify=_verify_wrong_token_is_what_was_sent,
    ),
    # -- backend-refuses-anonymous ----
    Scenario(
        "backend-answers-anonymous-requests",
        _anonymous(Reply(200, health_body())),
        {
            "backend-refuses-anonymous": "returned 200, expected 401",
            # A backend that accepts a request with no credential accepts every cookie too: nothing can be told apart.
            "no-secret-in-process-state": "a value the backend accepts as a session cookie in the environment of pid",
        },
    ),
    Scenario(
        "backend-redirects-anonymous-requests",
        _anonymous(Reply(302, b"", {"Location": "/login"})),
        {"backend-refuses-anonymous": "returned 302, expected 401"},
    ),
    Scenario(
        "backend-forbids-instead-of-asking-for-credentials",
        _anonymous(Reply(403, b"{}")),
        {"backend-refuses-anonymous": "returned 403, expected 401"},
    ),
    Scenario(
        "backend-server-error-for-anonymous-requests",
        _anonymous(Reply(500, b"oops")),
        {"backend-refuses-anonymous": "returned 500, expected 401"},
    ),
    Scenario(
        "backend-drops-anonymous-requests",
        _anonymous(Reply(None)),
        {"backend-refuses-anonymous": "got no answer", "no-secret-in-process-state": "gave no answer to 1 request(s)"},
    ),
    # -- backend-health ----
    Scenario(
        "backend-health-server-error-never-echoes-its-body",
        lambda s: s.backend.__setattr__("authenticated", Reply(500, f"debug dump {s.backend.token}".encode())),
        {"backend-health": "returned 500, expected 200"},
    ),
    Scenario(
        "backend-health-not-json",
        _health_answer(b"<html>ok</html>"),
        {"backend-health": "without the documented body"},
    ),
    Scenario(
        "backend-health-status-not-ok",
        _health_answer({"status": "degraded", "schema_version": 1, "version": "0.0.1"}),
        {"backend-health": "without the documented body"},
    ),
    Scenario(
        "backend-health-schema-version-is-text",
        _health_answer({"status": "ok", "schema_version": "1", "version": "0.0.1"}),
        {"backend-health": "without the documented body"},
    ),
    Scenario(
        "backend-health-version-is-a-number",
        _health_answer({"status": "ok", "schema_version": 1, "version": 1}),
        {"backend-health": "without the documented body"},
    ),
    Scenario(
        "backend-health-field-missing",
        _health_answer({"status": "ok", "schema_version": 1}),
        {"backend-health": "without the documented body"},
    ),
    Scenario(
        "backend-health-body-is-a-list",
        _health_answer([{"status": "ok", "schema_version": 1, "version": "0.0.1"}]),
        {"backend-health": "without the documented body"},
    ),
    Scenario(
        "backend-health-drops-authenticated-requests",
        _authenticated(Reply(None)),
        {"backend-health": "got no answer"},
    ),
    Scenario(
        "backend-health-long-version-is-cut",
        _authenticated(Reply(200, health_body(version="9" * 100))),
        verify=_verify_version_is_cut,
    ),
    # -- the backend's settings, read from the unit's environment ----
    Scenario(
        "backend-environment-is-not-a-valid-configuration",
        lambda s: s.set_unit(Environment=s.environment(PAI_HOST="not-an-ip")),
        {check: "not a valid backend configuration" for check in BACKEND_PROBE_CHECKS},
    ),
    Scenario(
        "backend-settings-left-to-defaults-zero-wait-and-a-bare-zero-capability-mask",
        lambda s: (
            s.set_unit(Environment=s.environment(PAI_HOST=None)),  # the backend's own default address
            s.set_process(capabilities="0"),  # any width of zeros is "none"
        ),
        env={"PAI_SELFCHECK_READY_TIMEOUT": "0"},  # one attempt, no waiting
    ),
    Scenario(
        "backend-environment-has-an-unbalanced-quote",
        lambda s: s.set_unit(Environment=s.environment() + ' "PAI_LOG_LEVEL=info'),
        {check: "cannot read the unit's environment" for check in BACKEND_PROBE_CHECKS},
    ),
    Scenario(
        "backend-code-missing-from-the-app-directory",
        lambda s: shutil.rmtree(s.root / "opt" / "pai"),
        {
            **{check: "cannot read the backend's settings" for check in BACKEND_PROBE_CHECKS},
            **{
                check: "cannot read the kiosk's settings" for check in KIOSK_PROBE_CHECKS
            },  # the kiosk is in /opt/pai too
        },
    ),
    Scenario(
        "backend-python-missing",
        lambda s: s.write(s.bin / "python3", "#!/bin/sh\necho 'python3: not available' >&2\nexit 127\n"),
        {
            "nft-default-drop": "python3: not available",
            "no-external-listeners": "python3: not available",
            **{check: "python3: not available" for check in BACKEND_PROBE_CHECKS},
            **{check: "the probe crashed: python3: not available" for check in KIOSK_PROBE_CHECKS},
        },
    ),
    Scenario("backend-on-ipv6-loopback", host="::1", verify=_verify_ipv6_backend),
    # -- backend-unprivileged ----
    Scenario("backend-no-user", _unit(User=""), {"backend-unprivileged": "sets no User="}),
    Scenario("backend-no-main-process", _unit(MainPID="0"), {"backend-unprivileged": "has no main process"}),
    Scenario(
        "backend-main-process-unreadable",
        _unit(MainPID="999"),
        {"backend-unprivileged": "cannot read"},
    ),
    Scenario(
        "backend-account-does-not-exist",
        lambda s: s.set_users({KIOSK_USER: KIOSK_UID}),
        {"backend-unprivileged": f"the account {SERVICE_USER} that {BACKEND_UNIT} runs as does not exist"},
    ),
    Scenario(
        "backend-account-is-uid-0",
        lambda s: s.set_users({SERVICE_USER: 0, KIOSK_USER: KIOSK_UID}),
        {"backend-unprivileged": "is uid 0"},
    ),
    Scenario(
        "backend-process-runs-as-root",
        _process(uids=(0, 0, 0, 0)),
        {"backend-unprivileged": f"are 0/0/0/0, not {SERVICE_UID} ({SERVICE_USER})"},
    ),
    Scenario(
        "backend-process-effective-uid-differs",
        _process(uids=(SERVICE_UID, 0, SERVICE_UID, SERVICE_UID)),
        {"backend-unprivileged": f"are {SERVICE_UID}/0/{SERVICE_UID}/{SERVICE_UID}"},
    ),
    Scenario(
        "backend-process-filesystem-uid-differs",
        _process(uids=(SERVICE_UID, SERVICE_UID, SERVICE_UID, 0)),
        {"backend-unprivileged": f"are {SERVICE_UID}/{SERVICE_UID}/{SERVICE_UID}/0"},
    ),
    Scenario(
        "backend-process-holds-capabilities",
        _process(capabilities="0000000000003000"),
        {"backend-unprivileged": "effective capabilities are 0000000000003000, not none"},
    ),
    Scenario(
        "backend-process-may-gain-privileges",
        _process(no_new_privs="0"),
        {"backend-unprivileged": "NoNewPrivs is 0, not 1"},
    ),
    Scenario(
        "backend-process-status-lacks-the-fields",
        lambda s: s.write(s.root / "proc" / str(SERVICE_PID) / "status", "Name:\tpython3\n"),
        {"backend-unprivileged": "effective capabilities are unknown, not none; NoNewPrivs is unknown, not 1"},
    ),
    Scenario(
        "backend-process-has-every-problem-at-once",
        _process(uids=(0, 0, 0, 0), capabilities="000001ffffffffff", no_new_privs="0"),
        {"backend-unprivileged": "uids real/effective/saved/filesystem are 0/0/0/0"},
        verify=_verify_three_problems,
    ),
    # -- backend-loopback-only ----
    Scenario(
        "backend-listens-on-every-address",
        lambda s: s.backend_listens_on(WILDCARD_V4),
        {
            "backend-loopback-only": "listening beyond loopback on the backend port: tcp 0.0.0.0:",
            "no-external-listeners": "tcp 0.0.0.0:",
        },
        verify=_verify_wildcard_backend,
    ),
    Scenario(
        "backend-listens-on-every-ipv6-address",
        lambda s: s.backend_listens_on("::"),
        {
            "backend-loopback-only": "listening beyond loopback on the backend port: tcp6 [::]:",
            "no-external-listeners": "tcp6 [::]:",
        },
    ),
    Scenario(
        "backend-also-listens-on-the-nic-address",
        lambda s: s.backend_listens_on("127.0.0.1", "10.0.2.15"),
        {
            "backend-loopback-only": "listening beyond loopback on the backend port: tcp 10.0.2.15:",
            "no-external-listeners": "tcp 10.0.2.15:",
        },
    ),
    Scenario(
        "backend-listens-on-another-loopback-address-than-configured",
        lambda s: s.backend_listens_on("127.0.0.2"),
        {"backend-loopback-only": "nothing listens on 127.0.0.1:"},
    ),
    Scenario(
        "backend-listens-on-another-port-than-configured",
        lambda s: s.backend_listens_on("127.0.0.1", port=1),
        {"backend-loopback-only": "nothing listens on 127.0.0.1:"},
    ),
    # -- backend-sandbox-exposure ----
    Scenario(
        "sandbox-exposure-at-the-limit",
        _analyze("1.2 OK :-)"),
        details={"backend-sandbox-exposure": "within the limit 1.2"},
    ),
    Scenario(
        "sandbox-exposure-one-tenth-above-the-limit",
        _analyze("1.3 OK :-)"),
        {"backend-sandbox-exposure": "exposure is 1.3, above the limit 1.2"},
    ),
    Scenario(
        "sandbox-exposure-two-digits",
        _analyze("10.0 UNSAFE"),
        {"backend-sandbox-exposure": "exposure is 10.0, above the limit 1.2"},
    ),
    Scenario(
        "sandbox-exposure-line-missing",
        lambda s: s.write(s.state / "analyze.out", "  NAME DESCRIPTION EXPOSURE\n"),
        {"backend-sandbox-exposure": "no exposure level in the systemd-analyze report"},
    ),
    Scenario(
        "sandbox-analysis-fails",
        lambda s: (s.write(s.state / "analyze.out", "Failed to connect to bus"), s.write(s.state / "analyze.rc", "1")),
        {"backend-sandbox-exposure": "systemd-analyze security failed: Failed to connect to bus"},
    ),
    # -- kiosk-active and kiosk-ready: the unit as systemd reports it ----
    Scenario(
        "kiosk-unit-inactive",
        _kiosk_unit(ActiveState="inactive"),
        _kiosk_is_not_up(f"{KIOSK_UNIT} is inactive"),
    ),
    Scenario("kiosk-unit-failed", _kiosk_unit(ActiveState="failed"), _kiosk_is_not_up(f"{KIOSK_UNIT} is failed")),
    Scenario(
        "kiosk-unit-not-installed",
        _kiosk_unit(LoadState="not-found", ActiveState="inactive"),
        _kiosk_is_not_up(f"{KIOSK_UNIT} is not installed"),
    ),
    Scenario(
        "kiosk-unit-still-activating-when-the-wait-ends",
        lambda s: s.unit_activates_after(1000, kiosk=True),
        _kiosk_is_not_up(f"{KIOSK_UNIT} is activating"),
    ),
    Scenario(
        "kiosk-unit-reaches-active-while-the-script-waits",
        lambda s: s.unit_activates_after(2, kiosk=True),
        env={"PAI_SELFCHECK_KIOSK_TIMEOUT": "20"},
    ),
    Scenario("kiosk-timeout-with-a-leading-zero-is-decimal", env={"PAI_SELFCHECK_KIOSK_TIMEOUT": "08"}),
    Scenario(
        "kiosk-timeout-is-not-a-number",
        env={"PAI_SELFCHECK_KIOSK_TIMEOUT": "soon"},
        failing=_kiosk_is_not_up("PAI_SELFCHECK_KIOSK_TIMEOUT is not a whole number of seconds"),
    ),
    Scenario(
        "kiosk-unit-reads-an-environment-file-the-self-check-cannot-see",
        _kiosk_unit(EnvironmentFiles="/etc/default/pai-kiosk-sim (ignore_errors=no)"),
        _kiosk_is_not_up("loads EnvironmentFile="),
    ),
    # -- kiosk: the kiosk's settings, read from the unit's environment ----
    Scenario(
        "kiosk-environment-is-not-a-valid-configuration",
        lambda s: s.set_kiosk_unit(Environment=s.kiosk_environment(PAI_KIOSK_READY_FILE="relative/ready")),
        _kiosk_is_not_up("not a valid kiosk configuration"),
    ),
    Scenario(
        "kiosk-environment-has-an-unbalanced-quote",
        lambda s: s.set_kiosk_unit(Environment=s.kiosk_environment() + ' "PAI_KIOSK_CHROMIUM_FLAGS=--x'),
        _kiosk_is_not_up("cannot read the unit's environment"),
    ),
    Scenario(
        "kiosk-code-missing-from-the-app-directory",
        lambda s: shutil.rmtree(s.root / "opt" / "pai" / "kiosk"),
        _kiosk_is_not_up("cannot read the kiosk's settings"),
    ),
    Scenario(
        "kiosk-readiness-contract-missing-from-the-app-directory",
        lambda s: (s.root / "opt" / "pai" / "kiosk" / "readiness.py").unlink(),
        _kiosk_is_not_up("cannot read the kiosk's readiness contract"),
    ),
    # -- kiosk-active: who the main process is ----
    Scenario("kiosk-no-user", _kiosk_unit(User=""), {"kiosk-active": "sets no User="}),
    Scenario(
        "kiosk-no-main-process",
        _kiosk_unit(MainPID="0"),
        {"kiosk-active": "has no main process", "kiosk-ready": "did not report 'ready'"},
    ),
    Scenario(
        "kiosk-main-process-is-gone-and-systemd-still-names-it",
        _kiosk_unit(MainPID="999"),
        {"kiosk-active": f"the main process of {KIOSK_UNIT}, pid 999, is gone (cannot read"},
        verify=_verify_the_pid_is_still_the_units,
    ),
    Scenario(
        "kiosk-main-process-is-gone-and-systemd-reports-another",
        # what systemd said while the script waited (a process that is gone), and what it says afterwards
        lambda s: s.unit_reports_differently_at_first(2, kiosk=True, MainPID="999"),
        {"kiosk-active": "pid 999, is gone (cannot read"},
        verify=_verify_the_pid_that_went_away_is_named,
    ),
    Scenario(
        "kiosk-restarted-while-the-script-waited-is-judged-by-its-new-main-process",
        # the first answer names a process that is gone, the next one the restarted kiosk's: the probe asks again
        lambda s: s.unit_reports_differently_at_first(1, kiosk=True, MainPID="999"),
        details={"kiosk-active": f"pid {KIOSK_PID} of {KIOSK_UNIT} runs as {KIOSK_USER}"},
    ),
    # -- what a failing kiosk check adds: the unit's state and journal ----
    Scenario(
        "kiosk-that-died-is-explained-by-systemd-and-its-journal-with-credentials-masked",
        _kiosk_died,
        _kiosk_is_not_up(f"{KIOSK_UNIT} is failed"),
        verify=_verify_a_failed_kiosk_is_explained,
    ),
    Scenario(
        "kiosk-diagnostics-keep-the-last-lines-of-the-journal-and-cut-each-line",
        _kiosk_died_with_a_long_journal,
        _kiosk_is_not_up(f"{KIOSK_UNIT} is inactive"),
        verify=_verify_only_the_last_journal_lines_and_each_one_cut,
    ),
    Scenario(
        "kiosk-diagnostics-say-when-the-journal-cannot-be-read",
        lambda s: (s.set_kiosk_unit(ActiveState="failed"), s.write(s.state / "journal.fails", "")),
        _kiosk_is_not_up("journalctl failed: Failed to open journal: Permission denied"),
    ),
    Scenario(
        "kiosk-diagnostics-say-when-the-journal-is-empty",
        _kiosk_unit(ActiveState="failed"),
        _kiosk_is_not_up(f"the journal of {KIOSK_UNIT} has no line"),
    ),
    Scenario(
        "kiosk-diagnostics-are-added-to-a-readiness-failure-too",
        lambda s: (s.ready_file.unlink(), s.set_journal(KIOSK_UNIT, ["launcher: waiting for the page"])),
        {"kiosk-ready": "does not exist: the kiosk has not published its readiness; systemd reports for"},
        details={"kiosk-ready": "launcher: waiting for the page"},
    ),
    Scenario(
        "kiosk-account-does-not-exist",
        lambda s: s.set_users({SERVICE_USER: SERVICE_UID}),
        {"kiosk-active": f"the account {KIOSK_USER} that {KIOSK_UNIT} runs as does not exist"},
    ),
    Scenario(
        "kiosk-account-is-uid-0",
        lambda s: s.set_users({SERVICE_USER: SERVICE_UID, KIOSK_USER: 0}),
        {"kiosk-active": "is uid 0"},
    ),
    Scenario(
        "kiosk-process-runs-as-root",
        lambda s: s.write_status(KIOSK_PID, (0, 0, 0, 0)),
        {"kiosk-active": f"are 0/0/0/0, not {KIOSK_UID} ({KIOSK_USER})"},
    ),
    Scenario(
        "kiosk-process-effective-uid-differs",
        lambda s: s.write_status(KIOSK_PID, (KIOSK_UID, 0, KIOSK_UID, KIOSK_UID)),
        {"kiosk-active": f"are {KIOSK_UID}/0/{KIOSK_UID}/{KIOSK_UID}"},
    ),
    # -- kiosk-active: the browser ----
    Scenario(
        "kiosk-browser-not-running",
        lambda s: (s.remove_process(BROWSER_PID), s.remove_process(BROWSER_CHILD_PID)),
        {"kiosk-active": f"no {BROWSER_NAME} process descends from pid {KIOSK_PID}"},
    ),
    Scenario(
        "kiosk-browser-is-not-below-the-main-process",
        lambda s: s.add_process(BROWSER_PID, ppid=1, comm=BROWSER_NAME, uid=KIOSK_UID),
        {"kiosk-active": f"no {BROWSER_NAME} process descends from pid {KIOSK_PID}"},
    ),
    Scenario(
        "kiosk-browser-is-another-process-than-the-one-the-settings-name",
        lambda s: s.set_kiosk_unit(Environment=s.kiosk_environment(PAI_KIOSK_CHROMIUM="/opt/sim/other-browser")),
        {"kiosk-active": "no other-browser process descends"},
    ),
    Scenario(
        "kiosk-browser-is-the-one-the-settings-name-even-with-a-long-name",
        lambda s: (
            s.set_kiosk_unit(Environment=s.kiosk_environment(PAI_KIOSK_CHROMIUM="/opt/sim/a-very-long-browser-name")),
            # the kernel cuts a process name at 15 characters
            s.add_process(BROWSER_PID, ppid=LAUNCHER_PID, comm="a-very-long-bro", uid=KIOSK_UID),
        ),
        details={"kiosk-active": "a-very-long-bro process(es) descend from pid"},
    ),
    Scenario(
        "kiosk-browser-appears-while-the-script-waits",
        _browser_appears_later,
        env={"PAI_SELFCHECK_KIOSK_TIMEOUT": "30"},
        details={"kiosk-active": f"{BROWSER_NAME} process(es) descend from pid {KIOSK_PID}"},
    ),
    # -- kiosk-ready ----
    Scenario(
        "kiosk-ready-file-missing",
        lambda s: s.ready_file.unlink(),
        {"kiosk-ready": "does not exist: the kiosk has not published its readiness"},
    ),
    Scenario(
        "kiosk-ready-file-is-where-the-settings-say",
        lambda s: (
            s.ready_file.unlink(),
            s.set_kiosk_unit(Environment=s.kiosk_environment(PAI_KIOSK_READY_FILE=(s.root / "elsewhere").as_posix())),
            s.write(s.root / "elsewhere", s.ready_report()),
        ),
        details={"kiosk-ready": "elsewhere says ready"},
    ),
    Scenario(
        "kiosk-reports-not-ready",
        _ready(state="not-ready", shell_rendered=False, status_bar=None),
        {"kiosk-ready": "the kiosk reports state not-ready, not ready"},
    ),
    Scenario(
        "kiosk-shell-did-not-render",
        _ready(shell_rendered=False),
        {"kiosk-ready": "the shell did not render"},
    ),
    Scenario(
        "kiosk-shell-rendered-is-text-not-true",
        _ready(shell_rendered="yes"),
        {"kiosk-ready": "the shell did not render"},
    ),
    Scenario(
        "kiosk-backend-still-connecting",
        _ready(status_bar="Backend connecting"),
        {"kiosk-ready": f"the status bar says 'Backend connecting', not '{CONNECTED_LABEL}'"},
    ),
    Scenario(
        "kiosk-backend-unreachable",
        _ready(status_bar="Backend unreachable Connection failed. Retrying."),
        {"kiosk-ready": "the status bar says 'Backend unreachable"},
    ),
    Scenario(
        "kiosk-page-has-no-valid-session",
        _ready(status_bar="No valid session This window has no valid session with the assistant service."),
        {"kiosk-ready": "the status bar says 'No valid session"},
    ),
    Scenario("kiosk-status-bar-missing", _ready(status_bar=None), {"kiosk-ready": "the status bar says 'None'"}),
    Scenario(
        "kiosk-status-bar-starts-with-the-label-but-is-another-word",
        _ready(status_bar=f"{CONNECTED_LABEL}ness"),
        {"kiosk-ready": "the status bar says"},
    ),
    Scenario(
        "kiosk-status-bar-is-the-label-alone",
        _ready(status_bar=CONNECTED_LABEL),
        details={"kiosk-ready": f"status bar '{CONNECTED_LABEL}'"},
    ),
    Scenario(
        "kiosk-status-line-is-cut-so-a-page-cannot-flood-the-detail",
        _ready(status_bar="x" * 500),
        {"kiosk-ready": "the status bar says 'xxxx"},
        verify=_verify_status_is_cut,
    ),
    Scenario(
        "kiosk-ready-file-is-not-json",
        lambda s: s.set_ready("not json"),
        {"kiosk-ready": "cannot read"},
    ),
    Scenario(
        "kiosk-ready-file-is-a-list",
        lambda s: s.set_ready("[1, 2]"),
        {"kiosk-ready": "does not hold a JSON object"},
    ),
    Scenario(
        "kiosk-ready-file-has-another-version",
        _ready(version=99),
        {"kiosk-ready": "has version 99, expected 1"},
    ),
    Scenario(
        "kiosk-ready-file-is-unreadable",
        lambda s: (s.ready_file.unlink(), s.ready_file.mkdir()),
        {"kiosk-ready": "cannot read"},
    ),
    Scenario(
        "kiosk-becomes-ready-while-the-script-waits",
        _ready_appears_later,
        env={"PAI_SELFCHECK_KIOSK_TIMEOUT": "30"},
        details={"kiosk-ready": "says ready"},
    ),
    Scenario(
        "kiosk-never-ready-ends-the-wait-at-the-limit",
        lambda s: s.ready_file.unlink(),
        {"kiosk-ready": "does not exist"},
        env={"PAI_SELFCHECK_KIOSK_TIMEOUT": "2"},
    ),
    # -- no-secret-in-process-state ----
    Scenario(
        "secret-bearer-token-in-an-argument-list",
        _process_with(LEAK_PID, "leaky", argv=lambda s: ["/usr/bin/leaky", f"--token={s.backend.token}"]),
        {"no-secret-in-process-state": f"the bearer token in the argument list of pid {LEAK_PID} (leaky)"},
        verify=_verify_the_token_is_found_both_ways,
    ),
    Scenario(
        "secret-bearer-token-in-an-environment",
        _process_with(LEAK_PID, "leaky", environ=lambda s: {"PAI_TOKEN": s.backend.token}),
        {"no-secret-in-process-state": f"the bearer token in the environment of pid {LEAK_PID} (leaky)"},
    ),
    Scenario(
        "secret-bearer-token-glued-to-other-characters-is-found-as-the-token",
        _process_with(LEAK_PID, "leaky", argv=lambda s: ["leaky", f"x{s.backend.token}"]),
        {"no-secret-in-process-state": f"the bearer token in the argument list of pid {LEAK_PID} (leaky)"},
        verify=_verify_only_the_token_hit,
    ),
    Scenario(
        "secret-bearer-token-in-a-url-fragment-of-the-browser",
        _process_with(
            BROWSER_CHILD_PID,
            BROWSER_NAME,
            ppid=BROWSER_PID,
            uid=KIOSK_UID,
            argv=lambda s: [BROWSER_NAME, f"--app=http://127.0.0.1:{s.backend.port}/#token={s.backend.token}"],
        ),
        {
            "no-secret-in-process-state": "the bearer token in the argument list of "
            f"pid {BROWSER_CHILD_PID} ({BROWSER_NAME})"
        },
    ),
    Scenario(
        "secret-session-id-in-an-environment",
        _process_with(LEAK_PID, "leaky", environ=lambda s: {"PAI_SESSION": s.backend.new_session()}),
        {
            "no-secret-in-process-state": "a value the backend accepts as a session cookie in the environment of pid "
            f"{LEAK_PID} (leaky)"
        },
        verify=_verify_session_is_not_printed,
    ),
    Scenario(
        "secret-session-id-in-an-argument-list",
        _process_with(LEAK_PID, "leaky", argv=lambda s: ["leaky", f"{SESSION_COOKIE}={s.backend.new_session()}"]),
        {
            "no-secret-in-process-state": "a value the backend accepts as a session cookie in the argument list of pid "
            f"{LEAK_PID} (leaky)"
        },
        verify=_verify_session_is_not_printed,
    ),
    Scenario(
        "secret-session-id-in-a-url-query-of-the-launcher",
        _process_with(
            LAUNCHER_PID,
            "python3",
            ppid=KIOSK_PID,
            uid=KIOSK_UID,
            argv=lambda s: ["python3", f"http://127.0.0.1:{s.backend.port}/?session={s.backend.new_session()}"],
        ),
        {"no-secret-in-process-state": f"in the argument list of pid {LAUNCHER_PID} (python3)"},
    ),
    Scenario(
        "secret-session-id-the-backend-no-longer-accepts-is-no-credential",
        _revoked_session,
        details={"no-secret-in-process-state": "2 credential-shaped strings, none accepted"},
    ),
    Scenario(
        "secret-strings-of-another-length-are-not-credential-shaped",
        _process_with(
            LEAK_PID,
            "leaky",
            environ=lambda s: {
                "SHORT": secrets.token_urlsafe(TOKEN_BYTES)[: CREDENTIAL_LENGTH - 1],
                "LONG": secrets.token_urlsafe(TOKEN_BYTES) + "a",
            },
        ),
        details={"no-secret-in-process-state": "1 credential-shaped strings, none accepted"},
    ),
    Scenario(
        "secret-environment-of-a-process-cannot-be-read",
        _unreadable_environ,
        {
            "no-secret-in-process-state": "cannot read the argument list or environment of 1 process(es): "
            f"pid {LEAK_PID} (hidden)"
        },
    ),
    Scenario(
        "secret-process-that-ends-while-the-scan-runs-is-skipped",
        _vanishing_process,
        details={"no-secret-in-process-state": "environment of 7 processes"},
    ),
    Scenario(
        "secret-more-candidates-than-the-check-tests-is-a-failure-and-asks-the-backend-nothing-more",
        _process_with(
            LEAK_PID,
            "noisy",
            environ=lambda s: {f"K{i}": secrets.token_urlsafe(TOKEN_BYTES) for i in range(MAX_CREDENTIAL_CANDIDATES)},
        ),
        {"no-secret-in-process-state": f"are more than the {MAX_CREDENTIAL_CANDIDATES} this check tests"},
        verify=_verify_nothing_was_tried,
    ),
    Scenario(
        "secret-endpoint-file-missing",
        lambda s: s.endpoint_file.unlink(),
        {"no-secret-in-process-state": "does not hold the loopback http origin of the backend: FileNotFoundError"},
        verify=_verify_nothing_was_tried,
    ),
    Scenario(
        "secret-endpoint-file-names-a-host-not-an-address",
        lambda s: s.write(s.endpoint_file, f"http://localhost:{s.backend.port}"),
        {"no-secret-in-process-state": "does not hold the loopback http origin of the backend: ValueError"},
        verify=_verify_nothing_was_tried,
    ),
    Scenario(
        "secret-endpoint-file-names-an-address-beyond-loopback-and-no-request-goes-there",
        lambda s: s.write(s.endpoint_file, f"http://10.0.2.15:{s.backend.port}"),
        {"no-secret-in-process-state": "does not hold the loopback http origin of the backend: ValueError"},
        verify=_verify_nothing_was_tried,
    ),
    Scenario(
        "secret-no-process-can-be-examined",
        lambda s: [shutil.rmtree(p) for p in (s.root / "proc").iterdir() if p.name.isdigit()],
        details={"no-secret-in-process-state": "no process could be examined"},
        exact=False,
    ),
    # -- no-default-credentials ----
    Scenario(
        "credentials-an-account-has-a-password-hash",
        lambda s: s.set_shadow({"root": "*", "sim-user": SHADOW_HASH}),
        {"no-default-credentials": "account(s) with a usable password hash: sim-user"},
        verify=_verify_no_hash_is_printed,
    ),
    Scenario(
        "credentials-the-well-known-live-password-hash-is-found-and-every-account-named",
        lambda s: s.set_shadow(
            {
                "root": "*",
                "alice": SHADOW_HASH,
                "daemon": "*",
                "bob": OLD_STYLE_HASH,
                "carol": "!*",
                "dave": "$y$j9T$sim",
            }
        ),
        {"no-default-credentials": "account(s) with a usable password hash: alice bob dave"},
        verify=_verify_no_hash_is_printed,
    ),
    Scenario(
        "credentials-an-account-with-an-empty-password-needs-none-to-log-in",
        lambda s: s.set_shadow({"root": "*", "sim-user": ""}),
        {"no-default-credentials": "account(s) with an empty password, which needs none to log in: sim-user"},
    ),
    Scenario(
        "credentials-every-lock-and-disable-marker-passes",
        lambda s: s.set_shadow(
            {"root": "*", "a": "!", "b": "!!", "c": "*", "d": "!*", "e": f"!{SHADOW_HASH}", "f": "*LK*"}
        ),
        details={"no-default-credentials": "7 accounts"},
    ),
    Scenario(
        "credentials-shadow-readable-by-everyone",
        lambda s: s.set_shadow({"root": "*"}, mode="644"),
        {"no-default-credentials": "has mode 644, which gives every account access to the password hashes"},
    ),
    Scenario(
        "credentials-shadow-writable-by-everyone",
        lambda s: s.set_shadow({"root": "*"}, mode="0662"),
        {"no-default-credentials": "has mode 0662"},
    ),
    Scenario(
        "credentials-shadow-readable-by-everyone-and-a-hash-are-both-reported",
        lambda s: s.set_shadow({"root": "*", "sim-user": SHADOW_HASH}, mode="604"),
        {"no-default-credentials": "has mode 604"},
        details={"no-default-credentials": "a usable password hash: sim-user"},
    ),
    Scenario(
        "credentials-shadow-with-no-access-for-anyone-but-root-passes",
        lambda s: s.set_shadow({"root": "*"}, mode="0"),
        details={"no-default-credentials": "mode 0"},
    ),
    Scenario(
        "credentials-mode-cannot-be-read",
        lambda s: s.write(s.state / "mode.shadow", "unknown\n"),
        {"no-default-credentials": "cannot read the mode of"},
    ),
    Scenario(
        "credentials-stat-fails",
        lambda s: (s.state / "mode.shadow").unlink(),
        {"no-default-credentials": "cannot examine"},
    ),
    Scenario(
        "credentials-shadow-file-missing",
        lambda s: (s.root / "etc" / "shadow").unlink(),
        {"no-default-credentials": "cannot read"},
    ),
    Scenario(
        "credentials-shadow-file-empty",
        lambda s: s.write(s.root / "etc" / "shadow", ""),
        {"no-default-credentials": "holds no account, so there is nothing to verify"},
    ),
    Scenario(
        "credentials-a-line-that-is-no-account-fails-and-blank-lines-are-ignored",
        lambda s: s.write(s.root / "etc" / "shadow", "root:*:1:::::\n\nnot-an-account\n:x:1:::::\n"),
        {"no-default-credentials": "2 line(s)"},
    ),
    # -- the whole script ----
    Scenario(
        "one-broken-check-does-not-stop-the-others",
        lambda s: (
            s.write(s.state / "nft.rc", "1"),
            s.write(s.state / "unit.nftables.service", "failed"),
            s.sysctl("net.sim.switch", "0", live="9", conf="91-extra.conf"),
            setattr(s.backend, "anonymous", Reply(200, health_body())),
            s.set_analyze_report("1.5 MEDIUM"),
        ),
        {
            "nft-default-drop": "nft -j list ruleset failed",
            "sysctl-live": "net.sim.switch",
            "units-active": "nftables.service is failed",
            "backend-refuses-anonymous": "returned 200",
            "backend-sandbox-exposure": "exposure is 1.5",
            "no-secret-in-process-state": "accepts as a session cookie",
        },
        verify=_verify_independence,
    ),
    Scenario(
        "detail-is-flattened-so-it-cannot-break-the-line-format",
        lambda s: (
            s.write(s.state / "nft.out", "boom|with pipes\x1b[31m and\nnewlines\tand tabs"),
            s.write(s.state / "nft.rc", "1"),
        ),
        {"nft-default-drop": "boom/with pipes"},
        verify=_verify_flattened,
    ),
    Scenario(
        "very-long-detail-is-truncated",
        lambda s: (s.write(s.state / "nft.out", "x" * 5000), s.write(s.state / "nft.rc", "1")),
        {"nft-default-drop": "xxxx"},
        verify=_verify_truncated,
    ),
    Scenario(
        "the-repositorys-own-nftables-modprobe-and-sysctl-configuration-is-understood",
        _arrange_shipped_configuration,
        verify=_verify_the_shipped_configuration,
    ),
    # -- installed-system mode: the two checks that only an installed system reports ----
    Scenario(
        "installed-healthy-system-passes-all-eighteen",
        installed=True,
        verify=lambda run: _verify_installed_healthy(run),
    ),
    Scenario(
        "installed-system-with-an-ordinary-getty-and-a-commented-nopasswd-line-has-no-false-positive",
        _all_of(
            lambda s: s.write(
                s.root / "etc" / "systemd" / "system" / "getty@.service.d" / "noclear.conf",
                "[Service]\nExecStart=\nExecStart=-/sbin/agetty --noclear %I $TERM\n",
            ),
            lambda s: s.write(s.root / "etc" / "sudoers", "# alice ALL=(ALL) NOPASSWD: ALL\nroot ALL=(ALL:ALL) ALL\n"),
            lambda s: s.write(s.root / "etc" / "sudoers.d" / "README", "# files here are read in order\n"),
        ),
        installed=True,
    ),
    Scenario(
        "installed-system-whose-live-boot-was-removed-keeping-only-its-configuration-passes",
        lambda s: s.set_dpkg_packages("python3", "live-boot", status="deinstall ok config-files"),
        installed=True,
    ),
    Scenario(
        "a-live-session-that-looks-installed-in-everything-else-still-runs-only-the-sixteen",
        lambda s: (
            s.boot_as_installed_system(),
            s.write(s.root / "proc" / "cmdline", f"{LIVE_CMDLINE_WORD} root=/dev/mapper/cryptroot-sim\n"),
        ),
        installed=False,
    ),
    Scenario(
        "a-mounted-live-medium-makes-a-live-session-even-without-boot-live-on-the-command-line",
        lambda s: (
            s.boot_as_installed_system(),
            s.write(
                s.root / "proc" / "self" / "mountinfo",
                f"22 1 254:0 / / rw - ext4 /dev/mapper/x rw\n"
                f"23 22 8:16 / {LIVE_MEDIUM_MOUNT} ro - iso9660 /dev/sr0 ro\n",
            ),
        ),
        installed=False,
    ),
    Scenario(
        "a-system-whose-command-line-cannot-be-read-is-treated-as-installed",
        lambda s: (s.boot_as_installed_system(), (s.root / "proc" / "cmdline").unlink()),
        installed=True,
    ),
    # root-encrypted
    Scenario(
        "installed-root-not-on-a-mapping-is-not-encrypted",
        lambda s: s.set_crypt_facts(
            root_dm="none", dm_kind=None, backing=None, luks_version=None, keyslots=None, kdfs=None
        ),
        {"root-encrypted": "is not on a device-mapper mapping, so it is not encrypted"},
        installed=True,
    ),
    Scenario(
        "installed-root-facts-file-missing-fails-and-names-the-unit",
        lambda s: (s.root / "run" / "pai-selfcheck" / "crypt-facts").unlink(),
        {"root-encrypted": "pai-selfcheck-crypt.service did not run or failed"},
        installed=True,
    ),
    Scenario(
        "installed-root-facts-with-an-error-fail-with-its-reason",
        lambda s: s.write(
            s.root / "run" / "pai-selfcheck" / "crypt-facts",
            "root_device=254:0\nerror=cryptsetup luksDump failed with status 4\n",
        ),
        {"root-encrypted": "could not be examined: cryptsetup luksDump failed with status 4"},
        installed=True,
    ),
    Scenario(
        "installed-root-facts-that-do-not-say-what-the-root-is-on-fail",
        lambda s: s.write(s.root / "run" / "pai-selfcheck" / "crypt-facts", "root_device=254:0\n"),
        {"root-encrypted": "do not say what the root filesystem is on"},
        installed=True,
    ),
    Scenario(
        "installed-root-on-a-mapping-that-is-not-dm-crypt-fails",
        lambda s: s.set_crypt_facts(dm_kind="other", backing=None, luks_version=None, keyslots=None, kdfs=None),
        {"root-encrypted": "is other, not CRYPT-LUKS2"},
        installed=True,
    ),
    Scenario(
        "installed-root-on-luks1-fails",
        lambda s: s.set_crypt_facts(dm_kind="CRYPT-LUKS1", luks_version="1"),
        {"root-encrypted": "is CRYPT-LUKS1, not CRYPT-LUKS2; the LUKS header is not version 2 (1)"},
        installed=True,
    ),
    Scenario(
        "installed-root-with-one-pbkdf2-keyslot-fails-naming-the-function",
        lambda s: s.set_crypt_facts(kdfs=f"{REQUIRED_LUKS_KDF},pbkdf2"),
        {"root-encrypted": "a keyslot derives its key with pbkdf2, not argon2id"},
        installed=True,
    ),
    Scenario(
        "installed-root-with-an-argon2i-keyslot-fails-because-only-argon2id-counts",
        lambda s: s.set_crypt_facts(kdfs="argon2i"),
        {"root-encrypted": "a keyslot derives its key with argon2i, not argon2id"},
        installed=True,
    ),
    Scenario(
        "installed-root-with-no-keyslot-read-fails",
        lambda s: s.set_crypt_facts(keyslots="0", kdfs=None),
        {"root-encrypted": "no keyslot was read (0); no key-derivation function was read"},
        installed=True,
    ),
    Scenario(
        "installed-root-with-a-single-argon2id-keyslot-passes",
        lambda s: s.set_crypt_facts(keyslots="1", kdfs=REQUIRED_LUKS_KDF),
        installed=True,
        details={"root-encrypted": "1 keyslot(s), every one argon2id"},
    ),
    # no-live-remnants
    Scenario(
        "installed-system-with-live-boot-still-installed-fails",
        lambda s: s.set_dpkg_packages("python3", "live-boot"),
        {"no-live-remnants": "live system package(s) still installed: live-boot"},
        installed=True,
    ),
    Scenario(
        "installed-system-with-live-config-systemd-still-installed-fails",
        lambda s: s.set_dpkg_packages("python3", "live-config-systemd", "live-boot-initramfs-tools", "live-tools"),
        {"no-live-remnants": "still installed: live-config-systemd live-boot-initramfs-tools live-tools"},
        installed=True,
    ),
    Scenario(
        "installed-system-with-a-half-removed-live-package-fails",
        lambda s: s.set_dpkg_packages("live-config", status="deinstall ok half-installed"),
        {"no-live-remnants": "still installed: live-config"},
        installed=True,
    ),
    Scenario(
        "installed-system-with-live-config-settings-fails",
        lambda s: s.write(s.root / "etc" / "live" / "config.conf", "LIVE_USERNAME=user\n"),
        {"no-live-remnants": "/etc/live exists"},
        installed=True,
    ),
    Scenario(
        "installed-system-with-the-live-user-account-fails-whatever-it-is-called",
        lambda s: s.set_passwd(
            {
                "root": ("0", "root"),
                "sim-owner": ("1000", "Owner"),
                "renamed-live": ("1001", f"{LIVE_USER_FULL_NAME},,,"),
            }
        ),
        {"no-live-remnants": 'account renamed-live was created by live-config (full name "Debian Live user")'},
        installed=True,
    ),
    Scenario(
        "installed-system-with-a-getty-autologin-drop-in-fails",
        lambda s: s.write(
            s.root / "etc" / "systemd" / "system" / "getty@tty1.service.d" / "autologin.conf",
            "[Service]\nExecStart=\nExecStart=-/sbin/agetty --noclear --autologin sim-owner %I $TERM\n",
        ),
        {"no-live-remnants": "autologin in /etc/systemd/system/getty@tty1.service.d/autologin.conf"},
        installed=True,
    ),
    Scenario(
        "installed-system-with-a-generated-autologin-unit-fails",
        lambda s: s.write(
            s.root / "run" / "systemd" / "generator" / "serial-getty@ttyS0.service.d" / "live.conf",
            "[Service]\nExecStart=-/sbin/agetty --skip-login --noclear %I $TERM\n",
        ),
        {"no-live-remnants": "autologin in /run/systemd/generator/serial-getty@ttyS0.service.d/live.conf"},
        installed=True,
    ),
    Scenario(
        "installed-system-with-a-passwordless-sudo-rule-fails",
        lambda s: s.write(s.root / "etc" / "sudoers.d" / "live", "user ALL=(ALL) NOPASSWD: ALL\n"),
        {"no-live-remnants": "/etc/sudoers.d/live grants a command without a password"},
        installed=True,
    ),
    Scenario(
        "installed-system-without-a-package-database-fails-instead-of-passing-unchecked",
        lambda s: (s.root / "var" / "lib" / "dpkg" / "status").unlink(),
        {"no-live-remnants": "cannot read"},
        installed=True,
    ),
    Scenario(
        "installed-system-without-a-passwd-file-fails-instead-of-passing-unchecked",
        lambda s: (s.root / "etc" / "passwd").unlink(),
        {"no-live-remnants": "cannot read"},
        installed=True,
    ),
    Scenario(
        "installed-system-reports-every-problem-of-the-live-remnants-check-together",
        lambda s: (
            s.set_dpkg_packages("live-boot"),
            s.write(s.root / "etc" / "live" / "x.conf", "x\n"),
            s.write(s.root / "etc" / "sudoers.d" / "live", "user ALL=(ALL) NOPASSWD: ALL\n"),
        ),
        {"no-live-remnants": "live-boot; /etc/live exists"},
        installed=True,
        verify=lambda run: _verify_the_installed_checks_are_independent(run),
    ),
    Scenario(
        "installed-system-with-a-failing-live-check-still-runs-the-installed-ones",
        lambda s: s.write(s.state / "nft.rc", "1"),
        {"nft-default-drop": "nft -j list ruleset failed"},
        installed=True,
        verify=lambda run: _verify_the_installed_checks_ran(run),
    ),
]


# ---- running the scenarios -------------------------------------------------------------------------------------------


class Unavailable(Exception):
    """The machine cannot host this scenario (for example no IPv6 loopback to listen on)."""


def _execute(base: Path, scenario: Scenario) -> Run:
    try:
        sim = Sim(base, host=scenario.host)
    except OSError as error:
        raise Unavailable(f"cannot listen on {scenario.host}: {error}") from error
    try:
        if scenario.installed:
            sim.boot_as_installed_system()
        scenario.arrange(sim)
        return sim.run(extra_env=dict(scenario.env))
    finally:
        sim.close()


@pytest.fixture(scope="module")
def runs(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Callable[[Scenario], Run]]:
    """Starts the selected scenarios together and hands each test the finished run of its own scenario."""
    selected: dict[str, Scenario] = {}
    for item in request.session.items:
        params = getattr(getattr(item, "callspec", None), "params", {})
        if item.module is request.module and isinstance(params.get("scenario"), Scenario):
            selected[params["scenario"].name] = params["scenario"]
    pool = ThreadPoolExecutor(max_workers=max(1, min(MAX_PARALLEL_RUNS, os.cpu_count() or 1)))
    futures: dict[str, Future[Run]] = {
        name: pool.submit(_execute, tmp_path_factory.mktemp(f"s{index}"), scenario)
        for index, (name, scenario) in enumerate(selected.items())
    }

    def result(scenario: Scenario) -> Run:
        try:
            return futures[scenario.name].result()
        except Unavailable as error:
            pytest.skip(str(error))

    try:
        yield result
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


def checks_of(scenario: Scenario) -> tuple[str, ...]:
    """The checks the script runs on this scenario's machine: an installed system reports two more."""
    return (*ALL_CHECKS, *INSTALLED_ONLY_CHECKS) if scenario.installed else ALL_CHECKS


def expected(failing: Mapping[str, str], checks: tuple[str, ...] = ALL_CHECKS) -> dict[str, str]:
    """Statuses of a run: every check passes except live-root, which always fails under the test prefix."""
    return {**dict.fromkeys(checks, "PASS"), "live-root": "FAIL", **dict.fromkeys(failing, "FAIL")}


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda scenario: scenario.name)
def test_scenario(runs: Callable[[Scenario], Run], scenario: Scenario) -> None:
    run = runs(scenario)
    if scenario.exact:
        checks = checks_of(scenario)
        assert run.status() == expected(scenario.failing, checks), run.stdout
        assert run.stderr == ""
        for check, text in scenario.failing.items():
            assert text in run.results[check].detail, run.results[check].detail
        # Whatever the scenario: one line per check in the script's order, then a summary that counts them.
        assert [line.split("|")[1] for line in run.stdout.splitlines()] == [*checks, "RESULT"]
        passed = list(run.status().values()).count("PASS")
        assert run.results["RESULT"] == CheckResult("RESULT", False, f"{passed}/{len(checks)}")
    for check, text in scenario.details.items():
        assert text in run.results[check].detail, run.results[check].detail
    if scenario.verify is not None:
        scenario.verify(run)


# ---- tests that are not one run of the unmodified script on a simulated machine --------------------------------------


@pytest.fixture
def sim(tmp_path: Path) -> Iterator[Sim]:
    machine = Sim(tmp_path)
    yield machine
    machine.close()


def test_every_allow_table_entry_names_its_table_port_and_a_justification() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    block = re.search(r"^LISTEN_ALLOW=\(\n(?P<body>.*?)^\)", text, re.DOTALL | re.MULTILINE)
    assert block is not None
    entries = re.findall(r'^\s*"([^"]+)"\s*$', block["body"], re.MULTILINE)
    assert entries
    for entry in entries:
        table, port, *justification = entry.split()
        assert table in {"tcp", "tcp6", "udp", "udp6"}, entry
        assert port.isdigit(), entry
        assert len(justification) >= 5, f"allow-table entry without a real justification: {entry}"


def test_a_script_with_no_checks_fails_instead_of_reporting_zero_of_zero(sim: Sim, tmp_path: Path) -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    emptied = re.sub(r"^CHECKS=\(\n.*?^\)", "CHECKS=()", text, flags=re.DOTALL | re.MULTILINE)
    assert emptied != text, "the CHECKS table was not found; this test no longer tests what it says"
    script = tmp_path / "no-checks.sh"
    script.write_text(emptied, encoding="utf-8", newline="\n")
    run = sim.run(script=script)
    assert run.returncode == 1
    assert run.results == {"RESULT": CheckResult("RESULT", False, "0/0")}
    assert "nothing was verified" in run.stderr
