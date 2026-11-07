"""Runs the real security-selfcheck.sh against a simulated /proc and /etc with fake nft, modprobe and systemctl.

Each check must be shown to PASS on a healthy tree and to FAIL when exactly the thing it guards is broken, and
one failing check must never stop the others. The script's test-only PAI_SELFCHECK_ROOT prefix redirects /proc and
/etc; the live-root check fails while it is set, so these runs can never be mistaken for a real one.

Module and sysctl names in the simulated trees are placeholders; the real image configuration is covered by one
test that feeds the repository's own nftables.conf, modprobe.d and sysctl.d through the script (with the ruleset real
`nft` printed for that nftables.conf, fixtures/nft_ruleset_shipped.json).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.bash_support import find_working_bash
from tests.end_to_end.selfcheck_output import REQUIRED_CHECKS, CheckResult, parse_selfcheck

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "os" / "security" / "rootfs" / "usr" / "lib" / "pai" / "security-selfcheck.sh"
IMAGE_ETC = REPO / "os" / "security" / "rootfs" / "etc"
SHIPPED_NFT_RULESET = Path(__file__).parent / "fixtures" / "nft_ruleset_shipped.json"

ALL_CHECKS = REQUIRED_CHECKS  # the script's order; test_selfcheck_wiring keeps it equal to the script's CHECKS table

# Every `bash` on PATH is tried, not just the first: on Windows the first can be the WSL launcher with no distribution.
BASH = find_working_bash()
pytestmark = pytest.mark.skipif(BASH is None, reason="no working bash on this machine")

FAKE_NFT = """#!/bin/sh
[ "$*" = "-j list ruleset" ] || { echo "fake nft: unexpected arguments: $*" >&2; exit 64; }
cat "$SIM_STATE/nft.out"
exit "$(cat "$SIM_STATE/nft.rc" 2>/dev/null || echo 0)"
"""

# Dry run (-n): prints "install /bin/false" unless the scenario wrote modprobe.dry.<module>. The check must never run
# modprobe for real (that could load a module), so a real run only exits 1; every call is logged for the safety tests.
FAKE_MODPROBE = """#!/bin/sh
dry=0; module=""
for arg in "$@"; do
    case "$arg" in -n) dry=1 ;; -*) ;; *) module=$arg ;; esac
done
if [ "$dry" = 1 ]; then
    echo "dry $module" >> "$SIM_STATE/modprobe.calls"
    if [ -f "$SIM_STATE/modprobe.dry.$module" ]; then cat "$SIM_STATE/modprobe.dry.$module"; exit 0; fi
    echo "install /bin/false "; exit 0
fi
echo "real $module" >> "$SIM_STATE/modprobe.calls"
exit 1
"""

FAKE_SYSTEMCTL = """#!/bin/sh
[ "$1" = is-active ] || { echo "fake systemctl: unexpected arguments: $*" >&2; exit 64; }
unit=$3
state=$(cat "$SIM_STATE/unit.$unit" 2>/dev/null || echo active)
echo "$state"
[ "$state" = active ]
"""


def _python_shim() -> str:
    # The image calls python3; this machine may only have a Windows alias or a venv python.
    return f'#!/bin/sh\nexec "{Path(sys.executable).as_posix()}" "$@"\n'


def ipv4_hex(address: str) -> str:
    raw = socket.inet_aton(address)
    return (raw[::-1] if sys.byteorder == "little" else raw).hex().upper()


def ipv6_hex(address: str) -> str:
    raw = ipaddress.IPv6Address(address).packed
    if sys.byteorder == "little":
        raw = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
    return raw.hex().upper()


WILDCARD_V4 = "0.0.0.0"  # noqa: S104 - an address in simulated /proc data; nothing binds to it
NET_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
STATE_LISTEN, STATE_ESTABLISHED, STATE_UNCONNECTED = "0A", "01", "07"


def sock_row(local_hex: str, port: int, state: str, *, remote_hex: str = "", remote_port: int = 0) -> str:
    remote_hex = remote_hex or "0" * len(local_hex)
    return (
        f"   0: {local_hex}:{port:04X} {remote_hex}:{remote_port:04X} {state} 00000000:00000000 "
        "00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"
    )


# A condition, as `nft -j` prints one: `iifname "lo"`. A rule holding one applies to some packets only.
MATCH: dict[str, object] = {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}
ACCEPT: dict[str, object] = {"accept": None}


def rule(chain_name: str, *expr: dict[str, object]) -> dict[str, object]:
    return {"family": "inet", "table": "t", "chain": chain_name, "expr": list(expr)}


# A healthy ruleset has accept rules, but only conditional ones.
HEALTHY_RULES = (rule("input", MATCH, ACCEPT), rule("output", MATCH, ACCEPT))


def nft_json(*chains: dict[str, object], rules: tuple[dict[str, object], ...] = HEALTHY_RULES) -> str:
    items: list[dict[str, object]] = [{"metainfo": {"version": "1.1.3"}}, {"table": {"family": "inet", "name": "t"}}]
    items += [{"chain": chain} for chain in chains]
    items += [{"rule": entry} for entry in rules]
    return json.dumps({"nftables": items})


def chain(
    hook: str, policy: str | None = "drop", *, kind: str = "filter", name: str | None = None
) -> dict[str, object]:
    base: dict[str, object] = {"family": "inet", "table": "t", "name": name or hook, "type": kind, "hook": hook}
    if policy is not None:
        base["policy"] = policy
    return base


HEALTHY_CHAINS = (chain("input"), chain("forward"), chain("output"))


def chain_regular(name: str) -> dict[str, object]:
    """A chain with no hook: only reached through jump or goto."""
    return {"family": "inet", "table": "t", "name": name}


# The shipped nftables.conf of the simulated machine: the base chains that HEALTHY_CHAINS loads.
NFT_CONF = """\
# placeholder firewall
table inet t {
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
    }
    chain forward { type filter hook forward priority filter; policy drop; }
    chain output {
        type filter hook output priority filter; policy drop;
    }
}
"""


def conf_with(extra_chain: str) -> str:
    """NFT_CONF with one more chain declaration inside its table."""
    return NFT_CONF.rstrip().removesuffix("}") + f"    {extra_chain}\n}}\n"


@dataclass
class Sim:
    """A simulated machine: a /proc + /etc tree, fake commands, and the state the fakes read."""

    base: Path
    conf_files: dict[str, list[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.root = self.base / "tree"
        self.bin = self.base / "bin"
        self.state = self.base / "state"
        for directory in (self.root / "proc" / "net", self.root / "proc" / "sys", self.bin, self.state):
            directory.mkdir(parents=True)
        for name, body in {
            "nft": FAKE_NFT,
            "modprobe": FAKE_MODPROBE,
            "systemctl": FAKE_SYSTEMCTL,
            "python3": _python_shim(),
        }.items():
            self.write(self.bin / name, body)
        self.write(
            self.root / "etc" / "modprobe.d" / "block.conf",
            "# placeholder host-share module\ninstall hostshare /bin/false\n",
        )
        self.write(
            self.root / "proc" / "modules", "ext4 1000 1 - Live 0x0000000000000000\nvirtio_net 2000 0 - Live 0x0\n"
        )
        self.write(self.root / "etc" / "nftables.conf", NFT_CONF)
        self.write(self.state / "nft.out", nft_json(*HEALTHY_CHAINS))
        self.set_sockets()
        self.sysctl("kernel.sim_flag", "2")
        self.sysctl("net.sim.switch", "0")
        self.sysctl("net.sim.triple", "4096 131072 6291456", live="4096\t131072\t6291456")

    @staticmethod
    def write(path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        path.chmod(0o755)
        return path

    def sysctl(
        self,
        key: str,
        value: str,
        *,
        live: str | None = None,
        live_present: bool = True,
        conf: str = "90-sim.conf",
        prefix: str = "",
    ) -> None:
        """Declare `key = value` in sysctl.d/<conf> and give /proc/sys a live value (default: the same value)."""
        self.conf_files.setdefault(conf, []).append(f"{prefix}{key} = {value}")
        self.write(self.root / "etc" / "sysctl.d" / conf, "\n".join(self.conf_files[conf]) + "\n")
        if live_present:
            live_value = value if live is None else live
            self.write(self.root / "proc" / "sys" / Path(*key.replace("/", ".").split(".")), live_value + "\n")

    def set_sockets(
        self,
        *,
        tcp: list[str] | None = None,
        tcp6: list[str] | None = None,
        udp: list[str] | None = None,
        udp6: list[str] | None = None,
    ) -> None:
        """Rows for each /proc/net table; the defaults are loopback listeners plus one established connection."""
        loopback4 = [
            sock_row(ipv4_hex("127.0.0.1"), 631, STATE_LISTEN),
            sock_row(ipv4_hex("127.0.0.53"), 53, STATE_LISTEN),
        ]
        established = sock_row(
            ipv4_hex("10.0.2.15"), 40000, STATE_ESTABLISHED, remote_hex=ipv4_hex("93.184.216.34"), remote_port=443
        )
        tables = {
            "tcp": [*loopback4, established] if tcp is None else tcp,
            "tcp6": [
                sock_row(ipv6_hex("::1"), 631, STATE_LISTEN),
                sock_row(ipv6_hex("::ffff:127.0.0.1"), 8080, STATE_LISTEN),
            ]
            if tcp6 is None
            else tcp6,
            "udp": [sock_row(ipv4_hex("127.0.0.53"), 53, STATE_UNCONNECTED)] if udp is None else udp,
            "udp6": [] if udp6 is None else udp6,
        }
        for name, rows in tables.items():
            self.write(self.root / "proc" / "net" / name, "\n".join([NET_HEADER, *rows]) + "\n")

    def set_nft(self, *chains: dict[str, object], rules: tuple[dict[str, object], ...] = HEALTHY_RULES) -> None:
        self.write(self.state / "nft.out", nft_json(*chains, rules=rules))

    def run(self, *, script: Path = SCRIPT, extra_env: dict[str, str] | None = None) -> Run:
        assert BASH is not None
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "PAI_SELFCHECK_ROOT": self.root.as_posix(),
            "SIM_STATE": self.state.as_posix(),
            **(extra_env or {}),
        }
        done = subprocess.run([BASH, str(script)], env=env, capture_output=True, text=True, check=False, timeout=180)  # noqa: S603
        return Run(
            done.returncode, done.stdout, done.stderr, {r.name: r for r in parse_selfcheck(done.stdout)}, self.state
        )


@dataclass
class Run:
    returncode: int
    stdout: str
    stderr: str
    results: dict[str, CheckResult]
    state: Path

    def status(self) -> dict[str, str]:
        return {
            name: ("PASS" if result.passed else "FAIL") for name, result in self.results.items() if name != "RESULT"
        }

    def modprobe_calls(self) -> list[str]:
        log = self.state / "modprobe.calls"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


@pytest.fixture
def sim(tmp_path: Path) -> Sim:
    return Sim(tmp_path)


def expected(**overrides: str) -> dict[str, str]:
    """Statuses of a healthy run: every check passes except live-root, which always fails under the test prefix."""
    return {**dict.fromkeys(ALL_CHECKS, "PASS"), "live-root": "FAIL", **overrides}


def test_healthy_tree_passes_every_check_except_the_test_prefix_guard(sim: Sim) -> None:
    run = sim.run()
    assert run.status() == expected()
    assert run.stderr == ""
    assert run.returncode == 1  # live-root fails by design under the prefix
    assert run.results["RESULT"] == CheckResult("RESULT", False, f"{len(ALL_CHECKS) - 1}/{len(ALL_CHECKS)}")
    assert "PAI_SELFCHECK_ROOT" in run.results["live-root"].detail


def test_output_is_one_line_per_check_then_the_summary(sim: Sim) -> None:
    lines = sim.run().stdout.splitlines()
    assert [line.split("|")[1] for line in lines] == [*ALL_CHECKS, "RESULT"]
    assert all(line.startswith("PAI-SELFCHECK|") and line.split("|")[2] in {"PASS", "FAIL"} for line in lines)


@dataclass(frozen=True)
class Case:
    name: str
    arrange: Callable[[Sim], None]
    failing: dict[str, str]  # check -> text its detail must contain


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


FAILURE_CASES = [
    Case("nft-output-accept", _nft_policy("output", "accept"), {"nft-default-drop": "inet/t/output policy=accept"}),
    Case("nft-input-accept", _nft_policy("input", "accept"), {"nft-default-drop": "inet/t/input policy=accept"}),
    Case(
        "nft-forward-no-policy",
        lambda s: s.set_nft(chain("input"), chain("forward", None), chain("output")),
        {"nft-default-drop": "policy=None"},
    ),
    Case(
        "nft-hook-missing",
        lambda s: s.set_nft(chain("input"), chain("output")),
        {"nft-default-drop": "no filter base chain on hook: forward"},
    ),
    Case("nft-empty-ruleset", lambda s: s.set_nft(), {"nft-default-drop": "input, forward, output"}),
    Case(
        "nft-extra-chain-open",
        lambda s: s.set_nft(*HEALTHY_CHAINS, chain("input", "accept", name="extra")),
        {"nft-default-drop": "inet/t/extra policy=accept"},
    ),
    Case(
        "nft-unconditional-accept",
        lambda s: s.set_nft(*HEALTHY_CHAINS, rules=(rule("input", ACCEPT),)),
        {"nft-default-drop": "unconditional accept in: inet/t/input"},
    ),
    Case(
        "nft-unconditional-accept-behind-conditional-rules",
        lambda s: s.set_nft(*HEALTHY_CHAINS, rules=(*HEALTHY_RULES, rule("output", {"counter": {}}, ACCEPT))),
        {"nft-default-drop": "unconditional accept in: inet/t/output"},
    ),
    Case(
        "nft-accept-reached-by-unconditional-jump",
        lambda s: s.set_nft(
            *HEALTHY_CHAINS,
            chain_regular("allow_all"),
            rules=(rule("forward", {"jump": {"target": "allow_all"}}), rule("allow_all", ACCEPT)),
        ),
        {"nft-default-drop": "unconditional accept in: inet/t/forward via inet/t/allow_all"},
    ),
    Case(
        "nft-accept-reached-by-unconditional-goto",
        lambda s: s.set_nft(
            *HEALTHY_CHAINS,
            chain_regular("allow_all"),
            rules=(rule("output", {"goto": {"target": "allow_all"}}), rule("allow_all", ACCEPT)),
        ),
        {"nft-default-drop": "inet/t/output via inet/t/allow_all"},
    ),
    Case(
        "nft-chain-in-config-not-loaded",
        lambda s: s.set_nft(*[{**c, "table": "other"} for c in HEALTHY_CHAINS], rules=()),
        {"nft-default-drop": "inet/t/input is configured but not loaded"},
    ),
    Case(
        "nft-config-chain-loaded-with-another-hook",
        lambda s: s.set_nft(chain("input"), chain("forward"), chain("output"), chain("prerouting", name="input")),
        {"nft-default-drop": "inet/t/input: configured filter hook input policy drop, live filter hook prerouting"},
    ),
    Case(
        "nft-config-file-missing",
        lambda s: (s.root / "etc" / "nftables.conf").unlink(),
        {"nft-default-drop": "cannot read"},
    ),
    Case(
        "nft-config-declares-no-base-chain",
        lambda s: s.write(s.root / "etc" / "nftables.conf", "table inet t { chain input { } }\n"),
        {"nft-default-drop": "nothing to verify"},
    ),
    Case("nft-not-json", lambda s: s.write(s.state / "nft.out", "not json"), {"nft-default-drop": "not valid JSON"}),
    Case(
        "nft-command-fails",
        lambda s: (s.write(s.state / "nft.out", "Operation not permitted"), s.write(s.state / "nft.rc", "1")),
        {"nft-default-drop": "nft -j list ruleset failed"},
    ),
    Case("module-loaded", _module_loaded, {"modules-blocked": "hostshare is loaded"}),
    Case("module-loaded-hyphen-vs-underscore", _module_hyphenated, {"modules-blocked": "host-share is loaded"}),
    Case(
        "module-install-override-missing",
        _override_not_blocking,
        {"modules-blocked": "would not run a blocking install command"},
    ),
    Case("module-no-install-lines", _no_install_lines, {"modules-blocked": "nothing to verify"}),
    Case(
        "sysctl-mismatch",
        lambda s: s.sysctl("net.sim.switch", "0", live="1", conf="91-extra.conf"),
        {"sysctl-live": "net.sim.switch: configured '0', live '1'"},
    ),
    Case(
        "sysctl-live-missing",
        lambda s: s.sysctl("net.sim.gone", "1", live_present=False, conf="91-extra.conf"),
        {"sysctl-live": "net.sim.gone: not readable"},
    ),
    Case(
        "sysctl-wildcard-key",
        lambda s: s.sysctl("net.sim.*.rp", "1", live_present=False, conf="91-extra.conf"),
        {"sysctl-live": "wildcard keys are not supported"},
    ),
    Case(
        "sysctl-multivalue-differs",
        lambda s: s.sysctl("net.sim.triple", "4096 131072 6291456", live="4096\t131072\t1", conf="91-extra.conf"),
        {"sysctl-live": "net.sim.triple"},
    ),
    Case(
        "sysctl-no-settings", lambda s: shutil.rmtree(s.root / "etc" / "sysctl.d"), {"sysctl-live": "nothing to verify"}
    ),
    Case(
        "listener-tcp-wildcard",
        _listener("tcp", ipv4_hex(WILDCARD_V4), 22, STATE_LISTEN),
        {"no-external-listeners": "tcp 0.0.0.0:22"},
    ),
    Case(
        "listener-tcp-on-nic-address",
        _listener("tcp", ipv4_hex("10.0.2.15"), 8080, STATE_LISTEN),
        {"no-external-listeners": "tcp 10.0.2.15:8080"},
    ),
    Case(
        "listener-tcp6-wildcard",
        _listener("tcp6", ipv6_hex("::"), 22, STATE_LISTEN),
        {"no-external-listeners": "tcp6 [::]:22"},
    ),
    Case(
        "listener-udp-wildcard",
        _listener("udp", ipv4_hex(WILDCARD_V4), 5353, STATE_UNCONNECTED),
        {"no-external-listeners": "udp 0.0.0.0:5353"},
    ),
    Case(
        "listener-udp6-link-local",
        _listener("udp6", ipv6_hex("fe80::1"), 5353, STATE_UNCONNECTED),
        {"no-external-listeners": "udp6 [fe80::1]:5353"},
    ),
    Case(
        "listener-allow-is-per-table",
        _listener("udp6", ipv6_hex("fe80::1"), 68, STATE_UNCONNECTED),
        {"no-external-listeners": "udp6 [fe80::1]:68"},
    ),
    Case(
        "listener-allow-never-covers-a-wildcard-bind-udp",
        _listener("udp", ipv4_hex(WILDCARD_V4), 68, STATE_UNCONNECTED),
        {"no-external-listeners": "udp 0.0.0.0:68"},
    ),
    Case(
        "listener-allow-never-covers-a-wildcard-bind-udp6",
        _listener("udp6", ipv6_hex("::"), 546, STATE_UNCONNECTED),
        {"no-external-listeners": "udp6 [::]:546"},
    ),
    Case(
        "listener-allow-never-covers-a-mapped-wildcard-bind",
        _listener("udp6", ipv6_hex(f"::ffff:{WILDCARD_V4}"), 546, STATE_UNCONNECTED),
        {"no-external-listeners": "udp6 [::ffff:0:0]:546"},
    ),
    Case(
        "listener-allow-is-per-port",
        _listener("udp", ipv4_hex(WILDCARD_V4), 69, STATE_UNCONNECTED),
        {"no-external-listeners": "udp 0.0.0.0:69"},
    ),
    Case(
        "net-table-unreadable",
        lambda s: (s.root / "proc" / "net" / "tcp").unlink(),
        {"no-external-listeners": "cannot read tcp"},
    ),
    Case(
        "unit-inactive", _unit_state("nftables.service", "inactive"), {"units-active": "nftables.service is inactive"}
    ),
    Case(
        "unit-failed",
        _unit_state("systemd-networkd.service", "failed"),
        {"units-active": "systemd-networkd.service is failed"},
    ),
]


@pytest.mark.parametrize("case", FAILURE_CASES, ids=lambda case: case.name)
def test_each_check_fails_when_what_it_guards_is_broken(sim: Sim, case: Case) -> None:
    case.arrange(sim)
    run = sim.run()
    assert run.status() == expected(**dict.fromkeys(case.failing, "FAIL")), run.stdout
    for check, text in case.failing.items():
        assert text in run.results[check].detail
    assert run.results["RESULT"].passed is False
    assert run.stderr == ""


def test_the_allow_table_admits_the_dhcp_client_ports_and_says_so(sim: Sim) -> None:
    sim.set_sockets(
        udp=[sock_row(ipv4_hex("10.0.2.15"), 68, STATE_UNCONNECTED)],
        udp6=[sock_row(ipv6_hex("fe80::5054:ff:fe12:3456"), 546, STATE_UNCONNECTED)],
    )
    run = sim.run()
    assert run.status() == expected()
    assert "udp 10.0.2.15:68" in run.results["no-external-listeners"].detail
    assert "udp6 [fe80::5054:ff:fe12:3456]:546" in run.results["no-external-listeners"].detail


def test_conditional_accepts_and_unreachable_accepts_are_not_a_hole(sim: Sim) -> None:
    sim.set_nft(
        *HEALTHY_CHAINS,
        chain_regular("helper"),
        chain_regular("unused"),
        rules=(
            rule("input", MATCH, {"jump": {"target": "helper"}}),  # a conditional jump into a chain that accepts
            rule("helper", ACCEPT),
            rule("unused", ACCEPT),  # nothing jumps here
            rule("output", {"drop": None}),  # an unconditional verdict ends the chain: the next rule is unreachable
            rule("output", ACCEPT),
            rule("forward", {"limit": {"rate": 5, "per": "second"}}, ACCEPT),  # rate-limited, so conditional
        ),
    )
    assert sim.run().status() == expected()


def test_a_config_chain_with_a_non_drop_policy_must_be_loaded_with_that_same_policy(sim: Sim) -> None:
    sim.write(
        sim.root / "etc" / "nftables.conf",
        conf_with("chain pre { type filter hook prerouting priority -300; policy accept; }"),
    )
    sim.set_nft(*HEALTHY_CHAINS, chain("prerouting", "accept", name="pre"))
    assert sim.run().status() == expected()  # declared accept, loaded accept: the file and the system agree
    sim.set_nft(*HEALTHY_CHAINS, chain("prerouting", "drop", name="pre"))
    run = sim.run()
    assert run.status() == expected(**{"nft-default-drop": "FAIL"})
    assert "inet/t/pre: configured filter hook prerouting policy accept, live filter hook prerouting policy drop" in (
        run.results["nft-default-drop"].detail
    )


def test_a_base_chain_without_a_policy_statement_is_read_as_policy_accept(sim: Sim) -> None:
    sim.write(sim.root / "etc" / "nftables.conf", conf_with("chain pre { type filter hook prerouting priority -300; }"))
    sim.set_nft(*HEALTHY_CHAINS, chain("prerouting", "accept", name="pre"))
    assert sim.run().status() == expected()


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


def test_established_connections_and_missing_ipv6_tables_are_not_listeners(sim: Sim) -> None:
    (sim.root / "proc" / "net" / "tcp6").unlink()
    (sim.root / "proc" / "net" / "udp6").unlink()
    assert sim.run().status() == expected()


def test_optional_sysctl_key_missing_from_the_kernel_is_not_a_failure(sim: Sim) -> None:
    sim.sysctl("net.sim.optional", "1", live_present=False, conf="91-extra.conf", prefix="-")
    assert sim.run().status() == expected()


def test_later_sysctl_file_overrides_an_earlier_one_like_systemd_sysctl(sim: Sim) -> None:
    sim.sysctl("net.sim.switch", "1", live="1", conf="99-later.conf")  # 90-sim.conf says 0; the later file wins
    assert sim.run().status() == expected()


def test_slash_separated_sysctl_keys_are_supported(sim: Sim) -> None:
    sim.sysctl("net/sim/slashed", "7", conf="91-extra.conf")
    assert sim.run().status() == expected()


def test_dash_module_name_in_config_matches_underscore_in_proc_modules_when_not_loaded(sim: Sim) -> None:
    sim.write(sim.root / "etc" / "modprobe.d" / "block.conf", "install host-share /bin/false\n")
    assert sim.run().status() == expected()


def test_a_true_install_command_counts_as_blocking(sim: Sim) -> None:
    sim.write(sim.root / "etc" / "modprobe.d" / "block.conf", "install hostshare /bin/true # no-op\n")
    sim.write(sim.state / "modprobe.dry.hostshare", "install /bin/true \n")
    assert sim.run().status() == expected()


def test_modprobe_is_never_really_run_for_a_module_that_is_not_proven_blocked(sim: Sim) -> None:
    _override_not_blocking(sim)
    run = sim.run()
    assert run.modprobe_calls() == ["dry hostshare"]  # the real, loading call must not happen


def test_modprobe_is_only_ever_run_as_a_dry_run_even_for_a_proven_block(sim: Sim) -> None:
    assert sim.run().modprobe_calls() == ["dry hostshare"]  # a real run could load a module and proves nothing more


def test_every_blocked_module_is_checked_and_every_failure_reported(sim: Sim) -> None:
    sim.write(
        sim.root / "etc" / "modprobe.d" / "block.conf", "install hostshare /bin/false\ninstall second_mod /bin/false\n"
    )
    sim.write(sim.root / "etc" / "modprobe.d" / "other.conf", "install third_mod /bin/false\noptions foo bar=1\n")
    sim.write(sim.root / "proc" / "modules", "second_mod 1 0 - Live 0x0\n")
    run = sim.run()
    assert run.status() == expected(**{"modules-blocked": "FAIL"})
    detail = run.results["modules-blocked"].detail
    assert "second_mod is loaded" in detail
    assert "hostshare is loaded" not in detail
    assert run.modprobe_calls() == ["dry hostshare", "dry third_mod"]


def test_one_broken_check_does_not_stop_the_others(sim: Sim) -> None:
    sim.write(sim.state / "nft.rc", "1")
    sim.write(sim.state / "unit.nftables.service", "failed")
    sim.sysctl("net.sim.switch", "0", live="9", conf="91-extra.conf")
    run = sim.run()
    assert run.status() == expected(**{"nft-default-drop": "FAIL", "sysctl-live": "FAIL", "units-active": "FAIL"})
    assert run.results["RESULT"].detail == "2/6"  # live-root fails too


def test_missing_python_fails_the_checks_that_need_it_and_only_those(sim: Sim) -> None:
    sim.write(sim.bin / "python3", "#!/bin/sh\necho 'python3: not available' >&2\nexit 127\n")
    assert sim.run().status() == expected(**{"nft-default-drop": "FAIL", "no-external-listeners": "FAIL"})


def test_detail_is_flattened_so_it_cannot_break_the_line_format(sim: Sim) -> None:
    sim.write(sim.state / "nft.out", "boom|with pipes\x1b[31m and\nnewlines\tand tabs")
    sim.write(sim.state / "nft.rc", "1")
    run = sim.run()
    detail = run.results["nft-default-drop"].detail
    assert "boom/with pipes" in detail
    assert all(ch.isprintable() for ch in detail)
    assert len(run.stdout.splitlines()) == len(ALL_CHECKS) + 1


def test_very_long_detail_is_truncated(sim: Sim) -> None:
    sim.write(sim.state / "nft.out", "x" * 5000)
    sim.write(sim.state / "nft.rc", "1")
    detail = sim.run().results["nft-default-drop"].detail
    assert detail.endswith("...") and len(detail) < 1100


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


def test_the_repositorys_own_nftables_modprobe_and_sysctl_configuration_is_understood(tmp_path: Path) -> None:
    """Feed the real image config through the script, with live values taken from that same config.

    The live ruleset is what real `nft -j list ruleset` printed after loading the shipped nftables.conf, so the
    script's reading of the configuration and of nft's JSON is checked against the real thing, not a hand-made shape.
    """
    sim = Sim(tmp_path)
    shutil.rmtree(sim.root / "etc")
    shutil.copytree(IMAGE_ETC / "modprobe.d", sim.root / "etc" / "modprobe.d")
    shutil.copytree(IMAGE_ETC / "sysctl.d", sim.root / "etc" / "sysctl.d")
    shutil.copy(IMAGE_ETC / "nftables.conf", sim.root / "etc" / "nftables.conf")
    sim.write(sim.state / "nft.out", SHIPPED_NFT_RULESET.read_text(encoding="utf-8"))
    shutil.rmtree(sim.root / "proc" / "sys")
    count = 0
    for conf in sorted((sim.root / "etc" / "sysctl.d").glob("*.conf")):
        for raw in conf.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0]
            if "=" in line:
                key, value = (part.strip() for part in line.split("=", 1))
                sim.write(sim.root / "proc" / "sys" / Path(*key.split(".")), value + "\n")
                count += 1
    assert count > 0
    run = sim.run()
    assert run.status() == expected(), run.stdout
    assert f"{count} settings match" in run.results["sysctl-live"].detail
    assert "vboxsf" in run.results["modules-blocked"].detail
    assert "input=1, forward=1, output=1" in run.results["nft-default-drop"].detail
    assert "3 configured base chains loaded as declared" in run.results["nft-default-drop"].detail
