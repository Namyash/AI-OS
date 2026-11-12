"""A simulated machine for running the real security-selfcheck.sh without booting anything.

The script has a test-only PAI_SELFCHECK_ROOT prefix that redirects /proc, /etc and /opt to a directory tree, and it
finds every command through PATH. `Sim` builds such a tree and puts fakes of the commands the script runs (`nft`,
`modprobe`, `systemctl`, `systemd-analyze`, `id`, `stat`, `python3`) first on PATH. The backend service and the
kiosk are simulated as well:

* `systemctl show` answers from per-unit property files (what a scenario says systemd knows about the unit);
* /proc/<pid>/{status,stat,comm,cmdline,environ} of every simulated process and /proc/net/* are files in the tree: the
  backend, and the kiosk's cage -> launcher -> Chromium tree, plus whatever a scenario adds;
* the code in /opt/pai is a copy of the real backend settings loader and of the real kiosk settings loader and
  readiness contract, so the script's probes read ports, paths and the readiness schema from the real things, fed with
  the units' Environment=;
* `FakeBackend` is a real HTTP server on a loopback port that answers GET /health the way the backend does (401 without
  credentials, 200 and the documented body with the bearer token, or with a live session id as the pai_session cookie),
  so the requests really travel over a socket;
* /etc/shadow, and its mode (the fake `stat` answers from a state file: a Windows checkout has no real file modes).

Everything a check examines can be broken one way at a time, and every fake rejects an argument list the script is not
meant to send, so a changed command line is a test failure instead of a silent difference from the real tools.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from backend.api.health import HealthResponse
from kiosk.readiness import ReadyReport, write_ready_file
from tests.bash_support import find_working_bash
from tests.end_to_end.selfcheck_output import CheckResult, parse_selfcheck

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "os" / "security" / "rootfs" / "usr" / "lib" / "pai" / "security-selfcheck.sh"
IMAGE_ETC = REPO / "os" / "security" / "rootfs" / "etc"
BACKEND_PACKAGE = REPO / "backend"
KIOSK_PACKAGE = REPO / "kiosk"
FIXTURES = Path(__file__).parent / "fixtures"
SHIPPED_NFT_RULESET = FIXTURES / "nft_ruleset_shipped.json"
ANALYZE_SECURITY_REPORT = FIXTURES / "systemd_analyze_security_backend.txt"

# Every `bash` on PATH is tried, not just the first: on Windows the first can be the WSL launcher with no distribution.
BASH = find_working_bash()

# The simulated backend is up before the script starts, so a run waits for nothing; the script's own default (minutes)
# is for emulated hardware. A scenario that is about waiting sets its own value.
READY_TIMEOUT_SECONDS = 0
KIOSK_TIMEOUT_SECONDS = 0  # the same for the kiosk
MIN_SECRET_LENGTH = 16  # shorter strings are too likely to occur in ordinary output to mean a leak
RUN_TIMEOUT_SECONDS = 60  # a run that takes longer than this has stalled and fails instead of hanging the suite


def script_value(name: str) -> str:
    """The value of a plain `NAME=value` or `NAME="value"` assignment of the script.

    The simulation reads the script's own facts (unit names, the shape of a credential, the label the kiosk's status bar
    shows) instead of repeating them."""
    match = re.search(rf'^{name}=("?)([^"\s]+(?: [^"\s]+)*)\1$', SCRIPT.read_text(encoding="utf-8"), re.MULTILINE)
    assert match is not None, f"{name} is not assigned in the script"
    return match[2]


BACKEND_UNIT = script_value("BACKEND_UNIT")
KIOSK_UNIT = script_value("KIOSK_UNIT")
CREDENTIAL_LENGTH = int(script_value("CREDENTIAL_LENGTH"))
SESSION_COOKIE = script_value("SESSION_COOKIE")
MAX_CREDENTIAL_CANDIDATES = int(script_value("MAX_CREDENTIAL_CANDIDATES"))
CONNECTED_LABEL = script_value("KIOSK_BACKEND_CONNECTED_LABEL")
LIVE_CMDLINE_WORD = script_value("LIVE_CMDLINE_WORD")
LIVE_MEDIUM_MOUNT = script_value("LIVE_MEDIUM_MOUNT")
REQUIRED_LUKS_KDF = script_value("REQUIRED_LUKS_KDF")
REQUIRED_CRYPT_KIND = script_value("REQUIRED_CRYPT_KIND")
LIVE_USER_FULL_NAME = (
    "Debian Live user"  # what live-config writes into the account's GECOS field; the script matches it
)
LIVE_PACKAGES = ("live-boot", "live-config")  # what makes a session live; the script matches both by pattern

# The bytes of entropy of a credential: the backend's own (backend/api/auth.py); the wiring tests keep them equal.
TOKEN_BYTES = 32

# Placeholder accounts and processes of the simulated machine (the real names, uids and pids are the image's business).
SERVICE_USER = "svc-sim"
SERVICE_UID = 1234
SERVICE_PID = 4242
KIOSK_USER = "ui-sim"
KIOSK_UID = 2345
KIOSK_PID = 5000  # the kiosk unit's main process (cage); the launcher and the browser are below it
LAUNCHER_PID = 5001
BROWSER_PID = 5002
BROWSER_CHILD_PID = 5003
OTHER_PID = 6001  # an unrelated process of the simulated machine
BROWSER_NAME = "chromium"
READY_STATUS = f"{CONNECTED_LABEL} Version 0.0.1"  # what the status bar says while the backend answers

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

# is-active: the state is in unit.<unit> (default active). show: prints only the requested properties, from
# show.<unit> (a unit without that file is unknown to systemd, as for `systemctl show` of a missing unit). While
# show.pending.<unit> holds a count above zero each call counts it down and answers from show.<unit>.early instead,
# which is how a unit that is still starting is simulated. show.rc makes `show` fail like a systemctl with no bus.
FAKE_SYSTEMCTL = """#!/bin/sh
case "$1" in
is-active)
    [ "$2" = -- ] || { echo "fake systemctl: is-active without -- before the unit: $*" >&2; exit 64; }
    unit=$3
    state=$(cat "$SIM_STATE/unit.$unit" 2>/dev/null || echo active)
    echo "$state"
    [ "$state" = active ]
    ;;
show)
    if [ -f "$SIM_STATE/show.rc" ]; then
        echo "Failed to connect to system scope bus: simulated failure" >&2
        exit "$(cat "$SIM_STATE/show.rc")"
    fi
    props=""; before=""; unit=""
    for arg in "$@"; do
        before=$unit; unit=$arg
        case "$arg" in --property=*) props="$props ${arg#--property=}" ;; esac
    done
    [ "$before" = -- ] || { echo "fake systemctl: show without -- before the unit: $*" >&2; exit 64; }
    file="$SIM_STATE/show.$unit"
    pending="$SIM_STATE/show.pending.$unit"
    # show.hook.<unit>: commands run once, in the background, the first time the unit is shown. A scenario uses it
    # to make something appear a while after the script has started waiting for it.
    hook="$SIM_STATE/show.hook.$unit"
    if [ -f "$hook" ]; then mv "$hook" "$hook.run"; sh "$hook.run" >/dev/null 2>&1 & fi
    if [ -f "$pending" ] && [ "$(cat "$pending")" -gt 0 ]; then
        echo $(($(cat "$pending") - 1)) > "$pending"
        file="$file.early"
    fi
    if [ -f "$file" ]; then cat "$file"; else printf 'LoadState=not-found\\nActiveState=inactive\\n'; fi |
        awk -F= -v props="$props" '
            BEGIN { n = split(props, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
            $1 in want'
    ;;
*)
    echo "fake systemctl: unexpected arguments: $*" >&2; exit 64
    ;;
esac
"""

FAKE_ANALYZE = """#!/bin/sh
[ "$1 $2 $3" = "security --no-pager --" ] || { echo "fake systemd-analyze: unexpected arguments: $*" >&2; exit 64; }
cat "$SIM_STATE/analyze.out"
exit "$(cat "$SIM_STATE/analyze.rc" 2>/dev/null || echo 0)"
"""

# `id -u -- <name>` against the users file ("<name> <uid>" per line), failing for an unknown account like the real one.
FAKE_ID = """#!/bin/sh
[ "$1 $2" = "-u --" ] || { echo "fake id: unexpected arguments: $*" >&2; exit 64; }
uid=$(awk -v name="$3" '$1 == name { print $2; exit }' "$SIM_STATE/users" 2>/dev/null)
[ -n "$uid" ] || { echo "id: '$3': no such user" >&2; exit 1; }
echo "$uid"
"""


# `stat -c %a -- <path>`: the mode of a file, from mode.<file name> in the state directory (a Windows checkout has no
# real file modes), failing for a file without one the way stat fails for a missing file.
FAKE_STAT = """#!/bin/sh
[ "$1 $2 $3" = "-c %a --" ] || { echo "fake stat: unexpected arguments: $*" >&2; exit 64; }
mode=$(cat "$SIM_STATE/mode.$(basename "$4")" 2>/dev/null) || {
    echo "stat: cannot statx '$4': No such file or directory" >&2; exit 1; }
echo "$mode"
"""


# `journalctl -u <unit> -n <lines> --no-pager -o cat`: the last lines of journal.<unit> in the state directory (nothing
# for a unit without one), failing when a test says so, like a journalctl that cannot open the journal.
FAKE_JOURNALCTL = """#!/bin/sh
{ [ "$1" = -u ] && [ "$3" = -n ] && [ "$5 $6 $7" = "--no-pager -o cat" ] && [ "$#" -eq 7 ]; } || {
    echo "fake journalctl: unexpected arguments: $*" >&2; exit 64; }
[ -f "$SIM_STATE/journal.fails" ] && { echo "Failed to open journal: Permission denied" >&2; exit 1; }
[ -f "$SIM_STATE/journal.$2" ] && tail -n "$4" "$SIM_STATE/journal.$2"
exit 0
"""


def _python_shim() -> str:
    """The image calls python3; this machine may only have a Windows alias or a venv python.

    PYTHONPATH is set here, for this one program, to a directory whose sitecustomize.py hides the repository (see
    SITECUSTOMIZE). The options in front of -c are logged, so a test can see how the script starts python.
    """
    return (
        "#!/bin/sh\n"
        'options=""\n'
        'for arg in "$@"; do\n'
        '    [ "$arg" = -c ] && break\n'
        '    options="$options $arg"\n'
        "done\n"
        'echo "$options" >> "$SIM_STATE/python3.options"\n'
        f'PYTHONPATH="$SIM_STATE/isolate" exec "{Path(sys.executable).as_posix()}" "$@"\n'
    )


# The repository is usually installed into the development environment in editable mode, which makes `import backend`
# succeed from anywhere. The image has the backend only under /opt/pai, so the simulated python must not see the
# repository either; otherwise a missing or broken app directory would go unnoticed. Runs in every python3 start.
SITECUSTOMIZE = """\
import sys

sys.meta_path[:] = [f for f in sys.meta_path if not getattr(f, "__module__", "").startswith("__editable__")]
"""


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


def listening_row(address: str, port: int) -> tuple[str, str]:
    """(/proc/net table, row) of a TCP socket in LISTEN on `address`."""
    if ipaddress.ip_address(address).version == 6:
        return "tcp6", sock_row(ipv6_hex(address), port, STATE_LISTEN)
    return "tcp", sock_row(ipv4_hex(address), port, STATE_LISTEN)


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


# ---- the backend service ---------------------------------------------------------------------------------------------


@dataclass
class Reply:
    """One answer of the fake backend. A status of None closes the connection without answering."""

    status: int | None
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)


def health_body(**overrides: object) -> bytes:
    """The documented /health body, built by the backend's own response model, with `overrides` applied after."""
    document = json.loads(HealthResponse(status="ok", schema_version=1, version="0.0.1").model_dump_json())
    return json.dumps({**document, **overrides}).encode()


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def do_GET(self) -> None:
        backend = self.server.backend
        authorization = self.headers.get("Authorization")
        cookie = self.headers.get("Cookie")
        backend.requests.append((self.path, authorization))
        if cookie is not None:
            backend.cookies.append(cookie)
        if self.path != "/health":
            reply = Reply(404)
        elif authorization is None:
            # Like the backend's guard: with no Authorization header at all, a live session cookie authenticates.
            session = (cookie or "").partition("=")[2] if (cookie or "").startswith(f"{SESSION_COOKIE}=") else None
            reply = backend.authenticated if session in backend.sessions else backend.anonymous
        elif authorization == f"Bearer {backend.token}":
            reply = backend.authenticated
        else:
            reply = backend.rejected
        if reply.status is None:
            self.close_connection = True
            return
        self.send_response(reply.status)
        for name, value in reply.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(reply.body)))
        self.end_headers()
        self.wfile.write(reply.body)

    def log_message(self, format: str, *args: object) -> None:
        """Silence the per-request log line."""


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    backend: FakeBackend


class FakeBackend:
    """A loopback HTTP server that answers GET /health as the backend does: 401 anonymous, 200 with the right token."""

    def __init__(self, host: str) -> None:
        self.token = secrets.token_urlsafe(TOKEN_BYTES)
        self.sessions: set[str] = set()  # live browser session ids; each is accepted as the pai_session cookie
        self.anonymous = Reply(401, b'{"detail":"unauthorized"}')
        self.authenticated = Reply(200, health_body())
        self.rejected = Reply(401, b'{"detail":"unauthorized"}')  # a bearer token that is not the backend's
        self.requests: list[tuple[str, str | None]] = []  # (path, Authorization header) of each request, in order
        self.cookies: list[str] = []  # the Cookie header of each request that had one, in order
        server_class = type(
            "Server", (_Server,), {"address_family": socket.AF_INET6 if ":" in host else socket.AF_INET}
        )
        self._server = server_class((host, 0), _Handler)
        self._server.backend = self
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def new_session(self) -> str:
        """Mint a session id the backend accepts, as `POST /v1/session` does."""
        session = secrets.token_urlsafe(TOKEN_BYTES)
        self.sessions.add(session)
        return session

    def stop(self) -> None:
        """Stop answering and release the port, so a connection to it is refused."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=10)


@dataclass
class Run:
    returncode: int
    stdout: str
    stderr: str
    results: dict[str, CheckResult]
    state: Path
    backend_requests: list[tuple[str, str | None]]
    backend_cookies: list[str]  # the Cookie header of each request that had one
    token: str  # the bearer token the simulated backend accepts
    benign_candidate: str  # the credential-shaped string the machine holds that is no credential
    sessions: list[str]  # the browser session ids the backend accepted when the run ended

    def status(self) -> dict[str, str]:
        return {
            name: ("PASS" if result.passed else "FAIL") for name, result in self.results.items() if name != "RESULT"
        }

    def modprobe_calls(self) -> list[str]:
        log = self.state / "modprobe.calls"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    def python_options(self) -> list[str]:
        """The options (before -c) of every python3 start of the run, one string each."""
        log = self.state / "python3.options"
        return [line.strip() for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


@dataclass
class Sim:
    """A simulated machine: a /proc + /etc + /opt tree, fake commands, a fake backend, and the state the fakes read."""

    base: Path
    host: str = "127.0.0.1"  # where the simulated backend listens
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
            "systemd-analyze": FAKE_ANALYZE,
            "id": FAKE_ID,
            "stat": FAKE_STAT,
            "journalctl": FAKE_JOURNALCTL,
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
        self.write(self.state / "isolate" / "sitecustomize.py", SITECUSTOMIZE)
        self.sysctl("kernel.sim_flag", "2")
        self.sysctl("net.sim.switch", "0")
        self.sysctl("net.sim.triple", "4096 131072 6291456", live="4096\t131072\t6291456")
        self.boot_as_live_session()
        self.sockets: dict[str, list[str]] = {}  # /proc/net rows by table, without the backend's own socket
        self.backend_sockets: dict[str, list[str]] = {}  # the backend's listening sockets, by table
        self._install_backend()
        self.set_sockets()

    def close(self) -> None:
        self.backend.stop()

    # -- writing ----

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
        """Rows for each /proc/net table; the defaults are loopback listeners plus one established connection.

        The backend's own listening socket is added to whatever is given, so a scenario about another socket does not
        also become a scenario about the backend; change that one with `backend_listens_on`.
        """
        loopback4 = [
            sock_row(ipv4_hex("127.0.0.1"), 631, STATE_LISTEN),
            sock_row(ipv4_hex("127.0.0.53"), 53, STATE_LISTEN),
        ]
        established = sock_row(
            ipv4_hex("10.0.2.15"), 40000, STATE_ESTABLISHED, remote_hex=ipv4_hex("93.184.216.34"), remote_port=443
        )
        self.sockets = {
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
        self._write_sockets()

    def backend_listens_on(self, *addresses: str, port: int | None = None) -> None:
        """Make /proc/net show the backend listening on exactly these addresses (default: its configured port)."""
        self.backend_sockets = {}
        for address in addresses:
            table, row = listening_row(address, self.backend.port if port is None else port)
            self.backend_sockets.setdefault(table, []).append(row)
        self._write_sockets()

    def _write_sockets(self) -> None:
        for name, rows in self.sockets.items():
            all_rows = [*rows, *self.backend_sockets.get(name, [])]
            self.write(self.root / "proc" / "net" / name, "\n".join([NET_HEADER, *all_rows]) + "\n")

    def set_nft(self, *chains: dict[str, object], rules: tuple[dict[str, object], ...] = HEALTHY_RULES) -> None:
        self.write(self.state / "nft.out", nft_json(*chains, rules=rules))

    # -- the backend ----

    def _install_backend(self) -> None:
        """A running backend: unit loaded and active, its process unprivileged, listening and answering on loopback."""
        self.backend = FakeBackend(self.host)
        self.token_file = self.root / "run" / "pai" / "token"
        self.endpoint_file = self.root / "run" / "pai" / "endpoint"
        self.data_dir = self.root / "var" / "lib" / "pai"
        self.static_dir = self.root / "opt" / "pai" / "frontend"
        self.write(self.token_file, self.backend.token)  # no trailing newline, as the backend publishes it
        self.write(self.endpoint_file, self.endpoint_url())
        self.data_dir.mkdir(parents=True, exist_ok=True)
        # The code the probes import: the backend's real settings loader, which is all the backend probe asks of it.
        app = self.root / "opt" / "pai" / "backend"
        (app / "core").mkdir(parents=True)
        shutil.copy(BACKEND_PACKAGE / "__init__.py", app / "__init__.py")
        for name in ("__init__.py", "config.py"):
            shutil.copy(BACKEND_PACKAGE / "core" / name, app / "core" / name)
        self.users: dict[str, int] = {SERVICE_USER: SERVICE_UID}
        self.unit: dict[str, str] = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "User": SERVICE_USER,
            "MainPID": str(SERVICE_PID),
            "Environment": self.environment(),
            "EnvironmentFiles": "",
        }
        self.backend_listens_on(self.host)
        self.set_unit()
        self.add_process(
            1, ppid=0, comm="systemd", uid=0, argv=["/sbin/init"], environ={"LANG": "C.UTF-8", "HOME": "/root"}
        )
        self.benign_candidate = secrets.token_urlsafe(TOKEN_BYTES)  # credential-shaped, and no credential at all
        self.add_process(
            OTHER_PID,
            comm="sim-daemon",
            uid=0,
            argv=["/usr/sbin/sim-daemon"],
            environ={"SIM_CACHE_KEY": self.benign_candidate},
        )
        self.add_process(
            SERVICE_PID,
            comm="python3",
            uid=SERVICE_UID,
            argv=["/usr/bin/python3", "-s", "-m", "backend"],
            environ={"PAI_HOST": self.host, "PAI_PORT": str(self.backend.port), "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.set_process()
        self.set_analyze_report("1.1 OK :-)")
        self._install_kiosk()
        self.install_accounts()

    def endpoint_url(self) -> str:
        """What the backend publishes in its endpoint file: the origin it listens on, no trailing newline."""
        return (
            f"http://[{self.host}]:{self.backend.port}"
            if ":" in self.host
            else f"http://{self.host}:{self.backend.port}"
        )

    def environment(self, **overrides: str | None) -> str:
        """The unit's Environment= as `systemctl show` prints it; `overrides` replace a PAI_ variable, None drops it."""
        variables: dict[str, str | None] = {
            "PYTHONDONTWRITEBYTECODE": "1",  # not a PAI_ variable: the probe must ignore it
            "PAI_HOST": self.host,
            "PAI_PORT": str(self.backend.port),
            "PAI_DATA_DIR": self.data_dir.as_posix(),
            "PAI_TOKEN_FILE": self.token_file.as_posix(),
            # On the image these are the defaults; a Windows checkout has no absolute default path to validate.
            "PAI_ENDPOINT_FILE": self.endpoint_file.as_posix(),
            "PAI_STATIC_DIR": self.static_dir.as_posix(),
            **overrides,
        }
        return " ".join(f"{name}={value}" for name, value in variables.items() if value is not None)

    def _write_show(self, unit: str, properties: dict[str, str], suffix: str = "") -> None:
        self.write(
            self.state / f"show.{unit}{suffix}", "".join(f"{key}={value}\n" for key, value in properties.items())
        )

    def set_unit(self, **properties: str) -> None:
        """Change what `systemctl show` reports for the backend unit (property names as systemd spells them)."""
        self.unit.update(properties)
        self._write_show(BACKEND_UNIT, self.unit)

    def unit_reports_differently_at_first(self, polls: int, *, kiosk: bool = False, **early: str) -> None:
        """The unit reports `early` properties instead of its own for the first `polls` calls of `systemctl show`: what
        systemd said before the unit changed (a restart gives it a new main process)."""
        name, properties = (KIOSK_UNIT, self.kiosk_unit) if kiosk else (BACKEND_UNIT, self.unit)
        self._write_show(name, {**properties, **early}, ".early")
        self.write(self.state / f"show.pending.{name}", f"{polls}\n")

    def unit_activates_after(self, polls: int, *, kiosk: bool = False) -> None:
        """The unit reports `activating` for the first `polls` calls of `systemctl show`, then `active`."""
        self.unit_reports_differently_at_first(polls, kiosk=kiosk, ActiveState="activating")

    def set_journal(self, unit: str, lines: list[str]) -> None:
        """What `journalctl -u <unit>` prints."""
        self.write(self.state / f"journal.{unit}", "".join(f"{line}\n" for line in lines))

    def after_unit_is_shown(self, unit: str, seconds: int, *commands: str) -> None:
        """Run shell `commands`, in the background, `seconds` after the script first asks systemd about `unit`."""
        self.write(self.state / f"show.hook.{unit}", "\n".join([f"sleep {seconds}", *commands]) + "\n")

    # -- processes ----

    def add_process(
        self,
        pid: int,
        *,
        ppid: int = 1,
        comm: str = "sim",
        uid: int = 0,
        argv: list[str] | tuple[str, ...] = (),
        environ: dict[str, str] | None = None,
    ) -> None:
        """/proc/<pid>/{status,stat,comm,cmdline,environ} of a process; its argument list and environment as the kernel
        shows them (entries end with a NUL)."""
        directory = self.root / "proc" / str(pid)
        self.write(directory / "comm", comm + "\n")
        self.write(
            directory / "stat",
            f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 5000 1000000 100\n",
        )
        self.write(directory / "cmdline", "".join(f"{word}\0" for word in argv))
        self.write(directory / "environ", "".join(f"{name}={value}\0" for name, value in (environ or {}).items()))
        self.write_status(pid, (uid,) * 4)

    def write_status(
        self,
        pid: int,
        uids: tuple[int, int, int, int],
        *,
        capabilities: str = "0000000000000000",
        no_new_privs: str = "1",
    ) -> None:
        real, effective, saved, filesystem = uids
        self.write(
            self.root / "proc" / str(pid) / "status",
            "Name:\tsim\nState:\tS (sleeping)\n"
            f"Uid:\t{real}\t{effective}\t{saved}\t{filesystem}\nGid:\t{real}\t{real}\t{real}\t{real}\n"
            f"CapInh:\t0000000000000000\nCapPrm:\t{capabilities}\nCapEff:\t{capabilities}\n"
            f"CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t{no_new_privs}\nSeccomp:\t2\n",
        )

    def remove_process(self, pid: int) -> None:
        shutil.rmtree(self.root / "proc" / str(pid))

    # -- the kiosk ----

    def _install_kiosk(self) -> None:
        """A running kiosk: unit active, cage (as its account) with the launcher and the browser below it, and a
        readiness file saying the shell rendered and the backend is connected."""
        app = self.root / "opt" / "pai" / "kiosk"
        app.mkdir(parents=True)
        # The code the probe imports: the kiosk's real settings loader and readiness contract.
        for name in ("__init__.py", "config.py", "errors.py", "readiness.py"):
            shutil.copy(KIOSK_PACKAGE / name, app / name)
        self.ready_file = self.root / "run" / "pai-ui" / "ready"
        self.users[KIOSK_USER] = KIOSK_UID
        self.kiosk_unit: dict[str, str] = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "User": KIOSK_USER,
            "MainPID": str(KIOSK_PID),
            "Environment": self.kiosk_environment(),
            "EnvironmentFiles": "",
        }
        self.set_kiosk_unit()
        self.add_process(
            KIOSK_PID,
            comm="cage",
            uid=KIOSK_UID,
            argv=["/usr/bin/cage", "-d", "--", "/usr/bin/python3", "-s", "-m", "kiosk"],
            environ={"XDG_RUNTIME_DIR": f"/run/user/{KIOSK_UID}", "WLR_RENDERER": "pixman"},
        )
        self.add_process(
            LAUNCHER_PID,
            ppid=KIOSK_PID,
            comm="python3",
            uid=KIOSK_UID,
            argv=["/usr/bin/python3", "-s", "-m", "kiosk"],
            environ={"XDG_RUNTIME_DIR": f"/run/user/{KIOSK_UID}"},
        )
        browser = [f"/usr/lib/chromium/{BROWSER_NAME}", "--app=about:blank", "--remote-debugging-pipe"]
        self.add_process(BROWSER_PID, ppid=LAUNCHER_PID, comm=BROWSER_NAME, uid=KIOSK_UID, argv=browser)
        self.add_process(
            BROWSER_CHILD_PID, ppid=BROWSER_PID, comm=BROWSER_NAME, uid=KIOSK_UID, argv=[*browser, "--type=zygote"]
        )
        self.set_ready()
        self.set_users(self.users)

    def kiosk_environment(self, **overrides: str | None) -> str:
        """The kiosk unit's Environment=; the unit sets no PAI_ variable, so the kiosk's own defaults apply on the
        image. Here the paths the kiosk settings validate as absolute are given, as on the image the defaults are."""
        variables: dict[str, str | None] = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PAI_ENDPOINT_FILE": self.endpoint_file.as_posix(),
            "PAI_TOKEN_FILE": self.token_file.as_posix(),
            "PAI_KIOSK_READY_FILE": self.ready_file.as_posix(),
            "PAI_KIOSK_PROFILE_DIR": (self.root / "var" / "lib" / "pai-ui" / "profile").as_posix(),
            **overrides,
        }
        return " ".join(f"{name}={value}" for name, value in variables.items() if value is not None)

    def set_kiosk_unit(self, **properties: str) -> None:
        """Change what `systemctl show` reports for the kiosk unit."""
        self.kiosk_unit.update(properties)
        self._write_show(KIOSK_UNIT, self.kiosk_unit)

    def ready_report(
        self, *, state: str = "ready", shell_rendered: object = True, status_bar: object = READY_STATUS, **extra: object
    ) -> str:
        """The readiness file's text, shaped by the kiosk's own report class (`extra` replaces or adds fields)."""
        with tempfile.TemporaryDirectory() as scratch:
            written = Path(scratch) / "ready"
            write_ready_file(
                written, ReadyReport(state=state, shell_rendered=bool(shell_rendered), status_bar=str(status_bar))
            )
            document = json.loads(written.read_text(encoding="utf-8"))
        document.update({"shell_rendered": shell_rendered, "status_bar": status_bar, **extra})
        return json.dumps(document, separators=(",", ":"))

    def set_ready(self, text: str | None = None, **fields: object) -> None:
        """Publish the kiosk's readiness file: the default says ready, shell rendered, backend connected."""
        self.write(self.ready_file, self.ready_report(**fields) if text is None else text)

    # -- accounts ----

    def install_accounts(self) -> None:
        """/etc/shadow with only locked and disabled password fields, as the image's accounts are, and its mode."""
        self.set_shadow(
            {
                "root": "*",
                SERVICE_USER: "!*",
                KIOSK_USER: "!*",
                "pai-selfcheck": "!*",
                "sim-user": "!",  # the live user, locked at boot
            }
        )

    # -- live session or installed system ----

    def boot_as_live_session(self) -> None:
        """What the kernel and live-boot leave on a live session: boot=live on the command line, the medium mounted, the
        live packages installed and the live user's account. The default of every simulated machine."""
        self.write(
            self.root / "proc" / "cmdline", f"BOOT_IMAGE=/vmlinuz {LIVE_CMDLINE_WORD} components console=ttyS0\n"
        )
        self.write(
            self.root / "proc" / "self" / "mountinfo",
            f"22 1 0:20 / / rw - overlay overlay rw\n23 22 8:16 / {LIVE_MEDIUM_MOUNT} ro - iso9660 /dev/sr0 ro\n",
        )
        self.set_dpkg_packages(*LIVE_PACKAGES, "python3", "sim-package")
        self.set_passwd(
            {
                "root": ("0", "root"),
                SERVICE_USER: (str(SERVICE_UID), "service"),
                "sim-user": ("1000", LIVE_USER_FULL_NAME),
            }
        )

    def boot_as_installed_system(self) -> None:
        """An installed system that passes both installed-only checks: no boot=live, no live medium, no live package or
        account, no autologin, no password-less sudo, and the root filesystem on a LUKS2 volume with argon2id keyslots.
        A scenario then breaks exactly one thing."""
        self.write(
            self.root / "proc" / "cmdline",
            "BOOT_IMAGE=/vmlinuz-sim root=/dev/mapper/cryptroot-sim ro console=ttyS0 pai.selfcheck=1\n",
        )
        self.write(self.root / "proc" / "self" / "mountinfo", "22 1 254:0 / / rw - ext4 /dev/mapper/cryptroot-sim rw\n")
        self.set_dpkg_packages("python3", "sim-package", "live-sim-unrelated", "cryptsetup")
        self.set_passwd(
            {
                "root": ("0", "root"),
                SERVICE_USER: (str(SERVICE_UID), "service"),
                "sim-owner": ("1000", "Owner,,,"),
            }
        )
        self.set_shadow({"root": "*", SERVICE_USER: "!*", KIOSK_USER: "!*", "pai-selfcheck": "!*", "sim-owner": "!"})
        self.set_crypt_facts()

    def set_crypt_facts(self, **overrides: str | None) -> None:
        """The facts file pai-selfcheck-crypt.service writes: by default a LUKS2 mapping with two argon2id keyslots (a
        passphrase and a recovery key). `overrides` replace a fact; None removes it."""
        facts: dict[str, str | None] = {
            "root_device": "254:0",
            "root_dm": "cryptroot-sim",
            "dm_kind": REQUIRED_CRYPT_KIND,
            "backing_count": "1",
            "backing": "/dev/vda4",
            "luks_version": "2",
            "keyslots": "2",
            "kdfs": f"{REQUIRED_LUKS_KDF},{REQUIRED_LUKS_KDF}",
            **overrides,
        }
        text = "".join(f"{key}={value}\n" for key, value in facts.items() if value is not None)
        self.write(self.root / "run" / "pai-selfcheck" / "crypt-facts", text)

    def set_dpkg_packages(self, *packages: str, status: str = "install ok installed") -> None:
        """/var/lib/dpkg/status with these packages (all in `status`), as dpkg writes it: stanzas split by a blank
        line."""
        stanzas = [f"Package: {name}\nStatus: {status}\nVersion: 1\n" for name in packages]
        self.write(self.root / "var" / "lib" / "dpkg" / "status", "\n".join(stanzas))

    def set_passwd(self, accounts: dict[str, tuple[str, str]]) -> None:
        """/etc/passwd with these accounts (name -> (uid, GECOS field))."""
        lines = "".join(
            f"{name}:x:{uid}:{uid}:{gecos}:/home/{name}:/bin/sh\n" for name, (uid, gecos) in accounts.items()
        )
        self.write(self.root / "etc" / "passwd", lines)

    # -- accounts ----

    def set_shadow(self, accounts: dict[str, str], *, mode: str = "640") -> None:
        """/etc/shadow with these accounts (name -> password field) and the mode the fake `stat` reports for it."""
        lines = "".join(f"{name}:{field}:20000:0:99999:7:::\n" for name, field in accounts.items())
        self.write(self.root / "etc" / "shadow", lines)
        self.write(self.state / "mode.shadow", mode + "\n")

    def set_process(
        self,
        *,
        uids: tuple[int, int, int, int] = (SERVICE_UID,) * 4,
        capabilities: str = "0000000000000000",
        no_new_privs: str = "1",
    ) -> None:
        """/proc/<MainPID>/status of the backend process, and the account database that names its user."""
        self.write_status(int(self.unit["MainPID"]), uids, capabilities=capabilities, no_new_privs=no_new_privs)
        self.set_users(self.users)

    def set_users(self, users: dict[str, int]) -> None:
        """The account database the fake `id` answers from."""
        self.users = users
        self.write(self.state / "users", "".join(f"{name} {uid}\n" for name, uid in users.items()))

    def set_analyze_report(self, verdict: str) -> None:
        """`systemd-analyze security` output: the backend unit's real report, verdict on its last line."""
        report = ANALYZE_SECURITY_REPORT.read_text(encoding="utf-8")
        last = report.rstrip("\n").rsplit("\n", 1)
        assert "Overall exposure level for" in last[1], "the fixture no longer ends with the exposure line"
        self.write(self.state / "analyze.out", f"{last[0]}\n-> Overall exposure level for {BACKEND_UNIT}: {verdict}\n")

    # -- running ----

    def run(self, *, script: Path = SCRIPT, extra_env: dict[str, str] | None = None) -> Run:
        assert BASH is not None
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "PAI_SELFCHECK_ROOT": self.root.as_posix(),
            "PAI_SELFCHECK_READY_TIMEOUT": str(READY_TIMEOUT_SECONDS),
            "PAI_SELFCHECK_KIOSK_TIMEOUT": str(KIOSK_TIMEOUT_SECONDS),
            "SIM_STATE": self.state.as_posix(),
            **(extra_env or {}),
        }
        # The image's units set no PYTHONPATH, and the working directory must not hold the repository's backend package
        # (python puts it first on its import path): the probe has to find the backend where the script says it is.
        env.pop("PYTHONPATH", None)
        self.backend.requests.clear()
        self.backend.cookies.clear()
        done = subprocess.run(  # noqa: S603
            [BASH, str(script)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=RUN_TIMEOUT_SECONDS,
            cwd=self.base,
        )
        # Whatever else a run does, it must never print the backend's bearer token, a live session id, or a string that
        # only looked like a credential (a candidate is never echoed, whether or not the backend accepted it).
        on_disk = ""
        if self.token_file.is_file():
            on_disk = self.token_file.read_text(encoding="utf-8", errors="replace").strip()
        for secret in {self.backend.token, on_disk, self.benign_candidate, *self.backend.sessions}:
            if len(secret) >= MIN_SECRET_LENGTH:
                assert secret not in done.stdout + done.stderr, (
                    "the self-check printed a token, session id or candidate"
                )
        return Run(
            done.returncode,
            done.stdout,
            done.stderr,
            {r.name: r for r in parse_selfcheck(done.stdout)},
            self.state,
            list(self.backend.requests),
            list(self.backend.cookies),
            self.backend.token,
            self.benign_candidate,
            sorted(self.backend.sessions),
        )
