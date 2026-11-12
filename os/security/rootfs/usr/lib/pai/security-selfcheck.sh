#!/bin/bash
# Private AI OS boot-time security self-check.
#
# Verifies that the RUNNING system matches the security configuration the image ships. Every expectation is derived
# at run time from the image's own files (/etc/nftables.conf, /etc/modprobe.d, /etc/sysctl.d) or is a policy statement
# kept in the tables below; nothing here repeats a value that lives in those files.
#
# Output, one line per check, then one summary line (parsed by tests/end_to_end/selfcheck_output.py):
#   PAI-SELFCHECK|<name>|PASS|<detail>
#   PAI-SELFCHECK|<name>|FAIL|<detail>
#   PAI-SELFCHECK|RESULT|PASS|<passed>/<total>      (or FAIL)
# The exit status is non-zero when any check fails, and also when there is no check to run: a run that verified
# nothing never reports success. Details name configuration keys, module names, socket addresses, paths, process ids
# and names, account names and status codes only. The secrets the checks touch (the backend's bearer token, and any
# credential-shaped string found in a process's argument list or environment) are tested against the backend and
# never printed.
#
# Run by pai-selfcheck.service, which only starts when the kernel command line has pai.selfcheck=1. The unit is not
# root; it holds exactly the capabilities these checks need to read what they examine (see the unit).
#
# Two modes, found out from the running system (is_live_session), never from a setting: a live session runs the checks
# in CHECKS; an installed system (docs/architecture/INSTALLER_DESIGN.md) runs those and then the ones in
# INSTALLED_CHECKS, which are about what an installation must have and a live session cannot (the root filesystem on
# an encrypted volume, and nothing left of the live system). A live session emits none of the installed-only checks.
#
# To add a check: write check_<what>() that prints a one-line detail and returns 0 (pass) or non-zero (fail), then
# add "<name>:check_<what>" to CHECKS. Checks must not rely on errexit; they handle every failure explicitly,
# and a check that crashes counts as a failure without stopping the others.
# The check_* functions are invoked indirectly through the CHECKS table, which ShellCheck cannot follow.
# shellcheck disable=SC2317
set -euo pipefail
export LC_ALL=C

# Test-only: a prefix for /proc, /etc and /opt so the checks can run against a simulated tree. The live-root check FAILs
# while it is set, so a run that did not look at the real system can never report overall success.
ROOT="${PAI_SELFCHECK_ROOT:-}"
PROC_DIR="$ROOT/proc"
APP_DIR="$ROOT/opt/pai" # where os/build/assemble-config.sh installs the backend and the kiosk; `python3 -m backend` and `-m kiosk` run from here
NFT_CONF="$ROOT/etc/nftables.conf"
MODPROBE_DIR="$ROOT/etc/modprobe.d"
SYSCTL_DIR="$ROOT/etc/sysctl.d"
SHADOW_FILE="$ROOT/etc/shadow"
PASSWD_FILE="$ROOT/etc/passwd"
SUDOERS_FILE="$ROOT/etc/sudoers"
SUDOERS_DIR="$ROOT/etc/sudoers.d"
LIVE_CONFIG_DIR="$ROOT/etc/live" # live-config's own configuration; the package and everything it wrote are gone from an installed system
CMDLINE_FILE="$PROC_DIR/cmdline"
MOUNTINFO_FILE="$PROC_DIR/self/mountinfo"
DPKG_STATUS_FILE="$ROOT/var/lib/dpkg/status"
# What pai-selfcheck-crypt.service writes (os/installer/rootfs/usr/lib/pai/selfcheck-crypt-facts.py): key=value lines about
# the device under the root filesystem. That unit has the one capability that reads a block device, which this one, with
# its private /dev, cannot.
CRYPT_FACTS_FILE="$ROOT/run/pai-selfcheck/crypt-facts"

# Room for the journal lines a failing kiosk check adds (see DIAGNOSTIC_* below).
DETAIL_LIMIT=4000

# ---- Policy tables ------------------------------------------------------------------------------------------------

# Hooks whose filter chains must all default to drop (docs/security/THREAT_MODEL.md, invariant 5, plus input). This
# is the policy floor: independent of the shipped nftables.conf, which the same check also compares with the live
# ruleset, so weakening the file and the running firewall together still fails.
REQUIRED_DROP_HOOKS=(input forward output)

# Units that must be active when the check runs.
REQUIRED_ACTIVE_UNITS=(nftables.service systemd-networkd.service)

# The backend service. Which account it runs as, where it listens and where it keeps its token are read from the
# running system (the unit, and the backend's own settings loader), never written down here.
BACKEND_UNIT=pai-backend.service

# How long to wait for the backend after boot. The unit is "active" as soon as python3 is executed, but the service
# then imports its libraries, migrates its database, binds the port and finally publishes the token, which under
# emulation takes a while. A backend still not answering after this is a failure. Well inside the 300 s that
# pai-selfcheck.service allows for the whole run. Test-only override: PAI_SELFCHECK_READY_TIMEOUT (whole seconds).
BACKEND_READY_TIMEOUT=${PAI_SELFCHECK_READY_TIMEOUT:-120}

# The kiosk (cage and Chromium, started by a launcher that is a child of the unit's main process). What the kiosk runs
# as, which browser it starts and where it publishes its readiness file are read from the running system (the unit,
# and the kiosk's own settings loader), never written down here. The unit starts after the backend and then needs the
# launcher to fetch a session, Chromium to start and the shell to render, which under software emulation takes
# minutes; the launcher's own bounds add up to four (60 s for the backend files, 60 s for the browser, 120 s for the
# page), so the default allows one full attempt with margin. One budget, counted from when the wait starts, covers
# both "Chromium is running" and "the shell reported ready". Well inside what pai-selfcheck.service allows for the
# whole run (TimeoutStartSec= there covers this and the backend wait). Test-only override: PAI_SELFCHECK_KIOSK_TIMEOUT
# (whole seconds).
KIOSK_UNIT=pai-kiosk.service
KIOSK_READY_TIMEOUT=${PAI_SELFCHECK_KIOSK_TIMEOUT:-300}

# What the readiness file's status line starts with when the page is talking to the backend: the label of the
# frontend's status bar (frontend/src/components/StatusBar.tsx). kiosk/readiness.py carries no machine-readable
# "backend connected" fact, only that line's text, so this is the one frontend wording the check relies on;
# tests/end_to_end/test_selfcheck_wiring.py keeps it equal to the frontend source.
KIOSK_BACKEND_CONNECTED_LABEL="Backend connected"

# What a failing kiosk check adds to its detail so the failure can be understood from the console alone (the unit's own
# output lives in the journal, which a boot test cannot read afterwards): what systemd says about the unit, and the tail of
# the unit's journal, with anything shaped like a credential (a run of CREDENTIAL_LENGTH or more urlsafe base64
# characters) replaced, as a precaution, by [masked]. Each journal line is cut to DIAGNOSTIC_LINE_LIMIT characters, and
# the detail as a whole to DETAIL_LIMIT. DIAGNOSTIC_TIMEOUT bounds each call, so the diagnostics never stretch the run.
DIAGNOSTIC_PROPERTIES=(ActiveState SubState Result MainPID ExecMainStatus ExecMainCode NRestarts)
DIAGNOSTIC_JOURNAL_LINES=20
DIAGNOSTIC_LINE_LIMIT=160
DIAGNOSTIC_TIMEOUT=20

# What a credential looks like, for no-secret-in-process-state. The backend mints its bearer token and every browser
# session id with secrets.token_urlsafe(TOKEN_BYTES) (backend/api/auth.py), i.e. CREDENTIAL_LENGTH characters of
# urlsafe base64. The session id is unknown to the check, so any string of this shape found in a process's argument
# list or environment is tested against the live backend. SESSION_COOKIE is the cookie the backend reads a session id
# from (backend/api/sessions.py). tests/end_to_end/test_selfcheck_wiring.py keeps both equal to the backend's own values.
CREDENTIAL_LENGTH=43
SESSION_COOKIE=pai_session
# More credential-shaped strings than this is not an ordinary process table: failing is safer than testing only some.
MAX_CREDENTIAL_CANDIDATES=200

# Highest `systemd-analyze security` exposure the running backend unit may have, in tenths (0 = no exposure, 100 = fully
# exposed), so 12 is 1.2. The unit as shipped scores 1.1 ("OK") both offline and as measured on a running system under
# systemd 257, so this allows one tenth of drift. Measured with `systemd-analyze security --offline=true` on copies of
# the unit each missing one directive: dropping any of 16 baseline directives scores 1.3 or more (CapabilityBoundingSet
# 2.9, RestrictNamespaces 1.8, RestrictAddressFamilies 1.6, PrivateDevices 1.4, the rest 1.3) and fails here; the
# other 8 (UMask, ProtectHostname, ProcSubset, MemoryDenyWriteExecute, LockPersonality, ...) cost at most 0.1 and are
# caught only by the exact lint in tests/security/test_systemd_units.py. What this check adds is that it scores the
# unit as the running systemd loaded it, drop-ins and overrides included, which the lint of the file cannot see.
# The image pins its package set (PAI_SNAPSHOT), so the score moves only when that snapshot does; a failure then is a
# prompt to look at the unit and, if the new score is understood, to change this number deliberately.
BACKEND_MAX_EXPOSURE_TENTHS=12

# Sockets allowed to listen on a non-loopback address; anything else beyond loopback is a failure. Found by booting
# the image and reading /proc/net/* together with the owning processes. Keyed by /proc/net table and local port (the
# owner of a socket cannot be looked up without CAP_SYS_PTRACE), so each entry says what the port is for and which
# firewall rule already limits it. Every exception that a run uses is printed in that check's detail.
# An entry only covers a socket bound to one specific address. A wildcard bind (0.0.0.0, ::) is reachable on every
# address the machine ever gets, which the firewall rule named in the justification does not narrow, so it is never
# allowed, whatever the table says.
# Format: "<table> <port> <justification>"
LISTEN_ALLOW=(
    "udp 68 DHCPv4 client sockets (systemd-networkd, dhcpcd), each bound to the address its lease gave it; the input chain admits only server replies (sport 67)"
    "udp6 546 DHCPv6 client sockets (dhcpcd), each bound to one of the interface's own addresses; the input chain admits only server replies (sport 547)"
)

# A modprobe.d "install" command that really blocks a module: /bin/false (loading fails) or /bin/true (silently a no-op).
BLOCKING_INSTALL='^/(usr/)?bin/(false|true)$'
# What `modprobe -n -v` prints when that install command is the one modprobe would run.
DRY_RUN_BLOCKED=$'(^|\n)install /(usr/)?bin/(false|true)([[:space:]]|$)'

# How a live session is told from an installed system. live-boot is what makes a session live: its boot=live option is
# on the kernel command line, and it mounts the medium it booted from at /run/live/medium. Either says live; an installed
# system has neither (the installer removes live-boot and writes its own boot configuration).
LIVE_CMDLINE_WORD=boot=live
LIVE_MEDIUM_MOUNT=/run/live/medium

# An installed system must have the root filesystem on a LUKS2 volume whose every keyslot derives its key with this
# function (docs/architecture/INSTALLER_DESIGN.md: LUKS2, argon2id). The kind is device-mapper's own uuid prefix.
REQUIRED_CRYPT_KIND=CRYPT-LUKS2
REQUIRED_LUKS_KDF=argon2id

# What no installed system may hold of the live system (check no-live-remnants). Packages: live-boot and live-config
# (and the packages built from them) are what make a session live and create the well-known login. The live user is
# found by what live-config writes into its account, not by its name (the name is configurable): the full name in the
# passwd file's GECOS field. Autologin: a line that starts getty with a login already done, in any unit or drop-in
# of the places systemd reads units from (including the generators' output under /run), which is how live-config
# logs the live user in on the console.
LIVE_PACKAGE_PATTERN='^live-(boot|config|tools)'
LIVE_USER_GECOS_PATTERN='^Debian Live user'
AUTOLOGIN_PATTERN='^[[:space:]]*ExecStart=.*(--autologin|--skip-login)'
AUTOLOGIN_UNIT_DIRS=(
    "$ROOT/etc/systemd/system"
    "$ROOT/run/systemd/system"
    "$ROOT/run/systemd/generator"
    "$ROOT/run/systemd/generator.early"
    "$ROOT/run/systemd/generator.late"
    "$ROOT/usr/lib/systemd/system"
)

# ---- Embedded parsers (python3 ships in the image) ----------------------------------------------------------------

# stdin: `nft -j list ruleset`; argv: <nftables.conf> <hook>...: the hooks that must have a default-drop filter chain.
# Fails unless (1) every filter base chain on those hooks has policy drop and each hook has one, (2) no such chain
# accepts packets unconditionally (a catch-all `accept` rule, also reached through an unconditional jump or goto,
# turns policy drop into accept-everything), and (3) every base chain declared in the shipped nftables.conf is loaded
# with the hook, type and policy it was declared with.
PY_NFT_POLICY=$(cat <<'PY'
import json
import re
import sys

conf_path, required = sys.argv[1], sys.argv[2:]
CONDITIONS = {"match", "limit", "quota"}  # statements that make a rule apply to some packets only
TERMINAL = {"accept", "drop", "reject", "goto", "return"}  # nothing after an unconditional one is reached
DECLARATIONS = re.compile(
    r"\btable\s+(?P<family>\w+)\s+(?P<table>[\w.-]+)\s*\{"
    r"|\bchain\s+(?P<chain>[\w.-]+)\s*\{"
    r"|\btype\s+(?P<type>\w+)\s+hook\s+(?P<hook>\w+)\b[^;{}]*;(?:\s*policy\s+(?P<policy>\w+)\s*;)?"
)


def label(key):
    return "/".join(str(part) for part in key)


def configured_base_chains(path):
    """(family, table, chain) -> (type, hook, policy) for every base chain the configuration file declares."""
    with open(path, encoding="utf-8") as handle:
        text = re.sub(r"#[^\n]*", "", handle.read())
    declared, family, table, name = {}, None, None, None
    for match in DECLARATIONS.finditer(text):
        if match["table"]:
            family, table = match["family"], match["table"]
        elif match["chain"]:
            name = match["chain"]
        else:  # a base chain without a policy statement defaults to accept
            declared[(family, table, name)] = (match["type"], match["hook"], match["policy"] or "accept")
    return declared


try:
    ruleset = json.load(sys.stdin)
except ValueError as error:
    print(f"nft output is not valid JSON: {error}")
    sys.exit(1)
try:
    configured = configured_base_chains(conf_path)
except OSError as error:
    print(f"cannot read {conf_path}: {error.strerror}")
    sys.exit(1)
if not configured:
    print(f"no base chain declared in {conf_path}, so there is nothing to verify")
    sys.exit(1)

chains, rules = {}, {}
for item in ruleset.get("nftables", []):
    if "chain" in item:
        live = item["chain"]
        chains[(live.get("family"), live.get("table"), live.get("name"))] = live
    elif "rule" in item:
        rule = item["rule"]
        rules.setdefault((rule.get("family"), rule.get("table"), rule.get("chain")), []).append(rule.get("expr", []))


def accepts_unconditionally(key, seen):
    """The chain holding an unconditional accept that packets entering chain `key` reach, or None."""
    if key in seen:
        return None
    seen.add(key)
    for expr in rules.get(key, []):
        statements = [next(iter(s)) for s in expr if isinstance(s, dict) and s]
        if CONDITIONS & set(statements):
            continue
        if "accept" in statements:
            return key
        for statement in expr:
            for verb in ("jump", "goto"):
                if isinstance(statement, dict) and verb in statement:
                    found = accepts_unconditionally((key[0], key[1], statement[verb].get("target")), seen)
                    if found is not None:
                        return found
        if TERMINAL & set(statements):
            return None
    return None


counts = dict.fromkeys(required, 0)
not_drop, open_chains = [], []
for key, live in chains.items():
    if live.get("type") != "filter" or live.get("hook") not in counts:
        continue
    counts[live["hook"]] += 1
    if live.get("policy") != "drop":
        not_drop.append(f"{label(key)} policy={live.get('policy')}")
    if (where := accepts_unconditionally(key, set())) is not None:
        open_chains.append(label(key) if where == key else f"{label(key)} via {label(where)}")

mismatches = []
for key, (kind, hook, policy) in configured.items():
    live = chains.get(key)
    if live is None:
        mismatches.append(f"{label(key)} is configured but not loaded")
    elif (live.get("type"), live.get("hook"), live.get("policy")) != (kind, hook, policy):
        mismatches.append(
            f"{label(key)}: configured {kind} hook {hook} policy {policy}, "
            f"live {live.get('type')} hook {live.get('hook')} policy {live.get('policy')}"
        )

missing = [hook for hook, count in counts.items() if count == 0]
if missing:
    print("no filter base chain on hook: " + ", ".join(missing))
if not_drop:
    print("chain without policy drop: " + "; ".join(not_drop))
if open_chains:
    print("unconditional accept in: " + "; ".join(open_chains))
if mismatches:
    print("live ruleset differs from " + conf_path + ": " + "; ".join(mismatches))
if missing or not_drop or open_chains or mismatches:
    sys.exit(1)
summary = ", ".join(f"{hook}={count}" for hook, count in counts.items())
loaded = f"{len(configured)} configured base chains loaded as declared"
print(f"filter base chains with policy drop: {summary}; no unconditional accept; {loaded}")
PY
)

# Shared by the programs below: reads the listening sockets of /proc/net/{tcp,tcp6,udp,udp6}.
PY_NET=$(cat <<'PY'
import ipaddress
import sys

TABLES = {"tcp": "0A", "tcp6": "0A", "udp": "07", "udp6": "07"}  # state of a listening / unconnected-bound socket
REQUIRED_TABLES = {"tcp", "udp"}  # tcp6/udp6 are absent when IPv6 is disabled


def decode(hex_address):
    raw = bytes.fromhex(hex_address)
    if sys.byteorder == "little":  # /proc prints each 32-bit word in host byte order
        raw = b"".join(raw[i : i + 4][::-1] for i in range(0, len(raw), 4))
    return ipaddress.ip_address(raw)


def is_loopback(address):
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_loopback or (mapped is not None and mapped.is_loopback)


def is_wildcard(address):
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_unspecified or (mapped is not None and mapped.is_unspecified)


def show(table, address, port):
    return f"{table} [{address}]:{port}" if address.version == 6 else f"{table} {address}:{port}"


def listening_sockets(net_dir):
    """([(table, address, port)] of every listening socket, ["<table>: <reason>"] of every unreadable required table)."""
    sockets, unreadable = [], []
    for table, listening_state in TABLES.items():
        try:
            with open(f"{net_dir}/{table}", encoding="ascii") as handle:
                rows = handle.read().splitlines()[1:]
        except OSError as error:
            if table in REQUIRED_TABLES:
                unreadable.append(f"{table}: {error.strerror}")
            continue
        for row in rows:
            fields = row.split()
            if len(fields) < 4 or fields[3] != listening_state:
                continue
            hex_address, hex_port = fields[1].rsplit(":", 1)
            sockets.append((table, decode(hex_address), int(hex_port, 16)))
    return sockets, unreadable
PY
)

# argv: <proc net directory> <allowed "table:port"...>. Prints a verdict line; exit 1 when a listener is not allowed.
# An allowed "table:port" covers a socket bound to a specific address only; a wildcard bind is always a failure.
PY_LISTENERS=$(cat <<'PY'
net_dir, allowed = sys.argv[1], set(sys.argv[2:])
sockets, unreadable = listening_sockets(net_dir)
offending, used = [], []
for table, address, port in sockets:
    if is_loopback(address):
        continue
    if f"{table}:{port}" in allowed and not is_wildcard(address):
        used.append(show(table, address, port))
    else:
        offending.append(show(table, address, port))

if unreadable:
    print("cannot read " + ", ".join(unreadable))
if offending:
    print("listening beyond loopback: " + ", ".join(offending))
if unreadable or offending:
    sys.exit(1)
print("no listener beyond loopback" + (f"; allowed: {', '.join(sorted(set(used)))}" if used else ""))
PY
)

# Shared by the programs below: builds a service's settings from its unit's Environment=. The service's own settings
# loader (code the image installs under <app dir>) is fed with the PAI_ variables of the unit, so no default is
# repeated in this script.
PY_UNIT_SETTINGS=$(cat <<'PY'
import importlib
import shlex
import sys


def load_unit_settings(label, module, app_dir, environment):
    """(settings, "") from `module`.load_settings fed with the PAI_ variables of `environment`, or (None, reason)."""
    sys.path.insert(0, app_dir)
    try:
        config = importlib.import_module(module)
    except ImportError as error:
        return None, f"cannot read the {label}'s settings from {app_dir}: {type(error).__name__}: {error}"
    try:
        variables = dict(word.partition("=")[::2] for word in shlex.split(environment) if "=" in word)
        return config.load_settings({name: value for name, value in variables.items() if name.startswith("PAI_")}), ""
    except config.ConfigError as error:
        return None, f"the unit's environment is not a valid {label} configuration: {error}"
    except ValueError as error:  # shlex: the Environment= text has an unbalanced quote
        return None, f"cannot read the unit's environment: {type(error).__name__}: {error}"
PY
)

# Shared by the programs below: one HTTP GET to the backend's loopback address.
PY_HTTP=$(cat <<'PY'
import http.client
import urllib.error
import urllib.request

MAX_BODY = 65536
REQUEST_TIMEOUT = 10


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a redirect is an answer to report, not a hop to follow
        return None


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)  # never through an HTTP proxy


def get(where, path, headers=None):
    """(status, body) of GET <path> on <where> (host:port), or (None, reason) when no answer came."""
    request = urllib.request.Request(f"http://{where}{path}", headers=headers or {})
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            return response.status, response.read(MAX_BODY)
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read(MAX_BODY)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
        return None, str(getattr(error, "reason", error))
PY
)

# Examines the running backend from outside, in one process (a Python start is slow under emulation). Meant to follow
# PY_NET, PY_UNIT_SETTINGS and PY_HTTP. argv: <app directory> <Environment= of the unit> <proc net directory> <seconds
# to wait for it>. stdout: one line per fact, "<fact>|PASS|<detail>" or "<fact>|FAIL|<detail>", for ready, loopback,
# anonymous and health. Where the backend listens, and where it keeps its token, come from the backend's own settings
# loader fed with the unit's environment. The token is read to authenticate one request and is never printed: details
# hold addresses, paths and status codes only.
PY_BACKEND_PROBE=$(cat <<'PY'
import json
import os
import socket
import time

FACTS = ("ready", "loopback", "anonymous", "health")
app_dir, environment, net_dir, wait = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])


def report(fact, ok, detail):
    print(f"{fact}|{'PASS' if ok else 'FAIL'}|{' '.join(str(detail).split())}", flush=True)


def report_all(ok, detail, facts=FACTS):
    for fact in facts:
        report(fact, ok, detail)


settings, problem = load_unit_settings("backend", "backend.core.config", app_dir, environment)
if problem:
    report_all(False, problem)
    sys.exit(0)

host, port, token_file = settings.host, settings.port, str(settings.token_file)
where = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

# The token is published after the port is bound, so "ready" means both: the port accepts a connection and the file exists.
deadline, reason = time.monotonic() + wait, "not tried"
while True:
    try:
        socket.create_connection((host, port), timeout=2).close()
        if os.stat(token_file).st_size == 0:
            raise OSError("the token file is empty")
        reason = ""
    except OSError as error:
        reason = f"{where} or its token file is not ready: {error}"
    if not reason or time.monotonic() >= deadline:
        break
    time.sleep(1)
ready = not reason
report("ready", ready, f"accepts connections on {where} and has published its token file" if ready else reason)

# Loopback only: something listens on the configured address, and every listener on that port is a loopback address.
sockets, unreadable = listening_sockets(net_dir)
on_port = [(table, address) for table, address, listening_port in sockets if listening_port == port]
beyond = [show(table, address, port) for table, address in on_port if not is_loopback(address)]
configured = ipaddress.ip_address(host)
if unreadable:
    report("loopback", False, "cannot read " + ", ".join(unreadable))
elif beyond:
    report("loopback", False, "listening beyond loopback on the backend port: " + ", ".join(beyond))
elif not any(address == configured for _, address in on_port):
    report("loopback", False, f"nothing listens on {where} (the configured address)")
else:
    report("loopback", True, f"listens on {where} and nowhere else on port {port}")

if not ready:
    report_all(False, "the backend is not ready, so it was not asked", ("anonymous", "health"))
    sys.exit(0)


status, body = get(where, "/health")
if status is None:
    report("anonymous", False, f"GET /health without credentials got no answer: {body}")
elif status == 401:
    report("anonymous", True, "GET /health without credentials is refused with 401")
else:
    report("anonymous", False, f"GET /health without credentials returned {status}, expected 401")

try:
    with open(token_file, encoding="ascii") as handle:
        token = handle.read().strip()
except (OSError, UnicodeDecodeError) as error:
    report("health", False, f"cannot read the token file {token_file}: {type(error).__name__}")
    sys.exit(0)
status, body = get(where, "/health", {"Authorization": f"Bearer {token}"} if token else None)
if status is None:
    report("health", False, f"authenticated GET /health got no answer: {body}")
elif status != 200:
    report("health", False, f"authenticated GET /health returned {status}, expected 200")
else:
    try:
        health = json.loads(body)
        valid = (
            isinstance(health, dict)
            and health.get("status") == "ok"
            and isinstance(health.get("schema_version"), int)
            and isinstance(health.get("version"), str)
        )
    except ValueError:
        valid = False
    if valid:
        version = health["version"][:64]
        report("health", True, f"authenticated GET /health returned 200: schema {health['schema_version']}, version {version}")
    else:
        report("health", False, "authenticated GET /health returned 200 without the documented body (status ok, schema_version, version)")
PY
)

# Examines the running kiosk, in one process. Meant to follow PY_UNIT_SETTINGS. argv: <app directory> <Environment= of
# the unit> <proc directory> <MainPID of the unit> <status label of a connected backend> <seconds to wait>. Waits until
# both facts hold or the time is up, then prints "<fact>|PASS|<detail>" or "<fact>|FAIL|<detail>" for chromium (the
# browser is running as a descendant of the unit's main process) and ready (the readiness file says the shell
# rendered and the backend is connected). Which browser it is, and where the readiness file lives, come from the
# kiosk's own settings loader fed with the unit's environment; the file's schema (version, state) from
# kiosk/readiness.py, which writes it. The file holds no secret.
PY_KIOSK_PROBE=$(cat <<'PY'
import json
import os
import time

FACTS = ("chromium", "ready")
app_dir, environment, proc_dir, main_pid, connected_label = sys.argv[1:6]
wait = float(sys.argv[6])
MAX_SHOWN = 60


def report(fact, ok, detail):
    print(f"{fact}|{'PASS' if ok else 'FAIL'}|{' '.join(str(detail).split())}", flush=True)


def report_all(ok, detail):
    for fact in FACTS:
        report(fact, ok, detail)


def shown(value):
    """`value` as one short line: the readiness file is written by another account, so it is cut and flattened."""
    return " ".join(str(value).split())[:MAX_SHOWN]


settings, problem = load_unit_settings("kiosk", "kiosk.config", app_dir, environment)
if problem:
    report_all(False, problem)
    sys.exit(0)
try:
    from kiosk.readiness import READY_FILE_VERSION, STATE_READY
except ImportError as error:
    report_all(False, f"cannot read the kiosk's readiness contract from {app_dir}: {type(error).__name__}: {error}")
    sys.exit(0)

browser = os.path.basename(settings.chromium)[:15]  # a process name (comm) is cut at 15 characters
ready_file = str(settings.ready_file)


def processes():
    """{pid: (parent pid, name)} of every process in the proc directory, read from its stat file."""
    found = {}
    for entry in os.listdir(proc_dir):
        if not entry.isdigit():
            continue
        try:
            with open(f"{proc_dir}/{entry}/stat", encoding="utf-8", errors="replace") as handle:
                stat = handle.read()
        except OSError:
            continue  # the process ended meanwhile
        name = stat[stat.find("(") + 1 : stat.rfind(")")]  # the name may hold spaces and parentheses: cut at the last one
        fields = stat[stat.rfind(")") + 1 :].split()  # state, parent pid, ...
        if len(fields) >= 2 and fields[1].isdigit():
            found[entry] = (fields[1], name)
    return found


def browsers_under(root):
    """The pids of the browser's processes among the descendants of process `root`."""
    table = processes()
    children = {}
    for pid, (parent, _) in table.items():
        children.setdefault(parent, []).append(pid)
    found, queue, seen = [], [root], {root}
    while queue:
        for pid in children.get(queue.pop(), []):
            if pid not in seen:
                seen.add(pid)
                queue.append(pid)
                if table[pid][1] == browser:
                    found.append(pid)
    return found


def readiness():
    """(ok, detail): does the readiness file say the shell rendered and the backend is connected?"""
    try:
        with open(ready_file, encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        return False, f"{ready_file} does not exist: the kiosk has not published its readiness"
    except (OSError, ValueError) as error:
        return False, f"cannot read {ready_file}: {type(error).__name__}"
    if not isinstance(document, dict):
        return False, f"{ready_file} does not hold a JSON object"
    if document.get("version") != READY_FILE_VERSION:
        return False, f"{ready_file} has version {shown(document.get('version'))}, expected {READY_FILE_VERSION}"
    if document.get("state") != STATE_READY:
        return False, f"the kiosk reports state {shown(document.get('state'))}, not {STATE_READY}"
    if document.get("shell_rendered") is not True:
        return False, "the kiosk reports that the shell did not render"
    status = document.get("status_bar")
    if not (isinstance(status, str) and (status == connected_label or status.startswith(connected_label + " "))):
        return False, f"the status bar says '{shown(status)}', not '{connected_label}'"
    return True, f"{ready_file} says {STATE_READY}: shell rendered, status bar '{shown(status)}'"


deadline = time.monotonic() + wait
while True:
    found = browsers_under(main_pid)
    ready, ready_detail = readiness()
    if (found and ready) or time.monotonic() >= deadline:
        break
    time.sleep(1)
if found:
    report("chromium", True, f"{len(found)} {browser} process(es) descend from pid {main_pid}")
else:
    report("chromium", False, f"no {browser} process descends from pid {main_pid}")
report("ready", ready, ready_detail)
PY
)

# Looks for a live credential in the argument list and environment of EVERY process, as one program. Meant to follow
# PY_UNIT_SETTINGS and PY_HTTP. argv: <proc directory> <app directory> <Environment= of the backend unit> <credential
# length> <session cookie name> <most candidates to test>. The bearer token is read from the backend's token file (inside
# this program: it is never on a command line or in an environment) and searched for in every argument list and
# environment. A browser session id is not known here, so every string of the credential's shape (urlsafe base64
# characters, exactly CREDENTIAL_LENGTH of them, bounded by other characters) is also tried against the live backend,
# as a bearer token and as the session cookie, with GET /health on the address the backend published; a 200 means a
# working credential is readable by every local account. Prints one verdict line and exits 1 on a failure. Nothing it
# prints can hold a token, a session id or a candidate: only counts, process ids and process names.
PY_SECRET_SCAN=$(cat <<'PY'
import ipaddress
import os
import re
import urllib.parse

proc_dir, app_dir, environment = sys.argv[1], sys.argv[2], sys.argv[3]
length, cookie, limit = int(sys.argv[4]), sys.argv[5], int(sys.argv[6])
MAX_SHOWN = 10
CANDIDATE = re.compile(rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{%d}(?![A-Za-z0-9_-])" % length)


def read_proc_file(path):
    """The bytes of a /proc file, or None when its process has ended meanwhile. Any other failure is raised."""
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except (FileNotFoundError, ProcessLookupError):
        return None


def label(pid):
    """'pid N (name)': the name is read from the process and cut down to harmless characters."""
    try:
        with open(f"{proc_dir}/{pid}/comm", encoding="ascii", errors="replace") as handle:
            name = re.sub(r"[^A-Za-z0-9_.+:@-]", "?", handle.read().strip())[:32]
    except OSError:
        name = "?"
    return f"pid {pid} ({name})"


def loopback_origin(path):
    """host:port (an IPv6 host in brackets) of the loopback http origin the file holds; ValueError otherwise."""
    with open(path, encoding="ascii") as handle:
        parts = urllib.parse.urlsplit(handle.read().strip())
    host, port = parts.hostname, parts.port
    if parts.scheme != "http" or host is None or port is None or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("not a plain http origin")
    address = ipaddress.ip_address(host)  # a host name is refused here
    if not address.is_loopback:
        raise ValueError("not a loopback address")
    return f"[{host}]:{port}" if address.version == 6 else f"{host}:{port}"


def scan():
    """(ok, detail)"""
    settings, problem = load_unit_settings("backend", "backend.core.config", app_dir, environment)
    if problem:
        return False, problem
    try:
        with open(settings.token_file, "rb") as handle:
            token = handle.read().strip()
    except OSError as error:
        return False, f"cannot read the token file {settings.token_file}: {type(error).__name__}"
    if not token:
        return False, f"the token file {settings.token_file} is empty"
    try:
        where = loopback_origin(settings.endpoint_file)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        return False, f"{settings.endpoint_file} does not hold the loopback http origin of the backend: {type(error).__name__}"

    examined, unreadable, hits, candidates = 0, [], set(), {}
    for pid in sorted((entry for entry in os.listdir(proc_dir) if entry.isdigit()), key=int):
        try:
            argv = read_proc_file(f"{proc_dir}/{pid}/cmdline")
            environ = read_proc_file(f"{proc_dir}/{pid}/environ")
        except OSError:
            unreadable.append(pid)
            continue
        if argv is None or environ is None:
            continue
        examined += 1
        for place, blob in (("argument list", argv), ("environment", environ)):
            if token in blob:
                hits.add(("the bearer token", place, pid))
            for found in CANDIDATE.findall(blob):
                candidates.setdefault(found, set()).add((place, pid))

    problems, unanswered = [], 0
    if len(candidates) > limit:
        problems.append(f"{len(candidates)} credential-shaped strings are more than the {limit} this check tests")
    else:
        for candidate in sorted(candidates):
            text = candidate.decode("ascii")
            for what, headers in (
                ("a value the backend accepts as a bearer token", {"Authorization": f"Bearer {text}"}),
                ("a value the backend accepts as a session cookie", {"Cookie": f"{cookie}={text}"}),
            ):
                status, _ = get(where, "/health", headers)
                if status is None:
                    unanswered += 1
                elif status == 200:
                    hits.update((what, place, pid) for place, pid in candidates[candidate])
    if hits:
        ordered = sorted(hits, key=lambda hit: (int(hit[2]), hit[0], hit[1]))
        found = [f"{what} in the {place} of {label(pid)}" for what, place, pid in ordered[:MAX_SHOWN]]
        more = f"; and {len(ordered) - MAX_SHOWN} more" if len(ordered) > MAX_SHOWN else ""
        problems.append("a live credential is visible in process state: " + "; ".join(found) + more)
    if unreadable:
        names = ", ".join(label(pid) for pid in unreadable[:MAX_SHOWN])
        problems.append(f"cannot read the argument list or environment of {len(unreadable)} process(es): {names}")
    if unanswered:
        problems.append(f"the backend gave no answer to {unanswered} request(s) that test credential-shaped strings")
    if not examined:
        problems.append("no process could be examined")
    if problems:
        return False, "; ".join(problems)
    return True, (
        f"examined the argument list and environment of {examined} processes: {len(candidates)} credential-shaped "
        "strings, none accepted by the backend as a bearer token or a session cookie, and the bearer token is in none of them"
    )


try:
    ok, detail = scan()
except Exception as error:  # noqa: BLE001 - only the type is shown: a message could quote what was being read
    ok, detail = False, f"the scan crashed: {type(error).__name__}"
print(detail)
sys.exit(0 if ok else 1)
PY
)

# ---- Output -------------------------------------------------------------------------------------------------------

# emit <name> <PASS|FAIL> <detail>: one machine-parseable line; the detail is flattened so it cannot break the format.
emit() {
    local detail=${3//[^[:print:]]/ }
    detail=${detail//|//}
    if [ "${#detail}" -gt "$DETAIL_LIMIT" ]; then
        detail="${detail:0:DETAIL_LIMIT}..."
    fi
    printf 'PAI-SELFCHECK|%s|%s|%s\n' "$1" "$2" "$detail"
}

# join_details <detail>...: prints the details separated by "; " (the failure list of a check).
join_details() {
    local joined=$1 detail
    shift
    for detail in "$@"; do
        joined+="; $detail"
    done
    echo "$joined"
}

# ---- Checks -------------------------------------------------------------------------------------------------------

check_live_root() {
    if [ -n "$ROOT" ]; then
        echo "PAI_SELFCHECK_ROOT is set ($ROOT): results describe a simulated tree, not this system"
        return 1
    fi
    echo "examining the live /proc, /etc and tools"
}

check_nft_default_drop() {
    local ruleset
    if ! ruleset=$(nft -j list ruleset 2>&1); then
        echo "nft -j list ruleset failed: $ruleset"
        return 1
    fi
    python3 -c "$PY_NFT_POLICY" "$NFT_CONF" "${REQUIRED_DROP_HOOKS[@]}" <<<"$ruleset" 2>&1
}

# load_config_lines <dir>: fills CONFIG_LINES with every line of <dir>/*.conf, files in sorted order. Prints the
# reason and returns 1 when a file cannot be read, so an unreadable file is never silently skipped.
load_config_lines() {
    local file
    CONFIG_LINES=()
    for file in "$1"/*.conf; do
        [ -e "$file" ] || continue # the glob matched nothing
        if ! mapfile -t -O "${#CONFIG_LINES[@]}" CONFIG_LINES 2>/dev/null <"$file"; then
            echo "cannot read $file"
            return 1
        fi
    done
}

module_is_loaded() {
    local name
    while read -r name _; do
        if [ "$name" = "$1" ]; then
            return 0
        fi
    done <"$PROC_DIR/modules"
    return 1
}

# verify_module_blocked <module>: prints why and returns 1 unless the module is really blocked. Only a dry run is
# ever executed (`modprobe -n -v`, which prints the command modprobe would run), so this check cannot load a module
# whatever the configuration says. When the dry run shows the blocking install command, a real run would only
# execute /bin/false or /bin/true: its outcome is fixed by that command and tells nothing more.
verify_module_blocked() {
    local module=$1 dry_run
    if module_is_loaded "${module//-/_}"; then
        echo "$module is loaded"
        return 1
    fi
    if ! dry_run=$(modprobe -n -v -- "$module" 2>&1); then
        echo "$module: modprobe dry run failed: $dry_run"
        return 1
    fi
    if ! [[ $dry_run =~ $DRY_RUN_BLOCKED ]]; then
        echo "$module: modprobe would not run a blocking install command: $dry_run"
        return 1
    fi
}

check_modules_blocked() {
    local line keyword module install_cmd reason
    local -A blocked=()
    local -a modules=() failures=()
    if ! [ -r "$PROC_DIR/modules" ]; then
        echo "cannot read $PROC_DIR/modules"
        return 1
    fi
    load_config_lines "$MODPROBE_DIR" || return 1
    for line in "${CONFIG_LINES[@]}"; do
        read -r keyword module install_cmd _ <<<"${line%%#*}" || true
        if [ "$keyword" = install ] && [[ $install_cmd =~ $BLOCKING_INSTALL ]]; then
            blocked[$module]=1
        fi
    done
    if [ "${#blocked[@]}" -eq 0 ]; then
        echo "no blocking install line found under $MODPROBE_DIR, so there is nothing to verify"
        return 1
    fi
    mapfile -t modules < <(printf '%s\n' "${!blocked[@]}" | sort)
    for module in "${modules[@]}"; do
        if ! reason=$(verify_module_blocked "$module"); then
            failures+=("$reason")
        fi
    done
    if [ "${#failures[@]}" -gt 0 ]; then
        join_details "${failures[@]}"
        return 1
    fi
    echo "blocked and not loaded: ${modules[*]}"
}

check_sysctl_live() {
    local line key live path optional
    local -A expected=() is_optional=()
    local -a keys=() failures=() words=()
    load_config_lines "$SYSCTL_DIR" || return 1
    for line in "${CONFIG_LINES[@]}"; do
        line=${line%%#*}
        [[ $line == *=* ]] || continue
        read -r key <<<"${line%%=*}" || true
        read -r -a words <<<"${line#*=}" || true
        if [ -z "$key" ] || [[ $key == \;* ]]; then
            continue
        fi
        optional=0
        if [[ $key == -* ]]; then # a leading "-" means a setting the kernel lacks is not an error
            optional=1
            key=${key#-}
        fi
        [ -n "${expected[$key]+set}" ] || keys+=("$key")
        expected[$key]="${words[*]:-}" # later lines override earlier ones, as systemd-sysctl does
        is_optional[$key]=$optional
    done
    if [ "${#keys[@]}" -eq 0 ]; then
        echo "no sysctl setting found under $SYSCTL_DIR, so there is nothing to verify"
        return 1
    fi
    for key in "${keys[@]}"; do
        if [[ $key == *[\*\?\[]* ]]; then
            failures+=("$key: wildcard keys are not supported by this check")
            continue
        fi
        if [[ $key == */* ]]; then path="$PROC_DIR/sys/$key"; else path="$PROC_DIR/sys/${key//./\/}"; fi
        if ! { live=$(<"$path"); } 2>/dev/null; then
            if [ "${is_optional[$key]}" -eq 0 ]; then
                failures+=("$key: not readable at /proc/sys")
            fi
            continue
        fi
        read -r -a words <<<"$live" || true
        live="${words[*]:-}" # /proc/sys separates multi-value settings with tabs; sysctl.d uses spaces
        if [ "$live" != "${expected[$key]}" ]; then
            failures+=("$key: configured '${expected[$key]}', live '$live'")
        fi
    done
    if [ "${#failures[@]}" -gt 0 ]; then
        join_details "${failures[@]}"
        return 1
    fi
    echo "${#keys[@]} settings match the live kernel"
}

check_no_external_listeners() {
    local entry table port allowed=()
    for entry in "${LISTEN_ALLOW[@]}"; do
        read -r table port _ <<<"$entry"
        allowed+=("$table:$port")
    done
    python3 -c "$PY_NET"$'\n'"$PY_LISTENERS" "$PROC_DIR/net" "${allowed[@]}" 2>&1
}

check_units_active() {
    local unit state
    local -a inactive=()
    for unit in "${REQUIRED_ACTIVE_UNITS[@]}"; do
        state=$(systemctl is-active -- "$unit" 2>/dev/null) || true
        if [ "$state" != active ]; then
            inactive+=("$unit is ${state:-unknown}")
        fi
    done
    if [ "${#inactive[@]}" -gt 0 ]; then
        join_details "${inactive[@]}"
        return 1
    fi
    echo "active: ${REQUIRED_ACTIVE_UNITS[*]}"
}

# ---- The services the self-check waits for -------------------------------------------------------------------------

# What the checks of a service share, gathered once before any check runs (a check runs in a subshell and cannot hand
# anything on). Filled by wait_for_unit and the probe of that service; <PREFIX> is BACKEND or KIOSK. They are read and
# written through namerefs (local -n) in wait_for_unit, unit_problem and probe_fact, which ShellCheck cannot follow, so
# it reports them (SC2034) here and in the functions that fill them.
# shellcheck disable=SC2034
BACKEND_LOAD_STATE="" BACKEND_STATE="" BACKEND_USER="" BACKEND_MAIN_PID="" BACKEND_ENVIRONMENT="" BACKEND_ENVIRONMENT_FILES=""
# shellcheck disable=SC2034
KIOSK_LOAD_STATE="" KIOSK_STATE="" KIOSK_USER="" KIOSK_MAIN_PID="" KIOSK_ENVIRONMENT="" KIOSK_ENVIRONMENT_FILES=""
BACKEND_NOTE="" # why the backend cannot be examined, when it cannot
KIOSK_NOTE=""   # the same for the kiosk
declare -A BACKEND_FACT=() # fact -> "PASS|<detail>" or "FAIL|<detail>", reported by PY_BACKEND_PROBE
declare -A KIOSK_FACT=()   # the same, reported by PY_KIOSK_PROBE
BACKEND_PROBE_ERROR=""
KIOSK_PROBE_ERROR=""

# whole_seconds <value>: succeeds when the value is a plain number of seconds. Validated before it is used in
# arithmetic: bash evaluates a word there as an expression (a name is read as a variable, and under set -u an unset
# one aborts the script), and a leading zero would read as octal.
whole_seconds() { [[ $1 =~ ^[0-9]+$ ]]; }

# seconds_left <deadline>: whole seconds until the deadline (a value of SECONDS), never negative.
seconds_left() {
    local left=$(($1 - SECONDS))
    echo "$((left > 0 ? left : 0))"
}

# wait_for_unit <unit> <deadline> <PREFIX>: polls `systemctl show` until the unit is active, failed or not installed,
# or SECONDS reaches the deadline, and leaves what systemd last reported in <PREFIX>_LOAD_STATE, _STATE, _USER,
# _MAIN_PID, _ENVIRONMENT and _ENVIRONMENT_FILES.
# shellcheck disable=SC2034 # assigns through namerefs
wait_for_unit() {
    local unit=$1 deadline=$2 shown line key value
    local -n load_state=${3}_LOAD_STATE state=${3}_STATE unit_user=${3}_USER main_pid=${3}_MAIN_PID
    local -n environment=${3}_ENVIRONMENT environment_files=${3}_ENVIRONMENT_FILES
    while :; do
        shown=$(systemctl show --property=LoadState --property=ActiveState --property=User --property=MainPID \
            --property=Environment --property=EnvironmentFiles -- "$unit" 2>&1) || true
        while IFS= read -r line; do
            key=${line%%=*}
            value=${line#*=}
            case $key in
                LoadState) load_state=$value ;;
                ActiveState) state=$value ;;
                User) unit_user=$value ;;
                MainPID) main_pid=$value ;;
                Environment) environment=$value ;;
                EnvironmentFiles) environment_files=$value ;;
            esac
        done <<<"$shown"
        # failed: systemd has given up restarting it. not-found: the image does not have the unit at all.
        if [ "$state" = active ] || [ "$state" = failed ] || [ "$load_state" = not-found ]; then
            break
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            break
        fi
        sleep 1
    done
}

# unit_problem <PREFIX> <unit>: after wait_for_unit, prints why the unit cannot be examined (nothing when it can).
unit_problem() {
    local -n load_state=${1}_LOAD_STATE state=${1}_STATE environment_files=${1}_ENVIRONMENT_FILES
    if [ "$load_state" = not-found ]; then
        echo "$2 is not installed"
    elif [ "$state" != active ]; then
        echo "$2 is ${state:-unknown}"
    elif [ -n "$environment_files" ]; then
        # The environment of the running process is not readable from here: a variable that file sets would be missed.
        echo "$2 loads EnvironmentFile= ($environment_files), which this self-check does not read"
    fi
}

# probe_fact <facts array> <error variable> <what asked> <fact>: prints what the probe reported for the fact; fails
# when it reported FAIL or nothing.
probe_fact() {
    local -n facts=$1 probe_error=$2
    local reported=${facts[$4]:-}
    if [ -z "$reported" ]; then
        echo "$3 did not report '$4'${probe_error:+ ($probe_error)}"
        return 1
    fi
    echo "${reported#*|}"
    [ "${reported%%|*}" = PASS ]
}

# Processes. The checks of a unit's main process share this reading of /proc/<pid>/status.
PROCESS_UID="" PROCESS_CAPS="" PROCESS_NO_NEW_PRIVS=""
declare -a PROCESS_PROBLEMS=()

# unit_now <unit> <pid>: what systemd says now about <pid>, the main process the self-check saw earlier: still the
# unit's, or replaced because the unit restarted (or died) in between.
unit_now() {
    local shown line state="" current=""
    shown=$(timeout "$DIAGNOSTIC_TIMEOUT" systemctl show --property=ActiveState --property=MainPID -- "$1" 2>&1) || true
    while IFS= read -r line; do
        case ${line%%=*} in
            ActiveState) state=${line#*=} ;;
            MainPID) current=${line#*=} ;;
        esac
    done <<<"$shown"
    if [ "$current" = "$2" ]; then
        echo "systemd still names that pid (ActiveState=${state:-unknown})"
    elif [ -n "$current" ]; then
        echo "systemd now reports MainPID=$current (ActiveState=${state:-unknown}): the unit restarted or died after the wait began"
    else
        echo "systemd gave no answer about the unit now"
    fi
}

# unit_diagnostics <unit>: one line of what systemd reports for the unit (DIAGNOSTIC_PROPERTIES) and the last
# DIAGNOSTIC_JOURNAL_LINES lines of its journal, joined by " / ", credential-shaped strings masked. Never fails: a call
# that does not work says so in the text instead.
unit_diagnostics() {
    local shown journal property text line mask first
    local -a args=() lines=() kept=()
    mask="[A-Za-z0-9_-]{$CREDENTIAL_LENGTH,}"
    for property in "${DIAGNOSTIC_PROPERTIES[@]}"; do
        args+=("--property=$property")
    done
    if shown=$(timeout "$DIAGNOSTIC_TIMEOUT" systemctl show "${args[@]}" -- "$1" 2>&1); then
        text="systemd reports for $1: ${shown//$'\n'/ }"
    else
        text="systemctl show of $1 failed: ${shown##*$'\n'}"
    fi
    if ! journal=$(timeout "$DIAGNOSTIC_TIMEOUT" journalctl -u "$1" -n "$DIAGNOSTIC_JOURNAL_LINES" --no-pager -o cat 2>&1); then
        journal="journalctl failed: ${journal##*$'\n'}"
    fi
    mapfile -t lines <<<"$journal"
    # The last lines only. A negative offset longer than the array would give nothing at all, so the start is computed.
    first=$((${#lines[@]} > DIAGNOSTIC_JOURNAL_LINES ? ${#lines[@]} - DIAGNOSTIC_JOURNAL_LINES : 0))
    for line in "${lines[@]:first}"; do
        if [ -n "$line" ]; then
            kept+=("${line:0:DIAGNOSTIC_LINE_LIMIT}")
        fi
    done
    if [ "${#kept[@]}" -eq 0 ]; then
        text+="; the journal of $1 has no line"
    else
        printf -v journal '%s / ' "${kept[@]}"
        text+="; journal of $1 (last ${#kept[@]} lines): ${journal% / }"
    fi
    if ! text=$(printf '%s' "$text" | sed -E "s/$mask/[masked]/g"); then
        text="diagnostics withheld: the credential mask could not be applied"
    fi
    echo "$text"
}

# with_diagnostics <unit> <function>: runs the function; when it fails, its detail gets the unit's diagnostics added.
with_diagnostics() {
    local detail
    if detail=$("$2" 2>&1); then
        echo "$detail"
        return 0
    fi
    echo "$detail; $(unit_diagnostics "$1")"
    return 1
}

# read_unit_process <unit> <user> <pid>: examines the unit's main process. Prints why and returns 1 when it cannot be
# examined (no User=, no main process, no such account, an account that is uid 0, no /proc entry). Otherwise leaves
# the uid of the account in PROCESS_UID, the effective capability mask and NoNewPrivs of the process in PROCESS_CAPS and
# PROCESS_NO_NEW_PRIVS, and in PROCESS_PROBLEMS what is wrong with its real, effective, saved and filesystem uid (they
# must all be the account's). Needs the process's own /proc entry, which pai-selfcheck.service therefore does not
# hide (ProtectProc waiver).
read_unit_process() {
    local unit=$1 account=$2 pid=$3 status key rest id real="" effective="" saved="" filesystem=""
    PROCESS_UID="" PROCESS_CAPS="" PROCESS_NO_NEW_PRIVS="" PROCESS_PROBLEMS=()
    if [ -z "$account" ]; then
        echo "$unit sets no User=, so it would run as root"
        return 1
    fi
    if ! [[ $pid =~ ^[1-9][0-9]*$ ]]; then
        echo "$unit has no main process (MainPID=${pid:-unset})"
        return 1
    fi
    if ! PROCESS_UID=$(id -u -- "$account" 2>&1) || ! [[ $PROCESS_UID =~ ^[0-9]+$ ]]; then
        echo "the account $account that $unit runs as does not exist: $PROCESS_UID"
        return 1
    fi
    if [ "$PROCESS_UID" -eq 0 ]; then
        echo "the account $account that $unit runs as is uid 0"
        return 1
    fi
    status="$PROC_DIR/$pid/status"
    if ! [ -r "$status" ]; then
        echo "the main process of $unit, pid $pid, is gone (cannot read $status): $(unit_now "$unit" "$pid")"
        return 1
    fi
    while read -r key rest; do
        case $key in
            Uid:) read -r real effective saved filesystem <<<"$rest" || true ;;
            CapEff:) PROCESS_CAPS=$rest ;;
            NoNewPrivs:) PROCESS_NO_NEW_PRIVS=$rest ;;
        esac
    done <"$status"
    for id in "$real" "$effective" "$saved" "$filesystem"; do
        if [ "$id" != "$PROCESS_UID" ]; then
            PROCESS_PROBLEMS+=("uids real/effective/saved/filesystem are ${real:-?}/${effective:-?}/${saved:-?}/${filesystem:-?}, not $PROCESS_UID ($account)")
            break
        fi
    done
}

# ---- The backend --------------------------------------------------------------------------------------------------

# probe_backend: waits (at most BACKEND_READY_TIMEOUT seconds) for the unit to become active, then has one python3
# process ask the running service the questions behind the backend-* checks. A failing probe is recorded and
# reported by each check that needs its answer; it never stops the self-check.
# shellcheck disable=SC2034 # fills BACKEND_FACT and BACKEND_PROBE_ERROR, which probe_fact reads through namerefs
probe_backend() {
    local deadline line fact output=""
    if ! whole_seconds "$BACKEND_READY_TIMEOUT"; then
        BACKEND_NOTE="PAI_SELFCHECK_READY_TIMEOUT is not a whole number of seconds"
        return 0
    fi
    deadline=$((SECONDS + 10#$BACKEND_READY_TIMEOUT))
    wait_for_unit "$BACKEND_UNIT" "$deadline" BACKEND
    BACKEND_NOTE=$(unit_problem BACKEND "$BACKEND_UNIT")
    if [ -n "$BACKEND_NOTE" ]; then
        return 0
    fi
    if ! output=$(python3 -s -B -c "$PY_NET"$'\n'"$PY_UNIT_SETTINGS"$'\n'"$PY_HTTP"$'\n'"$PY_BACKEND_PROBE" \
        "$APP_DIR" "$BACKEND_ENVIRONMENT" "$PROC_DIR/net" "$(seconds_left "$deadline")" 2>&1); then
        BACKEND_PROBE_ERROR="the probe crashed: ${output##*$'\n'}"
    fi
    while IFS= read -r line; do
        fact=${line%%|*}
        case $fact in
            ready | loopback | anonymous | health) BACKEND_FACT[$fact]=${line#*|} ;;
        esac
    done <<<"$output"
}

backend_fact() { probe_fact BACKEND_FACT BACKEND_PROBE_ERROR "the backend probe" "$1"; }

check_backend_active() {
    if [ -n "$BACKEND_NOTE" ]; then
        echo "$BACKEND_NOTE"
        return 1
    fi
    backend_fact ready
}

# The main process runs as the account the unit names (never root), holds no capability, and cannot gain privileges.
check_backend_unprivileged() {
    if [ -n "$BACKEND_NOTE" ]; then
        echo "$BACKEND_NOTE"
        return 1
    fi
    read_unit_process "$BACKEND_UNIT" "$BACKEND_USER" "$BACKEND_MAIN_PID" || return 1
    [[ $PROCESS_CAPS =~ ^0+$ ]] || PROCESS_PROBLEMS+=("effective capabilities are ${PROCESS_CAPS:-unknown}, not none")
    [ "$PROCESS_NO_NEW_PRIVS" = 1 ] || PROCESS_PROBLEMS+=("NoNewPrivs is ${PROCESS_NO_NEW_PRIVS:-unknown}, not 1")
    if [ "${#PROCESS_PROBLEMS[@]}" -gt 0 ]; then
        join_details "pid $BACKEND_MAIN_PID of $BACKEND_UNIT: ${PROCESS_PROBLEMS[0]}" "${PROCESS_PROBLEMS[@]:1}"
        return 1
    fi
    echo "pid $BACKEND_MAIN_PID runs as $BACKEND_USER (uid $PROCESS_UID) with no capabilities and no_new_privs"
}

check_backend_loopback_only() { backend_fact loopback; }
check_backend_refuses_anonymous() { backend_fact anonymous; }
check_backend_health() { backend_fact health; }

# The exposure score of the unit as the running systemd sees it, parsed from the last line of the report.
check_backend_sandbox_exposure() {
    local report tenths limit="$((BACKEND_MAX_EXPOSURE_TENTHS / 10)).$((BACKEND_MAX_EXPOSURE_TENTHS % 10))"
    if ! report=$(systemd-analyze security --no-pager -- "$BACKEND_UNIT" 2>&1); then
        echo "systemd-analyze security failed: ${report##*$'\n'}"
        return 1
    fi
    if ! [[ $report =~ Overall\ exposure\ level\ for\ [^:]+:\ ([0-9]+)\.([0-9]) ]]; then
        echo "no exposure level in the systemd-analyze report: ${report##*$'\n'}"
        return 1
    fi
    tenths=$((10#${BASH_REMATCH[1]} * 10 + 10#${BASH_REMATCH[2]}))
    if [ "$tenths" -gt "$BACKEND_MAX_EXPOSURE_TENTHS" ]; then
        echo "$BACKEND_UNIT exposure is ${BASH_REMATCH[1]}.${BASH_REMATCH[2]}, above the limit $limit"
        return 1
    fi
    echo "$BACKEND_UNIT exposure is ${BASH_REMATCH[1]}.${BASH_REMATCH[2]}, within the limit $limit"
}

# ---- The kiosk ----------------------------------------------------------------------------------------------------

# unit_main_pid <unit>: the unit's MainPID as systemd reports it now (nothing when it cannot be read).
unit_main_pid() {
    local shown line
    shown=$(timeout "$DIAGNOSTIC_TIMEOUT" systemctl show --property=MainPID -- "$1" 2>&1) || true
    while IFS= read -r line; do
        if [ "${line%%=*}" = MainPID ]; then
            echo "${line#*=}"
        fi
    done <<<"$shown"
}

# kiosk_look <seconds to wait>: has one python3 process look for the kiosk's browser below KIOSK_MAIN_PID and for its
# readiness file, waiting at most that long, and records the facts it reports.
# shellcheck disable=SC2034 # fills KIOSK_FACT and KIOSK_PROBE_ERROR, which probe_fact reads through namerefs
kiosk_look() {
    local line fact output=""
    KIOSK_PROBE_ERROR=""
    if ! output=$(python3 -s -B -c "$PY_UNIT_SETTINGS"$'\n'"$PY_KIOSK_PROBE" "$APP_DIR" "$KIOSK_ENVIRONMENT" \
        "$PROC_DIR" "$KIOSK_MAIN_PID" "$KIOSK_BACKEND_CONNECTED_LABEL" "$1" 2>&1); then
        KIOSK_PROBE_ERROR="the probe crashed: ${output##*$'\n'}"
    fi
    KIOSK_FACT=()
    while IFS= read -r line; do
        fact=${line%%|*}
        case $fact in
            chromium | ready) KIOSK_FACT[$fact]=${line#*|} ;;
        esac
    done <<<"$output"
}

# probe_kiosk: waits (at most KIOSK_READY_TIMEOUT seconds, one budget for everything below) for the unit to become
# active, then has one python3 process wait for the rest: a Chromium process among the descendants of the unit's main
# process, and the readiness file saying the shell rendered and the backend is connected. A kiosk that systemd restarted
# while that went on has a new main process, whose browser is not below the old pid: when the unit names another one
# afterwards it is looked at once more (without waiting), and the checks judge that process. Like probe_backend, a
# failing probe is recorded and reported by the checks that need its answer.
probe_kiosk() {
    local deadline now
    if ! whole_seconds "$KIOSK_READY_TIMEOUT"; then
        KIOSK_NOTE="PAI_SELFCHECK_KIOSK_TIMEOUT is not a whole number of seconds"
        return 0
    fi
    deadline=$((SECONDS + 10#$KIOSK_READY_TIMEOUT))
    wait_for_unit "$KIOSK_UNIT" "$deadline" KIOSK
    KIOSK_NOTE=$(unit_problem KIOSK "$KIOSK_UNIT")
    if [ -n "$KIOSK_NOTE" ]; then
        return 0
    fi
    if ! [[ $KIOSK_MAIN_PID =~ ^[1-9][0-9]*$ ]]; then
        return 0 # no process to look under; check_kiosk_active says so, and the facts below stay unreported
    fi
    kiosk_look "$(seconds_left "$deadline")"
    now=$(unit_main_pid "$KIOSK_UNIT")
    if [[ $now =~ ^[1-9][0-9]*$ ]] && [ "$now" != "$KIOSK_MAIN_PID" ]; then
        KIOSK_MAIN_PID=$now
        kiosk_look 0
    fi
}

kiosk_fact() { probe_fact KIOSK_FACT KIOSK_PROBE_ERROR "the kiosk probe" "$1"; }

# The unit is active, its main process runs as the account the unit names (never root), and Chromium is running
# below it.
kiosk_active() {
    local browser
    if [ -n "$KIOSK_NOTE" ]; then
        echo "$KIOSK_NOTE"
        return 1
    fi
    read_unit_process "$KIOSK_UNIT" "$KIOSK_USER" "$KIOSK_MAIN_PID" || return 1
    if [ "${#PROCESS_PROBLEMS[@]}" -gt 0 ]; then
        join_details "pid $KIOSK_MAIN_PID of $KIOSK_UNIT: ${PROCESS_PROBLEMS[0]}" "${PROCESS_PROBLEMS[@]:1}"
        return 1
    fi
    if ! browser=$(kiosk_fact chromium); then
        echo "pid $KIOSK_MAIN_PID of $KIOSK_UNIT runs as $KIOSK_USER (uid $PROCESS_UID), but $browser"
        return 1
    fi
    echo "pid $KIOSK_MAIN_PID of $KIOSK_UNIT runs as $KIOSK_USER (uid $PROCESS_UID); $browser"
}

kiosk_ready() {
    if [ -n "$KIOSK_NOTE" ]; then
        echo "$KIOSK_NOTE"
        return 1
    fi
    kiosk_fact ready
}

# A failing kiosk check says why the unit is in that state, not only that it is.
check_kiosk_active() { with_diagnostics "$KIOSK_UNIT" kiosk_active; }
check_kiosk_ready() { with_diagnostics "$KIOSK_UNIT" kiosk_ready; }

# ---- Secrets and credentials --------------------------------------------------------------------------------------

# Neither the bearer token nor any browser session id may be readable in a process's argument list or environment,
# which every local account can read (/proc/<pid>/cmdline) or, for the environment, anyone with the process's uid.
# Needs CAP_SYS_PTRACE to read other accounts' /proc/<pid>/environ (the unit has it for this check only). The program
# reads the token file itself: the token is never passed to it, or to anything else, on a command line or in an
# environment. It tests candidates against the backend, so it cannot say anything when the backend was not examined.
check_no_secret_in_process_state() {
    if [ -n "$BACKEND_NOTE" ]; then
        echo "credentials cannot be tested without the backend: $BACKEND_NOTE"
        return 1
    fi
    python3 -s -B -c "$PY_UNIT_SETTINGS"$'\n'"$PY_HTTP"$'\n'"$PY_SECRET_SCAN" "$PROC_DIR" "$APP_DIR" \
        "$BACKEND_ENVIRONMENT" "$CREDENTIAL_LENGTH" "$SESSION_COOKIE" "$MAX_CREDENTIAL_CANDIDATES" 2>&1
}

# No account may be able to log in with a password that ships in the image: every account in /etc/shadow has a lock
# marker (! or *, which no password hashes to) in the password field, and the file is not readable by everyone. An
# empty field is a login with no password at all, so it fails like a hash does. Names are printed, never hashes. Needs
# CAP_DAC_READ_SEARCH to read the file (the unit has it for this check only); the mode alone needs nothing.
check_no_default_credentials() {
    local mode line name hash accounts=0 malformed=0
    local -a lines=() hashed=() empty=() problems=()
    if ! mode=$(stat -c %a -- "$SHADOW_FILE" 2>&1); then
        echo "cannot examine $SHADOW_FILE: $mode"
        return 1
    fi
    if ! [[ $mode =~ ^[0-7]{1,4}$ ]]; then
        echo "cannot read the mode of $SHADOW_FILE from: $mode"
        return 1
    fi
    if [ $((8#$mode & 7)) -ne 0 ]; then
        problems+=("$SHADOW_FILE has mode $mode, which gives every account access to the password hashes")
    fi
    if ! mapfile -t lines 2>/dev/null <"$SHADOW_FILE"; then
        problems+=("cannot read $SHADOW_FILE")
    fi
    for line in "${lines[@]}"; do
        [ -n "$line" ] || continue
        accounts=$((accounts + 1))
        if ! [[ $line == [!:]*:* ]]; then
            malformed=$((malformed + 1))
            continue
        fi
        name=${line%%:*}
        hash=${line#*:}
        hash=${hash%%:*}
        case $hash in
            '!'* | '*'*) ;; # locked or disabled: no password matches
            '') empty+=("$name") ;;
            *) hashed+=("$name") ;;
        esac
    done
    if [ "$accounts" -eq 0 ] && [ "${#problems[@]}" -eq 0 ]; then
        problems+=("$SHADOW_FILE holds no account, so there is nothing to verify")
    fi
    if [ "${#hashed[@]}" -gt 0 ]; then
        problems+=("account(s) with a usable password hash: ${hashed[*]}")
    fi
    if [ "${#empty[@]}" -gt 0 ]; then
        problems+=("account(s) with an empty password, which needs none to log in: ${empty[*]}")
    fi
    if [ "$malformed" -gt 0 ]; then
        problems+=("$malformed line(s) in $SHADOW_FILE without an account name and a password field")
    fi
    if [ "${#problems[@]}" -gt 0 ]; then
        join_details "${problems[@]}"
        return 1
    fi
    echo "$accounts accounts in $SHADOW_FILE, every password field locked or disabled; mode $mode"
}

# ---- Installed-system checks ---------------------------------------------------------------------------------------

# is_live_session: succeeds when the running system is a live session (see LIVE_CMDLINE_WORD). Both signals come from the
# kernel's own account of the boot. A system whose command line cannot be read is treated as installed: that adds
# checks, which can only make a run stricter.
is_live_session() {
    local -a words=() fields=()
    local word mount_point
    if [ -r "$CMDLINE_FILE" ]; then
        read -r -a words <"$CMDLINE_FILE" || true
        for word in "${words[@]}"; do
            [ "$word" = "$LIVE_CMDLINE_WORD" ] && return 0
        done
    fi
    if [ -r "$MOUNTINFO_FILE" ]; then
        # mountinfo: id parent major:minor root mount-point options ... ; the mount point is the fifth field.
        while read -r -a fields; do
            mount_point=${fields[4]:-}
            [ "$mount_point" = "$LIVE_MEDIUM_MOUNT" ] && return 0
        done <"$MOUNTINFO_FILE"
    fi
    return 1
}

# The root filesystem of an installed system is on a LUKS2 volume with argon2id keyslots. The facts come from
# pai-selfcheck-crypt.service (see CRYPT_FACTS_FILE); this check only judges them. A missing file, a fact that could not
# be observed (error=) or a missing fact fails: nothing is assumed. Nothing secret is in the facts or in the detail:
# device names, the mapping's name, counts and the names of key-derivation functions.
check_root_encrypted() {
    local line key value kdf
    local -A fact=()
    local -a kdfs=() problems=()
    if [ ! -r "$CRYPT_FACTS_FILE" ]; then
        echo "no facts about the root device at $CRYPT_FACTS_FILE: pai-selfcheck-crypt.service did not run or failed"
        return 1
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        key=${line%%=*}
        value=${line#*=}
        if [[ $line == *=* && $key =~ ^[a-z_]+$ ]]; then
            fact[$key]=$value
        fi
    done <"$CRYPT_FACTS_FILE"
    if [ -n "${fact[error]:-}" ]; then
        echo "the root device could not be examined: ${fact[error]}"
        return 1
    fi
    if [ -z "${fact[root_dm]:-}" ]; then
        echo "the facts do not say what the root filesystem is on"
        return 1
    fi
    if [ "${fact[root_dm]}" = none ]; then
        echo "the root filesystem (device ${fact[root_device]:-unknown}) is not on a device-mapper mapping, so it is not encrypted"
        return 1
    fi
    if [ "${fact[dm_kind]:-}" != "$REQUIRED_CRYPT_KIND" ]; then
        problems+=("mapping ${fact[root_dm]} is ${fact[dm_kind]:-of unknown kind}, not $REQUIRED_CRYPT_KIND")
    fi
    if [ "${fact[luks_version]:-}" != 2 ]; then
        problems+=("the LUKS header is not version 2 (${fact[luks_version]:-not read})")
    fi
    if ! [[ ${fact[keyslots]:-} =~ ^[1-9][0-9]*$ ]]; then
        problems+=("no keyslot was read (${fact[keyslots]:-not read})")
    fi
    if [ -n "${fact[kdfs]:-}" ]; then
        IFS=, read -r -a kdfs <<<"${fact[kdfs]}"
    fi
    for kdf in ${kdfs[@]+"${kdfs[@]}"}; do
        if [ "$kdf" != "$REQUIRED_LUKS_KDF" ]; then
            problems+=("a keyslot derives its key with $kdf, not $REQUIRED_LUKS_KDF")
        fi
    done
    if [ "${#kdfs[@]}" -eq 0 ]; then
        problems+=("no key-derivation function was read")
    fi
    if [ "${#problems[@]}" -gt 0 ]; then
        join_details "${problems[@]}"
        return 1
    fi
    echo "root is on dm-crypt mapping ${fact[root_dm]} (LUKS2, on ${fact[backing]:-an unnamed device}); ${fact[keyslots]} keyslot(s), every one $REQUIRED_LUKS_KDF"
}

# installed_live_packages: prints the name of each package dpkg lists as present (installed, unpacked or half-done; not
# removed with only its configuration left, which cannot run) that matches LIVE_PACKAGE_PATTERN.
installed_live_packages() {
    local line package="" status
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            "Package: "*) package=${line#Package: } ;;
            "Status: "*)
                status=${line##* }
                if [[ $package =~ $LIVE_PACKAGE_PATTERN && $status != config-files && $status != not-installed ]]; then
                    echo "$package"
                fi
                ;;
        esac
    done <"$DPKG_STATUS_FILE"
}

# Nothing of the live system is left on an installed system: no live-boot or live-config package, no live-config
# settings, no account live-config created, no autologin, no password-less sudo grant. (That no account has a usable
# password is the job of no-default-credentials, which runs in both modes.)
check_no_live_remnants() {
    local line file name gecos found
    local -a problems=() packages=() autologin_dirs=() sudoers=()
    if [ ! -r "$DPKG_STATUS_FILE" ]; then
        echo "cannot read $DPKG_STATUS_FILE, so the installed packages are unknown"
        return 1
    fi
    mapfile -t packages < <(installed_live_packages)
    if [ "${#packages[@]}" -gt 0 ]; then
        problems+=("live system package(s) still installed: ${packages[*]}")
    fi

    if [ -e "$LIVE_CONFIG_DIR" ]; then
        problems+=("${LIVE_CONFIG_DIR#"$ROOT"} exists (live-config's configuration)")
    fi

    if [ ! -r "$PASSWD_FILE" ]; then
        problems+=("cannot read $PASSWD_FILE, so the accounts are unknown")
    else
        while IFS=: read -r name _ _ _ gecos _; do
            if [[ $gecos =~ $LIVE_USER_GECOS_PATTERN ]]; then
                problems+=("account $name was created by live-config (full name \"${gecos%%,*}\")")
            fi
        done <"$PASSWD_FILE"
    fi

    for file in "${AUTOLOGIN_UNIT_DIRS[@]}"; do
        if [ -d "$file" ]; then
            autologin_dirs+=("$file")
        fi
    done
    if [ "${#autologin_dirs[@]}" -gt 0 ]; then
        while IFS= read -r file; do
            problems+=("autologin in ${file#"$ROOT"}")
        done < <(grep -rIlE -e "$AUTOLOGIN_PATTERN" -- "${autologin_dirs[@]}" 2>/dev/null | sort || true)
    fi

    if [ -f "$SUDOERS_FILE" ]; then
        sudoers+=("$SUDOERS_FILE")
    fi
    if [ -d "$SUDOERS_DIR" ]; then
        for file in "$SUDOERS_DIR"/*; do
            if [ -f "$file" ]; then
                sudoers+=("$file")
            fi
        done
    fi
    for file in ${sudoers[@]+"${sudoers[@]}"}; do
        found=0
        while IFS= read -r line || [ -n "$line" ]; do
            [[ $line =~ ^[[:space:]]*# ]] && continue
            if [[ $line == *NOPASSWD* ]]; then
                found=1
            fi
        done <"$file"
        if [ "$found" -eq 1 ]; then
            problems+=("${file#"$ROOT"} grants a command without a password")
        fi
    done

    if [ "${#problems[@]}" -gt 0 ]; then
        join_details "${problems[@]}"
        return 1
    fi
    echo "no live-boot or live-config package, live-config setting, live account, autologin or password-less sudo rule"
}

# "<name>:<function>", run in this order. backend-active comes first among the backend checks, and before the
# listener check, so a backend that opens a wildcard socket is already bound when no-external-listeners looks. The
# kiosk checks and the two checks of what a process or an account holds come last: they ask about the whole machine
# once the services the earlier checks examine are known to be up.
CHECKS=(
    live-root:check_live_root
    backend-active:check_backend_active
    nft-default-drop:check_nft_default_drop
    modules-blocked:check_modules_blocked
    sysctl-live:check_sysctl_live
    no-external-listeners:check_no_external_listeners
    units-active:check_units_active
    backend-unprivileged:check_backend_unprivileged
    backend-loopback-only:check_backend_loopback_only
    backend-refuses-anonymous:check_backend_refuses_anonymous
    backend-health:check_backend_health
    backend-sandbox-exposure:check_backend_sandbox_exposure
    kiosk-active:check_kiosk_active
    kiosk-ready:check_kiosk_ready
    no-secret-in-process-state:check_no_secret_in_process_state
    no-default-credentials:check_no_default_credentials
)

# Run after CHECKS, and only on a system that is not a live session (is_live_session). tests/end_to_end/
# test_selfcheck_wiring.py keeps this list equal to the harness's INSTALLED_ONLY_CHECKS.
INSTALLED_CHECKS=(
    root-encrypted:check_root_encrypted
    no-live-remnants:check_no_live_remnants
)

# ---- Run ----------------------------------------------------------------------------------------------------------

finished=0
# If the script dies before the summary (a bug here), still say so: a missing RESULT line is a boot-test failure.
trap 'if [ "$finished" -eq 0 ]; then emit RESULT FAIL "self-check aborted before completion"; fi' EXIT

probe_backend
probe_kiosk

run_list=("${CHECKS[@]}")
if ! is_live_session; then
    run_list+=("${INSTALLED_CHECKS[@]}")
fi

passed=0
total=0
for entry in "${run_list[@]}"; do
    name=${entry%%:*}
    total=$((total + 1))
    if detail=$("${entry#*:}" 2>&1); then
        status=PASS
        passed=$((passed + 1))
    else
        status=FAIL
    fi
    emit "$name" "$status" "$detail"
done

finished=1
if [ "$total" -eq 0 ]; then
    # Zero of zero is not a pass: an empty CHECKS table must never read as success.
    echo "security-selfcheck.sh: CHECKS is empty, so nothing was verified" >&2
    emit RESULT FAIL "0/0"
    exit 1
fi
if [ "$passed" -eq "$total" ]; then
    emit RESULT PASS "$passed/$total"
    exit 0
fi
emit RESULT FAIL "$passed/$total"
exit 1
