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
# nothing never reports success. Details name configuration keys, module names, socket addresses, paths and status
# codes only. The one secret the checks touch, the backend's bearer token, is read to authenticate a single request
# and is never printed.
#
# Run by pai-selfcheck.service, which only starts when the kernel command line has pai.selfcheck=1.
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
BACKEND_APP_DIR="$ROOT/opt/pai" # where os/build/assemble-config.sh installs the backend; `python3 -m backend` runs from here
NFT_CONF="$ROOT/etc/nftables.conf"
MODPROBE_DIR="$ROOT/etc/modprobe.d"
SYSCTL_DIR="$ROOT/etc/sysctl.d"

DETAIL_LIMIT=1000

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

# Examines the running backend from outside, in one process (a Python start is slow under emulation). Meant to follow
# PY_NET. argv: <backend app directory> <Environment= of the unit> <proc net directory> <seconds to wait for it>.
# stdout: one line per fact, "<fact>|PASS|<detail>" or "<fact>|FAIL|<detail>", for ready, loopback, anonymous and
# health. Where the backend listens, and where it keeps its token, come from the backend's own settings loader fed
# with the unit's environment, so the defaults are never repeated here. The token is read to authenticate one
# request and is never printed: details hold addresses, paths and status codes only.
PY_BACKEND_PROBE=$(cat <<'PY'
import http.client
import json
import os
import shlex
import socket
import time
import urllib.error
import urllib.request

FACTS = ("ready", "loopback", "anonymous", "health")
app_dir, environment, net_dir, wait = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
MAX_BODY = 65536
REQUEST_TIMEOUT = 10


def report(fact, ok, detail):
    print(f"{fact}|{'PASS' if ok else 'FAIL'}|{' '.join(str(detail).split())}", flush=True)


def report_all(ok, detail, facts=FACTS):
    for fact in facts:
        report(fact, ok, detail)


try:
    sys.path.insert(0, app_dir)
    from backend.core.config import ConfigError, load_settings

    variables = dict(word.partition("=")[::2] for word in shlex.split(environment) if "=" in word)
    settings = load_settings({name: value for name, value in variables.items() if name.startswith("PAI_")})
except ConfigError as error:
    report_all(False, f"the unit's environment is not a valid backend configuration: {error}")
    sys.exit(0)
except (ImportError, ValueError) as error:
    report_all(False, f"cannot read the backend's settings from {app_dir}: {type(error).__name__}: {error}")
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a redirect is an answer to report, not a hop to follow
        return None


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)  # never through an HTTP proxy


def get(path, token=None):
    """(status, body) of GET <path> on the backend, or (None, reason) when no answer came."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(f"http://{where}{path}", headers=headers)
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            return response.status, response.read(MAX_BODY)
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read(MAX_BODY)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
        return None, str(getattr(error, "reason", error))


status, body = get("/health")
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
status, body = get("/health", token or None)
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

# ---- The backend --------------------------------------------------------------------------------------------------

# What the backend checks share, gathered once before any check runs (a check runs in a subshell and cannot hand
# anything on). Filled by probe_backend.
BACKEND_STATE=""    # ActiveState of the unit when the wait ended
BACKEND_NOTE=""     # why the backend cannot be examined, when it cannot
BACKEND_USER=""     # User= of the unit, as systemd loaded it
BACKEND_MAIN_PID="" # MainPID of the unit
declare -A BACKEND_FACT=() # fact -> "PASS|<detail>" or "FAIL|<detail>", reported by PY_BACKEND_PROBE
BACKEND_PROBE_ERROR=""

# probe_backend: waits (at most BACKEND_READY_TIMEOUT seconds) for the unit to become active, then has one python3
# process ask the running service the questions behind the backend-* checks. A failing probe is recorded and
# reported by each check that needs its answer; it never stops the self-check.
probe_backend() {
    local deadline=$((SECONDS + BACKEND_READY_TIMEOUT)) shown line key value
    local load_state="" environment="" environment_files="" remaining output="" fact
    if ! [[ $BACKEND_READY_TIMEOUT =~ ^[0-9]+$ ]]; then
        BACKEND_NOTE="PAI_SELFCHECK_READY_TIMEOUT is not a whole number of seconds"
        return 0
    fi
    while :; do
        shown=$(systemctl show --property=LoadState --property=ActiveState --property=User --property=MainPID \
            --property=Environment --property=EnvironmentFiles -- "$BACKEND_UNIT" 2>&1) || true
        while IFS= read -r line; do
            key=${line%%=*}
            value=${line#*=}
            case $key in
                LoadState) load_state=$value ;;
                ActiveState) BACKEND_STATE=$value ;;
                User) BACKEND_USER=$value ;;
                MainPID) BACKEND_MAIN_PID=$value ;;
                Environment) environment=$value ;;
                EnvironmentFiles) environment_files=$value ;;
            esac
        done <<<"$shown"
        # failed: systemd has given up restarting it. not-found: the image does not have the unit at all.
        if [ "$BACKEND_STATE" = active ] || [ "$BACKEND_STATE" = failed ] || [ "$load_state" = not-found ]; then
            break
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            break
        fi
        sleep 1
    done
    if [ "$load_state" = not-found ]; then
        BACKEND_NOTE="$BACKEND_UNIT is not installed"
        return 0
    fi
    if [ "$BACKEND_STATE" != active ]; then
        BACKEND_NOTE="$BACKEND_UNIT is ${BACKEND_STATE:-unknown}"
        return 0
    fi
    if [ -n "$environment_files" ]; then
        # The environment of the running process is not readable from here: a variable that file sets would be missed.
        BACKEND_NOTE="$BACKEND_UNIT loads EnvironmentFile= ($environment_files), which this self-check does not read"
        return 0
    fi
    remaining=$((deadline - SECONDS))
    [ "$remaining" -gt 0 ] || remaining=0
    if ! output=$(python3 -s -B -c "$PY_NET"$'\n'"$PY_BACKEND_PROBE" \
        "$BACKEND_APP_DIR" "$environment" "$PROC_DIR/net" "$remaining" 2>&1); then
        BACKEND_PROBE_ERROR="the probe crashed: ${output##*$'\n'}"
    fi
    while IFS= read -r line; do
        fact=${line%%|*}
        case $fact in
            ready | loopback | anonymous | health) BACKEND_FACT[$fact]=${line#*|} ;;
        esac
    done <<<"$output"
}

# backend_fact <fact>: prints what the probe reported for it; fails when it reported FAIL or nothing.
backend_fact() {
    local reported=${BACKEND_FACT[$1]:-}
    if [ -z "$reported" ]; then
        echo "the backend probe did not report '$1'${BACKEND_PROBE_ERROR:+ ($BACKEND_PROBE_ERROR)}"
        return 1
    fi
    echo "${reported#*|}"
    [ "${reported%%|*}" = PASS ]
}

check_backend_active() {
    if [ -n "$BACKEND_NOTE" ]; then
        echo "$BACKEND_NOTE"
        return 1
    fi
    backend_fact ready
}

# The main process runs as the account the unit names (never root), holds no capability, and cannot gain privileges.
# Needs the process's own /proc entry, which pai-selfcheck.service therefore does not hide (ProtectProc waiver).
check_backend_unprivileged() {
    local uid status key rest id real="" effective="" saved="" filesystem="" caps="" no_new_privs=""
    local -a problems=()
    if [ -n "$BACKEND_NOTE" ]; then
        echo "$BACKEND_NOTE"
        return 1
    fi
    if [ -z "$BACKEND_USER" ]; then
        echo "$BACKEND_UNIT sets no User=, so it would run as root"
        return 1
    fi
    if ! [[ $BACKEND_MAIN_PID =~ ^[1-9][0-9]*$ ]]; then
        echo "$BACKEND_UNIT has no main process (MainPID=${BACKEND_MAIN_PID:-unset})"
        return 1
    fi
    if ! uid=$(id -u -- "$BACKEND_USER" 2>&1) || ! [[ $uid =~ ^[0-9]+$ ]]; then
        echo "the account $BACKEND_USER that $BACKEND_UNIT runs as does not exist: $uid"
        return 1
    fi
    if [ "$uid" -eq 0 ]; then
        echo "the account $BACKEND_USER that $BACKEND_UNIT runs as is uid 0"
        return 1
    fi
    status="$PROC_DIR/$BACKEND_MAIN_PID/status"
    if ! [ -r "$status" ]; then
        echo "cannot read $status"
        return 1
    fi
    while read -r key rest; do
        case $key in
            Uid:) read -r real effective saved filesystem <<<"$rest" || true ;;
            CapEff:) caps=$rest ;;
            NoNewPrivs:) no_new_privs=$rest ;;
        esac
    done <"$status"
    for id in "$real" "$effective" "$saved" "$filesystem"; do
        if [ "$id" != "$uid" ]; then
            problems+=("uids real/effective/saved/filesystem are ${real:-?}/${effective:-?}/${saved:-?}/${filesystem:-?}, not $uid ($BACKEND_USER)")
            break
        fi
    done
    [[ $caps =~ ^0+$ ]] || problems+=("effective capabilities are ${caps:-unknown}, not none")
    [ "$no_new_privs" = 1 ] || problems+=("NoNewPrivs is ${no_new_privs:-unknown}, not 1")
    if [ "${#problems[@]}" -gt 0 ]; then
        join_details "pid $BACKEND_MAIN_PID of $BACKEND_UNIT: ${problems[0]}" "${problems[@]:1}"
        return 1
    fi
    echo "pid $BACKEND_MAIN_PID runs as $BACKEND_USER (uid $uid) with no capabilities and no_new_privs"
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

# "<name>:<function>", run in this order. backend-active comes first among the backend checks, and before the
# listener check, so a backend that opens a wildcard socket is already bound when no-external-listeners looks.
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
)

# ---- Run ----------------------------------------------------------------------------------------------------------

finished=0
# If the script dies before the summary (a bug here), still say so: a missing RESULT line is a boot-test failure.
trap 'if [ "$finished" -eq 0 ]; then emit RESULT FAIL "self-check aborted before completion"; fi' EXIT

probe_backend

passed=0
total=0
for entry in "${CHECKS[@]}"; do
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
