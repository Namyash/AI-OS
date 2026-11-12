#!/usr/bin/env bash
# Runs INSIDE a debian:trixie-slim container, as root, started by run.sh: the real kiosk against the real backend.
#
# What is real: Debian's packages from the image's own package list, the production build of the frontend, the files
# os/build/assemble-config.sh installs under /opt/pai, the account definitions (sysusers) of the image, the Chromium
# policy of the image, `python3 -m backend`, `python3 -m kiosk`, cage (headless Wayland backend, software renderer) and
# Chromium with its sandbox on. What is not: systemd (no unit, no PAM session, no VT), the kernel, the display.
#
# Inputs (mounted by run.sh): /repo (the repository, read-only) and /dist (the built frontend, read-only).
# Exits 0 only when every check passed; every check prints one PASS or FAIL line.
set -euo pipefail

REPO=/repo
DIST=/dist
WORK=/pai-it
FAILED=0
now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN {printf "%.1f", b - a}'; }
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILED=1; }

export DEBIAN_FRONTEND=noninteractive
T_START=$(now)

# --- 1. packages: the image's list, minus what only a booted machine can use ---------------------------------------
apt-get update -qq >/dev/null 2>&1
mapfile -t PACKAGES < <(sed 's/#.*//' "$REPO/os/configuration/package-lists/pai-base.list.chroot" | awk 'NF {print $1}' \
    | grep -v -x -E 'linux-image-amd64|live-boot|cryptsetup-initramfs|open-vm-tools')
T0=$(now)
apt-get install -y -qq --no-install-recommends "${PACKAGES[@]}" procps >/dev/null 2>&1
T1=$(now)
echo "INFO  installed ${#PACKAGES[@]} listed packages with dependencies in $(elapsed "$T0" "$T1") s: $(dpkg-query -f '${binary:Package}\n' -W | wc -l) packages, $(dpkg-query -f '${Installed-Size}\n' -W | awk '{s += $1} END {printf "%.0f", s / 1024}') MiB installed"
echo "INFO  $(chromium --version 2>/dev/null | head -1), cage $(cage -v 2>&1 | head -1)"
if dpkg -s seatd >/dev/null 2>&1; then fail "seatd (a root seat daemon) was pulled in"; else pass "seatd is not installed"; fi
if dpkg -s chromium-sandbox >/dev/null 2>&1; then fail "the setuid sandbox helper was pulled in"; else pass "no setuid chromium-sandbox helper"; fi

# --- 2. the image's accounts, code, policy ---------------------------------------------------------------------------
systemd-sysusers "$REPO/os/systemd/rootfs/usr/lib/sysusers.d/pai.conf" >/dev/null 2>&1
bash "$REPO/os/build/assemble-config.sh" "$REPO/os" "$REPO/backend" "$REPO/kiosk" "$DIST" /tmp/config >/dev/null
cp -a /tmp/config/includes.chroot/opt/pai /opt/pai
mkdir -p /etc/chromium
cp -a /tmp/config/includes.chroot/etc/chromium/. /etc/chromium/
UI_UID=$(id -u pai-ui)
install -d -o pai -g pai -m 0750 /run/pai
install -d -o pai -g pai -m 0700 /var/lib/pai
install -d -o pai-ui -g pai-ui -m 0700 /var/lib/pai-ui
install -d -o pai-ui -g pai-ui -m 0755 /run/pai-ui
install -d -o pai-ui -g pai-ui -m 0700 "/run/user/$UI_UID"
install -d -m 1777 "$WORK"  # the tee fixture writes its log here as pai-ui
cp "$REPO/kiosk/tests/integration/tee_browser.py" "$REPO/kiosk/tests/integration/scan_processes.py" "$WORK/"
chmod 0755 "$WORK/tee_browser.py" "$WORK/scan_processes.py"
[ "$(stat -c '%U %a' /opt/pai/kiosk/launcher.py)" = "root 644" ] && pass "/opt/pai/kiosk is root-owned and not writable by the service account" || fail "/opt/pai/kiosk ownership or mode"

# --- 3. the real backend, as its own unprivileged account -------------------------------------------------------------
T_BACKEND=$(now)
(cd /opt/pai && runuser -u pai -- env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 python3 -s -m backend >"$WORK/backend.log" 2>&1 &)
for _ in $(seq 1 100); do [ -s /run/pai/token ] && [ -s /run/pai/endpoint ] && break; sleep 0.1; done
[ -s /run/pai/token ] || { cat "$WORK/backend.log"; fail "the backend did not publish its token"; exit 1; }
T_PUBLISHED=$(now)
echo "INFO  backend published its endpoint and token $(elapsed "$T_BACKEND" "$T_PUBLISHED") s after it was started: $(cat /run/pai/endpoint)"
TOKEN=$(cat /run/pai/token)
ENDPOINT=$(cat /run/pai/endpoint)

http_status() {  # http_status <extra curl-less python args...>: prints the status of GET / with the given Cookie header
    python3 - "$ENDPOINT" "${1:-}" <<'PY'
import sys, urllib.request, urllib.error
url, cookie = sys.argv[1] + "/", sys.argv[2]
request = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
try:
    print(urllib.request.urlopen(request, timeout=5).status)
except urllib.error.HTTPError as error:
    print(error.code)
PY
}
[ "$(http_status "")" = 401 ] && pass "the UI is not served without a session (401): rendering it later proves the cookie" || fail "the backend served the UI without credentials"

# --- 4. the real launcher under cage, as the kiosk account ------------------------------------------------------------
rm -f "$WORK/tee.log"
T_LAUNCH=$(now)
(cd /opt/pai && runuser -u pai-ui -- env -i \
    PATH=/usr/bin:/bin XDG_RUNTIME_DIR="/run/user/$UI_UID" XDG_SESSION_TYPE=wayland \
    WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_NO_HARDWARE_CURSORS=1 WLR_LIBINPUT_NO_DEVICES=1 PYTHONDONTWRITEBYTECODE=1 \
    PAI_KIOSK_CHROMIUM="$WORK/tee_browser.py" PAI_KIOSK_CHROMIUM_FLAGS="--tee-log=$WORK/tee.log" PAI_KIOSK_STATUS_INTERVAL=2 \
    cage -d -- /usr/bin/python3 -s -m kiosk >"$WORK/kiosk.log" 2>&1 &)
READY=/run/pai-ui/ready
for _ in $(seq 1 600); do [ -s "$READY" ] && break; sleep 0.1; done
T_READY=$(now)
if [ -s "$READY" ]; then
    echo "INFO  launcher started to readiness file: $(elapsed "$T_LAUNCH" "$T_READY") s"
    echo "INFO  readiness file: $(cat "$READY")"
else
    echo "---- kiosk log"; grep -v 'ERROR:dbus\|object_proxy' "$WORK/kiosk.log" | tail -20
    fail "no readiness file within 60 s"; exit 1
fi
python3 - "$READY" <<'PY' && pass "readiness file: ready, shell rendered, status bar says the backend is connected" || fail "readiness file content"
import json, sys
ready = json.load(open(sys.argv[1], encoding="utf-8"))
assert set(ready) == {"version", "state", "shell_rendered", "status_bar", "updated"}, ready
assert ready["state"] == "ready" and ready["shell_rendered"] is True, ready
assert ready["status_bar"].startswith("Backend connected"), ready
PY
sleep 3   # a few status refreshes and the browser's helper processes settle

# --- 5. what the launcher said to the browser, from the tee ------------------------------------------------------------
python3 - "$WORK/tee.log" "$WORK/session-ids" <<'PY' && pass "cookie installed as designed (HttpOnly, SameSite=Strict, host-only, with an expiry) and the page navigated to the plain URL" || fail "the DevTools conversation"
import json, sys, time
entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
commands = [e for e in entries if e["dir"] == "command"]
cookies = [c for e in commands if e["msg"]["method"] == "Storage.setCookies" for c in e["msg"]["params"]["cookies"]]
assert len(cookies) == 1, cookies
cookie = cookies[0]
endpoint_origin = cookie["url"].rstrip("/")
assert cookie["name"] == "pai_session" and cookie["httpOnly"] is True and cookie["sameSite"] == "Strict", cookie
assert "domain" not in cookie and cookie["path"] == "/" and cookie["expires"] > time.time() + 3600, cookie
navigate = [e["msg"]["params"] for e in commands if e["msg"]["method"] == "Page.navigate"]
assert navigate == [{"url": cookie["url"]}], navigate
order = [e["msg"]["method"] for e in commands]
assert order.index("Storage.setCookies") < order.index("Page.navigate"), order
replies = {e["msg"]["id"]: e["msg"] for e in entries if e["dir"] == "reply" and "id" in e["msg"]}
cookie_command = next(e for e in commands if e["msg"]["method"] == "Storage.setCookies")
assert "error" not in replies[cookie_command["msg"]["id"]], replies[cookie_command["msg"]["id"]]
open(sys.argv[2], "w", encoding="utf-8").write(cookie["value"] + "\n")
start = commands[0]["t"]
print(f"INFO  DevTools timeline: cookie installed {cookie_command['t'] - start:.2f} s and navigate "
      f"{next(e for e in commands if e['msg']['method'] == 'Page.navigate')['t'] - start:.2f} s after the first command")
PY
SESSION_ID=$(cat "$WORK/session-ids")
echo "$TOKEN" > "$WORK/token-copy"
[ "$(http_status "pai_session=$SESSION_ID")" = 200 ] && pass "the installed session id opens the UI (200)" || fail "the installed session id is not accepted"
[ "$(http_status "pai_session=$TOKEN")" = 401 ] && pass "the bearer token is not a valid cookie value (401)" || fail "the token worked as a cookie"

# --- 6. neither secret in any process's argv or environ (root's view of /proc) ------------------------------------
echo "INFO  process tree of the kiosk:"
ps -eo pid,ppid,user:12,args --forest | grep -E 'cage|kiosk|tee_browser|chromium' | grep -v grep | cut -c1-150 | head -16 | sed 's/^/INFO    /'
# A control first: the scanner must find a secret that really is on a command line, or "zero findings" means nothing.
(sh -c 'sleep 20; :' "$TOKEN" &) ; sleep 0.3
if python3 "$WORK/scan_processes.py" "literal:$TOKEN" >"$WORK/control.out" 2>&1; then
    fail "the scanner did not find the decoy process that carries the token in its argv"
elif grep -q "sleep 20" "$WORK/control.out"; then pass "scanner control: it finds a token placed on a command line"; else fail "scanner control found the wrong thing"; fi
pkill -f 'sleep 20' || true
if SCAN=$(python3 "$WORK/scan_processes.py" "$WORK/token-copy" "$WORK/session-ids" 2>&1); then
    pass "no process has the bearer token or the session id in argv or environ ($(echo "$SCAN" | tail -1))"
else
    echo "$SCAN"; fail "a secret is in process state"
fi
# Files the launcher writes: readiness file and the log hold no secret either.
if grep -q -F -e "$TOKEN" -e "$SESSION_ID" "$READY" "$WORK/kiosk.log"; then fail "a secret is in the readiness file or the launcher's log"; else pass "no secret in the readiness file or the launcher's log"; fi
LEAKED=$(grep -r -l -F -e "$TOKEN" -e "$SESSION_ID" /var/lib/pai-ui /run/pai-ui 2>/dev/null | head -3 || true)
[ -z "$LEAKED" ] && pass "no secret in plain text in the browser profile or the runtime directory" || fail "a secret is stored in clear in: $LEAKED"

# --- 7. the browser is who it should be -------------------------------------------------------------------------------
BAD=$(ps -eo user:12,stat,args | awk '$2 !~ /^Z/' | grep -E 'chromium|cage -d|-m kiosk|tee_browser' | grep -v -E 'grep|runuser|^pai-ui' | head -3 || true)  # runuser is this script's own wrapper
[ -z "$BAD" ] && pass "every kiosk process runs as pai-ui" || fail "a kiosk process runs as another account: $BAD"
if ps -eo args | grep -E -- '--no-sandbox|--remote-debugging-port' | grep -v grep >/dev/null; then fail "an insecure browser flag is in use"; else pass "no --no-sandbox, no debugging port"; fi
SANDBOXED=0; RENDERERS=0
for pid in $(pgrep -f -- '--type=renderer' || true); do
    RENDERERS=$((RENDERERS + 1))
    if [ "$(readlink /proc/$pid/ns/user)" != "$(readlink /proc/1/ns/user)" ] && grep -q '^Seccomp:.2' /proc/$pid/status; then SANDBOXED=$((SANDBOXED + 1)); fi
done
[ "$RENDERERS" -gt 0 ] && [ "$SANDBOXED" = "$RENDERERS" ] && pass "all $RENDERERS renderers run in their own user namespace under seccomp" || fail "sandbox check: $SANDBOXED of $RENDERERS renderers"
EXTERNAL=$(awk 'NR > 1 && ($4 == "0A" || $4 == "07") {split($2, a, ":"); if (a[1] != "0100007F" && a[1] != "00000000000000000000000001000000") print $2}' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 | sort -u || true)
[ -z "$EXTERNAL" ] && pass "no listening socket outside loopback" || fail "listening on a non-loopback address: $EXTERNAL"
python3 - "$ENDPOINT" <<'PY' && pass "the browser's managed policy blocks a URL outside loopback" || fail "policy check"
import json, sys
policy = json.load(open("/etc/chromium/policies/managed/pai-kiosk.json", encoding="utf-8"))
assert "*" in policy["URLBlocklist"] and all(e.startswith("http://127.") or e.startswith("http://[::1]") for e in policy["URLAllowlist"])
PY

# --- 8. stopping: the launcher exits cleanly and takes the browser with it ------------------------------------------------
T_STOP=$(now)
pkill -TERM -x cage || true
for _ in $(seq 1 100); do pgrep -x cage >/dev/null || break; sleep 0.1; done
sleep 1
T_STOPPED=$(now)
LEFT=$(ps -u pai-ui -o pid,stat,args --no-headers | awk '$2 !~ /^Z/' | head -3 || true)  # a zombie is already dead
if [ -n "$LEFT" ]; then fail "processes of pai-ui outlived the stop: $LEFT"; else pass "stop took $(elapsed "$T_STOP" "$T_STOPPED") s and left no process of pai-ui"; fi
if [ ! -e "$READY" ] || grep -q '"state":"not-ready"' "$READY"; then pass "after the stop the readiness file is gone or says not-ready"; else fail "stale ready file after stop"; fi

echo "INFO  total $(elapsed "$T_START" "$(now)") s"
[ "$FAILED" = 0 ] && echo "RESULT PASS" || echo "RESULT FAIL"
exit "$FAILED"
