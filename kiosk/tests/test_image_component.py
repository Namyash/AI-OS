"""The image component (os/kiosk) against the launcher it runs: the files must agree with the code and with each other.

Nothing here boots anything. These are the facts a unit, a policy and a package list state about the kiosk, kept equal
to what ``kiosk/`` and the backend assume, so a change on one side fails a test instead of failing on a booted image.
"""

from __future__ import annotations

import ast
import json
import re
import shlex
from pathlib import Path

import pytest

from kiosk import config
from kiosk.errors import EXIT_CONFIG
from tests.security.test_systemd_units import Unit, parse_unit

REPO = Path(__file__).resolve().parents[2]
COMPONENT = REPO / "os" / "kiosk"
UNIT = COMPONENT / "rootfs" / "etc" / "systemd" / "system" / "pai-kiosk.service"
POLICY = COMPONENT / "rootfs" / "etc" / "chromium" / "policies" / "managed" / "pai-kiosk.json"
HOOK = COMPONENT / "hooks" / "0300-enable-pai-kiosk.hook.chroot"
PACKAGE_LIST = REPO / "os" / "configuration" / "package-lists" / "pai-base.list.chroot"
SYSUSERS = REPO / "os" / "systemd" / "rootfs" / "usr" / "lib" / "sysusers.d" / "pai.conf"
BACKEND_UNIT = REPO / "os" / "systemd" / "rootfs" / "etc" / "systemd" / "system" / "pai-backend.service"
BACKEND_SETTINGS = REPO / "backend" / "core" / "config.py"


def unit() -> Unit:
    return parse_unit(UNIT.name, UNIT.read_text(encoding="utf-8"))


def unit_section(directive: str) -> list[str]:
    """Every word of ``directive`` in the [Unit] section (the lint's parser keeps only [Service])."""
    words: list[str] = []
    in_unit = False
    for raw in UNIT.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_unit = line == "[Unit]"
        elif in_unit and line.startswith(f"{directive}="):
            words += line.partition("=")[2].split()
    return words


def backend_constant(name: str) -> str:
    for node in ast.parse(BACKEND_SETTINGS.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            assert isinstance(node.value, ast.Call | ast.Constant)
            argument = node.value.args[0] if isinstance(node.value, ast.Call) else node.value
            assert isinstance(argument, ast.Constant)
            return str(argument.value)
    raise AssertionError(f"{name} is not defined in {BACKEND_SETTINGS}")


# ---------------------------------------------------------------------------------------------- the unit
def test_the_unit_runs_cage_with_the_launcher_as_the_kiosk_account_from_the_installed_code() -> None:
    kiosk = unit()
    assert kiosk.scalar("User") == "pai-ui"
    assert kiosk.scalar("WorkingDirectory") == "/opt/pai"  # where assemble-config.sh installs kiosk/
    command = shlex.split(kiosk.scalar("ExecStart") or "")
    assert command[0] == "/usr/bin/cage"
    assert command[command.index("--") + 1 :] == ["/usr/bin/python3", "-s", "-m", "kiosk"]
    assert "-s" not in command[1 : command.index("--")], "cage's -s would let anyone switch to another terminal"


def test_the_unit_is_ordered_after_the_backend_and_restarts_with_it() -> None:
    assert "pai-backend.service" in unit_section("After")
    assert "pai-backend.service" in unit_section("Wants")
    # A backend restart ends every session (they live in its memory): the kiosk has to start over with it.
    assert unit_section("PartOf") == ["pai-backend.service"]
    # Sessions and the user runtime directory need logind, and logging in needs systemd-user-sessions.
    assert {"systemd-user-sessions.service", "systemd-logind.service"} <= set(unit_section("After"))


def test_the_unit_restarts_on_failure_but_not_on_the_configuration_error_status_the_launcher_ends_with() -> None:
    kiosk = unit()
    assert kiosk.scalar("Restart") == "on-failure"
    assert kiosk.words("RestartPreventExitStatus") == [str(EXIT_CONFIG)]
    assert int(kiosk.scalar("RestartSec") or 0) >= 1, "a failing launcher must not spin"


def test_the_unit_takes_tty1_and_a_login_session_through_the_standard_pam_stack() -> None:
    kiosk = unit()
    assert kiosk.scalar("PAMName") == "login"
    assert kiosk.scalar("TTYPath") == "/dev/tty1"
    assert kiosk.scalar("StandardInput") == "tty-fail"
    assert "getty@tty1.service" in unit_section("Conflicts")
    assert kiosk.scalar("TTYVTDisallocate") == "yes"


def test_the_unit_state_and_runtime_directories_are_where_the_launcher_writes() -> None:
    kiosk = unit()
    state, runtime = kiosk.scalar("StateDirectory"), kiosk.scalar("RuntimeDirectory")
    assert config.DEFAULT_PROFILE_DIR.parent.as_posix() == f"/var/lib/{state}"
    assert config.DEFAULT_READY_FILE.parent.as_posix() == f"/run/{runtime}"
    assert kiosk.scalar("StateDirectoryMode") == "0700", "the profile holds the browser's private state"
    # The boot self-check runs as another account and reads the readiness file: the directory must be traversable.
    assert int(kiosk.scalar("RuntimeDirectoryMode") or "0", 8) & 0o005 == 0o005


def test_the_kiosks_own_state_is_not_under_the_backends_directories() -> None:
    backend_state = Path(backend_constant("DEFAULT_DATA_DIR"))
    backend_runtime = Path(backend_constant("DEFAULT_TOKEN_FILE")).parent
    for path in (config.DEFAULT_PROFILE_DIR, config.DEFAULT_READY_FILE):
        assert not path.is_relative_to(backend_state)
        assert not path.is_relative_to(backend_runtime)
    writable = " ".join((unit().words("ReadWritePaths") or []) + (unit().words("BindPaths") or []))
    assert backend_state.as_posix() not in writable
    assert backend_runtime.as_posix() not in writable


def test_the_unit_leaves_the_files_the_backend_publishes_at_their_defaults() -> None:
    environment = " ".join(unit().assignments.get("Environment", ()))
    assert not re.search(r"\bPAI_(ENDPOINT_FILE|TOKEN_FILE|HOST|PORT)\b", environment)
    assert not re.search(r"token|secret|password|session_id|pai_session", environment, re.IGNORECASE), "no credential"
    backend = parse_unit(BACKEND_UNIT.name, BACKEND_UNIT.read_text(encoding="utf-8"))
    assert not re.search(r"\bPAI_(ENDPOINT_FILE|TOKEN_FILE)\b", " ".join(backend.assignments.get("Environment", ())))


def test_the_kiosk_account_exists_and_reads_the_token_through_the_backends_group() -> None:
    entries = [
        shlex.split(line) for line in SYSUSERS.read_text(encoding="utf-8").splitlines() if line and line[0] in "um"
    ]
    users = {entry[1] for entry in entries if entry[0] == "u"}
    assert unit().scalar("User") in users
    backend_group = parse_unit(BACKEND_UNIT.name, BACKEND_UNIT.read_text("utf-8")).scalar("Group")
    assert ["m", "pai-ui", backend_group] in [entry[:3] for entry in entries]


def test_the_unit_keeps_the_sandbox_it_can_and_documents_each_deviation_with_a_measurement() -> None:
    kiosk = unit()
    text = UNIT.read_text(encoding="utf-8")
    assert kiosk.scalar("NoNewPrivileges") == "yes"
    assert kiosk.words("CapabilityBoundingSet") == []
    assert kiosk.scalar("ProtectSystem") == "strict"
    assert kiosk.scalar("SystemCallErrorNumber") == "EPERM"
    # Chromium's own sandbox needs exactly these namespaces: no more than the three that were measured to be needed.
    assert kiosk.words("RestrictNamespaces") == ["user", "pid", "net"]
    assert "~" not in (kiosk.scalar("SystemCallFilter") or ""), "the filter stays an allow list"
    waivers = re.findall(r"^# pai-lint: (waive \w+|network-justified):", text, re.MULTILINE)
    assert sorted(waivers) == sorted(
        [
            "network-justified",
            "waive ProtectHome",
            "waive PrivateDevices",
            "waive ProcSubset",
            "waive RestrictNamespaces",
            "waive MemoryDenyWriteExecute",
            "waive SystemCallFilter",
        ]
    ), "a deviation was added or dropped: its comment, its measurement and this list move together"
    for reason in re.findall(r"^# pai-lint: [^:]+: (.*)$", text, re.MULTILINE):
        assert len(reason) > 60, "a waiver's reason must say what was measured or why, not just name the directive"


def test_the_unit_does_not_pretend_to_enforce_what_the_login_session_takes_it_out_of() -> None:
    # With PAMName= logind moves the processes into a session scope outside this unit's cgroup (measured). The cgroup
    # based controls would then look protective and do nothing, so they must not be there: a reader would trust them.
    kiosk = unit()
    for directive in ("IPAddressDeny", "IPAddressAllow", "DevicePolicy", "DeviceAllow", "MemoryMax", "TasksMax"):
        assert kiosk.scalar(directive) is None, (
            f"{directive} is attached to the unit's cgroup, which the session leaves"
        )


# ---------------------------------------------------------------------------------------------- the hook
def hook_commands() -> list[list[str]]:
    lines = (line.strip() for line in HOOK.read_text(encoding="utf-8").splitlines())
    return [shlex.split(line, comments=True) for line in lines if line and not line.startswith("#")]


def test_the_hook_enables_the_unit_the_overlay_ships_and_stops_at_the_first_failure() -> None:
    assert HOOK.read_text(encoding="utf-8").startswith("#!/bin/sh\n")
    commands = hook_commands()
    assert any(c[0] == "set" and any(a.startswith("-") and "e" in a for a in c[1:]) for c in commands)
    assert ["systemctl", "enable", UNIT.name] in commands
    assert UNIT.is_file()


def test_the_hook_masks_the_getty_on_tty1_and_only_that_one_so_serial_consoles_keep_working() -> None:
    masked = [name for c in hook_commands() if c[:2] == ["systemctl", "mask"] for name in c[2:]]
    assert masked == ["getty@tty1.service"]


def test_the_hook_does_not_repeat_the_mode_rule_of_the_assembly_script() -> None:
    assert [c for c in hook_commands() if c[0] in {"chmod", "chown", "find"}] == []


# ---------------------------------------------------------------------------------------------- the policy
def load_policy() -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        keys = [key for key, _ in pairs]
        assert len(keys) == len(set(keys)), f"a policy is set twice: {sorted({k for k in keys if keys.count(k) > 1})}"
        return dict(pairs)

    policy = json.loads(POLICY.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    assert isinstance(policy, dict)
    return policy


def test_the_policy_blocks_everything_and_allows_only_loopback_origins() -> None:
    policy = load_policy()
    assert "*" in policy["URLBlocklist"]  # type: ignore[operator]
    allowed = policy["URLAllowlist"]
    assert isinstance(allowed, list)
    assert allowed, "with nothing allowed the kiosk could not show the UI"
    for entry in allowed:
        assert re.fullmatch(r"http://(127(\.\d{1,3}){3}|\[::1\])", entry), f"{entry} is not a plain loopback origin"
    assert f"http://{backend_constant('DEFAULT_HOST')}" in allowed, "the backend's default address must be allowed"


def test_the_policy_blocks_the_browsers_own_pages_and_the_devtools_front_end() -> None:
    blocked = load_policy()["URLBlocklist"]
    assert isinstance(blocked, list)
    for scheme in ("chrome://*", "chrome-untrusted://*", "devtools://*", "view-source:*", "file://*", "javascript:*"):
        assert scheme in blocked


def test_the_policy_keeps_the_devtools_pipe_usable() -> None:
    policy = load_policy()
    # Measured on Debian's Chromium 156: DeveloperToolsAvailability=2 makes Target.attachToTarget fail with
    # "Not allowed", and the launcher cannot navigate the page or look at it. 0 and 1 attach.
    assert policy["DeveloperToolsAvailability"] in (0, 1)
    assert policy.get("RemoteDebuggingAllowed", True) is True


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MetricsReportingEnabled", False),
        ("SafeBrowsingProtectionLevel", 0),
        ("BackgroundModeEnabled", False),
        ("SyncDisabled", True),
        ("ComponentUpdatesEnabled", False),
        ("ChromeVariations", 2),
        ("UrlKeyedAnonymizedDataCollectionEnabled", False),
        ("NetworkPredictionOptions", 2),
        ("BuiltInDnsClientEnabled", False),
        ("DnsOverHttpsMode", "off"),
        ("EnableMediaRouter", False),
        ("SpellcheckEnabled", False),
        ("SearchSuggestEnabled", False),
        ("AlternateErrorPagesEnabled", False),
        ("BrowserSignin", 0),
        ("DownloadRestrictions", 3),
        ("ExtensionInstallBlocklist", ["*"]),
        ("PasswordManagerEnabled", False),
        ("DefaultGeolocationSetting", 2),
        ("AudioCaptureAllowed", False),
        ("VideoCaptureAllowed", False),
        ("ScreenCaptureAllowed", False),
    ],
)
def test_the_policy_turns_off_telemetry_sync_updates_background_networking_and_what_a_kiosk_has_no_use_for(
    name: str, value: object
) -> None:
    assert load_policy()[name] == value


def test_the_policy_is_a_plain_lf_json_object_without_comments() -> None:
    raw = POLICY.read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    assert isinstance(json.loads(raw), dict)


# ---------------------------------------------------------------------------------------------- the packages
def package_entries() -> dict[str, list[str]]:
    """Each package of the list and the comment lines directly above it."""
    found: dict[str, list[str]] = {}
    comments: list[str] = []
    for line in PACKAGE_LIST.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            comments.append(line)
        elif line.strip():
            found[line.strip()] = comments
            comments = []
        else:
            comments = []
    return found


@pytest.mark.parametrize("package", ["cage", "chromium", "fonts-dejavu-core", "libpam-systemd"])
def test_every_kiosk_package_is_in_the_list_with_its_reason_above_it(package: str) -> None:
    entries = package_entries()
    assert package in entries
    assert entries[package], f"{package} has no comment saying why it is on the image"
    assert len(" ".join(entries[package])) > 60


def test_the_setuid_sandbox_helper_and_the_seat_daemon_are_deliberately_absent() -> None:
    entries = package_entries()
    assert "chromium-sandbox" not in entries  # a setuid-root helper the user-namespace sandbox does not need
    assert "seatd" not in entries  # a root daemon; the kiosk takes its seat from logind


def test_the_launcher_needs_no_python_package_beyond_the_interpreter_the_image_has() -> None:
    assert "python3" in package_entries()
