"""Static checks that the pieces of the boot self-check name each other correctly.

The same facts are written in several places: the kernel flag that triggers the unit (unit and harness), the script's
path (unit and build hook), the unit's name (build hook), the configuration files the script reads (script and
overlay), the list of checks (script and the harness's verdict), the names of the backend and kiosk units the script
examines (script and the units' files), how long the unit may run against how long the script waits (unit and script),
and what a credential looks like, which cookie carries a session and what the status bar says when the backend is
connected (script, backend and frontend). A mismatch in any of them shows only in a full ISO build plus a boot of
several minutes, as "no PAI-SELFCHECK output" or a check that cannot pass. These tests read the real files and fail in
milliseconds instead.
"""

from __future__ import annotations

import posixpath
import re
import secrets
import shlex
from pathlib import Path

from backend.api.auth import TOKEN_BYTES
from backend.api.sessions import SESSION_COOKIE_NAME
from kiosk.config import DEFAULT_BROWSER_TIMEOUT, DEFAULT_HANDOFF_TIMEOUT, DEFAULT_RENDER_TIMEOUT
from tests.end_to_end import boot_harness, selfcheck_sim
from tests.end_to_end.container_boot import KERNEL_ARGS
from tests.end_to_end.selfcheck_output import INSTALLED_ONLY_CHECKS, REQUIRED_CHECKS, parse_selfcheck

SECURITY = Path(__file__).resolve().parents[2] / "os" / "security"
ROOTFS = SECURITY / "rootfs"
SCRIPT = ROOTFS / "usr" / "lib" / "pai" / "security-selfcheck.sh"
UNIT = ROOTFS / "etc" / "systemd" / "system" / "pai-selfcheck.service"
HOOK = SECURITY / "hooks" / "0100-enable-selfcheck.hook.chroot"
SYSUSERS = SECURITY.parent / "systemd" / "rootfs" / "usr" / "lib" / "sysusers.d" / "pai.conf"
BACKEND_UNIT = SECURITY.parent / "systemd" / "rootfs" / "etc" / "systemd" / "system" / "pai-backend.service"
KIOSK_UNIT = SECURITY.parent / "kiosk" / "rootfs" / "etc" / "systemd" / "system" / "pai-kiosk.service"
STATUS_BAR = SECURITY.parents[1] / "frontend" / "src" / "components" / "StatusBar.tsx"
BACKEND_GROUP = "pai"  # the group of the backend's token file; test_systemd_units ties it to the unit's Group=
# What the unit may run beyond its two waits: starting python a handful of times under emulation, reading /proc.
UNIT_MARGIN_SECONDS = 60
# What the guest needs to boot to the point where the unit starts, with room for a slow machine.
BOOT_MARGIN_SECONDS = 300
# The capabilities the unit keeps, each for the check named beside it (the unit's own comment says the same).
SELFCHECK_CAPABILITIES = {
    "CAP_NET_ADMIN": "nft-default-drop lists the live ruleset",
    "CAP_SYS_PTRACE": "no-secret-in-process-state reads every process's environment",
    "CAP_DAC_READ_SEARCH": "no-default-credentials reads /etc/shadow",
}
# Files the script reads that the base system provides (the accounts), so the overlay does not ship them.
BASE_SYSTEM_FILES = {"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d"}
INSTALLER = SECURITY.parent / "installer"
CRYPT_UNIT = INSTALLER / "rootfs" / "etc" / "systemd" / "system" / "pai-selfcheck-crypt.service"
CRYPT_FACTS_SCRIPT = INSTALLER / "rootfs" / "usr" / "lib" / "pai" / "selfcheck-crypt-facts.py"
INSTALLER_HOOK = INSTALLER / "hooks" / "0400-enable-pai-installer.hook.chroot"


def unit_values(key: str) -> list[str]:
    """Every `key=value` assignment in the unit file (the unit sets a few keys more than once), in file order."""
    prefix = f"{key}="
    lines = (line.strip() for line in UNIT.read_text(encoding="utf-8").splitlines())
    return [line.removeprefix(prefix).strip() for line in lines if line.startswith(prefix)]


def hook_commands() -> list[str]:
    """The hook's non-comment, non-empty lines."""
    lines = (line.strip() for line in HOOK.read_text(encoding="utf-8").splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def in_overlay(absolute_path: str) -> Path:
    return ROOTFS / absolute_path.lstrip("/")


def script_checks_table(table: str = "CHECKS") -> list[tuple[str, str]]:
    """(check name, function) of every entry in one of the script's check tables (CHECKS: every boot; INSTALLED_CHECKS:
    installed systems only), in order."""
    block = re.search(rf"^{table}=\(\n(?P<body>.*?)^\)", SCRIPT.read_text(encoding="utf-8"), re.DOTALL | re.MULTILINE)
    assert block is not None, f"{table} table not found in the script"
    entries = [line.split("#", 1)[0].strip() for line in block["body"].splitlines()]
    return [tuple(entry.split(":", 1)) for entry in entries if entry]  # type: ignore[misc]


# ---- the checks the harness requires are the checks the script runs ------------------------------------------------


def defined_functions() -> set[str]:
    """Names of the functions the script defines at the start of a line: `name() {` alone or with a one-line body."""
    return set(re.findall(r"^([A-Za-z_]\w*)\(\) *\{", SCRIPT.read_text(encoding="utf-8"), re.MULTILINE))


def test_the_harness_requires_exactly_the_checks_the_script_runs() -> None:
    """REQUIRED_CHECKS is written down on purpose instead of read from the script: a script edited to drop a check
    must not lower the bar the harness holds an image to. This test is what keeps the two lists equal, in order."""
    assert [name for name, _ in script_checks_table()] == list(REQUIRED_CHECKS)


def test_the_harness_requires_exactly_the_installed_only_checks_the_script_adds_on_an_installed_system() -> None:
    assert [name for name, _ in script_checks_table("INSTALLED_CHECKS")] == list(INSTALLED_ONLY_CHECKS)


def all_script_checks() -> list[tuple[str, str]]:
    return [*script_checks_table(), *script_checks_table("INSTALLED_CHECKS")]


def test_no_check_is_listed_twice_in_the_table() -> None:
    names = [name for name, _ in all_script_checks()]
    functions = [function for _, function in all_script_checks()]
    assert len(set(names)) == len(names), "a check name appears twice: the harness would read two results as a conflict"
    assert len(set(functions)) == len(functions), "two entries run the same function"


def test_every_table_entry_is_a_name_the_harness_can_read_and_a_function_name() -> None:
    for name, function in all_script_checks():
        assert re.fullmatch(r"[A-Za-z_]\w*", function), f"{name}: {function!r} is not a function name"
        # The name must survive the parser that reads the console, which accepts only its own name pattern.
        assert [result.name for result in parse_selfcheck(f"PAI-SELFCHECK|{name}|PASS|x")] == [name]


def test_every_check_in_the_table_is_a_defined_function() -> None:
    defined = defined_functions()
    for name, function in all_script_checks():
        assert function in defined, f"{name}: {function}() is not defined"


def test_every_check_function_the_script_defines_is_in_the_table() -> None:
    """A check_* function that no table entry runs is a check that silently never happens."""
    listed = {function for _, function in all_script_checks()}
    assert {name for name in defined_functions() if name.startswith("check_")} == listed


# ---- the kernel flag that triggers the unit ------------------------------------------------------------------------


def test_the_unit_starts_only_on_the_kernel_flag_the_harness_passes() -> None:
    (condition,) = unit_values("ConditionKernelCommandLine")
    assert condition in KERNEL_ARGS.split()


# ---- the unit runs the script the overlay ships --------------------------------------------------------------------


def test_the_unit_runs_a_script_that_exists_in_the_overlay() -> None:
    (exec_start,) = unit_values("ExecStart")
    script_path = exec_start.split()[0]
    assert in_overlay(script_path) == SCRIPT
    assert SCRIPT.is_file()
    assert SCRIPT.read_text(encoding="utf-8").startswith("#!/bin/bash\n")


def test_the_unit_runs_unprivileged_with_only_the_capabilities_its_checks_need_to_read() -> None:
    (user,) = unit_values("User")
    assert user not in {"", "root", "0", "nobody"}  # an account of its own: shared accounts share a uid with others
    (ambient,) = unit_values("AmbientCapabilities")
    (bounding,) = unit_values("CapabilityBoundingSet")
    assert ambient.split() == bounding.split()
    assert set(bounding.split()) == set(SELFCHECK_CAPABILITIES), (
        "a capability was added or dropped: name its check here"
    )


def script_value(name: str) -> str:
    return selfcheck_sim.script_value(name)


def test_the_script_names_the_units_it_examines_as_their_files_do() -> None:
    assert script_value("BACKEND_UNIT") == BACKEND_UNIT.name
    assert script_value("KIOSK_UNIT") == KIOSK_UNIT.name


def test_the_unit_starts_after_the_services_whose_checks_it_runs() -> None:
    (after,) = unit_values("After")
    assert {BACKEND_UNIT.name, KIOSK_UNIT.name} <= set(after.split())


def default_seconds(variable: str) -> int:
    """The default of a wait in the script, written as ${VARIABLE:-<seconds>}."""
    match = re.search(r"\$\{" + variable + r":-(\d+)\}", SCRIPT.read_text(encoding="utf-8"))
    assert match is not None, f"{variable} has no default in the script"
    return int(match[1])


def test_the_unit_may_run_longer_than_both_of_the_scripts_waits_together() -> None:
    (limit,) = unit_values("TimeoutStartSec")
    waits = default_seconds("PAI_SELFCHECK_READY_TIMEOUT") + default_seconds("PAI_SELFCHECK_KIOSK_TIMEOUT")
    assert int(limit) >= waits + UNIT_MARGIN_SECONDS, (
        "the unit would be killed while the script is still allowed to wait"
    )


def test_the_boot_harness_gives_the_guest_longer_than_the_unit_may_run() -> None:
    """The boot itself comes first, and under emulation it takes minutes; the harness must not give up before the unit's
    own limit, or a slow but healthy run is reported as a timeout instead of a verdict."""
    (limit,) = unit_values("TimeoutStartSec")
    assert int(limit) + BOOT_MARGIN_SECONDS <= boot_harness.DEFAULT_TIMEOUT_S


def test_the_kiosk_wait_covers_one_full_attempt_of_the_launcher() -> None:
    """The launcher bounds its phases (backend files, browser, page); a wait shorter than their sum could end while a
    healthy kiosk is still inside them."""
    launcher = DEFAULT_HANDOFF_TIMEOUT + DEFAULT_BROWSER_TIMEOUT + DEFAULT_RENDER_TIMEOUT
    assert default_seconds("PAI_SELFCHECK_KIOSK_TIMEOUT") >= launcher


# ---- what the script assumes about the backend, the kiosk and the frontend -------------------------------------


def test_a_credential_is_as_long_as_the_backend_makes_it_and_arrives_in_the_cookie_the_backend_reads() -> None:
    assert int(script_value("CREDENTIAL_LENGTH")) == len(secrets.token_urlsafe(TOKEN_BYTES))
    assert script_value("SESSION_COOKIE") == SESSION_COOKIE_NAME
    assert selfcheck_sim.TOKEN_BYTES == TOKEN_BYTES  # the simulated backend mints credentials the real way


def test_the_label_that_means_the_backend_is_connected_is_the_one_the_frontend_shows() -> None:
    label = script_value("KIOSK_BACKEND_CONNECTED_LABEL")
    assert re.search(f"label: '{re.escape(label)}'", STATUS_BAR.read_text(encoding="utf-8")), (
        f"{STATUS_BAR.name} no longer shows {label!r} for a connected backend: the kiosk-ready check cannot pass"
    )


def test_the_account_the_unit_runs_as_is_defined_without_a_login_and_can_read_the_backend_token() -> None:
    (user,) = unit_values("User")
    entries = [shlex.split(line) for line in SYSUSERS.read_text(encoding="utf-8").splitlines() if line.strip()]
    entries = [entry for entry in entries if not entry[0].startswith("#")]
    (definition,) = [entry for entry in entries if entry[:2] == ["u", user]]
    assert definition[-1] == "/usr/sbin/nologin"
    # The check authenticates against the backend, so it needs the token, which the backend's group may read.
    assert ["m", user, BACKEND_GROUP] in entries


def test_the_hook_leaves_account_creation_to_the_sysusers_file() -> None:
    assert not [command for command in hook_commands() if command.startswith(("useradd", "adduser"))]


def test_the_unit_carries_no_root_justification() -> None:
    assert "root-justified" not in UNIT.read_text(encoding="utf-8")


# ---- the hook enables the unit; the modes are the assembly script's job ----------------------------------------------


def test_the_hook_enables_the_unit_the_overlay_provides() -> None:
    enabled = [
        command.removeprefix("systemctl enable ").strip()
        for command in hook_commands()
        if command.startswith("systemctl enable ")
    ]
    assert enabled == [UNIT.name]
    assert UNIT.is_file()


def test_the_hook_does_not_repeat_the_mode_rule_of_the_assembly_script() -> None:
    """os/build/assemble-config.sh makes the script 0755 (it starts with #!) and the unit 0644 for every component."""
    assert not [command for command in hook_commands() if command.startswith(("chmod ", "chown ", "find "))]
    assert SCRIPT.read_text(encoding="utf-8").startswith("#!")
    assert not UNIT.read_text(encoding="utf-8").startswith("#!")


# ---- the script reads configuration the overlay ships --------------------------------------------------------------


def test_the_configuration_the_script_reads_is_shipped_in_the_overlay() -> None:
    """The script reads these under $ROOT, which is empty on a real boot: so they must be image paths."""
    paths = re.findall(r'^[A-Z_]+="\$ROOT(/etc/[\w./-]+)"$', SCRIPT.read_text(encoding="utf-8"), re.MULTILINE)
    assert {"/etc/nftables.conf", "/etc/modprobe.d", "/etc/sysctl.d"} <= set(paths)
    assert set(paths) >= BASE_SYSTEM_FILES, "BASE_SYSTEM_FILES names a file the script no longer reads"
    for path in paths:
        if path not in BASE_SYSTEM_FILES:
            assert in_overlay(path).exists(), f"the script reads {path}, which the overlay does not provide"


# ---- installed systems: how the script tells them from a live session, and where its facts come from -----------------


def test_the_script_takes_the_kernel_option_of_the_harnesss_live_boot_for_a_live_session() -> None:
    """The harness boots the live ISO with the arguments in KERNEL_ARGS; the script must call exactly that live."""
    assert script_value("LIVE_CMDLINE_WORD") in KERNEL_ARGS.split()


def crypt_unit_values(key: str) -> list[str]:
    prefix = f"{key}="
    lines = (line.strip() for line in CRYPT_UNIT.read_text(encoding="utf-8").splitlines())
    return [line.removeprefix(prefix).strip() for line in lines if line.startswith(prefix)]


def test_the_facts_unit_writes_where_the_script_reads_and_runs_the_program_the_overlay_ships() -> None:
    (exec_start,) = crypt_unit_values("ExecStart")
    words = shlex.split(exec_start)
    assert in_installer_overlay(words[-2]) == CRYPT_FACTS_SCRIPT
    assert CRYPT_FACTS_SCRIPT.is_file()
    facts_path = words[-1]
    declared = re.search(r'^CRYPT_FACTS_FILE="\$ROOT(/[\w./-]+)"$', SCRIPT.read_text(encoding="utf-8"), re.MULTILINE)
    assert declared is not None
    assert declared[1] == facts_path
    # The unit's RuntimeDirectory is the directory the file goes into.
    (runtime,) = crypt_unit_values("RuntimeDirectory")
    assert posixpath.dirname(facts_path) == f"/run/{runtime}"


def in_installer_overlay(absolute_path: str) -> Path:
    return INSTALLER / "rootfs" / absolute_path.lstrip("/")


def test_the_facts_unit_runs_only_in_a_selfcheck_boot_before_the_selfcheck_as_the_same_account() -> None:
    (condition,) = crypt_unit_values("ConditionKernelCommandLine")
    assert condition == unit_values("ConditionKernelCommandLine")[0]
    assert UNIT.name in crypt_unit_values("Before")[0].split()
    assert crypt_unit_values("User") == unit_values("User")
    assert crypt_unit_values("WantedBy") == unit_values("WantedBy")
    assert "RemainAfterExit=yes" in CRYPT_UNIT.read_text(encoding="utf-8")  # its directory and file outlive the unit


def test_the_facts_unit_keeps_one_read_only_capability_and_no_root() -> None:
    assert crypt_unit_values("CapabilityBoundingSet") == ["CAP_DAC_READ_SEARCH"]
    assert crypt_unit_values("AmbientCapabilities") == ["CAP_DAC_READ_SEARCH"]
    assert "root-justified" not in CRYPT_UNIT.read_text(encoding="utf-8")


def test_every_fact_the_check_reads_is_one_the_facts_program_writes() -> None:
    check = re.search(
        r"^check_root_encrypted\(\) \{(?P<body>.*?)^\}", SCRIPT.read_text(encoding="utf-8"), re.DOTALL | re.MULTILINE
    )
    assert check is not None
    read = set(re.findall(r"\$\{fact\[(\w+)\]", check["body"]))
    assert read, "the check no longer reads any fact"
    written = set(re.findall(r'facts\["(\w+)"\]', CRYPT_FACTS_SCRIPT.read_text(encoding="utf-8"))) | {"error"}
    assert read <= written, f"the check reads facts that nothing writes: {sorted(read - written)}"


def test_the_names_the_check_compares_with_are_the_ones_the_facts_program_and_cryptsetup_use() -> None:
    program = CRYPT_FACTS_SCRIPT.read_text(encoding="utf-8")
    assert script_value("REQUIRED_CRYPT_KIND") == "CRYPT-LUKS2"
    assert "f\"CRYPT-{match['type']}\"" in program  # the program builds the kind the same way
    assert script_value("REQUIRED_LUKS_KDF") == "argon2id"  # the name in LUKS2 keyslot metadata ("kdf": {"type": ...})


def test_the_installer_hook_enables_both_units_the_installer_component_ships() -> None:
    commands = [
        line.strip()
        for line in INSTALLER_HOOK.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    enabled = [word for command in commands if command.startswith("systemctl enable ") for word in command.split()[2:]]
    shipped = sorted(path.name for path in (INSTALLER / "rootfs" / "etc" / "systemd" / "system").glob("*.service"))
    assert sorted(enabled) == shipped
