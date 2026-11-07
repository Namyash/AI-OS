"""Static checks that the pieces of the boot self-check name each other correctly.

The same facts are written in several places: the kernel flag that triggers the unit (unit and harness), the script's
path (unit and build hook), the unit's name (build hook), the configuration files the script reads (script and
overlay), and the list of checks (script and the harness's verdict). A mismatch in any of them shows only in a full
ISO build plus a boot of several minutes, as "no PAI-SELFCHECK output". These tests read the real files and fail in
milliseconds instead.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from tests.end_to_end.container_boot import KERNEL_ARGS
from tests.end_to_end.selfcheck_output import REQUIRED_CHECKS

SECURITY = Path(__file__).resolve().parents[2] / "os" / "security"
ROOTFS = SECURITY / "rootfs"
SCRIPT = ROOTFS / "usr" / "lib" / "pai" / "security-selfcheck.sh"
UNIT = ROOTFS / "etc" / "systemd" / "system" / "pai-selfcheck.service"
HOOK = SECURITY / "hooks" / "0100-enable-selfcheck.hook.chroot"
SYSUSERS = SECURITY.parent / "systemd" / "rootfs" / "usr" / "lib" / "sysusers.d" / "pai.conf"
BACKEND_UNIT = SECURITY.parent / "systemd" / "rootfs" / "etc" / "systemd" / "system" / "pai-backend.service"
BACKEND_GROUP = "pai"  # the group of the backend's token file; test_systemd_units ties it to the unit's Group=


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


def script_checks_table() -> list[tuple[str, str]]:
    """(check name, function) of every entry in the script's CHECKS table, in order."""
    block = re.search(r"^CHECKS=\(\n(?P<body>.*?)^\)", SCRIPT.read_text(encoding="utf-8"), re.DOTALL | re.MULTILINE)
    assert block is not None, "CHECKS table not found in the script"
    entries = [line.split("#", 1)[0].strip() for line in block["body"].splitlines()]
    return [tuple(entry.split(":", 1)) for entry in entries if entry]  # type: ignore[misc]


# ---- the checks the harness requires are the checks the script runs ------------------------------------------------


def test_the_harness_requires_exactly_the_checks_the_script_runs() -> None:
    assert [name for name, _ in script_checks_table()] == list(REQUIRED_CHECKS)


def test_every_check_in_the_table_is_a_defined_function() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    for name, function in script_checks_table():
        assert re.search(rf"^{re.escape(function)}\(\) \{{$", text, re.MULTILINE), (
            f"{name}: {function}() is not defined"
        )


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


def test_the_unit_runs_unprivileged_with_only_the_capability_the_firewall_listing_needs() -> None:
    (user,) = unit_values("User")
    assert user not in {"", "root", "0", "nobody"}  # an account of its own: shared accounts share a uid with others
    assert unit_values("AmbientCapabilities") == unit_values("CapabilityBoundingSet") == ["CAP_NET_ADMIN"]


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
    for path in paths:
        assert in_overlay(path).exists(), f"the script reads {path}, which the overlay does not provide"
