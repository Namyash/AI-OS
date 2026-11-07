"""Policy-as-code linter for every systemd service unit shipped in the image.

Units are discovered at run time, in every directory systemd loads system units from that an overlay can fill
(``UNIT_DIRECTORIES``, under ``os/**``), never from a list of names, so a new unit is held to the baseline the
moment it is added. Changing a rule below is a deliberate security decision: say why in the change.

A unit is judged as written. Drop-in files (``<unit>.service.d/*.conf``, ``service.d/*.conf``) are refused
outright: they are systemd's way of changing a unit after the fact, so a drop-in beside a compliant unit could
undo any rule here without this test seeing it. A change belongs in the unit file.

How a unit is judged (only ``[Service]`` directives count):

* ``BASELINE`` is a policy table: each sandbox directive and the values that meet the baseline. A directive the
  unit omits counts as violating it, because systemd's default for every one of them is the weaker setting.
  Directives the policy does not know (``Restart``, ``Environment``, anything added to systemd later) are ignored,
  so a new unrelated directive can never break the lint, while everything the table does know is enforced.
* Identity, capabilities, network, system calls, writable paths and privileged command lines need more than a
  single value, so each has its own check below.
* A unit may deviate only with a documented need, as a comment line in the unit file with a non-empty reason::

      # pai-lint: root-justified: <reason>            the unit runs as root (also needs NoNewPrivileges and a
                                                       non-empty CapabilityBoundingSet narrower than all)
      # pai-lint: capabilities-justified: <reason>    a non-root unit keeps listed capabilities
      # pai-lint: network-justified: <reason>         the unit needs more than loopback IP traffic
      # pai-lint: waive <Directive>: <reason>         a baseline or path directive is deliberately weaker, or an
                                                       Exec* directive may run a command with full privileges

  ``NoNewPrivileges`` can never be waived.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

OS_DIR = Path(__file__).resolve().parents[2] / "os"
# Where systemd loads system units from, relative to an image root, that an os/<component>/rootfs overlay can fill.
# (User units, /etc/systemd/user, run in a user manager and are not services of the system instance.)
UNIT_DIRECTORIES = (
    "etc/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
    "usr/local/lib/systemd/system",
    "run/systemd/system",
)

TRUTHY = frozenset({"yes", "true", "1", "on"})


@dataclass(frozen=True)
class Requirement:
    accepted: frozenset[str]  # lower-case values that meet the baseline
    waivable: bool = True


BASELINE: dict[str, Requirement] = {
    "NoNewPrivileges": Requirement(TRUTHY, waivable=False),
    "ProtectSystem": Requirement(frozenset({"strict"})),
    "ProtectHome": Requirement(TRUTHY | {"tmpfs"}),
    "PrivateTmp": Requirement(TRUTHY | {"disconnected"}),
    "PrivateDevices": Requirement(TRUTHY),
    "ProtectKernelTunables": Requirement(TRUTHY),
    "ProtectKernelModules": Requirement(TRUTHY),
    "ProtectKernelLogs": Requirement(TRUTHY),
    "ProtectControlGroups": Requirement(TRUTHY),
    "ProtectClock": Requirement(TRUTHY),
    "ProtectHostname": Requirement(TRUTHY),
    "ProtectProc": Requirement(frozenset({"invisible"})),
    "ProcSubset": Requirement(frozenset({"pid"})),
    "RestrictNamespaces": Requirement(TRUTHY),
    "RestrictRealtime": Requirement(TRUTHY),
    "RestrictSUIDSGID": Requirement(TRUTHY),
    "LockPersonality": Requirement(TRUTHY),
    "MemoryDenyWriteExecute": Requirement(TRUTHY),
    "SystemCallArchitectures": Requirement(frozenset({"native"})),
    "UMask": Requirement(frozenset({"0077", "077"})),
}
REQUIRED_SYSCALL_ALLOW = frozenset({"@system-service"})
REQUIRED_SYSCALL_DENY = frozenset({"@privileged", "@resources"})
ALLOWED_ADDRESS_FAMILIES = frozenset({"AF_UNIX", "AF_INET", "AF_INET6"})
LOOPBACK_ADDRESSES = frozenset({"localhost", "127.0.0.0/8", "127.0.0.1", "127.0.0.1/32", "::1", "::1/128"})
ROOT_EQUIVALENT_CAPABILITIES = frozenset({"CAP_SYS_ADMIN"})
# Made writable, these undo ProtectSystem=strict wholesale (only the exact path: /run/app and /var/lib/app are fine).
BROAD_WRITABLE_PATHS = frozenset({"/", "/run", "/var"})
# Made writable, these, and everything inside them, give write access to what root runs or trusts: binaries,
# libraries, configuration, units (/etc/systemd/system, /usr/lib/systemd/system, /run/systemd/system), sudoers and
# cron drop-ins, the installed code (/opt/pai) and the boot files. A unit that truly must write inside one
# documents it with a waiver.
PROTECTED_TREES = (
    "/etc",
    "/usr",
    "/opt",
    "/boot",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/proc",
    "/sys",
    "/dev",
    "/run/systemd",
)
WRITABLE_PATH_DIRECTIVES = ("ReadWritePaths", "BindPaths")
# Exec*= prefixes that systemd accepts in any order before the command; "+" and "!" (and "!!") run it with
# elevated privileges, outside the unit's User=, CapabilityBoundingSet= and namespace sandbox.
EXEC_PREFIX_CHARACTERS = "@-:+!"
EXEC_PRIVILEGED_PREFIXES = frozenset("+!")
EXEC_NON_COMMAND_DIRECTIVES = frozenset({"ExecSearchPath", "ExecPaths"})  # path lists that share the Exec prefix

_PRAGMA = re.compile(r"^[#;]\s*pai-lint:\s*(?P<tag>[A-Za-z][\w-]*(?:\s+[A-Za-z]\w*)?)\s*:\s*(?P<reason>.*)$")
_CAPABILITY = re.compile(r"^CAP_[A-Z_]+$")


# ------------------------------------------------------------------ parsing
@dataclass(frozen=True)
class Unit:
    name: str
    has_service_section: bool
    assignments: dict[str, tuple[str, ...]]  # [Service] directive -> every assigned value, in file order
    justifications: dict[str, str]  # pai-lint tag -> reason (empty when the comment gave none)

    def scalar(self, directive: str) -> str | None:
        """The effective value of a single-valued directive (the last assignment wins), or None if unset."""
        values = self.assignments.get(directive)
        return values[-1] if values else None

    def words(self, directive: str) -> list[str] | None:
        """The effective word list of a list-valued directive, or None if unset. An empty assignment resets it."""
        values = self.assignments.get(directive)
        if values is None:
            return None
        words: list[str] = []
        for value in values:
            if value.strip():
                words.extend(value.split())
            else:
                words = []
        return words


def parse_unit(name: str, text: str) -> Unit:
    assignments: dict[str, list[str]] = {}
    justifications: dict[str, str] = {}
    section = ""
    has_service_section = False
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not pending and line.startswith(("#", ";")):
            if match := _PRAGMA.match(line):
                justifications[" ".join(match["tag"].split())] = match["reason"].strip()
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line, pending = pending + line, ""
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            has_service_section = has_service_section or section == "Service"
        elif section == "Service" and "=" in line:
            key, _, value = line.partition("=")
            assignments.setdefault(key.strip(), []).append(value.strip())
    return Unit(name, has_service_section, {k: tuple(v) for k, v in assignments.items()}, justifications)


def discover_units(root: Path = OS_DIR) -> list[Path]:
    return sorted(
        {path for directory in UNIT_DIRECTORIES for path in root.glob(f"**/{directory}/*.service") if path.is_file()}
    )


def _is_drop_in_directory(path: Path) -> bool:
    """``<unit>.service.d`` overrides one unit; ``service.d`` and ``<prefix>-.service.d`` override many."""
    return path.is_dir() and (path.name == "service.d" or path.name.endswith(".service.d"))


def discover_drop_ins(root: Path = OS_DIR) -> list[Path]:
    """Every ``*.conf`` file (the only kind systemd reads) in a service drop-in directory under a unit directory."""
    return sorted(
        {
            conf
            for directory in UNIT_DIRECTORIES
            for candidate in root.glob(f"**/{directory}/*")
            if _is_drop_in_directory(candidate)
            for conf in candidate.glob("*.conf")
            if conf.is_file()
        }
    )


# ------------------------------------------------------------------ checks
def _justified(unit: Unit, tag: str, problems: list[str]) -> bool:
    """True when the unit documents ``tag`` with a non-empty reason. A comment with no reason is itself a problem."""
    reason = unit.justifications.get(tag)
    if reason == "":
        problems.append(f"'# pai-lint: {tag}:' must give a non-empty reason")
    return bool(reason)


def _show(values: frozenset[str] | list[str] | None) -> str:
    return "unset" if values is None else ", ".join(sorted(values)) or "empty"


def _check_baseline(unit: Unit, problems: list[str]) -> None:
    for directive, requirement in BASELINE.items():
        if requirement.waivable and _justified(unit, f"waive {directive}", problems):
            continue
        value = unit.scalar(directive)
        suffix = "" if requirement.waivable else " (cannot be waived)"
        if value is None:
            problems.append(f"{directive} is not set; systemd's default is weaker than the baseline{suffix}")
        elif value.lower() not in requirement.accepted:
            allowed = _show(requirement.accepted)
            problems.append(f"{directive}={value} is weaker than the baseline (one of: {allowed}){suffix}")


def _is_root_user(user: str | None) -> bool:
    """Unset, empty, ``root``, or a numeric id that is zero however it is spelled (``0``, ``00``)."""
    return user is None or user in {"", "root"} or (user.isdecimal() and int(user) == 0)


def _runs_as_root(unit: Unit) -> bool:
    if (dynamic := unit.scalar("DynamicUser")) and dynamic.lower() in TRUTHY:
        return False
    return _is_root_user(unit.scalar("User"))


def _capability_list_problems(capabilities: list[str], who: str) -> list[str]:
    problems = []
    if any(c.startswith("~") for c in capabilities):
        problems.append(
            f"{who}: CapabilityBoundingSet uses the deny-list form (~), which keeps almost every capability"
        )
    elif bad := [c for c in capabilities if not _CAPABILITY.match(c)]:
        problems.append(f"{who}: unrecognised capability {', '.join(bad)} in CapabilityBoundingSet")
    elif equivalent := ROOT_EQUIVALENT_CAPABILITIES & set(capabilities):
        problems.append(f"{who}: {', '.join(sorted(equivalent))} in CapabilityBoundingSet is effectively all of root")
    return problems


def _check_identity_and_capabilities(unit: Unit, problems: list[str]) -> None:
    bounding = unit.words("CapabilityBoundingSet")
    ambient = unit.words("AmbientCapabilities") or []
    if _runs_as_root(unit):
        if not _justified(unit, "root-justified", problems):
            problems.append("runs as root without '# pai-lint: root-justified: <reason>'")
        if not bounding:
            problems.append(
                "root unit must set CapabilityBoundingSet to a non-empty list narrower than all capabilities"
            )
        else:
            problems += _capability_list_problems(bounding, "root unit")
        return
    if bounding == [] and not ambient:
        return
    granted = "all, CapabilityBoundingSet is unset" if bounding is None else ", ".join([*bounding, *ambient])
    if not _justified(unit, "capabilities-justified", problems):
        problems.append(
            f"grants capabilities ({granted}) without '# pai-lint: capabilities-justified: <reason>'; "
            "the baseline is an empty CapabilityBoundingSet and AmbientCapabilities"
        )
    elif not bounding:
        problems.append("capabilities-justified needs an explicit CapabilityBoundingSet list")
    else:
        problems += _capability_list_problems(bounding, "unit")
        if outside := set(ambient) - set(bounding):
            problems.append(f"AmbientCapabilities {', '.join(sorted(outside))} lie outside CapabilityBoundingSet")


def _check_network(unit: Unit, problems: list[str]) -> None:
    if _justified(unit, "network-justified", problems):
        return
    hint = "; needing more is a documented '# pai-lint: network-justified: <reason>'"
    if "any" not in (unit.words("IPAddressDeny") or []):
        problems.append(f"IPAddressDeny must include 'any'{hint}")
    if wider := [a for a in unit.words("IPAddressAllow") or [] if a not in LOOPBACK_ADDRESSES]:
        problems.append(f"IPAddressAllow grants {', '.join(wider)}, beyond loopback{hint}")
    families = unit.words("RestrictAddressFamilies")
    if not families:
        problems.append(f"RestrictAddressFamilies is not set, so every socket family is allowed{hint}")
    elif any(f.startswith("~") for f in families):
        problems.append(f"RestrictAddressFamilies uses the deny-list form (~), which allows unlisted families{hint}")
    elif extra := set(families) - ALLOWED_ADDRESS_FAMILIES:
        problems.append(f"RestrictAddressFamilies allows {', '.join(sorted(extra))}, beyond UNIX/INET/INET6{hint}")


@dataclass(frozen=True)
class SyscallFilter:
    allow_list: bool  # False: the first line started with "~", so everything not listed stays allowed
    allowed: frozenset[str]  # groups and calls added to the allow list (and not removed again)
    denied: frozenset[str]  # groups removed from it that no later line can have added back
    ignored: tuple[str, ...]  # words systemd skips: a "~" anywhere but the very start of a value


def _syscall_filter(unit: Unit) -> SyscallFilter | None:
    """What the ``SystemCallFilter=`` lines mean to systemd, or None when the unit sets none.

    systemd reads a value's ``~`` only as its very first character. The first line after a reset fixes the mode:
    without ``~`` the filter is an allow list, with it a deny list that leaves everything else allowed. In an
    allow list a later ``~`` line removes calls from it and a plain line adds calls. One name is a *group* of
    calls, and groups overlap (``@system-service`` contains calls that ``@privileged`` also names), so a group
    removed earlier can be added back piecemeal by any later adding line. ``denied`` therefore keeps only
    removals that no later line follows with an addition: put the ``~`` lines last.
    """
    values = unit.assignments.get("SystemCallFilter")
    if values is None:
        return None
    allow_list: bool | None = None
    allowed: set[str] = set()
    denied: set[str] = set()
    ignored: list[str] = []
    for value in values:
        if not value.strip():  # an empty assignment resets the filter
            allow_list, allowed, denied, ignored = None, set(), set(), []
            continue
        invert = value.startswith("~")
        words = (value[1:] if invert else value).split()
        ignored += [word for word in words if word.startswith("~")]
        if allow_list is None:
            allow_list = not invert
        if not allow_list:
            continue
        if invert:
            allowed -= set(words)
            denied |= set(words)
        elif words:
            allowed |= set(words)
            denied = set()
    return SyscallFilter(allow_list is not False, frozenset(allowed), frozenset(denied), tuple(ignored))


def _check_syscalls(unit: Unit, problems: list[str]) -> None:
    if _justified(unit, "waive SystemCallFilter", problems):
        return
    syscalls = _syscall_filter(unit)
    if syscalls is None:
        problems.append(f"SystemCallFilter must allow {', '.join(sorted(REQUIRED_SYSCALL_ALLOW))}")
        return
    for word in syscalls.ignored:
        problems.append(f"SystemCallFilter word {word} is ignored: systemd honours '~' only at the start of a value")
    if not syscalls.allow_list:
        problems.append(
            "SystemCallFilter is a deny list (its first line starts with '~'), so every call not listed stays "
            f"allowed; the baseline is an allow list of {', '.join(sorted(REQUIRED_SYSCALL_ALLOW))}"
        )
        return
    if missing := REQUIRED_SYSCALL_ALLOW - syscalls.allowed:
        problems.append(f"SystemCallFilter must allow {', '.join(sorted(missing))}")
    if missing := REQUIRED_SYSCALL_DENY - syscalls.denied:
        problems.append(
            f"SystemCallFilter must deny {', '.join('~' + m for m in sorted(missing))}, each on a line that starts "
            "with '~' and comes after every line that allows calls"
        )


def _canonical_path(path: str) -> str:
    """The path as systemd resolves it: normalised, never ``//``-rooted, and ``/var/run`` is ``/run``."""
    normalized = "/" + posixpath.normpath(path).lstrip("/")  # POSIX normpath keeps a leading "//"
    return re.sub(r"^/var/run(?=/|$)", "/run", normalized)


def _writable_path_problem(path: str) -> str | None:
    canonical = _canonical_path(path)
    if canonical in BROAD_WRITABLE_PATHS:
        return "undoes ProtectSystem=strict"
    for tree in PROTECTED_TREES:
        if canonical == tree or canonical.startswith(f"{tree}/"):
            return f"is inside {tree}, which holds what root runs or trusts"
    return None


def _check_writable_paths(unit: Unit, problems: list[str]) -> None:
    for directive in WRITABLE_PATH_DIRECTIVES:
        if _justified(unit, f"waive {directive}", problems):
            continue
        for entry in unit.words(directive) or []:
            for part in entry.lstrip("-+!").split(":")[:2]:
                if reason := _writable_path_problem(part):
                    problems.append(f"{directive} makes {part} writable, which {reason}")


def _check_exec_privileges(unit: Unit, problems: list[str]) -> None:
    """A ``+`` or ``!`` prefix runs that command line with full privileges, outside everything the unit sets."""
    for directive, values in unit.assignments.items():
        if not directive.startswith("Exec") or directive in EXEC_NON_COMMAND_DIRECTIVES:
            continue
        if _justified(unit, f"waive {directive}", problems):
            continue
        for value in values:
            prefix = value[: len(value) - len(value.lstrip(EXEC_PREFIX_CHARACTERS))]
            if EXEC_PRIVILEGED_PREFIXES & set(prefix):
                problems.append(
                    f"{directive}={prefix}... runs a command with full privileges, outside User=, "
                    f"CapabilityBoundingSet= and the sandbox; needing it is a documented "
                    f"'# pai-lint: waive {directive}: <reason>'"
                )


def lint_unit(unit: Unit) -> list[str]:
    if not unit.has_service_section:
        return ["has no [Service] section"]
    problems: list[str] = []
    _check_baseline(unit, problems)
    _check_identity_and_capabilities(unit, problems)
    _check_network(unit, problems)
    _check_syscalls(unit, problems)
    _check_writable_paths(unit, problems)
    _check_exec_privileges(unit, problems)
    return problems


# ------------------------------------------------------------------ the real units
UNITS = discover_units()


def _relative(path: Path) -> str:
    return path.relative_to(OS_DIR).as_posix()


def test_units_are_discovered() -> None:
    # Guards against the parametrized lint below passing vacuously on an empty set.
    assert UNITS, f"no *.service files found under {OS_DIR}"


def test_no_service_has_a_drop_in() -> None:
    # A drop-in overrides a unit after the fact, so the lint of the unit file alone would say nothing about it.
    drop_ins = [_relative(path) for path in discover_drop_ins()]
    assert drop_ins == [], "drop-ins are not allowed (put the setting in the unit file): " + ", ".join(drop_ins)


@pytest.mark.parametrize("unit_path", UNITS, ids=_relative)
def test_unit_meets_the_sandbox_baseline(unit_path: Path) -> None:
    problems = lint_unit(parse_unit(unit_path.name, unit_path.read_text(encoding="utf-8")))
    assert problems == [], f"{_relative(unit_path)}:\n  " + "\n  ".join(problems)


@pytest.mark.parametrize("unit_path", UNITS, ids=_relative)
def test_unit_uses_lf_line_endings(unit_path: Path) -> None:
    # systemd would read a trailing carriage return as part of every value.
    assert b"\r" not in unit_path.read_bytes()


# ------------------------------------------------------------------ the backend unit and its contracts
SYSTEMD_ROOT = OS_DIR / "systemd"
BACKEND_UNIT = SYSTEMD_ROOT / "rootfs" / "etc" / "systemd" / "system" / "pai-backend.service"
SYSUSERS = SYSTEMD_ROOT / "rootfs" / "usr" / "lib" / "sysusers.d" / "pai.conf"
BACKEND_HOOK = SYSTEMD_ROOT / "hooks" / "0200-enable-pai-backend.hook.chroot"


def _backend_unit() -> Unit:
    return parse_unit(BACKEND_UNIT.name, BACKEND_UNIT.read_text(encoding="utf-8"))


def _sysusers_entries() -> list[list[str]]:
    lines = (line.strip() for line in SYSUSERS.read_text(encoding="utf-8").splitlines())
    return [shlex.split(line) for line in lines if line and not line.startswith("#")]


def test_backend_unit_runs_unprivileged_from_the_installed_code() -> None:
    unit = _backend_unit()
    assert not _runs_as_root(unit)
    assert unit.scalar("User") == unit.scalar("Group") == "pai"
    assert unit.scalar("Type") == "exec"
    assert unit.scalar("Restart") == "on-failure"
    assert unit.scalar("WorkingDirectory") == "/opt/pai"
    assert unit.scalar("ExecStart") == "/usr/bin/python3 -s -m backend"
    assert unit.words("CapabilityBoundingSet") == []
    assert unit.words("AmbientCapabilities") == []
    assert unit.words("IPAddressDeny") == ["any"]
    assert unit.words("IPAddressAllow") == ["localhost"]


def test_backend_unit_state_and_runtime_directories_match_the_backend_defaults() -> None:
    from backend.api.auth import TOKEN_DIRECTORY_MODE
    from backend.core.config import DATA_DIR_MODE, DEFAULT_DATA_DIR, DEFAULT_TOKEN_FILE

    unit = _backend_unit()
    assert DEFAULT_DATA_DIR.as_posix() == f"/var/lib/{unit.scalar('StateDirectory')}"
    assert DEFAULT_TOKEN_FILE.parent.as_posix() == f"/run/{unit.scalar('RuntimeDirectory')}"
    assert unit.scalar("StateDirectoryMode") == f"{DATA_DIR_MODE:04o}"
    assert unit.scalar("RuntimeDirectoryMode") == f"{TOKEN_DIRECTORY_MODE:04o}"


def test_only_the_runtime_directory_is_shared_with_the_kiosk_group() -> None:
    from backend.api.auth import TOKEN_DIRECTORY_MODE
    from backend.core.config import DATA_DIR_MODE

    # The kiosk user shares the service's group to read the token, not to see the data it keeps.
    assert not DATA_DIR_MODE & 0o077, "the data directory must be private to the service account"
    assert TOKEN_DIRECTORY_MODE & 0o050 == 0o050, "the group must be able to list and enter the token directory"
    assert not TOKEN_DIRECTORY_MODE & 0o027, "the group must not write to it and others must have no access"


def _interpreter_options(command: str) -> list[str]:
    """The interpreter's own options: the words between the interpreter and ``-m``."""
    words = shlex.split(command)
    assert "-m" in words, f"{command!r} does not run a module"
    return words[1 : words.index("-m")]


def test_backend_unit_does_not_load_code_from_the_user_site_of_its_own_writable_home() -> None:
    # HOME is the service's writable state directory. Without -s (or PYTHONNOUSERSITE) a *.pth file or
    # usercustomize.py written there would run inside the service at every start, whatever protects /opt/pai.
    options = _interpreter_options(_backend_unit().scalar("ExecStart") or "")
    interpreter = getattr(sys, "_base_executable", sys.executable)  # a virtual environment has no user site
    with tempfile.TemporaryDirectory() as scratch:
        base = Path(scratch)
        environment = {**os.environ, "PYTHONUSERBASE": str(base / "userbase")}
        environment.pop("PYTHONNOUSERSITE", None)
        user_site = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [interpreter, "-c", "import site; print(site.getusersitepackages())"],
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        Path(user_site).mkdir(parents=True)
        marker = base / "probe-ran"
        (Path(user_site) / "pai_probe.pth").write_text(
            f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ran')\n", encoding="utf-8"
        )

        # Control: the same interpreter without the unit's options runs the probe, so passing below proves something.
        subprocess.run([interpreter, "-c", "pass"], env=environment, check=True)  # noqa: S603
        if not marker.exists():
            pytest.skip("this interpreter does not load a user site directory, so there is nothing to prove")
        marker.unlink()

        subprocess.run([interpreter, *options, "-c", "pass"], env=environment, check=True)  # noqa: S603
        assert not marker.exists(), f"python3 {' '.join(options)} still ran code from the user site directory"


def test_backend_unit_does_not_override_the_loopback_only_settings() -> None:
    environment = " ".join(_backend_unit().assignments.get("Environment", ()))
    assert not re.search(r"\bPAI_(HOST|PORT)\b", environment)


def test_backend_unit_does_not_restart_after_exits_a_restart_cannot_fix() -> None:
    from backend.core.exit_codes import EXIT_CONFIG, EXIT_REFUSED_ROOT

    assert set(_backend_unit().words("RestartPreventExitStatus") or []) == {str(EXIT_REFUSED_ROOT), str(EXIT_CONFIG)}


def test_sysusers_defines_the_planned_service_accounts_without_login() -> None:
    entries = _sysusers_entries()
    users = {entry[1]: entry for entry in entries if entry[0] == "u"}
    # The PHASE1_PLAN M1.3 accounts, the M1.4 kiosk account and the account of the boot self-check (M1.2).
    assert set(users) == {"pai", "pai-llm", "pai-ui", "pai-selfcheck"}
    assert all(entry[-1] == "/usr/sbin/nologin" for entry in users.values())
    assert _backend_unit().scalar("User") in users


@pytest.mark.parametrize("unit_path", UNITS, ids=_relative)
def test_every_unit_runs_as_an_account_the_image_defines(unit_path: Path) -> None:
    # An account that no sysusers file defines does not exist on the image: systemd would fail the unit at boot with
    # status 217/USER. Root and DynamicUser units have no account to define.
    unit = parse_unit(unit_path.name, unit_path.read_text(encoding="utf-8"))
    user = unit.scalar("User")
    if _runs_as_root(unit) or user is None:
        pytest.skip("runs as root or as a dynamic user")
    assert user in {entry[1] for entry in _sysusers_entries() if entry[0] == "u"}, f"{user} is not in any sysusers file"


def test_the_model_runtime_account_joins_no_group() -> None:
    # pai-llm runs untrusted model files without a network; it must not share the backend's token or data.
    assert [entry for entry in _sysusers_entries() if entry[0] == "m" and entry[1] == "pai-llm"] == []


def test_token_group_lets_the_kiosk_read_but_not_write_the_token() -> None:
    from backend.api.auth import TOKEN_FILE_MODE

    # The backend creates the token as <User>:<Group> with TOKEN_FILE_MODE; the kiosk user must be in that group, and
    # so must the boot self-check, which proves the API accepts the token and refuses requests without it. Nobody
    # else may read the token, so the members are exactly these two.
    unit = _backend_unit()
    members = {entry[1] for entry in _sysusers_entries() if entry[0] == "m" and entry[2] == unit.scalar("Group")}
    assert members == {"pai-ui", "pai-selfcheck"}
    assert TOKEN_FILE_MODE & 0o040, "the group must be able to read the token"
    assert not TOKEN_FILE_MODE & 0o020, "the group must not be able to write the token"
    assert not TOKEN_FILE_MODE & 0o007, "others must have no access to the token"


def _hook_commands() -> list[list[str]]:
    """The hook's executable lines, split as the shell splits them; comments (and the shebang) are dropped."""
    lines = (line.strip() for line in BACKEND_HOOK.read_text(encoding="utf-8").splitlines())
    return [shlex.split(line, comments=True) for line in lines if line and not line.startswith("#")]


def _in_the_overlay(image_path: str) -> Path:
    return SYSTEMD_ROOT / "rootfs" / image_path.lstrip("/")


def test_hook_is_a_shell_script_that_stops_at_the_first_failure() -> None:
    assert BACKEND_HOOK.read_text(encoding="utf-8").startswith("#!/bin/sh\n")
    # Without set -e a failed account creation would not stop the image build.
    assert any(c[0] == "set" and any(a.startswith("-") and "e" in a for a in c[1:]) for c in _hook_commands())


def test_hook_creates_the_accounts_from_the_sysusers_file_the_overlay_ships() -> None:
    # Created at build time because the boot-time systemd-sysusers.service runs only when /etc needs an update.
    targets = [c[1] for c in _hook_commands() if c[:1] == ["systemd-sysusers"] and len(c) == 2]
    assert targets == ["/" + SYSUSERS.relative_to(SYSTEMD_ROOT / "rootfs").as_posix()]
    assert _in_the_overlay(targets[0]).is_file()


def test_hook_enables_the_unit_the_overlay_ships() -> None:
    assert ["systemctl", "enable", BACKEND_UNIT.name] in _hook_commands()
    assert _in_the_overlay(f"/etc/systemd/system/{BACKEND_UNIT.name}").is_file()


def test_hook_does_not_repeat_the_mode_rule_of_the_assembly_script() -> None:
    # os/build/assemble-config.sh gives every installed file its mode (tests/security/test_image_assembly.py), so
    # a chmod here would be a second copy of that rule that can drift from it.
    assert [c for c in _hook_commands() if c[0] in {"chmod", "chown", "find"}] == []


# ------------------------------------------------------------------ linter self-tests
# A reference unit that must pass. It restates the baseline literally (not from the tables above) so a mistake
# in a table is caught here instead of being copied into both sides.
GOOD_UNIT = """\
[Unit]
Description=Reference unit

[Service]
Type=exec
User=svc
ExecStart=/usr/bin/true
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
UMask=0077
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
"""


def lint(text: str) -> list[str]:
    return lint_unit(parse_unit("test.service", text))


def without(text: str, directive: str) -> str:
    kept = [line for line in text.splitlines() if not line.startswith(f"{directive}=")]
    assert len(kept) < len(text.splitlines()), f"{directive} is not in the reference unit"
    return "\n".join(kept) + "\n"


def replaced(text: str, directive: str, value: str) -> str:
    lines = text.splitlines()
    assert any(line.startswith(f"{directive}=") for line in lines), f"{directive} is not in the reference unit"
    out = [f"{directive}={value}" if line.startswith(f"{directive}=") else line for line in lines]
    return "\n".join(out) + "\n"


def with_service_lines(text: str, *lines: str) -> str:
    return text.replace("[Install]", "\n".join(lines) + "\n\n[Install]")


def as_root(text: str, *, reason: str = "needs the raw device", bounding: str = "CAP_DAC_READ_SEARCH") -> str:
    text = without(text, "User")
    text = replaced(text, "CapabilityBoundingSet", bounding)
    return f"# pai-lint: root-justified: {reason}\n" + text


def mentions(problems: list[str], *needles: str) -> bool:
    return any(all(needle in problem for needle in needles) for problem in problems)


def test_reference_unit_passes() -> None:
    assert lint(GOOD_UNIT) == []


def test_reference_unit_covers_every_baseline_directive() -> None:
    assert set(BASELINE) <= {line.split("=")[0] for line in GOOD_UNIT.splitlines()}


@pytest.mark.parametrize("directive", sorted(BASELINE))
def test_omitting_a_baseline_directive_is_a_violation(directive: str) -> None:
    assert mentions(lint(without(GOOD_UNIT, directive)), directive, "not set")


@pytest.mark.parametrize(
    ("directive", "weak"),
    [
        ("NoNewPrivileges", "no"),
        ("ProtectSystem", "full"),
        ("ProtectSystem", "yes"),
        ("ProtectHome", "no"),
        ("ProtectHome", "read-only"),
        ("PrivateTmp", "no"),
        ("PrivateDevices", "no"),
        ("ProtectKernelTunables", "no"),
        ("ProtectKernelModules", "no"),
        ("ProtectKernelLogs", "no"),
        ("ProtectControlGroups", "no"),
        ("ProtectClock", "no"),
        ("ProtectHostname", "no"),
        ("ProtectProc", "default"),
        ("ProtectProc", "ptraceable"),
        ("ProcSubset", "all"),
        ("RestrictNamespaces", "no"),
        ("RestrictRealtime", "no"),
        ("RestrictSUIDSGID", "no"),
        ("LockPersonality", "no"),
        ("MemoryDenyWriteExecute", "no"),
        ("SystemCallArchitectures", "x86-64"),
        ("UMask", "0022"),
        ("UMask", "0027"),
    ],
)
def test_weakening_a_baseline_directive_is_a_violation(directive: str, weak: str) -> None:
    assert mentions(lint(replaced(GOOD_UNIT, directive, weak)), directive, "weaker")


def test_boolean_spellings_are_all_accepted() -> None:
    for spelling in ("yes", "true", "1", "on", "YES", "True"):
        assert lint(replaced(GOOD_UNIT, "PrivateTmp", spelling)) == []


def test_a_later_assignment_overrides_an_earlier_one() -> None:
    weakened = with_service_lines(GOOD_UNIT, "NoNewPrivileges=no")
    assert mentions(lint(weakened), "NoNewPrivileges=no")


def test_directives_outside_the_service_section_do_not_count() -> None:
    moved = without(GOOD_UNIT, "NoNewPrivileges").replace("[Unit]", "[Unit]\nNoNewPrivileges=yes")
    assert mentions(lint(moved), "NoNewPrivileges", "not set")


def test_a_unit_without_a_service_section_is_rejected() -> None:
    assert lint("[Unit]\nDescription=x\n") == ["has no [Service] section"]


def test_unknown_directives_are_ignored() -> None:
    assert lint(with_service_lines(GOOD_UNIT, "SomeFutureDirective=on", "Restart=always", "Environment=A=b")) == []


def test_parser_handles_continuations_comments_and_spacing() -> None:
    text = GOOD_UNIT.replace("UMask=0077", "; a comment\nUMask = 0077")
    text = text.replace(
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "RestrictAddressFamilies=AF_UNIX \\\n  AF_INET \\\n  AF_INET6",
    )
    assert lint(text) == []
    assert parse_unit("x", text).words("RestrictAddressFamilies") == ["AF_UNIX", "AF_INET", "AF_INET6"]


# --- root
@pytest.mark.parametrize("setting", [None, "User=root", "User=0", "User=00", "User=000", "User="])
def test_root_without_justification_is_rejected(setting: str | None) -> None:
    text = without(GOOD_UNIT, "User")
    text = text if setting is None else with_service_lines(text, setting)
    text = replaced(text, "CapabilityBoundingSet", "CAP_DAC_READ_SEARCH")
    assert mentions(lint(text), "runs as root without")


def test_root_with_an_empty_justification_is_rejected() -> None:
    problems = lint(as_root(GOOD_UNIT, reason=""))
    assert mentions(problems, "non-empty reason")
    assert mentions(problems, "runs as root without")


def test_justified_root_with_a_narrow_capability_set_passes() -> None:
    assert lint(as_root(GOOD_UNIT)) == []


def test_justified_root_still_needs_no_new_privileges() -> None:
    assert mentions(lint(without(as_root(GOOD_UNIT), "NoNewPrivileges")), "NoNewPrivileges", "cannot be waived")


def test_no_new_privileges_cannot_be_waived() -> None:
    text = "# pai-lint: waive NoNewPrivileges: because\n" + replaced(GOOD_UNIT, "NoNewPrivileges", "no")
    assert mentions(lint(text), "NoNewPrivileges=no")


@pytest.mark.parametrize(
    "bounding", ["", "~", "~CAP_SYS_ADMIN", "~CAP_NET_RAW", "CAP_SYS_ADMIN", "CAP_NET_ADMIN CAP_SYS_ADMIN"]
)
def test_justified_root_needs_a_non_empty_capability_list_narrower_than_all(bounding: str) -> None:
    assert lint(as_root(GOOD_UNIT, bounding=bounding)) != []


def test_justified_root_with_an_unset_capability_bounding_set_is_rejected() -> None:
    assert mentions(lint(without(as_root(GOOD_UNIT), "CapabilityBoundingSet")), "root unit", "CapabilityBoundingSet")


@pytest.mark.parametrize("user", ["1", "01", "1000", "pai", "svc"])
def test_a_user_that_is_not_root_is_not_treated_as_root(user: str) -> None:
    assert lint(replaced(GOOD_UNIT, "User", user)) == []


def test_dynamic_user_is_not_root() -> None:
    text = with_service_lines(without(GOOD_UNIT, "User"), "DynamicUser=yes")
    assert lint(text) == []


def test_justification_may_use_a_semicolon_comment() -> None:
    text = as_root(GOOD_UNIT).replace("# pai-lint:", "; pai-lint:")
    assert lint(text) == []


# --- capabilities
@pytest.mark.parametrize(
    "extra",
    [
        ["CapabilityBoundingSet=CAP_NET_BIND_SERVICE"],
        ["AmbientCapabilities=CAP_NET_BIND_SERVICE"],
        ["CapabilityBoundingSet=~CAP_SYS_ADMIN"],
        ["CapabilityBoundingSet=~"],
    ],
)
def test_granting_capabilities_without_a_documented_need_is_rejected(extra: list[str]) -> None:
    assert mentions(lint(with_service_lines(GOOD_UNIT, *extra)), "capabilities")


def test_leaving_the_capability_bounding_set_unset_is_rejected() -> None:
    assert mentions(lint(without(GOOD_UNIT, "CapabilityBoundingSet")), "all, CapabilityBoundingSet is unset")


def test_a_reset_removes_earlier_capabilities() -> None:
    text = with_service_lines(GOOD_UNIT, "CapabilityBoundingSet=CAP_NET_RAW", "CapabilityBoundingSet=")
    assert lint(text) == []


def test_documented_capabilities_are_accepted() -> None:
    text = replaced(GOOD_UNIT, "CapabilityBoundingSet", "CAP_NET_BIND_SERVICE")
    text = replaced(text, "AmbientCapabilities", "CAP_NET_BIND_SERVICE")
    assert lint("# pai-lint: capabilities-justified: binds a low port\n" + text) == []


@pytest.mark.parametrize(
    ("bounding", "ambient"),
    [
        ("~CAP_SYS_ADMIN", ""),
        ("CAP_SYS_ADMIN", ""),
        ("", "CAP_NET_RAW"),
        ("CAP_NET_RAW", "CAP_CHOWN"),
        ("cap_net_raw", ""),
    ],
)
def test_documented_capabilities_must_still_be_narrow_and_consistent(bounding: str, ambient: str) -> None:
    text = replaced(replaced(GOOD_UNIT, "CapabilityBoundingSet", bounding), "AmbientCapabilities", ambient)
    assert lint("# pai-lint: capabilities-justified: a reason\n" + text) != []


def test_capability_justification_without_a_reason_does_not_count() -> None:
    text = replaced(GOOD_UNIT, "CapabilityBoundingSet", "CAP_NET_RAW")
    assert mentions(lint("# pai-lint: capabilities-justified:\n" + text), "non-empty reason")


# --- network
def test_missing_ip_deny_is_rejected() -> None:
    assert mentions(lint(without(GOOD_UNIT, "IPAddressDeny")), "IPAddressDeny")


@pytest.mark.parametrize("allowed", ["any", "192.168.0.0/16", "localhost 10.0.0.0/8", "link-local", "multicast"])
def test_ip_allow_beyond_loopback_is_rejected(allowed: str) -> None:
    assert mentions(lint(replaced(GOOD_UNIT, "IPAddressAllow", allowed)), "IPAddressAllow")


@pytest.mark.parametrize(
    "families", ["AF_UNIX AF_INET AF_INET6 AF_NETLINK", "AF_PACKET", "~AF_PACKET", "AF_UNIX AF_BLUETOOTH"]
)
def test_socket_families_beyond_unix_and_ip_are_rejected(families: str) -> None:
    assert mentions(lint(replaced(GOOD_UNIT, "RestrictAddressFamilies", families)), "RestrictAddressFamilies")


def test_unset_or_empty_address_families_are_rejected() -> None:
    assert mentions(lint(without(GOOD_UNIT, "RestrictAddressFamilies")), "RestrictAddressFamilies")
    assert mentions(lint(replaced(GOOD_UNIT, "RestrictAddressFamilies", "")), "RestrictAddressFamilies")


def test_documented_network_need_is_accepted() -> None:
    text = replaced(GOOD_UNIT, "RestrictAddressFamilies", "AF_UNIX AF_NETLINK")
    text = replaced(without(text, "IPAddressDeny"), "IPAddressAllow", "10.0.0.0/8")
    assert lint("# pai-lint: network-justified: reads interface state over netlink\n" + text) == []


def test_network_justification_without_a_reason_does_not_count() -> None:
    text = replaced(GOOD_UNIT, "RestrictAddressFamilies", "AF_NETLINK")
    assert mentions(lint("# pai-lint: network-justified:   \n" + text), "non-empty reason")


# --- system calls
def syscall_filter_lint(*lines: str) -> list[str]:
    return lint(with_service_lines(without(GOOD_UNIT, "SystemCallFilter"), *lines))


@pytest.mark.parametrize(
    "lines",
    [
        ["SystemCallFilter="],  # reset, then nothing
        ["SystemCallFilter=", "SystemCallFilter=@system-service"],
        ["SystemCallFilter=", "SystemCallFilter=~@privileged"],
        ["SystemCallFilter=", "SystemCallFilter=@system-service ~@privileged"],
        ["SystemCallFilter=", "SystemCallFilter=@system-service ~@resources"],
        ["SystemCallFilter=", "SystemCallFilter=~@privileged @resources"],
        ["SystemCallFilter=@system-service", "SystemCallFilter=~@privileged"],
        ["SystemCallFilter=@system-service", "SystemCallFilter=~@resources"],
    ],
)
def test_incomplete_syscall_filters_are_rejected(lines: list[str]) -> None:
    assert mentions(syscall_filter_lint(*lines), "SystemCallFilter")


# Each of these is weaker than the baseline when systemd 257 reads it (checked with `systemd-analyze security
# --offline=true`: the baseline scores 1.1, these 1.3 to 2.2). The first line fixes allow list or deny list, a "~"
# counts only at the very start of a value, and a later line that allows calls can add back what an earlier "~" removed.
@pytest.mark.parametrize(
    ("lines", "reason"),
    [
        (["SystemCallFilter=@system-service ~@privileged ~@resources"], "ignored"),  # "~" mid-value is not an operator
        (["SystemCallFilter=@system-service ~@privileged @resources"], "ignored"),
        (["SystemCallFilter=~@privileged @resources", "SystemCallFilter=@system-service"], "deny list"),
        (["SystemCallFilter=~@privileged @resources"], "deny list"),
        (
            [
                "SystemCallFilter=@system-service",
                "SystemCallFilter=~@privileged @resources",
                "SystemCallFilter=@privileged",
            ],
            "deny",
        ),
        (
            [
                "SystemCallFilter=@system-service",
                "SystemCallFilter=~@privileged @resources",
                "SystemCallFilter=@file-system",
            ],
            "after every line",
        ),
        (
            [
                "SystemCallFilter=@system-service",
                "SystemCallFilter=~@privileged @resources",
                "SystemCallFilter=~@system-service",
            ],
            "must allow",
        ),
    ],
)
def test_syscall_filters_that_systemd_reads_as_weaker_are_rejected(lines: list[str], reason: str) -> None:
    assert mentions(syscall_filter_lint(*lines), "SystemCallFilter", reason)


@pytest.mark.parametrize(
    "lines",
    [
        ["SystemCallFilter=@system-service", "SystemCallFilter=~@privileged", "SystemCallFilter=~@resources"],
        ["SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources"],
        ["SystemCallFilter=@system-service @file-system", "SystemCallFilter=~@privileged @resources"],
        [
            "SystemCallFilter=@file-system",
            "SystemCallFilter=@system-service",
            "SystemCallFilter=~@privileged @resources",
        ],
        [
            "SystemCallFilter=@system-service",
            "SystemCallFilter=~ @privileged @resources",
        ],  # "~" then a space: same value
        ["SystemCallFilter=@system-service", "SystemCallFilter=~@privileged", "SystemCallFilter=~@resources @mount"],
    ],
)
def test_equivalent_ways_of_writing_the_syscall_filter_are_accepted(lines: list[str]) -> None:
    assert syscall_filter_lint(*lines) == []


def test_a_reset_discards_an_earlier_deny_list_and_the_next_line_decides_again() -> None:
    lines = [
        "SystemCallFilter=~@mount",
        "SystemCallFilter=",
        "SystemCallFilter=@system-service",
        "SystemCallFilter=~@privileged @resources",
    ]
    assert syscall_filter_lint(*lines) == []


def test_a_missing_syscall_filter_is_rejected() -> None:
    assert mentions(lint(without(GOOD_UNIT, "SystemCallFilter")), "SystemCallFilter must allow")


# --- writable paths
@pytest.mark.parametrize(
    "entry",
    [
        "/", "/etc", "/usr", "/var", "/run", "-/etc", "/etc/", "/var/lib/..", "/data /etc",
        "//etc",  # POSIX normpath keeps a leading "//"; systemd reads it as "/etc"
        "/var/run",  # a symlink to /run
    ],
)  # fmt: skip
def test_making_system_directories_writable_is_rejected(entry: str) -> None:
    assert mentions(lint(with_service_lines(GOOD_UNIT, f"ReadWritePaths={entry}")), "ReadWritePaths", "writable")


@pytest.mark.parametrize(
    "entry",
    [
        # Inside a system tree: write access there is write access to what root runs or trusts.
        "/etc/systemd/system", "/usr/local/bin", "/etc/sudoers.d", "/etc/cron.d", "/usr/lib/systemd/system",
        "/opt/pai", "/boot/efi", "/lib/systemd/system", "/dev/shm", "/sys/fs/cgroup",  # noqa: S108
        "/run/systemd/system", "/var/run/systemd/system", "/etc/./ssh/../systemd",
    ],
)  # fmt: skip
def test_making_a_path_inside_a_system_tree_writable_is_rejected(entry: str) -> None:
    problems = lint(with_service_lines(GOOD_UNIT, f"ReadWritePaths={entry}"))
    assert mentions(problems, "ReadWritePaths", "writable", "inside")


def test_bind_mounts_over_system_directories_are_rejected() -> None:
    assert mentions(lint(with_service_lines(GOOD_UNIT, "BindPaths=/srv/data:/etc")), "BindPaths")
    assert mentions(lint(with_service_lines(GOOD_UNIT, "BindPaths=/srv/x:/etc/systemd/system")), "BindPaths", "inside")
    assert mentions(lint(with_service_lines(GOOD_UNIT, "BindPaths=/usr/local/bin:/srv/x")), "BindPaths", "inside")


def test_writable_application_subdirectories_are_accepted() -> None:
    assert lint(with_service_lines(GOOD_UNIT, "ReadWritePaths=/var/lib/app /run/app", "BindPaths=/srv/a:/mnt/a")) == []


@pytest.mark.parametrize(
    "entry", ["/etcetera/data", "/optional", "/usr2/x", "/run/appsystemd", "/var/log/app", "/srv/usr"]
)
def test_a_name_that_merely_starts_like_a_system_tree_is_not_inside_it(entry: str) -> None:
    assert lint(with_service_lines(GOOD_UNIT, f"ReadWritePaths={entry}")) == []


# --- privileged command lines
COMMAND_DIRECTIVES = [
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecCondition",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
]


@pytest.mark.parametrize("prefix", ["+", "!", "!!", "-+", "+-", "@+", ":!", "-!!", "!-"])
@pytest.mark.parametrize("directive", COMMAND_DIRECTIVES)
def test_a_command_line_run_with_full_privileges_is_rejected(directive: str, prefix: str) -> None:
    # "+" and "!" run the line outside User=, the capability bound and the namespaces: the sandbox does not apply.
    problems = lint(with_service_lines(GOOD_UNIT, f"{directive}={prefix}/bin/sh -c 'cp /x /usr/local/bin/x'"))
    assert mentions(problems, directive, "full privileges")


@pytest.mark.parametrize("prefix", ["", "-", "@", ":", "-@", "@-:"])
@pytest.mark.parametrize("directive", COMMAND_DIRECTIVES)
def test_command_lines_with_harmless_prefixes_are_accepted(directive: str, prefix: str) -> None:
    assert lint(with_service_lines(GOOD_UNIT, f"{directive}={prefix}/usr/bin/true")) == []


def test_an_arguments_plus_sign_is_not_a_prefix() -> None:
    assert lint(with_service_lines(GOOD_UNIT, "ExecStartPre=/usr/bin/env A=+1 B=!x /usr/bin/true")) == []


def test_exec_directives_that_are_not_commands_are_not_judged_as_commands() -> None:
    assert lint(with_service_lines(GOOD_UNIT, "ExecSearchPath=/usr/bin", "ExecPaths=+/usr/bin")) == []


def test_resetting_a_command_list_is_accepted() -> None:
    assert lint(with_service_lines(GOOD_UNIT, "ExecStartPre=", "ExecStopPost=")) == []


def test_a_privileged_command_can_be_waived_for_that_directive_only_with_a_reason() -> None:
    text = with_service_lines(GOOD_UNIT, "ExecStartPre=+/usr/bin/install -d /run/x", "ExecStopPost=!/usr/bin/true")
    problems = lint("# pai-lint: waive ExecStartPre: creates a directory the unit's user may not\n" + text)
    assert not mentions(problems, "ExecStartPre")
    assert mentions(problems, "ExecStopPost", "full privileges")
    assert mentions(lint("# pai-lint: waive ExecStartPre:\n" + text), "non-empty reason")


# --- waivers
def test_a_documented_waiver_allows_one_weaker_directive() -> None:
    text = replaced(GOOD_UNIT, "MemoryDenyWriteExecute", "no")
    assert lint("# pai-lint: waive MemoryDenyWriteExecute: the interpreter JIT needs W+X memory\n" + text) == []


def test_a_waiver_applies_only_to_the_named_directive() -> None:
    text = replaced(replaced(GOOD_UNIT, "MemoryDenyWriteExecute", "no"), "PrivateDevices", "no")
    problems = lint("# pai-lint: waive MemoryDenyWriteExecute: needs W+X\n" + text)
    assert mentions(problems, "PrivateDevices")
    assert not mentions(problems, "MemoryDenyWriteExecute")


def test_a_waiver_without_a_reason_does_not_count() -> None:
    text = "# pai-lint: waive MemoryDenyWriteExecute:\n" + replaced(GOOD_UNIT, "MemoryDenyWriteExecute", "no")
    problems = lint(text)
    assert mentions(problems, "non-empty reason")
    assert mentions(problems, "MemoryDenyWriteExecute=no")


def test_the_syscall_filter_and_path_checks_can_be_waived_with_a_reason() -> None:
    text = with_service_lines(without(GOOD_UNIT, "SystemCallFilter"), "ReadWritePaths=/etc")
    waived = "# pai-lint: waive SystemCallFilter: legacy tool\n# pai-lint: waive ReadWritePaths: edits /etc\n" + text
    assert lint(waived) == []


# --- discovery
def _touch(path: Path, text: str = "[Service]\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_discovery_finds_units_in_every_systemd_unit_directory_and_nothing_else(tmp_path: Path) -> None:
    wanted = [
        _touch(tmp_path / "a" / "rootfs" / "etc" / "systemd" / "system" / "one.service"),
        _touch(tmp_path / "b" / "rootfs" / "usr" / "lib" / "systemd" / "system" / "two.service"),
        _touch(tmp_path / "c" / "rootfs" / "lib" / "systemd" / "system" / "three.service"),
        _touch(tmp_path / "d" / "rootfs" / "usr" / "local" / "lib" / "systemd" / "system" / "four.service"),
        _touch(tmp_path / "e" / "rootfs" / "run" / "systemd" / "system" / "five.service"),
    ]
    for ignored in (
        tmp_path / "a" / "rootfs" / "etc" / "systemd" / "system" / "note.txt",
        tmp_path / "a" / "rootfs" / "etc" / "systemd" / "system" / "timer.timer",
        tmp_path / "a" / "rootfs" / "etc" / "systemd" / "user" / "user.service",
        tmp_path / "docs" / "example.service",
    ):
        _touch(ignored)
    assert discover_units(tmp_path) == sorted(wanted)


def test_discovery_of_an_empty_tree_finds_nothing(tmp_path: Path) -> None:
    assert discover_units(tmp_path) == []
    assert discover_drop_ins(tmp_path) == []


def test_drop_ins_are_found_wherever_a_service_can_be_overridden(tmp_path: Path) -> None:
    etc = tmp_path / "a" / "rootfs" / "etc" / "systemd" / "system"
    lib = tmp_path / "b" / "rootfs" / "usr" / "lib" / "systemd" / "system"
    wanted = [
        _touch(etc / "pai-backend.service.d" / "10-debug.conf"),  # one unit
        _touch(lib / "service.d" / "20-all.conf"),  # every service
        _touch(etc / "pai--.service.d" / "30-prefix.conf"),  # every service with the prefix
        _touch(etc / "worker@.service.d" / "40-template.conf"),  # a template
    ]
    for ignored in (
        etc / "pai-backend.service.d" / "readme.txt",  # systemd reads only *.conf
        etc / "multi-user.target.wants" / "pai-backend.service",
        etc / "pai.timer.d" / "10.conf",
        tmp_path / "a" / "rootfs" / "etc" / "systemd" / "user" / "x.service.d" / "10.conf",
        tmp_path / "docs" / "x.service.d" / "10.conf",
    ):
        _touch(ignored)
    assert discover_drop_ins(tmp_path) == sorted(wanted)
