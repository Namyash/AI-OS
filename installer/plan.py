"""The installation plan: strict parsing and validation of ``plan.json`` (the schema of INSTALLER_DESIGN.md).

Everything is validated before anything touches a disk: unknown keys, wrong types and out-of-range values are all
errors, reported together. Error messages name the field and the rule, never the value, so a rejected plan cannot
echo the passphrase. The passphrase is held in a ``Secret`` so it cannot be printed by accident later either.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from installer.errors import PlanError
from installer.secret import Secret

PLAN_VERSION = 1
MAX_PLAN_BYTES = 64 * 1024

MIN_PASSPHRASE_LENGTH = 12
MAX_PASSPHRASE_LENGTH = 512  # what the initramfs prompt and cryptsetup's interactive mode accept

PASSPHRASE_SOURCES = ("stdin", "plan")
AFTER_ACTIONS = ("poweroff", "reboot", "none")

# Debian's adduser NAME_REGEX narrowed to what is valid on every Linux (and never "root").
_USERNAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_RESERVED_USERNAMES = frozenset({"root"})
# One RFC 1123 label: what /etc/hostname should hold (no dots: a fully qualified name belongs in /etc/hosts).
_HOSTNAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_BY_ID = re.compile(r"[A-Za-z0-9_:+@=,-][A-Za-z0-9._:+@=,-]{0,254}")
_DEVICE_PATH = re.compile(r"/dev/[A-Za-z0-9._:+@=,/-]{1,200}")

MAX_KERNEL_ARGS_LENGTH = 256
MAX_KERNEL_ARG_WORDS = 32
# Characters that would end or change the meaning of the quoted value in a shell-sourced GRUB file.
_FORBIDDEN_IN_KERNEL_ARGS = frozenset("\"'\\`$")

KDF_MEMORY_RANGE = (32, 4_194_304)  # KiB: cryptsetup's argon2 limits
KDF_ITER_TIME_RANGE = (1, 600_000)  # ms
_FORBIDDEN_RECOVERY_PARENTS = ("/dev", "/proc", "/sys")

_TOP_LEVEL_KEYS = frozenset(
    {
        "version",
        "target",
        "confirm_wipe",
        "hostname",
        "username",
        "passphrase_source",
        "passphrase",
        "recovery_key_file",
        "kdf",
        "extra_kernel_args",
        "after",
    }
)
_REQUIRED_KEYS = ("version", "target", "confirm_wipe", "hostname", "username", "passphrase_source", "recovery_key_file")


@dataclass(frozen=True)
class TargetSpec:
    """The disk to install to, named explicitly: exactly one of the two forms is set."""

    by_id: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class KdfParams:
    """Argon2id overrides; ``None`` leaves cryptsetup's benchmarked default."""

    memory_kib: int | None = None
    iter_time_ms: int | None = None


@dataclass(frozen=True)
class Plan:
    target: TargetSpec
    hostname: str
    username: str
    passphrase_source: str
    recovery_key_file: str
    passphrase: Secret | None = field(default=None, repr=False)
    kdf: KdfParams = KdfParams()
    extra_kernel_args: tuple[str, ...] = ()
    after: str = "none"

    def with_passphrase(self, passphrase: str) -> Plan:
        """The plan with the passphrase read from standard input (``passphrase_source`` = ``stdin``)."""
        problem = passphrase_problem(passphrase)
        if problem:
            raise PlanError(f"passphrase: {problem}")
        return replace(self, passphrase=Secret(passphrase))


def passphrase_problem(value: str) -> str | None:
    """Why ``value`` is not an acceptable passphrase, or ``None``. The message never contains the value."""
    if len(value) < MIN_PASSPHRASE_LENGTH:
        return f"must be at least {MIN_PASSPHRASE_LENGTH} characters"
    if len(value) > MAX_PASSPHRASE_LENGTH:
        return f"must be at most {MAX_PASSPHRASE_LENGTH} characters"
    if len(set(value)) == 1:
        return "must not be a single character repeated"
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return "must not contain control characters (it has to be typeable at the unlock prompt)"
    return None


def parse_plan(document: object) -> Plan:
    """Validate a decoded plan document and return it as a ``Plan``. Raises ``PlanError`` listing every problem."""
    problems: list[str] = []
    plan = _parse(document, problems)
    if problems or plan is None:
        raise PlanError("invalid plan: " + "; ".join(problems))
    return plan


def load_plan_text(text: str) -> Plan:
    """Decode and validate plan JSON. Duplicate keys are rejected: the second would silently win."""
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        # The decoder's message names a position and a rule, not the text found there.
        raise PlanError(f"plan is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})") from None
    except _DuplicateKey:
        raise PlanError("plan is not valid: a key appears twice in one object") from None
    return parse_plan(document)


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _DuplicateKey
    return dict(pairs)


# --------------------------------------------------------------------------------------------------- field parsers
def _parse(document: object, problems: list[str]) -> Plan | None:
    if not isinstance(document, dict):
        problems.append("the plan must be a JSON object")
        return None
    _check_keys("plan", document, _TOP_LEVEL_KEYS, problems)
    for key in _REQUIRED_KEYS:
        if key not in document:
            problems.append(f"{key}: required")

    if "version" in document and not (_is_int(document["version"]) and document["version"] == PLAN_VERSION):
        problems.append(f"version: must be the integer {PLAN_VERSION}")
    if "confirm_wipe" in document and document["confirm_wipe"] is not True:
        problems.append("confirm_wipe: must be true (the target's contents will be destroyed)")

    target = _parse_target(document.get("target"), problems) if "target" in document else None
    hostname = _parse_hostname(document.get("hostname"), problems) if "hostname" in document else None
    username = _parse_username(document.get("username"), problems) if "username" in document else None
    recovery_key_file = (
        _parse_recovery_key_file(document.get("recovery_key_file"), problems)
        if "recovery_key_file" in document
        else None
    )
    source, passphrase = _parse_passphrase(document, problems)
    kdf = _parse_kdf(document.get("kdf", {}), problems)
    kernel_args = _parse_kernel_args(document.get("extra_kernel_args", ""), problems)
    after = _parse_after(document.get("after", "none"), problems)

    required = (target, hostname, username, recovery_key_file, source)
    if problems or any(item is None for item in required) or target is None or source is None:
        return None
    assert hostname is not None and username is not None and recovery_key_file is not None  # noqa: S101 - narrowing
    return Plan(
        target=target,
        hostname=hostname,
        username=username,
        passphrase_source=source,
        recovery_key_file=recovery_key_file,
        passphrase=passphrase,
        kdf=kdf,
        extra_kernel_args=kernel_args,
        after=after,
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _safe_key_name(key: object) -> str:
    text = str(key)
    return text if re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", text) else "<unprintable key>"


def _check_keys(where: str, obj: Mapping[str, object], allowed: frozenset[str], problems: list[str]) -> None:
    unknown = sorted(_safe_key_name(key) for key in obj if key not in allowed)
    if unknown:
        problems.append(f"{where}: unknown key(s) {', '.join(unknown)}")


def _parse_target(value: object, problems: list[str]) -> TargetSpec | None:
    if not isinstance(value, dict):
        problems.append("target: must be an object with exactly one of by_id or path")
        return None
    _check_keys("target", value, frozenset({"by_id", "path"}), problems)
    present = [key for key in ("by_id", "path") if key in value]
    if len(present) != 1:
        problems.append("target: give exactly one of by_id or path")
        return None
    key = present[0]
    text = value[key]
    if not isinstance(text, str):
        problems.append(f"target.{key}: must be a string")
        return None
    if key == "by_id":
        if not _BY_ID.fullmatch(text):
            problems.append("target.by_id: must be one name from /dev/disk/by-id (no slash, no leading dot)")
            return None
        return TargetSpec(by_id=text)
    if not _DEVICE_PATH.fullmatch(text) or posixpath.normpath(text) != text:
        problems.append("target.path: must be a normalised absolute path under /dev")
        return None
    return TargetSpec(path=text)


def _parse_hostname(value: object, problems: list[str]) -> str | None:
    if not isinstance(value, str):
        problems.append("hostname: must be a string")
    elif not _HOSTNAME.fullmatch(value):
        problems.append(
            "hostname: must be 1 to 63 lowercase letters, digits or hyphens, not starting or ending with '-'"
        )
    else:
        return value
    return None


def _parse_username(value: object, problems: list[str]) -> str | None:
    if not isinstance(value, str):
        problems.append("username: must be a string")
    elif not _USERNAME.fullmatch(value) or value in _RESERVED_USERNAMES:
        problems.append(
            "username: must start with a lowercase letter and have at most 32 lowercase letters, digits, '_' or '-' "
            "(and not be a reserved name)"
        )
    else:
        return value
    return None


def _parse_recovery_key_file(value: object, problems: list[str]) -> str | None:
    if not isinstance(value, str):
        problems.append("recovery_key_file: must be a string")
        return None
    clean = (
        value.startswith("/")
        and len(value) <= 4096
        and posixpath.normpath(value) == value
        and not value.endswith("/")
        and all(0x20 <= ord(char) < 0x7F for char in value)
        and not any(value == parent or value.startswith(parent + "/") for parent in _FORBIDDEN_RECOVERY_PARENTS)
    )
    if not clean:
        problems.append("recovery_key_file: must be a normalised absolute file path (not under /dev, /proc or /sys)")
        return None
    return value


def _parse_passphrase(document: Mapping[str, object], problems: list[str]) -> tuple[str | None, Secret | None]:
    source = document.get("passphrase_source")
    if "passphrase_source" in document and source not in PASSPHRASE_SOURCES:
        problems.append(f"passphrase_source: must be one of {', '.join(PASSPHRASE_SOURCES)}")
        return None, None
    if "passphrase_source" not in document:
        return None, None
    value = document.get("passphrase")
    if source == "stdin":
        if "passphrase" in document:
            problems.append("passphrase: must not be in the plan when passphrase_source is stdin")
        return "stdin", None
    if "passphrase" not in document:
        problems.append("passphrase: required when passphrase_source is plan")
        return "plan", None
    if not isinstance(value, str):
        problems.append("passphrase: must be a string")
        return "plan", None
    problem = passphrase_problem(value)
    if problem:
        problems.append(f"passphrase: {problem}")
        return "plan", None
    return "plan", Secret(value)


def _parse_kdf(value: object, problems: list[str]) -> KdfParams:
    if not isinstance(value, dict):
        problems.append("kdf: must be an object")
        return KdfParams()
    _check_keys("kdf", value, frozenset({"memory_kib", "iter_time_ms"}), problems)
    memory = _optional_int("kdf.memory_kib", value.get("memory_kib"), KDF_MEMORY_RANGE, problems)
    iterations = _optional_int("kdf.iter_time_ms", value.get("iter_time_ms"), KDF_ITER_TIME_RANGE, problems)
    return KdfParams(memory_kib=memory, iter_time_ms=iterations)


def _optional_int(name: str, value: object, bounds: tuple[int, int], problems: list[str]) -> int | None:
    if value is None:
        return None
    low, high = bounds
    if not _is_int(value) or not low <= value <= high:  # type: ignore[operator]
        problems.append(f"{name}: must be null or an integer from {low} to {high}")
        return None
    return int(value)  # type: ignore[call-overload]


def _parse_kernel_args(value: object, problems: list[str]) -> tuple[str, ...]:
    if not isinstance(value, str):
        problems.append("extra_kernel_args: must be a string")
        return ()
    if len(value) > MAX_KERNEL_ARGS_LENGTH:
        problems.append(f"extra_kernel_args: must be at most {MAX_KERNEL_ARGS_LENGTH} characters")
        return ()
    if any(not 0x20 <= ord(char) < 0x7F for char in value):
        problems.append("extra_kernel_args: must be printable ASCII words separated by spaces")
        return ()
    if any(char in _FORBIDDEN_IN_KERNEL_ARGS for char in value):
        problems.append("extra_kernel_args: must not contain quotes, backslashes, backticks or '$'")
        return ()
    words = tuple(value.split())
    if len(words) > MAX_KERNEL_ARG_WORDS:
        problems.append(f"extra_kernel_args: at most {MAX_KERNEL_ARG_WORDS} words")
        return ()
    return words


def _parse_after(value: object, problems: list[str]) -> str:
    if value not in AFTER_ACTIONS:
        problems.append(f"after: must be one of {', '.join(AFTER_ACTIONS)}")
        return "none"
    return str(value)
