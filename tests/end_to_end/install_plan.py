"""The plan the install test hands the installer engine, and the secrets that go with it. Pure: no Docker, no QEMU.

The plan format is the contract in docs/architecture/INSTALLER_DESIGN.md ("Plan and CLI"). The test builds it fresh for
every run with a random passphrase that exists only in memory, in the plan medium inside a throwaway Docker volume and,
typed, on QEMU's input. Nothing here prints it: a `Secret` shows "<secret>" for repr and str, so a failed assertion or a
log line that mentions one cannot reveal it, and a value is read out only with `reveal()`, at the two places that need
it (the plan's JSON and the keystrokes).
"""

from __future__ import annotations

import json
import secrets

# The volume label of the plan medium and the serial of the target disk. pai-install-auto.service looks for the label
# (test_installer_component.py keeps the unit equal to this constant); the engine names the target through udev's
# /dev/disk/by-id link, which for a virtio disk is "virtio-<serial>" (QEMU: -drive ...,if=virtio,serial=<serial>).
PLAN_VOLUME_LABEL = "PAI-PLAN"
PLAN_FILE_NAME = "plan.json"
TARGET_SERIAL = "PAITARGET"
TARGET_BY_ID = f"virtio-{TARGET_SERIAL}"

PLAN_VERSION = 1
# The engine refuses a shorter passphrase and one that is a single repeated character (design: safety rule 6).
MIN_PASSPHRASE_LENGTH = 12
PASSPHRASE_RANDOM_BYTES = 24  # 32 URL-safe characters: no character that a serial console or a shell treats specially
# argon2id costs, small enough for software emulation (an unlock happens at every boot of the installed disk, under
# the same emulation). The engine must still produce argon2id keyslots; the installed self-check verifies it.
DEFAULT_KDF_MEMORY_KIB = 65536
DEFAULT_KDF_ITER_TIME_MS = 100
# What the installed system's kernel gets besides the engine's own arguments: the serial console, so the unlock prompt
# and the self-check verdict appear where the harness reads, and the flag that makes the self-check run (and the
# machine power itself off afterwards).
INSTALLED_KERNEL_ARGS = "console=ttyS0 pai.selfcheck=1"
# Where the engine writes the recovery key (a path in the live system; design: recovery_key_file). The unit's
# sandbox lets it write exactly there.
RECOVERY_KEY_FILE = "/run/pai-install/recovery-key"
DEFAULT_HOSTNAME = "pai-test"
DEFAULT_USERNAME = "paitest"

# What a plan may contain, one source of truth for the test that keeps the builder in step with the design document.
PLAN_KEYS = frozenset(
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


class Secret:
    """A string that never prints: repr and str are a fixed marker, whatever the value.

    Deliberately not a dataclass: pytest explains a failed `==` between two dataclasses by listing their fields, which
    would print the value. Equality is identity; compare secrets with `reveal()`.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<secret>"

    __str__ = __repr__


def generate_passphrase() -> Secret:
    """A fresh random passphrase of PASSPHRASE_RANDOM_BYTES bytes of entropy."""
    return Secret(secrets.token_urlsafe(PASSPHRASE_RANDOM_BYTES))


def generate_wrong_passphrase(correct: Secret) -> Secret:
    """A random passphrase of the same shape that is not `correct` (a collision is as good as impossible; checked
    anyway)."""
    while (wrong := generate_passphrase()).reveal() == correct.reveal():
        pass
    return wrong


def build_plan(
    passphrase: Secret,
    *,
    hostname: str = DEFAULT_HOSTNAME,
    username: str = DEFAULT_USERNAME,
    kdf_memory_kib: int = DEFAULT_KDF_MEMORY_KIB,
    kdf_iter_time_ms: int = DEFAULT_KDF_ITER_TIME_MS,
    extra_kernel_args: str = INSTALLED_KERNEL_ARGS,
    after: str = "poweroff",
) -> dict[str, object]:
    """The plan for a fully unattended install onto the disk whose serial is TARGET_SERIAL, ending in power-off.

    The passphrase travels in the plan (passphrase_source "plan"), the engine's unattended mode: there is no one to
    type it. Raises ValueError for a passphrase the engine would refuse, so a bad test setup fails here, not after an
    hour of emulation.
    """
    value = passphrase.reveal()
    if len(value) < MIN_PASSPHRASE_LENGTH or len(set(value)) < 2:
        raise ValueError(
            f"the passphrase must have at least {MIN_PASSPHRASE_LENGTH} characters and not be one repeated"
        )
    return {
        "version": PLAN_VERSION,
        "target": {"by_id": TARGET_BY_ID},
        "confirm_wipe": True,
        "hostname": hostname,
        "username": username,
        "passphrase_source": "plan",
        "passphrase": value,
        "recovery_key_file": RECOVERY_KEY_FILE,
        "kdf": {"memory_kib": kdf_memory_kib, "iter_time_ms": kdf_iter_time_ms},
        "extra_kernel_args": extra_kernel_args,
        "after": after,
    }


def plan_bytes(plan: dict[str, object]) -> bytes:
    """The plan as the UTF-8 JSON the plan medium holds."""
    return json.dumps(plan, indent=2, sort_keys=True).encode("utf-8") + b"\n"
