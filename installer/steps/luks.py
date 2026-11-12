"""The encryption steps: LUKS2 with argon2id, a recovery key in a second keyslot, verification, and the mapping.

The passphrase goes to ``cryptsetup`` on standard input (``--key-file=-``), exactly as given: with ``--key-file=-``
cryptsetup does not strip a newline, so none is sent, and what the user types at the unlock prompt (the prompt strips
its newline) is the same string. The recovery key is created and written to its file *before* anything is destroyed,
so the installer can never encrypt a disk with a key the user has no way to read. It is added with
``luksAddKey <device> <recovery key file>``, so it too is never in argv, only the path of its 0600 file.
"""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import Callable

from installer import timeouts
from installer.context import MAPPING_NAME, InstallContext
from installer.errors import VerificationError
from installer.log import LOGGER_NAME, register_secret
from installer.plan import KdfParams
from installer.secret import Secret

log = logging.getLogger(f"{LOGGER_NAME}.luks")

RECOVERY_KEY_BYTES = 32  # 256 bits
RECOVERY_GROUP = 4
EXPECTED_KEYSLOTS = 2  # the passphrase and the recovery key


def format_recovery_key(raw: bytes) -> str:
    """Base32 (A-Z and 2-7: nothing that looks like another character) in dash-separated groups of four."""
    text = base64.b32encode(raw).decode("ascii").rstrip("=")
    return "-".join(text[i : i + RECOVERY_GROUP] for i in range(0, len(text), RECOVERY_GROUP))


def prepare_recovery_key(ctx: InstallContext, generate: Callable[[int], bytes]) -> str:
    """Generate the recovery key and write it to ``recovery_key_file`` (0600, new file) before any disk is touched."""
    raw = generate(RECOVERY_KEY_BYTES)
    if len(raw) != RECOVERY_KEY_BYTES:
        raise VerificationError("the recovery key generator did not return 256 bits")
    text = format_recovery_key(raw)
    register_secret(text)
    register_secret(text.replace("-", ""))
    # Written exactly, without a trailing newline: the file's bytes are the key, and what a person types is the text.
    ctx.host.write_secret_file(ctx.plan.recovery_key_file, text)
    ctx.recovery_key = Secret(text)
    ctx.recovery_key_written = True
    return "recovery key written to its file (mode 0600)"


def discard_recovery_key(ctx: InstallContext) -> None:
    """After a failed installation the key opens nothing: remove it so it is not mistaken for a valid one.

    Once the installation is complete the key opens the installed disk, so it is kept whatever happens after.
    """
    if ctx.recovery_key_written and not ctx.installation_complete:
        ctx.host.remove_file(ctx.plan.recovery_key_file)
        ctx.recovery_key_written = False


def _kdf_arguments(kdf: KdfParams) -> list[str]:
    arguments = ["--pbkdf", "argon2id"]
    if kdf.memory_kib is not None:
        arguments.append(f"--pbkdf-memory={kdf.memory_kib}")
    if kdf.iter_time_ms is not None:
        arguments.append(f"--iter-time={kdf.iter_time_ms}")
    return arguments


def luks_format(ctx: InstallContext) -> str:
    root = ctx.require_partitions().root
    ctx.cmd.run(
        [
            "cryptsetup",
            "luksFormat",
            "--type",
            "luks2",
            *_kdf_arguments(ctx.plan.kdf),
            "--batch-mode",
            "--key-file=-",
            root,
        ],
        timeout=timeouts.KDF,
        stdin=ctx.require_passphrase(),
    )
    return f"LUKS2 container created on {root}"


def add_recovery_key(ctx: InstallContext) -> str:
    root = ctx.require_partitions().root
    ctx.require_recovery_key()  # the key file exists only if prepare_recovery_key ran
    ctx.cmd.run(
        [
            "cryptsetup",
            "luksAddKey",
            *_kdf_arguments(ctx.plan.kdf),
            "--batch-mode",
            "--key-file=-",
            root,
            ctx.plan.recovery_key_file,
        ],
        timeout=timeouts.KDF,
        stdin=ctx.require_passphrase(),
    )
    return "recovery key added in a second keyslot"


def verify_luks(ctx: InstallContext) -> str:
    """The container must be LUKS2 with exactly two keyslots, both argon2id. ``luksDump`` prints LUKS2 as JSON."""
    root = ctx.require_partitions().root
    result = ctx.cmd.run(["cryptsetup", "luksDump", "--dump-json-metadata", root], timeout=timeouts.QUICK)
    try:
        slots = json.loads(result.stdout)["keyslots"]
        found = [(slot["type"], slot["kdf"]["type"]) for slot in slots.values()]
    except (ValueError, KeyError, TypeError, AttributeError):
        raise VerificationError(f"{root} did not dump as LUKS2 metadata") from None
    if len(found) != EXPECTED_KEYSLOTS:
        raise VerificationError(f"expected {EXPECTED_KEYSLOTS} keyslots, found {len(found)}")
    if any(slot_type != "luks2" or kdf != "argon2id" for slot_type, kdf in found):
        raise VerificationError("every keyslot must be luks2 with the argon2id key derivation")
    return "LUKS2, argon2id, 2 keyslots"


def _close_mapping(ctx: InstallContext) -> None:
    if ctx.host.exists(ctx.mapper_path):
        ctx.cmd.run(["cryptsetup", "close", MAPPING_NAME], timeout=timeouts.QUICK)


def open_luks(ctx: InstallContext) -> str:
    root = ctx.require_partitions().root
    ctx.resources.push(f"the mapping {MAPPING_NAME}", lambda: _close_mapping(ctx))
    ctx.cmd.run(
        ["cryptsetup", "open", "--type", "luks2", "--key-file=-", root, MAPPING_NAME],
        timeout=timeouts.KDF,
        stdin=ctx.require_passphrase(),
    )
    return f"opened as {ctx.mapper_path}"
