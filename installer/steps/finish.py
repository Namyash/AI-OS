"""The ending: release everything in order, prove nothing is left, then perform the requested ``after`` action."""

from __future__ import annotations

from installer import timeouts
from installer.context import MAPPING_NAME, InstallContext
from installer.errors import CommandError, VerificationError
from installer.steps.filesystems import mounts_below


def close_everything(ctx: InstallContext) -> str:
    """Flush, unmount in reverse order, close the mapping, and check that nothing is mounted or mapped."""
    ctx.cmd.run(["sync"], timeout=timeouts.COPY)
    failures = ctx.resources.unwind()
    if failures:
        raise CommandError("; ".join(failures), ["umount"])
    left = mounts_below(ctx, ctx.work_dir)
    if left:
        raise VerificationError(f"something is still mounted under {ctx.work_dir}: {', '.join(left)}")
    if ctx.host.exists(ctx.mapper_path):
        raise VerificationError(f"the mapping {MAPPING_NAME} is still open")
    ctx.installation_complete = True
    return "everything unmounted and the encrypted volume closed"


def run_after_action(ctx: InstallContext) -> str:
    """``--no-block``: the job is queued and the command returns, so the result event is written before power-off."""
    action = ctx.plan.after
    if action == "none":
        return "no after-action requested"
    ctx.cmd.run(["systemctl", "--no-block", action], timeout=timeouts.QUICK)
    return f"{action} requested"
