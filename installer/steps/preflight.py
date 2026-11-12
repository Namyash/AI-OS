"""Steps that only read: they decide whether the installation may start, before anything is destroyed."""

from __future__ import annotations

from installer.context import InstallContext
from installer.target import GIB, resolve_target


def choose_target(ctx: InstallContext) -> str:
    """Resolve the disk named in the plan and apply the safety rules; the plan always names it, nothing is guessed."""
    ctx.target = resolve_target(ctx.plan.target, ctx.host)
    return f"{ctx.target.path}, {ctx.target.size_bytes / GIB:.1f} GiB"
