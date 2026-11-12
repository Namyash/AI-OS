"""The installation: the steps in order, each reported as an event, with rollback on any failure.

Order matters for safety. Everything that can refuse runs first and touches nothing (target safety rules, finding
the system to copy, writing the recovery key file). Only then does anything destructive start. Resources (the
mapping, the mounts) are registered for undo before they are acquired, so a failure, a timeout or an interrupt at
any point unwinds them in reverse order. The same stack is what the orderly ending unwinds.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass

from installer.context import DEFAULT_WORK_DIR, InstallContext
from installer.errors import InstallerError
from installer.events import EventSink
from installer.host import Host
from installer.log import LOGGER_NAME, redact, register_secret
from installer.plan import Plan
from installer.runner import Commander, Runner
from installer.steps import boot, configure, copy, disk, filesystems, finish, luks, preflight

log = logging.getLogger(f"{LOGGER_NAME}.engine")

StepFunction = Callable[[InstallContext], "str | None"]


@dataclass(frozen=True)
class Step:
    name: str
    run: StepFunction


class Engine:
    def __init__(
        self,
        plan: Plan,
        runner: Runner,
        host: Host,
        events: EventSink,
        *,
        work_dir: str = DEFAULT_WORK_DIR,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if plan.passphrase is None:
            raise InstallerError("internal error: the engine needs the passphrase (read it from stdin first)")
        register_secret(plan.passphrase.reveal())
        self._events = events
        self._random_bytes = random_bytes
        self.context = InstallContext(plan=plan, cmd=Commander(runner), host=host, work_dir=work_dir)

    def steps(self) -> list[Step]:
        return [
            Step("resolve-target", preflight.choose_target),
            Step("find-source", copy.find_source),
            Step("prepare-recovery-key", lambda ctx: luks.prepare_recovery_key(ctx, self._random_bytes)),
            # ---- nothing above this line changed anything; below, the target is destroyed
            Step("wipe", disk.wipe_signatures),
            Step("partition", disk.write_partition_table),
            Step("verify-layout", disk.verify_layout),
            Step("luks-format", luks.luks_format),
            Step("luks-recovery-key", luks.add_recovery_key),
            Step("luks-verify", luks.verify_luks),
            Step("luks-open", luks.open_luks),
            Step("mkfs", filesystems.make_filesystems),
            Step("identify-filesystems", filesystems.identify_filesystems),
            Step("mount", filesystems.mount_target_tree),
            Step("copy-system", copy.copy_system),
            Step("configure-files", configure.write_configuration_files),
            Step("chroot-mounts", configure.mount_chroot_binds),
            Step("remove-live-session", configure.remove_live_session),
            Step("accounts", configure.create_accounts),
            Step("machine-id", configure.reset_machine_id),
            Step("initramfs", boot.build_initramfs),
            Step("bootloader", boot.install_bootloader),
            Step("verify-installation", self._verify_installation),
            Step("close", finish.close_everything),
            Step("after", finish.run_after_action),
        ]

    @staticmethod
    def _verify_installation(ctx: InstallContext) -> str:
        return f"{configure.verify_accounts(ctx)}; {boot.verify_boot_files(ctx)}"

    def run(self) -> bool:
        """Run every step. Returns True only if all finished; emits the final result event either way."""
        current = "start"
        try:
            for step in self.steps():
                current = step.name
                self._run_step(step)
        except BaseException as exc:  # the boundary: every failure, even an interrupt, must roll back and report
            error = self._failure_message(current, exc)
            error += self._roll_back()
            self._events.result(False, error)
            if not isinstance(exc, Exception):
                raise
            return False
        self._events.result(True)
        return True

    def _run_step(self, step: Step) -> None:
        self._events.step(step.name, "start")
        try:
            detail = step.run(self.context)
        except BaseException as exc:
            self._events.step(step.name, "failed", self._describe(exc))
            raise
        self._events.step(step.name, "done", detail or "")

    @staticmethod
    def _describe(exc: BaseException) -> str:
        if isinstance(exc, InstallerError):
            return str(exc)
        return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__

    def _failure_message(self, step: str, exc: BaseException) -> str:
        return f"step {step} failed: {self._describe(exc)}"

    def _roll_back(self) -> str:
        """Release everything acquired, newest first, and drop the recovery key. Returns text to append to the error."""
        self._events.step("rollback", "start")
        failures = self.context.resources.unwind()
        try:
            luks.discard_recovery_key(self.context)
        except OSError as exc:
            failures.append(f"could not remove the recovery key file: {redact(str(exc))}")
        if failures:
            detail = "; ".join(failures)
            self._events.step("rollback", "failed", detail)
            log.error("rollback incomplete: %s", detail)
            return f"; rollback incomplete, manual cleanup needed: {detail}"
        self._events.step("rollback", "done", "everything released")
        return ""
