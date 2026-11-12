"""Tests of what the installer component puts on the image (os/installer): the unattended-install script, its unit and
the program that gathers the root device's facts for the installed-mode self-check.

install-auto.sh runs for real under bash against a scratch tree: `udevadm`, `stat`, `mount`, `umount` and the engine's
`python3` are fakes first on PATH that record how they were called, and the script's test-only overrides point it at
scratch directories. The facts program is imported and run against a simulated /proc and /sys, with `cryptsetup`
replaced by a stand-in; the real tools are covered by running it in a privileged container (docs/development/
INSTALL_TESTING.md). Nothing here needs Docker, root or a hypervisor.
"""

from __future__ import annotations

import importlib.util
import json
import os
import posixpath
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest

from tests.bash_support import find_working_bash

REPO = Path(__file__).resolve().parents[2]
COMPONENT = REPO / "os" / "installer"
AUTO_SCRIPT = COMPONENT / "rootfs" / "usr" / "lib" / "pai" / "install-auto.sh"
AUTO_UNIT = COMPONENT / "rootfs" / "etc" / "systemd" / "system" / "pai-install-auto.service"
FACTS_PROGRAM = COMPONENT / "rootfs" / "usr" / "lib" / "pai" / "selfcheck-crypt-facts.py"

BASH = find_working_bash()
needs_bash = pytest.mark.skipif(BASH is None, reason="no working bash on this machine")

LABEL = "PAI-PLAN"
SECRET_MARKER = "never-print-this-passphrase-0123456789"  # noqa: S105 - a test marker
MARKER_PLAN = json.dumps({"version": 1, "passphrase": SECRET_MARKER})

# ---- install-auto.sh -------------------------------------------------------------------------------------------------

FAKE_UDEVADM = """#!/bin/sh
echo "udevadm $*" >> "$SIM_LOG"
exit "${SIM_UDEVADM_RC:-0}"
"""

# `stat -c %F -- <path>`: "block special file" for the device the scenario calls a block device, else a regular file.
FAKE_STAT = """#!/bin/sh
[ "$1 $2" = "-c %F" ] && [ "$3" = -- ] || { echo "fake stat: unexpected arguments: $*" >&2; exit 64; }
if [ "$(readlink -f "$4")" = "$SIM_BLOCK_DEVICE" ]; then echo "block special file"; else echo "regular file"; fi
"""

# mount -o <options> -- <device> <mount point>: records the call and fills the mount point from the scenario's medium.
FAKE_MOUNT = """#!/bin/sh
echo "mount $*" >> "$SIM_LOG"
[ "${SIM_MOUNT_RC:-0}" = 0 ] || { echo "mount: wrong fs type" >&2; exit 32; }
[ "$1" = -o ] && [ "$3" = -- ] || { echo "fake mount: unexpected arguments: $*" >&2; exit 64; }
cp -a "$SIM_MEDIUM/." "$5/"
"""

FAKE_UMOUNT = """#!/bin/sh
echo "umount $*" >> "$SIM_LOG"
[ "$1" = -- ] || { echo "fake umount: unexpected arguments: $*" >&2; exit 64; }
rm -rf "$2"/*
"""

# The engine: records its arguments and working directory, never reads the plan, prints one event line.
FAKE_PYTHON = """#!/bin/sh
echo "python3 $* (in $(pwd))" >> "$SIM_LOG"
echo '{"event": "result", "ok": true}'
exit "${SIM_ENGINE_RC:-0}"
"""


@dataclass
class AutoRun:
    returncode: int
    stdout: str
    stderr: str
    log: list[str]
    work: Path
    engine_dir: Path


def run_auto(
    tmp_path: Path,
    *,
    medium: Callable[[Path], None] | None = None,
    attach: bool = True,
    label_argument: str | None = LABEL,
    env: dict[str, str] | None = None,
) -> AutoRun:
    """One run of install-auto.sh. `medium` fills the directory the fake mount "mounts"; `attach` makes the
    by-label link."""
    assert BASH is not None
    bin_dir, work, by_label, engine_dir, medium_dir = (
        tmp_path / name for name in ("bin", "work", "by-label", "engine", "medium")
    )
    for directory in (bin_dir, work, by_label, engine_dir, medium_dir):
        directory.mkdir()
    for name, body in {
        "udevadm": FAKE_UDEVADM,
        "stat": FAKE_STAT,
        "mount": FAKE_MOUNT,
        "umount": FAKE_UMOUNT,
        "python3": FAKE_PYTHON,
    }.items():
        (bin_dir / name).write_text(body, encoding="utf-8", newline="\n")
        (bin_dir / name).chmod(0o755)
    # The by-label entry is the "device" itself (a regular file) rather than a link to one: this host may not allow
    # symbolic links, and the script resolves the entry with readlink -f either way.
    device = by_label / LABEL if attach else tmp_path / "absent"
    if attach:
        device.write_text("")
    if medium is not None:
        medium(medium_dir)
    log = tmp_path / "calls.log"
    log.write_text("")
    argv = [BASH, AUTO_SCRIPT.as_posix(), *([label_argument] if label_argument is not None else [])]
    done = subprocess.run(  # noqa: S603
        argv,
        env={
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "PAI_INSTALL_PLAN_DIR": work.as_posix(),
            "PAI_INSTALL_BY_LABEL_DIR": by_label.as_posix(),
            "PAI_INSTALL_ENGINE_DIR": engine_dir.as_posix(),
            "PAI_INSTALL_WAIT": "0",
            "SIM_LOG": log.as_posix(),
            "SIM_BLOCK_DEVICE": device.resolve().as_posix(),
            "SIM_MEDIUM": medium_dir.as_posix(),
            **(env or {}),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return AutoRun(
        done.returncode, done.stdout, done.stderr, log.read_text(encoding="utf-8").splitlines(), work, engine_dir
    )


def plan_medium(directory: Path) -> None:
    (directory / "plan.json").write_text(MARKER_PLAN, encoding="utf-8")


def calls(run: AutoRun, program: str) -> list[str]:
    return [line for line in run.log if line.startswith(f"{program} ")]


@needs_bash
def test_a_plan_on_a_labelled_medium_is_installed_from_read_only_and_the_medium_is_unmounted_afterwards(
    tmp_path: Path,
) -> None:
    run = run_auto(tmp_path, medium=plan_medium)
    assert run.returncode == 0, run.stderr
    (mount_call,) = calls(run, "mount")
    assert " -o ro,nosuid,nodev,noexec -- " in mount_call
    assert mount_call.endswith(f"{(run.work / 'medium').as_posix()}")
    assert f"{LABEL} " in mount_call  # the device the by-label entry resolves to
    (engine_call,) = calls(run, "python3")
    plan = (run.work / "medium" / "plan.json").as_posix()
    assert engine_call == f"python3 -s -B -m installer --plan {plan} (in {run.engine_dir.as_posix()})"
    assert [line.split()[0] for line in run.log if line.split()[0] in {"mount", "python3", "umount"}] == [
        "mount",
        "python3",
        "umount",
    ]
    assert not (run.work / "medium").exists(), "the mount point is removed again"


def test_the_plan_medium_is_mounted_outside_the_engines_own_work_directory() -> None:
    """Regression (first complete real install): the engine's last step fails when anything is mounted below its work
    directory, so a plan medium mounted there made every install report failure after it had succeeded."""
    from installer.context import DEFAULT_WORK_DIR

    script = AUTO_SCRIPT.read_text(encoding="utf-8")
    default = re.search(r"^PLAN_DIR=\$\{PAI_INSTALL_PLAN_DIR:-(?P<path>[^}]+)\}", script, re.MULTILINE)
    assert default is not None, "install-auto.sh must name the default directory of the plan medium"
    plan_dir = default["path"]
    assert not (plan_dir + "/").startswith(DEFAULT_WORK_DIR.rstrip("/") + "/")
    assert not (DEFAULT_WORK_DIR.rstrip("/") + "/").startswith(plan_dir.rstrip("/") + "/")
    unit = (COMPONENT / "rootfs" / "etc" / "systemd" / "system" / "pai-install-auto.service").read_text("utf-8")
    runtime_directories = re.search(r"^RuntimeDirectory=(?P<names>.+)$", unit, re.MULTILINE)
    writable = re.search(r"^ReadWritePaths=(?P<paths>.+)$", unit, re.MULTILINE)
    assert runtime_directories is not None and writable is not None
    assert posixpath.basename(plan_dir) in runtime_directories["names"].split()
    assert plan_dir in writable["paths"].split()


@needs_bash
def test_udev_is_settled_before_the_device_is_looked_for(tmp_path: Path) -> None:
    run = run_auto(tmp_path, medium=plan_medium)
    assert run.log[0].startswith("udevadm settle")


@needs_bash
def test_the_engines_exit_status_is_the_scripts_and_the_medium_is_still_unmounted(tmp_path: Path) -> None:
    run = run_auto(tmp_path, medium=plan_medium, env={"SIM_ENGINE_RC": "3"})
    assert run.returncode == 3
    assert "exited with status 3" in run.stdout
    assert len(calls(run, "umount")) == 1


@needs_bash
def test_the_engines_events_reach_the_standard_output_untouched(tmp_path: Path) -> None:
    run = run_auto(tmp_path, medium=plan_medium)
    assert '{"event": "result", "ok": true}' in run.stdout.splitlines()


@needs_bash
@pytest.mark.parametrize("engine_rc", ["0", "5"])
def test_the_plan_is_never_read_or_printed(tmp_path: Path, engine_rc: str) -> None:
    run = run_auto(tmp_path, medium=plan_medium, env={"SIM_ENGINE_RC": engine_rc})
    assert SECRET_MARKER not in run.stdout + run.stderr + "".join(run.log)


@needs_bash
def test_no_device_with_the_label_means_nothing_to_install_and_is_not_an_error(tmp_path: Path) -> None:
    run = run_auto(tmp_path, attach=False)
    assert run.returncode == 0
    assert f"no device carries the volume label {LABEL}" in run.stdout
    assert calls(run, "mount") == calls(run, "python3") == []


@needs_bash
def test_a_medium_without_a_plan_file_is_left_alone_and_unmounted(tmp_path: Path) -> None:
    run = run_auto(tmp_path, medium=lambda directory: (directory / "readme.txt").write_text("x"))
    assert run.returncode == 0
    assert "no regular file plan.json" in run.stdout
    assert calls(run, "python3") == []
    assert len(calls(run, "umount")) == 1


@needs_bash
def test_a_plan_that_is_a_symbolic_link_is_not_followed(tmp_path: Path) -> None:
    def medium(directory: Path) -> None:
        (directory / "secret.txt").write_text(SECRET_MARKER)
        try:
            (directory / "plan.json").symlink_to("secret.txt")
        except OSError:
            pytest.skip("this host does not allow creating symbolic links")

    run = run_auto(tmp_path, medium=medium)
    assert run.returncode == 0
    assert calls(run, "python3") == []
    assert SECRET_MARKER not in run.stdout + run.stderr


@needs_bash
def test_a_plan_file_larger_than_a_plan_can_be_fails_without_running_the_engine(tmp_path: Path) -> None:
    run = run_auto(tmp_path, medium=lambda d: (d / "plan.json").write_text("x" * (1024 * 1024 + 1)))
    assert run.returncode == 1
    assert "more than the 1048576 a plan may have" in run.stderr
    assert calls(run, "python3") == []
    assert len(calls(run, "umount")) == 1


@needs_bash
def test_a_medium_that_cannot_be_mounted_fails_without_running_the_engine(tmp_path: Path) -> None:
    run = run_auto(tmp_path, medium=plan_medium, env={"SIM_MOUNT_RC": "1"})
    assert run.returncode == 1
    assert "cannot mount" in run.stderr
    assert calls(run, "python3") == [] and calls(run, "umount") == []


@needs_bash
def test_a_label_link_that_does_not_lead_to_a_block_device_is_refused(tmp_path: Path) -> None:
    run = run_auto(tmp_path, medium=plan_medium, env={"SIM_BLOCK_DEVICE": "/nowhere"})
    assert run.returncode == 1
    assert "does not lead to a block device" in run.stderr
    assert calls(run, "mount") == []


@needs_bash
@pytest.mark.parametrize("label", ["", "has space", "a/b", "../x", "x;rm", "-n", "..", ".hidden", "a" * 33, "naïve"])
def test_a_label_that_is_not_a_plain_volume_label_is_refused(tmp_path: Path, label: str) -> None:
    run = run_auto(tmp_path, medium=plan_medium, label_argument=label)
    assert run.returncode == 1
    assert "volume label must match" in run.stderr
    assert calls(run, "mount") == []


@needs_bash
def test_the_script_needs_exactly_one_argument(tmp_path: Path) -> None:
    assert run_auto(tmp_path, label_argument=None).returncode == 2


@needs_bash
def test_a_wait_that_is_not_a_number_is_refused(tmp_path: Path) -> None:
    run = run_auto(tmp_path, medium=plan_medium, env={"PAI_INSTALL_WAIT": "soon"})
    assert run.returncode == 1
    assert "PAI_INSTALL_WAIT" in run.stderr


@needs_bash
def test_the_script_waits_the_configured_time_for_the_medium_before_giving_up(tmp_path: Path) -> None:
    run = run_auto(tmp_path, medium=plan_medium, attach=False, env={"PAI_INSTALL_WAIT": "1"})
    assert run.returncode == 0
    assert "after 1 s: nothing to install" in run.stdout


# ---- the unit --------------------------------------------------------------------------------------------------------


def unit_values(key: str) -> list[str]:
    prefix = f"{key}="
    lines = (line.strip() for line in AUTO_UNIT.read_text(encoding="utf-8").splitlines())
    return [line.removeprefix(prefix).strip() for line in lines if line.startswith(prefix)]


def test_the_unit_starts_only_on_the_kernel_flag_that_asks_for_an_unattended_install() -> None:
    assert unit_values("ConditionKernelCommandLine") == ["pai.install=auto"]


def test_the_unit_passes_the_label_the_install_test_builds_its_plan_medium_with() -> None:
    from tests.end_to_end.install_plan import PLAN_VOLUME_LABEL

    (exec_start,) = unit_values("ExecStart")
    assert exec_start == f"/usr/lib/pai/install-auto.sh {PLAN_VOLUME_LABEL}"


def test_the_unit_runs_the_script_the_overlay_ships_as_root() -> None:
    assert AUTO_SCRIPT.is_file()
    assert AUTO_SCRIPT.read_text(encoding="utf-8").startswith("#!/bin/bash\n")
    assert unit_values("User") == ["root"]


def test_the_unit_logs_where_the_install_test_reads_progress() -> None:
    assert unit_values("StandardOutput") == ["journal+console"]
    assert unit_values("StandardError") == ["journal+console"]


def test_a_normal_boot_and_a_selfcheck_boot_do_not_start_the_installer() -> None:
    from tests.end_to_end.container_boot import KERNEL_ARGS

    (condition,) = unit_values("ConditionKernelCommandLine")
    assert condition not in KERNEL_ARGS.split()  # the live boot test must never install
    text = AUTO_UNIT.read_text(encoding="utf-8")
    assert "Conflicts=" not in text, "a Conflicts= is acted on even when the unit's condition fails"
    assert "systemd-udev-settle.service" in " ".join(unit_values("After"))
    assert not re.search(r"^(Wants|Requires)=.*udev-settle", text, re.MULTILINE), "pulling settle in slows every boot"


def test_the_unit_has_no_time_limit_because_stopping_an_install_half_way_destroys_the_disk() -> None:
    assert unit_values("TimeoutStartSec") == ["infinity"]
    assert unit_values("Restart") == []


# ---- the facts program -----------------------------------------------------------------------------------------------


def load_facts_program() -> ModuleType:
    spec = importlib.util.spec_from_file_location("selfcheck_crypt_facts", FACTS_PROGRAM)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


facts = load_facts_program()
SALT = "c2VjcmV0LXNhbHQtdGhhdC1tdXN0LW5vdC1hcHBlYXI="  # base64 text standing in for a keyslot salt


def luks_metadata(*kdfs: str) -> str:
    keyslots = {
        str(index): {"type": "luks2", "key_size": 64, "kdf": {"type": kdf, "salt": SALT, "time": 4}}
        for index, kdf in enumerate(kdfs)
    }
    return json.dumps(
        {"keyslots": keyslots, "tokens": {}, "segments": {}, "digests": {"0": {"digest": SALT}}, "config": {}}
    )


@dataclass
class FactsMachine:
    """A simulated /proc and /sys of a machine whose root is on a device-mapper device, plus the stand-in cryptsetup."""

    root: Path
    cryptsetup_calls: list[list[str]]

    def mountinfo(self, text: str) -> None:
        path = self.root / "proc" / "self" / "mountinfo"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def block(
        self, major_minor: str, *, name: str | None = None, uuid: str | None = None, slaves: tuple[str, ...] = ()
    ) -> None:
        directory = self.root / "sys" / "dev" / "block" / major_minor
        (directory / "slaves").mkdir(parents=True, exist_ok=True)
        if name is not None:
            (directory / "dm").mkdir(exist_ok=True)
            (directory / "dm" / "name").write_text(name + "\n", encoding="utf-8")
        if uuid is not None:
            (directory / "dm" / "uuid").write_text(uuid + "\n", encoding="utf-8")
        for slave in slaves:
            (directory / "slaves" / slave).mkdir(exist_ok=True)


@pytest.fixture
def machine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FactsMachine:
    sim = FactsMachine(tmp_path, [])
    sim.mountinfo("22 1 254:0 / / rw - ext4 /dev/mapper/cryptroot rw\n")
    sim.block("254:0", name="cryptroot", uuid="CRYPT-LUKS2-0123456789abcdef-cryptroot", slaves=("vda4",))
    sim.metadata = luks_metadata("argon2id", "argon2id")  # type: ignore[attr-defined]
    sim.returncode = 0  # type: ignore[attr-defined]

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        sim.cryptsetup_calls.append(command)
        return subprocess.CompletedProcess(
            command, sim.returncode, sim.metadata if sim.returncode == 0 else "", "boom" if sim.returncode else ""
        )  # type: ignore[attr-defined]

    monkeypatch.setattr(facts.subprocess, "run", fake_run)
    return sim


def collect(machine: FactsMachine) -> tuple[dict[str, str], str | None]:
    gathered: dict[str, str] = {}
    try:
        facts.collect(machine.root, gathered)
    except facts.FactError as problem:
        return gathered, str(problem)
    return gathered, None


def test_an_encrypted_root_yields_every_fact_the_check_needs(machine: FactsMachine) -> None:
    gathered, error = collect(machine)
    assert error is None
    assert gathered == {
        "root_device": "254:0",
        "root_dm": "cryptroot",
        "dm_kind": "CRYPT-LUKS2",
        "backing_count": "1",
        "backing": "/dev/vda4",
        "luks_version": "2",
        "keyslots": "2",
        "kdfs": "argon2id,argon2id",
    }


def test_the_header_is_read_with_a_read_only_json_dump_of_the_one_backing_device(machine: FactsMachine) -> None:
    collect(machine)
    assert machine.cryptsetup_calls == [
        ["cryptsetup", "luksDump", "--dump-json-metadata", "--disable-locks", "--", "/dev/vda4"]
    ]


def test_no_salt_digest_or_other_header_content_reaches_the_facts(machine: FactsMachine) -> None:
    gathered, _ = collect(machine)
    assert SALT not in facts.render(gathered, None)


def test_a_root_that_is_not_on_a_mapping_says_so_and_runs_no_cryptsetup(machine: FactsMachine) -> None:
    machine.mountinfo("22 1 0:20 / / rw - overlay overlay rw\n")
    machine.block("0:20")
    gathered, error = collect(machine)
    assert (gathered, error) == ({"root_device": "0:20", "root_dm": "none"}, None)
    assert machine.cryptsetup_calls == []


def test_a_mapping_that_is_not_dm_crypt_has_no_header_to_read(machine: FactsMachine) -> None:
    machine.block("254:0", uuid="LVM-abcdef")
    gathered, error = collect(machine)
    assert error is None
    assert gathered["dm_kind"] == "other"
    assert "luks_version" not in gathered and machine.cryptsetup_calls == []


def test_the_last_mount_at_slash_is_the_one_in_effect(machine: FactsMachine) -> None:
    machine.mountinfo(
        "20 1 0:20 / / rw - overlay x rw\n"
        "22 20 254:0 / / rw - ext4 /dev/mapper/cryptroot rw\n"
        "23 22 8:1 / /boot rw - ext4 /dev/vda3 rw\n"
    )
    assert collect(machine)[0]["root_device"] == "254:0"


def test_a_mountinfo_without_a_root_mount_is_an_error(machine: FactsMachine) -> None:
    machine.mountinfo("23 22 8:1 / /boot rw - ext4 /dev/vda3 rw\n")
    assert collect(machine)[1] == "no filesystem is mounted at / in mountinfo"


def test_an_unreadable_mountinfo_is_an_error_not_a_crash(machine: FactsMachine) -> None:
    (machine.root / "proc" / "self" / "mountinfo").unlink()
    assert "cannot read mountinfo" in (collect(machine)[1] or "")


@pytest.mark.parametrize("slaves", [(), ("vda4", "vdb1")])
def test_a_mapping_that_is_not_on_exactly_one_device_is_an_error(
    machine: FactsMachine, slaves: tuple[str, ...]
) -> None:
    for entry in (machine.root / "sys" / "dev" / "block" / "254:0" / "slaves").iterdir():
        entry.rmdir()
    machine.block("254:0", slaves=slaves)
    gathered, error = collect(machine)
    assert f"the mapping sits on {len(slaves)} devices" in (error or "")
    assert machine.cryptsetup_calls == []
    assert gathered["backing_count"] == str(len(slaves))  # what was seen before the problem is kept


def test_a_failing_luks_dump_is_an_error_with_cryptsetups_status_and_no_output(machine: FactsMachine) -> None:
    machine.returncode = 4  # type: ignore[attr-defined]
    gathered, error = collect(machine)
    assert error == "cryptsetup luksDump failed with status 4: boom"
    assert gathered["backing"] == "/dev/vda4"


def test_output_that_is_not_json_is_an_error(machine: FactsMachine) -> None:
    machine.metadata = "LUKS header information\nVersion: 2\n"  # type: ignore[attr-defined]
    assert collect(machine)[1] == "cryptsetup luksDump did not print JSON metadata"


def test_cryptsetup_that_cannot_be_run_or_hangs_is_an_error(
    machine: FactsMachine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(command: list[str], **kwargs: object) -> None:
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(facts.subprocess, "run", missing)
    assert collect(machine)[1] == "cryptsetup luksDump could not run: FileNotFoundError"

    def hangs(command: list[str], **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(command, 1)

    monkeypatch.setattr(facts.subprocess, "run", hangs)
    assert collect(machine)[1] == "cryptsetup luksDump could not run: TimeoutExpired"


@pytest.mark.parametrize(
    ("kdfs", "expected"),
    [
        (("argon2id",), "argon2id"),
        (("argon2id", "pbkdf2"), "argon2id,pbkdf2"),
        (("argon2i", "argon2id"), "argon2i,argon2id"),
    ],
)
def test_the_kdf_of_every_keyslot_is_reported_in_keyslot_order(
    machine: FactsMachine, kdfs: tuple[str, ...], expected: str
) -> None:
    machine.metadata = luks_metadata(*kdfs)  # type: ignore[attr-defined]
    gathered, _ = collect(machine)
    assert gathered["kdfs"] == expected
    assert gathered["keyslots"] == str(len(kdfs))


@pytest.mark.parametrize(
    "metadata",
    [
        {"keyslots": {"0": {"type": "luks2"}}},  # no kdf object
        {"keyslots": {"0": {"kdf": {"type": 7}}}},  # not a name
        {"keyslots": {"0": {"kdf": {"type": "Argon2ID; rm -rf"}}}},  # not a plain lower-case name
        {"keyslots": {"0": "garbage"}},
    ],
)
def test_a_keyslot_whose_kdf_cannot_be_read_is_reported_as_unknown_never_as_argon2id(metadata: object) -> None:
    assert facts.luks_keyslot_kdfs(metadata) == ["unknown"]


@pytest.mark.parametrize("metadata", [[], {"keyslots": []}, {"tokens": {}}, "text", None])
def test_metadata_without_keyslots_is_an_error(metadata: object) -> None:
    with pytest.raises(facts.FactError, match="no keyslots"):
        facts.luks_keyslot_kdfs(metadata)


def test_the_facts_file_is_written_whole_and_the_exit_status_is_zero_even_for_a_finding(
    machine: FactsMachine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine.mountinfo("23 22 8:1 / /boot rw - ext4 /dev/vda3 rw\n")
    monkeypatch.setenv("PAI_SELFCHECK_CRYPT_ROOT", machine.root.as_posix())
    target = tmp_path / "out" / "crypt-facts"
    target.parent.mkdir()
    assert facts.main(["facts", target.as_posix()]) == 0
    assert target.read_text(encoding="utf-8") == "error=no filesystem is mounted at / in mountinfo\n"
    assert list(target.parent.iterdir()) == [target], "no partial file is left behind"


def test_an_error_text_cannot_add_a_line_to_the_facts_file() -> None:
    text = facts.render({"root_dm": "x"}, "bad\nroot_dm=injected\x1b[31m")
    assert text.count("\n") == 2
    assert text.splitlines()[1].startswith("error=bad root_dm=injected")


def test_the_program_needs_exactly_one_argument(capsys: pytest.CaptureFixture[str]) -> None:
    assert facts.main(["facts"]) == 2
    assert facts.main(["facts", "a", "b"]) == 2
    assert "usage" in capsys.readouterr().err
