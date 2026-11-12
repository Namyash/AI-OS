"""Runs the live-config component that locks the live session's login (risk R16) against a simulated machine.

Debian's live-config creates an account at boot with a password everybody knows and gives it passwordless sudo. The
component `os/security/rootfs/usr/lib/live/config/9980-pai-lock-live-user` runs after those and undoes both. It finds
the account by what it is (an ordinary login account whose password is not already locked), not by a name, so each test
here uses placeholder names and uids. The machine is a directory tree the script reads through its test-only
PAI_LIVE_LOCK_ROOT prefix, with fakes of `usermod` and `gpasswd` that edit that tree and refuse an argument list the
script is not meant to send. The real image result (no account with a usable hash) is proven at boot by the
no-default-credentials self-check.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.bash_support import find_working_bash

REPO = Path(__file__).resolve().parents[2]
COMPONENT = REPO / "os" / "security" / "rootfs" / "usr" / "lib" / "live" / "config" / "9980-pai-lock-live-user"
BASH = find_working_bash()
pytestmark = pytest.mark.skipif(BASH is None, reason="no working bash on this machine")

# Shaped like password hashes, made up.
LIVE_HASH = "Xy12abCDefGHi"
STRONG_HASH = "$y$j9T$simulatedsaltsimulated$simulatedhashsimulatedhashsimulatedhash"

# `usermod -p ! -- <account>`: sets the password field in the shadow file. Fails or does nothing when a test says so.
FAKE_USERMOD = """#!/bin/sh
[ "$1 $2 $3" = "-p ! --" ] && [ "$#" -eq 4 ] || { echo "fake usermod: unexpected arguments: $*" >&2; exit 64; }
echo "usermod $4" >> "$SIM_STATE/calls"
[ -f "$SIM_STATE/usermod.fails" ] && { echo "usermod: cannot lock the password" >&2; exit 1; }
[ -f "$SIM_STATE/usermod.noop" ] && exit 0
awk -F: -v OFS=: -v name="$4" '$1 == name { $2 = "!" } { print }' "$SIM_ROOT/etc/shadow" > "$SIM_ROOT/etc/shadow.new"
mv "$SIM_ROOT/etc/shadow.new" "$SIM_ROOT/etc/shadow"
"""

# `gpasswd -d <account> <group>`: takes the account out of the group's member list.
FAKE_GPASSWD = """#!/bin/sh
[ "$1" = "-d" ] && [ "$#" -eq 3 ] || { echo "fake gpasswd: unexpected arguments: $*" >&2; exit 64; }
echo "gpasswd $2 $3" >> "$SIM_STATE/calls"
awk -F: -v OFS=: -v user="$2" -v group="$3" '
    $1 == group { n = split($4, m, ","); out = ""
                  for (i = 1; i <= n; i++) if (m[i] != user) out = out (out == "" ? "" : ",") m[i]
                  $4 = out }
    { print }' "$SIM_ROOT/etc/group" > "$SIM_ROOT/etc/group.new"
mv "$SIM_ROOT/etc/group.new" "$SIM_ROOT/etc/group"
echo "Removing user $2 from group $3"
"""


@dataclass
class Machine:
    base: Path

    def __post_init__(self) -> None:
        self.root = self.base / "tree"
        self.bin = self.base / "bin"
        self.state = self.base / "state"
        for directory in (self.root / "etc" / "sudoers.d", self.bin, self.state):
            directory.mkdir(parents=True)
        for name, body in {"usermod": FAKE_USERMOD, "gpasswd": FAKE_GPASSWD}.items():
            (self.bin / name).write_text(body, encoding="utf-8", newline="\n")
        self.set_accounts({"root": (0, "*"), "daemon": (1, "*"), "nobody": (65534, "*")})
        self.set_group("sudo", [])

    def set_accounts(self, accounts: dict[str, tuple[int, str]]) -> None:
        """/etc/passwd and /etc/shadow with these accounts: name -> (uid, password field)."""
        passwd = "".join(f"{name}:x:{uid}:{uid}:sim:/home/{name}:/bin/sh\n" for name, (uid, _) in accounts.items())
        shadow = "".join(f"{name}:{field}:20000:0:99999:7:::\n" for name, (_, field) in accounts.items())
        (self.root / "etc" / "passwd").write_text(passwd, encoding="utf-8", newline="\n")
        (self.root / "etc" / "shadow").write_text(shadow, encoding="utf-8", newline="\n")

    def read(self, name: str) -> str:
        return (self.root / "etc" / name).read_text(encoding="utf-8")

    def shadow(self) -> dict[str, str]:
        """name -> password field of every account in /etc/shadow."""
        return {line.split(":")[0]: line.split(":")[1] for line in self.read("shadow").splitlines()}

    def set_group(self, name: str, members: list[str]) -> None:
        (self.root / "etc" / "group").write_text(f"{name}:x:27:{','.join(members)}\n", encoding="utf-8", newline="\n")

    def sudo_members(self) -> list[str]:
        return [member for member in self.read("group").strip().split(":")[3].split(",") if member]

    def grant_passwordless_sudo(self, account: str) -> Path:
        grant = self.root / "etc" / "sudoers.d" / "live"
        grant.write_text(f"{account} ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8", newline="\n")
        return grant

    def calls(self) -> list[str]:
        log = self.state / "calls"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    def run(self) -> subprocess.CompletedProcess[str]:
        assert BASH is not None
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "PAI_LIVE_LOCK_ROOT": self.root.as_posix(),
            "SIM_ROOT": self.root.as_posix(),
            "SIM_STATE": self.state.as_posix(),
        }
        # --posix: the component is a #!/bin/sh script, which on the image is dash, so bash's extensions are off.
        return subprocess.run(  # noqa: S603
            [BASH, "--posix", str(COMPONENT)], env=env, capture_output=True, text=True, check=False, timeout=60
        )


@pytest.fixture
def machine(tmp_path: Path) -> Machine:
    return Machine(tmp_path)


def live_user_machine(machine: Machine, *, name: str = "sim-user", uid: int = 1000) -> Path:
    """What live-config leaves: the account with the well-known hash, in the sudo group, with passwordless sudo."""
    machine.set_accounts({"root": (0, "*"), "daemon": (1, "*"), name: (uid, LIVE_HASH), "nobody": (65534, "*")})
    machine.set_group("sudo", [name])
    return machine.grant_passwordless_sudo(name)


# ---- what it locks -------------------------------------------------------------------------------------------------


def test_the_live_user_loses_its_password_the_sudo_group_and_the_passwordless_grant(machine: Machine) -> None:
    grant = live_user_machine(machine)
    done = machine.run()
    assert done.returncode == 0, done.stderr
    assert machine.shadow() == {"root": "*", "daemon": "*", "sim-user": "!", "nobody": "*"}
    assert machine.sudo_members() == []
    assert not grant.exists()
    assert machine.calls() == ["usermod sim-user", "gpasswd sim-user sudo"]
    assert LIVE_HASH not in machine.read("shadow")  # not "!"-prefixed: the old hash is gone for good


@pytest.mark.parametrize(
    ("name", "uid"),
    [("sim-user", 1000), ("whoever", 1234), ("kiosk-dev", 59999), ("an-account-with-a-long-name", 1001)],
)
def test_the_account_is_found_by_what_it_is_not_by_its_name_or_uid(machine: Machine, name: str, uid: int) -> None:
    live_user_machine(machine, name=name, uid=uid)
    assert machine.run().returncode == 0
    assert machine.shadow()[name] == "!"


def test_every_ordinary_login_account_is_locked_not_only_the_first(machine: Machine) -> None:
    machine.set_accounts(
        {"root": (0, "*"), "alice": (1000, LIVE_HASH), "bob": (1001, STRONG_HASH), "carol": (1002, "!locked-already")}
    )
    machine.set_group("sudo", ["alice", "bob", "carol"])
    assert machine.run().returncode == 0
    assert machine.shadow() == {"root": "*", "alice": "!", "bob": "!", "carol": "!locked-already"}
    assert machine.sudo_members() == []
    assert machine.calls() == [
        "usermod alice",
        "gpasswd alice sudo",
        "usermod bob",
        "gpasswd bob sudo",
        "gpasswd carol sudo",
    ]


def test_an_empty_password_field_is_a_login_with_no_password_and_is_locked(machine: Machine) -> None:
    machine.set_accounts({"root": (0, "*"), "sim-user": (1000, "")})
    assert machine.run().returncode == 0
    assert machine.shadow()["sim-user"] == "!"


@pytest.mark.parametrize("marker", ["!", "!!", "*", "!*", "!" + STRONG_HASH, "*LK*"])
def test_an_account_that_is_already_locked_is_not_touched(machine: Machine, marker: str) -> None:
    machine.set_accounts({"root": (0, "*"), "sim-user": (1000, marker)})
    assert machine.run().returncode == 0
    assert machine.shadow()["sim-user"] == marker
    assert machine.calls() == []


def test_a_second_run_changes_nothing(machine: Machine) -> None:
    live_user_machine(machine)
    assert machine.run().returncode == 0
    first = (machine.read("shadow"), machine.read("group"), machine.calls())
    assert machine.run().returncode == 0
    assert (machine.read("shadow"), machine.read("group"), machine.calls()) == first


def test_system_accounts_are_left_to_the_image_and_the_self_check_which_fails_on_a_hash_there(machine: Machine) -> None:
    machine.set_accounts({"root": (0, "*"), "system-thing": (999, STRONG_HASH), "nobody": (65534, STRONG_HASH)})
    assert machine.run().returncode == 0
    assert machine.shadow() == {"root": "*", "system-thing": STRONG_HASH, "nobody": STRONG_HASH}
    assert machine.calls() == []


def test_the_range_of_ordinary_accounts_is_what_login_defs_says(machine: Machine) -> None:
    (machine.root / "etc" / "login.defs").write_text(
        "# comment\nUID_MIN\t\t2000\nUID_MAX 3000\nSYS_UID_MAX 999\n", encoding="utf-8", newline="\n"
    )
    machine.set_accounts(
        {"root": (0, "*"), "below": (1500, LIVE_HASH), "inside": (2500, LIVE_HASH), "above": (3500, LIVE_HASH)}
    )
    assert machine.run().returncode == 0
    assert machine.shadow() == {"root": "*", "below": LIVE_HASH, "inside": "!", "above": LIVE_HASH}


def test_a_login_defs_without_the_numbers_falls_back_to_the_debian_range(machine: Machine) -> None:
    (machine.root / "etc" / "login.defs").write_text(
        "UID_MIN not-a-number\n# UID_MAX 5\n", encoding="utf-8", newline="\n"
    )
    machine.set_accounts({"root": (0, "*"), "low": (999, LIVE_HASH), "edge": (1000, LIVE_HASH)})
    assert machine.run().returncode == 0
    assert machine.shadow() == {"root": "*", "low": LIVE_HASH, "edge": "!"}


# ---- the sudo grant ------------------------------------------------------------------------------------------------


def test_the_group_is_left_alone_when_the_account_is_not_in_it(machine: Machine) -> None:
    live_user_machine(machine)
    machine.set_group("sudo", ["somebody-else"])
    assert machine.run().returncode == 0
    assert machine.sudo_members() == ["somebody-else"]
    assert machine.calls() == ["usermod sim-user"]


def test_a_machine_without_the_grant_is_fine(machine: Machine) -> None:
    live_user_machine(machine).unlink()
    assert machine.run().returncode == 0


def test_the_grant_goes_even_when_no_account_needs_locking(machine: Machine) -> None:
    grant = machine.grant_passwordless_sudo("sim-user")
    machine.set_accounts({"root": (0, "*"), "sim-user": (1000, "!")})
    assert machine.run().returncode == 0
    assert not grant.exists()


# ---- failing loudly ------------------------------------------------------------------------------------------------


def test_a_lock_that_does_not_take_effect_fails_and_names_the_account(machine: Machine) -> None:
    live_user_machine(machine)
    (machine.state / "usermod.noop").write_text("", encoding="utf-8")
    done = machine.run()
    assert done.returncode == 1
    assert "the password of account sim-user is still usable" in done.stderr
    assert LIVE_HASH not in done.stdout + done.stderr


def test_a_usermod_that_fails_does_not_stop_the_rest_and_is_reported(machine: Machine) -> None:
    grant = live_user_machine(machine)
    (machine.state / "usermod.fails").write_text("", encoding="utf-8")
    done = machine.run()
    assert done.returncode == 1
    assert "still usable" in done.stderr
    assert not grant.exists()  # the grant is removed whatever happened to the lock
    assert machine.sudo_members() == []


def test_a_grant_that_cannot_be_removed_fails(machine: Machine) -> None:
    live_user_machine(machine).unlink()
    (machine.root / "etc" / "sudoers.d" / "live").mkdir()  # rm -f cannot remove a directory
    done = machine.run()
    assert done.returncode != 0


# ---- the file itself -----------------------------------------------------------------------------------------------


def test_the_component_sorts_after_the_stock_components_that_create_the_login_and_the_grant() -> None:
    """live-config runs /usr/lib/live/config/* in name order: user-setup (0030) creates the account, sudo (0040)
    grants it passwordless sudo, policykit (1080) adds its administrator rule for the sudo group."""
    assert COMPONENT.parent.parts[-4:] == ("usr", "lib", "live", "config")
    for stock in ("0030-user-setup", "0040-sudo", "1080-policykit"):
        assert COMPONENT.name > stock
    assert COMPONENT.name[:4].isdigit()
    assert COMPONENT.name[4] == "-"


def test_the_component_is_a_posix_sh_script_that_stops_at_the_first_error() -> None:
    text = COMPONENT.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n")
    assert "\nset -eu\n" in text
    # "[[" as a test command, not inside a character class like [[:space:]]
    assert not re.search(r"(?m)(^|[\s;!(])\[\[ ", text), "[[ ]] is not POSIX sh (the image's /bin/sh is dash)"
    for bashism in ("local ", "function ", "=(", "pipefail", "<<<"):
        assert bashism not in text, f"{bashism!r} is not POSIX sh (the image's /bin/sh is dash)"
    assert b"\r" not in COMPONENT.read_bytes()
