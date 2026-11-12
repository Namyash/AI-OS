"""Starting, watching and stopping Chromium, with the DevTools pipe as its only control channel.

What is passed to the browser, and what is not:

* **No secret.** The command line is built here from fixed flags, the profile path, and flags the operator configured
  (``PAI_KIOSK_CHROMIUM_FLAGS``); nothing derived from the token or a session id is ever part of it.
* **A built environment, not an inherited one.** The browser gets the variables in ``PASSTHROUGH_ENV`` and the paths
  of its private profile, and nothing else, so no variable of the launcher (including any ``PAI_*``) reaches it.
* **Two inherited descriptors.** ``--remote-debugging-pipe`` makes Chromium read commands on descriptor 3 and write
  replies on descriptor 4. The launcher creates both pipes, hands the browser its ends there with a spawn file action
  (every other descriptor Python opens is close-on-exec, so nothing else is inherited) and keeps the other ends.

The spawn is POSIX only: it uses ``os.posix_spawn``. Importing this module works everywhere.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from kiosk.config import Settings
from kiosk.errors import ConfigError, KioskError

COMMAND_FD = 3  # Chromium reads DevTools commands here
REPLY_FD = 4  # Chromium writes DevTools replies and events here
_FIRST_FREE_FD = 10  # the launcher's pipe ends are moved above the child's fixed descriptors before the spawn

# The window the browser opens before the launcher has anything to show. Not about:blank: Chromium treats an app URL
# of about:blank as "no app", and opens a normal browser window (tab strip, new-tab page) instead of an app window.
BLANK_APP_URL = "data:text/html," + quote("<title>Private AI OS</title>", safe="")

# Fixed flags. Each is here for a reason; unknown flags are ignored by Chromium, so a stale entry is harmless but
# misleading, and a test keeps the security-relevant ones in place.
DEFAULT_FLAGS: tuple[str, ...] = (
    "--ozone-platform=wayland",  # draw on cage's Wayland output; no X11 fallback
    "--disable-gpu",  # no GPU in the target virtual machine: software compositing, no GL or Vulkan probing
    "--kiosk",  # full screen without browser chrome or ways to leave it
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--no-pings",
    "--disable-search-engine-choice-screen",
    "--password-store=basic",  # no keyring daemon to wait for or to hold anything
    "--noerrdialogs",
    "--disable-infobars",
    "--disable-session-crashed-bubble",
    # Features that talk to the network or open sockets by themselves (media router: mDNS on every interface).
    "--disable-features=Translate,MediaRouter,DialMediaRouteProvider,GlobalMediaControls,OptimizationHints",
)

# The only variables of the launcher's own environment that reach the browser: where Wayland and the session bus are,
# the search path, and locale/time zone. Any other variable, whatever its name, stays behind.
PASSTHROUGH_ENV = (
    "PATH",
    "LANG",
    "LC_ALL",
    "TZ",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
)
PROFILE_DIR_MODE = 0o700


def resolve_executable(name: str) -> str:
    """The browser's absolute path, or ``ConfigError`` (a restart cannot install a missing browser)."""
    found = shutil.which(name)
    if found is None:
        raise ConfigError(f"PAI_KIOSK_CHROMIUM: executable not found: {name}")
    return found


def build_command(settings: Settings, executable: str) -> list[str]:
    """The browser's argument vector: fixed flags, then the private profile and the pipe, then the operator's flags."""
    return [
        executable,
        *DEFAULT_FLAGS,
        f"--user-data-dir={settings.profile_dir}",
        f"--app={BLANK_APP_URL}",
        "--remote-debugging-pipe",
        *settings.chromium_flags,
    ]


def build_environment(parent: Mapping[str, str], settings: Settings) -> dict[str, str]:
    """The browser's whole environment: the passed-through variables plus paths inside its private profile."""
    environment = {name: parent[name] for name in PASSTHROUGH_ENV if name in parent}
    profile = settings.profile_dir
    environment["HOME"] = str(profile)
    environment["XDG_CONFIG_HOME"] = str(profile / ".config")
    environment["XDG_CACHE_HOME"] = str(profile / ".cache")
    return environment


def prepare_profile(profile_dir: Path) -> None:
    """Start the browser from an empty private profile, so no state survives from an earlier run.

    The directory is deleted and recreated, so it is only touched when it is plainly the launcher's own private
    directory (owned by this user, closed to everyone else): a mistyped path must not delete anything else.
    """
    if profile_dir.exists() or profile_dir.is_symlink():
        if profile_dir.is_symlink() or not profile_dir.is_dir():
            raise ConfigError(f"PAI_KIOSK_PROFILE_DIR: {profile_dir} exists and is not a directory of its own")
        info = profile_dir.stat()
        owner_check = hasattr(os, "getuid") and info.st_uid != os.getuid()
        if owner_check or stat.S_IMODE(info.st_mode) & 0o077:
            raise ConfigError(
                f"PAI_KIOSK_PROFILE_DIR: refusing to clear {profile_dir}: "
                "it is not a directory owned by this user and closed to everyone else"
            )
        shutil.rmtree(profile_dir)
    profile_dir.mkdir(mode=PROFILE_DIR_MODE, parents=True)
    profile_dir.chmod(PROFILE_DIR_MODE)  # mkdir's mode is masked by the umask, and not applied to parents


@dataclass
class BrowserProcess:
    """A running browser and the launcher's ends of its DevTools pipe."""

    pid: int
    command_fd: int  # the launcher writes DevTools commands here
    reply_fd: int  # the launcher reads DevTools replies here
    returncode: int | None = None

    def poll(self) -> int | None:
        """The exit status once the browser has exited (reaping it), None while it runs."""
        if self.returncode is None:
            try:
                reaped, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                self.returncode = -1  # someone else reaped it; the status is lost
            else:
                if reaped == self.pid:
                    self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def stop(self, grace: float = 5.0) -> None:
        """Ask the browser and its helper processes to exit, and kill them when they do not within ``grace`` seconds."""
        if self.poll() is not None:
            return  # already gone; its helpers exit when their connection to it closes
        self._signal_group(signal.SIGTERM)
        deadline = time.monotonic() + grace
        while self.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        self._signal_group(signal.SIGKILL)
        while self.poll() is None:
            time.sleep(0.05)

    def _signal_group(self, sig: int) -> None:
        # The browser leads its own process group (see spawn), so one signal reaches every process it started.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.pid, sig)


def spawn(command: list[str], environment: Mapping[str, str]) -> BrowserProcess:
    """Start ``command`` with the DevTools pipe on descriptors 3 and 4 and ``environment`` as its whole environment."""
    if not hasattr(os, "posix_spawn"):
        raise KioskError("starting the browser needs a POSIX system")
    import fcntl  # POSIX only, so imported here: the rest of this module must import on any development host

    commands_read, commands_write = os.pipe()
    replies_read, replies_write = os.pipe()
    # Move the ends the child will receive above its fixed descriptors, so duplicating one onto 3 or 4 can never
    # overwrite another (the launcher's own pipe ends may themselves be numbered 3 or 4).
    child_reads = fcntl.fcntl(commands_read, fcntl.F_DUPFD_CLOEXEC, _FIRST_FREE_FD)
    child_writes = fcntl.fcntl(replies_write, fcntl.F_DUPFD_CLOEXEC, _FIRST_FREE_FD)
    os.close(commands_read)
    os.close(replies_write)
    file_actions = [
        (os.POSIX_SPAWN_OPEN, 0, os.devnull, os.O_RDONLY, 0),
        (os.POSIX_SPAWN_DUP2, child_reads, COMMAND_FD),
        (os.POSIX_SPAWN_DUP2, child_writes, REPLY_FD),
    ]
    try:
        pid = os.posix_spawn(
            command[0],
            command,
            dict(environment),
            file_actions=file_actions,
            setpgroup=0,  # its own process group: stop() signals the browser and everything it started
            setsigdef=(signal.SIGPIPE, signal.SIGXFSZ),  # Python ignores these; the browser expects their defaults
        )
    except OSError as exc:
        os.close(commands_write)
        os.close(replies_read)
        raise KioskError(f"cannot start the browser {command[0]}: {exc.strerror or exc.__class__.__name__}") from None
    finally:
        os.close(child_reads)
        os.close(child_writes)
    return BrowserProcess(pid=pid, command_fd=commands_write, reply_fd=replies_read)
