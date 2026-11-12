"""Configuring the copied system: identity files, accounts, removal of everything that belongs to the live session.

Files are written with ``install`` (content on its standard input, never a shell string); anything that needs the
target's own tools runs inside a chroot whose bind mounts are registered for undo before they are made. The accounts
rule is verified at the end by reading the target's ``/etc/shadow``: every account must have a locked or absent
password, so no default credential can survive the installation.
"""

from __future__ import annotations

import re

from installer import timeouts
from installer.context import MAPPING_NAME, InstallContext, Uuids
from installer.errors import InstallerError, VerificationError
from installer.runner import CommandResult
from installer.steps.filesystems import push_unmount

GRUB_TIMEOUT_SECONDS = 2
CHROOT_ENVIRONMENT = {"DEBIAN_FRONTEND": "noninteractive"}

# Debian package families of the live session. Patterns, so companion packages (-initramfs-tools, -systemd, -doc) that
# happen to be installed are found; only what dpkg reports as installed is purged.
LIVE_PACKAGE_PATTERNS = ("live-boot", "live-boot-*", "live-config", "live-config-*", "live-tools")
# Where live-boot and live-config leave files behind (the packages' own files go with the purge).
LIVE_LEFTOVERS = ("/etc/live", "/lib/live/config", "/lib/live/boot", "/var/lib/live", "/etc/sudoers.d/live")
ADMIN_GROUPS = frozenset({"sudo", "admin", "wheel"})  # groups that grant administration on Debian-family systems
DEFAULT_LIVE_USER = "user"  # live-config's own default when no other name is configured

_PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*")
_USER_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_LIVE_USERNAME = re.compile(r"""^\s*(?:export\s+)?LIVE_USERNAME\s*=\s*["']?([^"'\s#]+)["']?""", re.MULTILINE)


# ------------------------------------------------------------------------------------------------ rendering
def render_fstab(uuids: Uuids) -> str:
    return (
        "# /etc/fstab: written by the Private AI OS installer. Filesystems are identified by UUID.\n"
        f"UUID={uuids.root_fs} / ext4 errors=remount-ro 0 1\n"
        f"UUID={uuids.boot_fs} /boot ext4 defaults 0 2\n"
        f"UUID={uuids.esp_fs} /boot/efi vfat umask=0077 0 2\n"
    )


def render_crypttab(uuids: Uuids, mapping_name: str) -> str:
    # No keyfile ("none": the passphrase is asked for) and no 'discard' (TRIM through the encryption leaks usage).
    return (
        "# /etc/crypttab: written by the Private AI OS installer.\n"
        f"{mapping_name} UUID={uuids.luks} none luks,initramfs\n"
    )


def render_hosts(hostname: str) -> str:
    return (
        "127.0.0.1 localhost\n"
        f"127.0.1.1 {hostname}\n"
        "::1 localhost ip6-localhost ip6-loopback\n"
        "ff02::1 ip6-allnodes\n"
        "ff02::2 ip6-allrouters\n"
    )


def render_grub_defaults(kernel_args: tuple[str, ...]) -> str:
    # A drop-in in /etc/default/grub.d, sourced after /etc/default/grub, so the distribution's file stays untouched.
    return (
        "# Written by the Private AI OS installer.\n"
        f'GRUB_CMDLINE_LINUX="{" ".join(kernel_args)}"\n'
        f"GRUB_TIMEOUT={GRUB_TIMEOUT_SECONDS}\n"
        "GRUB_DISABLE_OS_PROBER=true\n"
    )


# ------------------------------------------------------------------------------------------------ helpers
def write_target_file(ctx: InstallContext, path: str, content: str, mode: str = "0644") -> None:
    ctx.cmd.run(
        ["install", "-D", "-m", mode, "/dev/stdin", f"{ctx.target_root}{path}"],
        timeout=timeouts.QUICK,
        stdin=content.encode("utf-8"),
    )


def chroot_run(ctx: InstallContext, argv: list[str], timeout: float, check: bool = True) -> CommandResult:
    return ctx.cmd.run(["chroot", ctx.target_root, *argv], timeout=timeout, check=check, extra_env=CHROOT_ENVIRONMENT)


def _read_target(ctx: InstallContext, path: str) -> str | None:
    try:
        return ctx.host.read_text(f"{ctx.target_root}{path}")
    except OSError:
        return None


def parse_passwd_names(text: str) -> set[str]:
    return {line.split(":", 1)[0] for line in text.splitlines() if line and not line.startswith("#")}


# ------------------------------------------------------------------------------------------------ steps
def write_configuration_files(ctx: InstallContext) -> str:
    uuids = ctx.require_uuids()
    write_target_file(ctx, "/etc/fstab", render_fstab(uuids))
    write_target_file(ctx, "/etc/crypttab", render_crypttab(uuids, MAPPING_NAME))
    write_target_file(ctx, "/etc/hostname", f"{ctx.plan.hostname}\n")
    write_target_file(ctx, "/etc/hosts", render_hosts(ctx.plan.hostname))
    write_target_file(ctx, "/etc/default/grub.d/90-pai-installer.cfg", render_grub_defaults(ctx.plan.extra_kernel_args))
    return "fstab, crypttab, hostname, hosts and the GRUB defaults written"


def mount_chroot_binds(ctx: InstallContext) -> str:
    """The usual bind mounts for a chroot. ``--make-rslave`` first: it stops our unmounts reaching the live system."""
    root = ctx.target_root
    binds = (
        ("dev", ["--rbind", "/dev"]),
        ("sys", ["--rbind", "/sys"]),
        ("run", ["--bind", "/run"]),
    )
    push_unmount(ctx, f"{root}/proc")
    ctx.cmd.run(["mount", "-t", "proc", "proc", f"{root}/proc"], timeout=timeouts.QUICK)
    for name, options in binds:
        path = f"{root}/{name}"
        push_unmount(ctx, path)
        ctx.cmd.run(["mount", *options, path], timeout=timeouts.QUICK)
        ctx.cmd.run(["mount", "--make-rslave", path], timeout=timeouts.QUICK)
    return "proc, dev, sys and run available inside the target"


def discover_live_user(ctx: InstallContext) -> str | None:
    """The live session's user: from live-config's configuration, else its default; only if the account exists."""
    name = DEFAULT_LIVE_USER
    sources = []
    config = _read_target(ctx, "/etc/live/config.conf")
    if config is not None:
        sources.append(config)
    try:
        for entry in ctx.host.listdir(f"{ctx.target_root}/etc/live/config.conf.d"):
            text = _read_target(ctx, f"/etc/live/config.conf.d/{entry}")
            if text is not None:
                sources.append(text)
    except OSError:
        pass
    for text in sources:
        found = _LIVE_USERNAME.findall(text)
        if found:
            name = found[-1]
    if not _USER_NAME.fullmatch(name):
        raise InstallerError("the live session's user name in /etc/live is not a valid account name")
    passwd = _read_target(ctx, "/etc/passwd") or ""
    return name if name in parse_passwd_names(passwd) and name != "root" else None


def _autologin_dropins(ctx: InstallContext) -> list[str]:
    """Getty drop-ins (paths inside the target) that enable automatic login."""
    found = []
    base = "/etc/systemd/system"
    try:
        directories = [
            d for d in ctx.host.listdir(f"{ctx.target_root}{base}") if "getty" in d and d.endswith(".service.d")
        ]
    except OSError:
        return []
    for directory in directories:
        try:
            files = ctx.host.listdir(f"{ctx.target_root}{base}/{directory}")
        except OSError:
            continue
        for name in files:
            text = _read_target(ctx, f"{base}/{directory}/{name}")
            if name.endswith(".conf") and text is not None and "autologin" in text.lower():
                found.append(f"{base}/{directory}/{name}")
    return found


def installed_live_packages(ctx: InstallContext) -> list[str]:
    result = chroot_run(
        ctx,
        ["dpkg-query", "--show", "--showformat", "${db:Status-Status}\t${Package}\n", *LIVE_PACKAGE_PATTERNS],
        timeouts.QUICK,
        check=False,
    )
    if result.returncode not in (0, 1):  # 1: some pattern matched no package, which is normal here
        raise InstallerError(f"dpkg-query failed (exit {result.returncode}) while looking for live packages")
    packages = []
    for line in result.stdout.splitlines():
        status, _, package = line.partition("\t")
        if package and status != "not-installed" and _PACKAGE_NAME.fullmatch(package):
            packages.append(package)
    return sorted(set(packages))


def remove_live_session(ctx: InstallContext) -> str:
    """Delete the live user, purge live-boot/live-config and their companions, remove their leftovers."""
    live_user = discover_live_user(ctx)
    if live_user is not None:
        chroot_run(ctx, ["userdel", "--remove", live_user], timeouts.QUICK)
    packages = installed_live_packages(ctx)
    if packages:
        chroot_run(ctx, ["apt-get", "--yes", "--quiet", "purge", *packages], timeouts.PACKAGES)
    autologin = _autologin_dropins(ctx)
    chroot_run(ctx, ["rm", "-rf", "--one-file-system", "--", *LIVE_LEFTOVERS, *autologin], timeouts.QUICK)
    chroot_run(ctx, ["rmdir", "--ignore-fail-on-non-empty", "/lib/live"], timeouts.QUICK, check=False)
    return (
        f"removed the live user {live_user or '(none found)'}, purged {len(packages)} live package(s), "
        f"removed {len(autologin)} autologin drop-in(s)"
    )


def create_accounts(ctx: InstallContext) -> str:
    """Root locked; one primary user with a locked password and no sudo (no group beyond its own)."""
    username = ctx.plan.username
    chroot_run(ctx, ["passwd", "--lock", "root"], timeouts.QUICK)
    chroot_run(ctx, ["useradd", "--create-home", "--shell", "/bin/bash", "--user-group", username], timeouts.QUICK)
    chroot_run(ctx, ["passwd", "--lock", username], timeouts.QUICK)
    return f"root locked; user {username} created with a locked password"


def reset_machine_id(ctx: InstallContext) -> str:
    """An empty /etc/machine-id: systemd makes a new unique one on the first boot, so clones do not share an id."""
    chroot_run(ctx, ["truncate", "--size", "0", "/etc/machine-id"], timeouts.QUICK)
    chroot_run(ctx, ["rm", "-f", "/var/lib/dbus/machine-id"], timeouts.QUICK)
    return "machine-id emptied"


def verify_accounts(ctx: InstallContext) -> str:
    """No account anywhere may have a usable password; the primary user exists; the live remnants are gone."""
    shadow = _read_target(ctx, "/etc/shadow")
    if shadow is None:
        raise VerificationError("the installed system has no readable /etc/shadow")
    for line in shadow.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, rest = line.partition(":")
        password = rest.split(":", 1)[0]
        if not password.startswith(("!", "*")):
            raise VerificationError(f"the account {name!r} does not have a locked password")
    if ctx.plan.username not in parse_passwd_names(_read_target(ctx, "/etc/passwd") or ""):
        raise VerificationError(f"the primary user {ctx.plan.username!r} does not exist in the installed system")
    for line in (_read_target(ctx, "/etc/group") or "").splitlines():
        group, _, rest = line.partition(":")
        members = rest.split(":")[-1].split(",") if rest else []
        if group in ADMIN_GROUPS and ctx.plan.username in members:
            raise VerificationError(f"the primary user must not be a member of the administrative group {group!r}")
    if ctx.host.exists(f"{ctx.target_root}/etc/live") or _autologin_dropins(ctx):
        raise VerificationError("live-session files remain in the installed system")
    return "every account is locked, the primary user exists, no live remnants"
