"""Policy-as-code checks over the OS image sources.

These guard the invariants in docs/security/THREAT_MODEL.md section 5 so a future edit cannot quietly
weaken the firewall, re-enable host integration, or add remote-access packages.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.bash_support import find_working_bash

REPO = Path(__file__).resolve().parents[2]
OS_DIR = REPO / "os"
BACKEND_DIR = REPO / "backend"

# Policy tables (what to forbid/require), not facts about any one image.
FORBIDDEN_PACKAGES = {
    "openssh-server",
    "telnetd",
    "avahi-daemon",
    "cups",
    "bluez",
    "popularity-contest",
    "open-vm-tools-desktop",
    "virtualbox-guest-x11",
    "virtualbox-guest-utils",
    "vmhgfs-fuse",
}
REQUIRED_PACKAGES = {"nftables", "apparmor", "cryptsetup", "systemd-sysv"}
HOST_INTEGRATION_MODULES = {"vboxsf"}
# systemd-resolved settings that must hold: LLMNR and multicast DNS answer the local network on wildcard sockets.
RESOLVED_REQUIRED = {"LLMNR": {"no"}, "MulticastDNS": {"no"}}
SYSCTL_REQUIRED = {  # key -> acceptable values
    "net.ipv4.ip_forward": {"0"},
    "net.ipv6.conf.all.forwarding": {"0"},
    "kernel.kptr_restrict": {"2"},
    "kernel.dmesg_restrict": {"1"},
    "kernel.sysrq": {"0"},
    "kernel.unprivileged_bpf_disabled": {"1", "2"},
    "fs.protected_symlinks": {"1"},
    "fs.protected_hardlinks": {"1"},
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


def _packages() -> set[str]:
    names: set[str] = set()
    for path in OS_DIR.glob("**/package-lists/*.list.chroot"):
        names.update(name for line in _read(path).splitlines() if (name := _strip_comment(line)))
    return names


def _chains(ruleset: str) -> dict[str, tuple[str, list[str]]]:
    """Map hook name -> (policy, rule lines) for every base chain in an nftables ruleset."""
    chains: dict[str, tuple[str, list[str]]] = {}
    for match in re.finditer(r"chain\s+\w+\s*\{(?P<body>.*?)\n\s*\}", ruleset, re.DOTALL):
        body = match["body"]
        header = re.search(r"type\s+filter\s+hook\s+(\w+)\s+priority\s+[^;]+;\s*policy\s+(\w+);", body)
        if header:
            rules = [r for line in body.splitlines() if (r := _strip_comment(line)) and "hook" not in r]
            chains[header[1]] = (header[2], rules)
    return chains


NFT_CONF = OS_DIR / "security" / "rootfs" / "etc" / "nftables.conf"


def test_firewall_defaults_to_drop_in_every_direction() -> None:
    chains = _chains(_read(NFT_CONF))
    assert set(chains) == {"input", "forward", "output"}
    assert {hook: policy for hook, (policy, _) in chains.items()} == {
        "input": "drop",
        "forward": "drop",
        "output": "drop",
    }


def test_firewall_has_no_unconditional_accept() -> None:
    for hook, (_, rules) in _chains(_read(NFT_CONF)).items():
        assert "accept" not in rules, f"unconditional accept in {hook} chain"


def test_firewall_forward_chain_has_no_rules() -> None:
    assert _chains(_read(NFT_CONF))["forward"][1] == []


def test_host_integration_modules_cannot_load() -> None:
    blocked: set[str] = set()
    for path in OS_DIR.glob("**/modprobe.d/*.conf"):
        for line in _read(path).splitlines():
            parts = _strip_comment(line).split()
            if len(parts) >= 3 and parts[0] == "install" and parts[2] in {"/bin/false", "/bin/true"}:
                blocked.add(parts[1])
    assert blocked >= HOST_INTEGRATION_MODULES


def test_no_forbidden_packages() -> None:
    assert _packages() & FORBIDDEN_PACKAGES == set()


def test_required_packages_present() -> None:
    assert _packages() >= REQUIRED_PACKAGES


def _third_party_imports(package_dir: Path) -> set[str]:
    """Top-level names of the non-standard-library modules that the code under `package_dir` imports.

    The package's own tests are not shipped, so what only they import is not needed. Imports made at run time
    (importlib, __import__) are not visible to a static scan.
    """
    modules: set[str] = set()
    for path in package_dir.rglob("*.py"):
        if "tests" in path.relative_to(package_dir).parts:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                modules.add(node.module.split(".")[0])
    return {name for name in modules if name not in sys.stdlib_module_names and name != package_dir.name}


def test_every_third_party_module_the_backend_imports_has_a_debian_package_in_the_image() -> None:
    # Debian names a library's package python3-<module> (python3-fastapi, python3-starlette, ...). A module this
    # does not hold for needs its own entry here, with the reason, rather than a silent gap: the service would
    # install fine and then fail on its first import.
    imported = _third_party_imports(BACKEND_DIR)
    assert imported, f"no third-party import found under {BACKEND_DIR}: the scan would pass without looking"
    packages = _packages()
    missing = sorted(f"python3-{name}" for name in imported if f"python3-{name}" not in packages)
    assert missing == [], f"the backend imports modules whose Debian packages are not in the package list: {missing}"


def test_the_third_party_import_scan_ignores_tests_the_standard_library_and_the_package_itself(tmp_path: Path) -> None:
    package = tmp_path / "app"
    (package / "tests").mkdir(parents=True)
    (package / "core.py").write_text("import os\nimport requests.adapters\nfrom app import tests\nfrom . import x\n")
    (package / "tests" / "test_core.py").write_text("import pytest\nimport httpx\n")
    assert _third_party_imports(package) == {"requests"}


def test_sysctl_hardening_values() -> None:
    settings: dict[str, str] = {}
    for path in OS_DIR.glob("**/sysctl.d/*.conf"):
        for line in _read(path).splitlines():
            if "=" in (clean := _strip_comment(line)):
                key, value = (part.strip() for part in clean.split("=", 1))
                settings[key] = value
    for key, allowed in SYSCTL_REQUIRED.items():
        assert settings.get(key) in allowed, f"{key} = {settings.get(key)!r}, expected one of {allowed}"


def test_resolved_does_not_answer_llmnr_or_multicast_dns() -> None:
    # systemd-resolved reads resolved.conf.d/*.conf in file-name order, the last assignment of a key winning; only
    # the [Resolve] section holds these keys.
    settings: dict[str, str] = {}
    files = sorted(OS_DIR.glob("**/etc/systemd/resolved.conf.d/*.conf"), key=lambda path: path.name)
    for path in files:
        section = ""
        for line in _read(path).splitlines():
            if (clean := _strip_comment(line)).startswith("[") and clean.endswith("]"):
                section = clean[1:-1]
            elif section == "Resolve" and "=" in clean:
                key, value = (part.strip() for part in clean.split("=", 1))
                settings[key] = value.lower()
    assert files, "no resolved.conf.d drop-in ships: the global LLMNR and mDNS responders stay on"
    for key, allowed in RESOLVED_REQUIRED.items():
        assert settings.get(key) in allowed, f"{key} = {settings.get(key)!r}, expected one of {allowed}"


def _text_sources() -> list[Path]:
    suffixes = {".sh", ".conf", ".network", ".chroot", ".sql"}
    return [p for p in OS_DIR.rglob("*") if p.is_file() and (p.suffix in suffixes or p.name == "Dockerfile")]


def test_image_sources_use_lf_line_endings() -> None:
    # CRLF in a script or config breaks it inside the Linux build container.
    offenders = [p.relative_to(OS_DIR) for p in _text_sources() if b"\r\n" in p.read_bytes()]
    assert offenders == []


def _shell_scripts() -> list[Path]:
    return sorted(
        p for p in OS_DIR.rglob("*") if p.is_file() and (p.suffix == ".sh" or p.name.endswith(".hook.chroot"))
    )


@pytest.mark.parametrize("script", _shell_scripts(), ids=lambda p: p.name)
def test_shell_scripts_fail_fast(script: Path) -> None:
    text = _read(script)
    assert text.startswith("#!"), "missing shebang"
    assert re.search(r"^set -(e|eu|euo pipefail)\b", text, re.MULTILINE), "must enable errexit"


# Every `bash` on PATH is tried, not just the first: on Windows the first can be the WSL launcher with no distribution.
BASH = find_working_bash()


@pytest.mark.skipif(BASH is None, reason="no working bash on this machine")
@pytest.mark.parametrize("script", _shell_scripts(), ids=lambda p: p.name)
def test_shell_scripts_parse(script: Path) -> None:
    assert BASH is not None
    result = subprocess.run([BASH, "-n", str(script)], capture_output=True, text=True, check=False)  # noqa: S603
    assert result.returncode == 0, result.stderr
