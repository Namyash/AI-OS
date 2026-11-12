"""Installs the built ISO onto a blank disk under QEMU (software emulation) in a container and boots what it installed.

Very slow (tens of minutes) and needs Docker plus an ISO that contains the installer, so it is deselected by default:

    python -m pytest tests/end_to_end/test_install_iso.py -m e2e

It skips, with the reason, when Docker or an ISO is missing. The flow, in order (each test uses the result of the one
before; a failed install fails the rest instead of skipping them, so nothing passes unverified):

  1. the live ISO boots with a plan medium (volume label PAI-PLAN) and a blank 20 GiB disk attached, the engine
     installs and the guest powers off with a successful result event;
  2. the installed disk boots through SeaBIOS and its own GRUB, the passphrase is typed at the unlock prompt and the
     self-check passes all 18 checks;
  3. the same through UEFI (OVMF), when the QEMU image has firmware;
  4. three wrong passphrases never reach the self-check or a login.

The passphrase is random per run and never printed. Variables, defaults and how to read a failure:
docs/development/INSTALL_TESTING.md.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.end_to_end.boot_harness import (
    BootEnvironmentError,
    ConfigError,
    IsoNotFoundError,
    docker_unavailable_reason,
    ensure_image,
    locate_iso,
)
from tests.end_to_end.install_harness import ENV_UEFI, InstallConfig, InstallSession, StepResult

pytestmark = pytest.mark.e2e


def _fail(headline: str, step: StepResult) -> None:
    """Fail with the step's problems and the end of its console (already scrubbed of the passphrase)."""
    pytest.fail(
        "\n".join([headline, *step.problems, "", f"last console lines ({step.log}):", step.tail()]),
        pytrace=False,
    )


@pytest.fixture(scope="module")
def prerequisites() -> tuple[Path, InstallConfig]:
    """The ISO to install and the configuration, or a skip (nothing to test with) or a failure (a bad variable)."""
    if reason := docker_unavailable_reason():
        pytest.skip(f"cannot run the install test: {reason}")
    try:
        return locate_iso(), InstallConfig.from_env(os.environ)
    except IsoNotFoundError as error:
        pytest.skip(str(error))
    except ConfigError as error:
        pytest.fail(str(error), pytrace=False)


@pytest.fixture(scope="module")
def session(prerequisites: tuple[Path, InstallConfig]) -> Iterator[InstallSession]:
    """The run's Docker volume with the plan medium and the blank disk in it; removed when the module is done."""
    _, config = prerequisites
    try:
        with InstallSession(ensure_image(), config) as running:
            running.make_media()
            yield running
    except BootEnvironmentError as error:
        pytest.fail(f"cannot run the install test: {error}", pytrace=False)


@pytest.fixture(scope="module")
def installation(session: InstallSession, prerequisites: tuple[Path, InstallConfig]) -> StepResult:
    try:
        result = session.install(prerequisites[0])
    except BootEnvironmentError as error:
        pytest.fail(f"cannot run the install test: {error}", pytrace=False)
    print(f"install console log: {result.log}")
    return result


def _installed(installation: StepResult) -> None:
    if installation.problems:
        _fail("the install did not succeed, so there is no installed system to boot:", installation)


def test_the_engine_installs_the_iso_and_the_guest_powers_off(installation: StepResult) -> None:
    if installation.problems:
        _fail("the install did not succeed:", installation)


def test_the_installed_system_boots_through_bios_unlocks_and_passes_all_eighteen_checks(
    session: InstallSession, installation: StepResult
) -> None:
    _installed(installation)
    result = session.boot_installed("bios")
    print(f"BIOS boot console log: {result.log}")
    if result.problems:
        _fail("the installed system did not boot cleanly through BIOS:", result)


def test_the_installed_system_boots_through_uefi_unlocks_and_passes_all_eighteen_checks(
    session: InstallSession, installation: StepResult
) -> None:
    _installed(installation)
    mode = session.config.uefi
    if mode == "off":
        pytest.skip(f"{ENV_UEFI}=off")
    if not session.probe_uefi():
        if mode == "on":
            pytest.fail(f"{ENV_UEFI}=on but the QEMU image has no UEFI firmware", pytrace=False)
        pytest.skip("the QEMU image has no UEFI firmware (rebuild it: the Dockerfile installs ovmf)")
    result = session.boot_installed("uefi")
    print(f"UEFI boot console log: {result.log}")
    if result.problems:
        _fail("the installed system did not boot cleanly through UEFI:", result)


def test_three_wrong_passphrases_never_reach_the_selfcheck_or_a_login(
    session: InstallSession, installation: StepResult
) -> None:
    _installed(installation)
    result = session.boot_with_wrong_passphrases("bios")
    print(f"wrong-passphrase console log: {result.log}")
    if result.problems:
        _fail("wrong passphrases were not shown to keep the system locked:", result)
