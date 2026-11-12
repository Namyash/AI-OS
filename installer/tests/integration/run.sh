#!/usr/bin/env bash
# Integration test of the installer's disk steps with the REAL tools, in a privileged debian:trixie-slim container:
# a sparse file on a loop device is partitioned, LUKS2-formatted, given a recovery key, formatted, mounted, filled by
# the real copy step and closed, and the result is checked with cryptsetup, sfdisk, lsblk and blkid themselves.
# See docs/development/INSTALLER.md for what this does and does not prove.
#
# usage: bash installer/tests/integration/run.sh
#   PAI_IT_DISK_GIB=<n>   size of the sparse disk (default 20; the engine refuses anything under 16)
#
# Needs Docker, network access (Debian packages) and permission for a privileged container with loop devices. The
# container is named pai-inst-<random> and removed when the test ends. It only ever touches the loop device it makes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Every path handed to docker uses ROOT, the form the docker client understands (see os/build/build-iso.sh).
ROOT="$(cd "$SCRIPT_DIR/../../.." && (pwd -W 2>/dev/null || pwd))"
export MSYS_NO_PATHCONV=1

NAME="pai-inst-$(date +%s)-$$"
docker run --rm --init --privileged --name "$NAME" \
    -e PAI_IT_DISK_GIB="${PAI_IT_DISK_GIB:-20}" \
    -v "$ROOT:/repo:ro" \
    debian:trixie-slim bash /repo/installer/tests/integration/in_container.sh
