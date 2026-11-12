#!/usr/bin/env bash
# Runs INSIDE a privileged debian:trixie-slim container as root, started by run.sh.
# Creates a sparse disk on a loop device, runs real_tools_check.py against it, and always detaches the device.
set -euo pipefail

REPO=/repo
WORK=/pai-it
IMAGE="$WORK/disk.img"
DISK_GIB="${PAI_IT_DISK_GIB:-20}"
LOOP=""

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq --no-install-recommends \
    python3 cryptsetup util-linux fdisk dosfstools e2fsprogs rsync acl attr procps >/dev/null 2>&1
echo "tools: $(cryptsetup --version), $(sfdisk --version), $(rsync --version | head -1), $(python3 --version)"

mkdir -p "$WORK"
cleanup() {
    status=$?
    # The driver releases everything itself; this is the backstop for a crash. Only our own loop device is touched.
    if cryptsetup status cryptroot >/dev/null 2>&1; then
        umount -R /run/pai-install-it/target 2>/dev/null || true
        cryptsetup close cryptroot 2>/dev/null || true
    fi
    if [ -n "$LOOP" ]; then losetup -d "$LOOP" 2>/dev/null || true; fi
    exit "$status"
}
trap cleanup EXIT

truncate -s "${DISK_GIB}G" "$IMAGE"
# A fresh container may have no loop device nodes; the kernel's loop-control creates the devices, nodes are ours to make.
LOOP="$(losetup --find --show --partscan "$IMAGE")"
echo "loop device: $LOOP backed by $IMAGE (sparse ${DISK_GIB} GiB)"

python3 -I -B "$REPO/installer/tests/integration/real_tools_check.py" "$LOOP" "$WORK"

# The loop device must detach and nothing may remain mapped or mounted.
losetup -d "$LOOP"
if losetup --list --noheadings | grep -q "$IMAGE"; then echo "FAIL  the loop device is still attached"; exit 1; fi
LOOP=""
echo "PASS  the loop device is detached"
echo "ALL REAL-TOOL CHECKS PASSED"
