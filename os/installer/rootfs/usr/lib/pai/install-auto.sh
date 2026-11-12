#!/bin/bash
# Unattended install from a plan medium: the body of pai-install-auto.service.
#
# usage: install-auto.sh <volume-label>
#
# Finds the block device that carries the volume label (udev's /dev/disk/by-label link), mounts it READ-ONLY (no
# execution, no device nodes, no setuid), runs the installer engine on the plan.json it holds and unmounts the medium
# again, whatever the engine's outcome. The engine's own exit status is this script's, so the unit fails exactly when
# the install did.
#
# The plan can hold a passphrase (passphrase_source "plan"). This script never reads, prints or copies the plan: it
# checks only that plan.json is a regular file of a sane size and hands its path to the engine. Its own messages name
# the label, the device and the file name and nothing else. The engine writes its JSON-lines events to the standard
# output, which the unit sends to the journal and the console.
#
# Nothing to do is not an error: when no device carries the label (or it has no plan.json) the script says so and
# exits 0, because the unit's only condition is the kernel command line (a device that appears late cannot be a unit
# condition) and an operator who passed pai.install=auto without a medium has nothing to be failed over.
#
# Test-only overrides (the same convention as security-selfcheck.sh): PAI_INSTALL_PLAN_DIR, PAI_INSTALL_BY_LABEL_DIR,
# PAI_INSTALL_ENGINE_DIR and PAI_INSTALL_WAIT (whole seconds). The unit sets none of them.
set -euo pipefail
export LC_ALL=C

# The plan medium is mounted here, in a directory of its own. It must NOT be under /run/pai-install: that directory is
# the engine's (the target is mounted there and the engine's last step proves nothing is left mounted below it, which
# a mounted plan medium would trip; found on the first complete real install).
PLAN_DIR=${PAI_INSTALL_PLAN_DIR:-/run/pai-plan}          # the unit's second RuntimeDirectory
BY_LABEL_DIR=${PAI_INSTALL_BY_LABEL_DIR:-/dev/disk/by-label}
ENGINE_DIR=${PAI_INSTALL_ENGINE_DIR:-/opt/pai}           # holds the installer/ package; `python3 -m installer` runs from here
PLAN_FILE_NAME=plan.json
# How long to wait for the medium after boot: udev has to see the device and make its link. A medium that is attached
# is there within seconds even under emulation; one that is not costs the boot of an install-mode machine this much.
WAIT_SECONDS=${PAI_INSTALL_WAIT:-60}
# A plan is a few hundred bytes; a medium that holds more than this under that name is not a plan.
MAX_PLAN_BYTES=1048576
# The first character is never "-" (it could pass for an option) or "." (".." would leave the by-label directory).
LABEL_PATTERN='^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$'
# Mounted read-only and unable to run, create devices or grant privileges: the medium is data, not part of the system.
MOUNT_OPTIONS=ro,nosuid,nodev,noexec

say() { echo "pai-install-auto: $*"; }
die() {
    say "ERROR: $*" >&2
    exit 1
}

whole_seconds() { [[ $1 =~ ^[0-9]+$ ]]; }

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <volume-label>" >&2
    exit 2
fi
label=$1
[[ $label =~ $LABEL_PATTERN ]] || die "the volume label must match $LABEL_PATTERN"
whole_seconds "$WAIT_SECONDS" || die "PAI_INSTALL_WAIT must be a whole number of seconds"

# udev must have seen the devices that exist at boot before the by-label link can be trusted to be absent.
udevadm settle --timeout=30 || say "udev did not settle within 30 s; continuing"

link="$BY_LABEL_DIR/$label"
waited=0
until [ -e "$link" ]; do
    if [ "$waited" -ge "$WAIT_SECONDS" ]; then
        say "no device carries the volume label $label after $WAIT_SECONDS s: nothing to install"
        exit 0
    fi
    sleep 1
    waited=$((waited + 1))
done
device=$(readlink -f -- "$link")
kind=$(stat -c %F -- "$device" 2>/dev/null || true)
[ "$kind" = "block special file" ] || die "$link does not lead to a block device ($device)"

mount_point="$PLAN_DIR/medium"
mkdir -p -- "$mount_point"
mounted=0
cleanup() {
    if [ "$mounted" -eq 1 ]; then
        umount -- "$mount_point" || say "WARNING: could not unmount $mount_point" >&2
    fi
    rmdir -- "$mount_point" 2>/dev/null || true
}
trap cleanup EXIT

mount -o "$MOUNT_OPTIONS" -- "$device" "$mount_point" || die "cannot mount $device (volume label $label) read-only"
mounted=1

plan="$mount_point/$PLAN_FILE_NAME"
if [ ! -f "$plan" ] || [ -L "$plan" ]; then
    say "the medium with the volume label $label has no regular file $PLAN_FILE_NAME: nothing to install"
    exit 0
fi
size=$(wc -c <"$plan")
if [ "$size" -gt "$MAX_PLAN_BYTES" ]; then
    die "$PLAN_FILE_NAME is $size bytes, more than the $MAX_PLAN_BYTES a plan may have"
fi

say "installing from $PLAN_FILE_NAME on $device (volume label $label)"
cd -- "$ENGINE_DIR"
# -s: no per-user site directory; -B: the code is root-owned and read-only, so there is nowhere to write bytecode.
status=0
python3 -s -B -m installer --plan "$plan" || status=$?
say "the installer engine exited with status $status"
exit "$status"
