#!/usr/bin/env bash
# Runs INSIDE the builder container: assembles the live-build tree from os/ and builds the ISO.
# Inputs (environment, all optional):
#   PAI_DISTRIBUTION  Debian suite                     (default: trixie)
#   PAI_ARCH          target architecture              (default: amd64)
#   PAI_MIRROR        Debian mirror URL                (default: http://deb.debian.org/debian/)
#   PAI_SNAPSHOT      snapshot.debian.org timestamp    (e.g. 20251101T000000Z) -> reproducible package set
set -euo pipefail

SRC=/src/os
BACKEND_SRC=/src/backend # mounted read-only by build-iso.sh, like os/
WORK=/work/live
OUT=/out

DIST="${PAI_DISTRIBUTION:-trixie}"
ARCH="${PAI_ARCH:-amd64}"
MIRROR="${PAI_MIRROR:-http://deb.debian.org/debian/}"
SECURITY=true
UPDATES=true
if [ -n "${PAI_SNAPSHOT:-}" ]; then
    # A snapshot is a frozen archive: security/updates suites would defeat reproducibility.
    MIRROR="http://snapshot.debian.org/archive/debian/${PAI_SNAPSHOT}/"
    SECURITY=false
    UPDATES=false
fi

rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

lb config noauto \
    --distribution "$DIST" \
    --architectures "$ARCH" \
    --archive-areas main \
    --apt-recommends false \
    --binary-images iso-hybrid \
    --debian-installer none \
    --memtest none \
    --iso-application "Private AI OS" \
    --iso-volume "PRIVATE_AI_OS" \
    --bootappend-live "boot=live components quiet" \
    --mirror-bootstrap "$MIRROR" \
    --mirror-chroot "$MIRROR" \
    --mirror-binary "$MIRROR" \
    --security "$SECURITY" \
    --updates "$UPDATES"

# Package lists, overlays and hooks of every component under os/, and the backend code: see assemble-config.sh.
bash "$SRC/build/assemble-config.sh" "$SRC" "$BACKEND_SRC" config

lb build

mkdir -p "$OUT"
iso_count=0
for iso in "$WORK"/*.iso; do
    [ -e "$iso" ] || continue
    cp "$iso" "$OUT/"
    (cd "$OUT" && sha256sum "$(basename "$iso")" > "$(basename "$iso").sha256")
    iso_count=$((iso_count + 1))
done
if [ "$iso_count" -eq 0 ]; then
    echo "ERROR: live-build finished without producing an ISO" >&2
    exit 1
fi
echo "Built $iso_count ISO file(s) into $OUT"
