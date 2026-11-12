#!/usr/bin/env bash
# Integration test of the kiosk without a virtual machine: the real backend, the real built frontend, the real launcher,
# cage (headless) and Chromium, in a debian:trixie-slim container. See docs/development/KIOSK.md for what it proves.
#
# usage: bash kiosk/tests/integration/run.sh
#   PAI_IT_DIST=<dir>   use this built frontend (the contents of dist/) instead of building one in the builder image
#
# Needs Docker and network access (Debian packages, npm packages). The container runs with seccomp unconfined: Docker's
# default profile forbids the user namespaces Chromium's sandbox is made of. That is a property of this test
# container, not of the image (the image's unit allows exactly user, pid and net namespaces).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Every path handed to docker uses ROOT, the form the docker client understands (see os/build/build-iso.sh).
ROOT="$(cd "$SCRIPT_DIR/../../.." && (pwd -W 2>/dev/null || pwd))"
export MSYS_NO_PATHCONV=1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
WORK_FOR_DOCKER="$(cd "$WORK" && (pwd -W 2>/dev/null || pwd))"

if [ -n "${PAI_IT_DIST:-}" ]; then
    DIST="$PAI_IT_DIST"
else
    BUILDER=pai-kiosk-it-builder
    docker build -q -t "$BUILDER" "$ROOT/os/build" >/dev/null
    docker run --rm --name pai-kiosk-it-frontend \
        -v "$ROOT/os:/src/os:ro" -v "$ROOT/frontend:/src/frontend:ro" -v "$WORK_FOR_DOCKER:/out" \
        "$BUILDER" bash /src/os/build/build-frontend.sh /src/frontend /out/dist
    DIST="$WORK_FOR_DOCKER/dist"
fi

docker run --rm --init --name pai-kiosk-it --security-opt seccomp=unconfined \
    -v "$ROOT:/repo:ro" -v "$DIST:/dist:ro" \
    debian:trixie-slim bash /repo/kiosk/tests/integration/in_container.sh
