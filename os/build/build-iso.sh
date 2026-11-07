#!/usr/bin/env bash
# Host entry point: builds the ISO inside a container. Works from Linux, macOS, or Git Bash on Windows
# with Docker. Output: dist/*.iso and dist/*.iso.sha256.
#
# The live-build work directory is a Docker named volume (pai-live-build), not a bind mount: debootstrap
# needs a real Linux filesystem (device nodes, ownership) that Windows-backed mounts cannot provide.
# --privileged is required because live-build mounts /proc, /sys and /dev inside its chroot.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Every path handed to docker uses ROOT, the form the docker client understands:
# `pwd -W` yields a Windows path under Git Bash and does not exist elsewhere, where plain `pwd` is already native.
ROOT="$(cd "$SCRIPT_DIR/../.." && (pwd -W 2>/dev/null || pwd))"
IMAGE="${PAI_BUILDER_IMAGE:-pai-os-builder}"

export MSYS_NO_PATHCONV=1   # stop Git Bash rewriting container-side paths
mkdir -p "$SCRIPT_DIR/../../dist"

docker build -t "$IMAGE" "$ROOT/os/build"
docker run --rm --privileged \
    -e PAI_DISTRIBUTION -e PAI_ARCH -e PAI_MIRROR -e PAI_SNAPSHOT \
    -v "$ROOT/os:/src/os:ro" \
    -v "$ROOT/backend:/src/backend:ro" \
    -v pai-live-build:/work \
    -v "$ROOT/dist:/out" \
    "$IMAGE" /src/os/build/in-container-build.sh
