#!/usr/bin/env bash
# Builds the production UI from the frontend sources. Runs inside the builder container (Debian's own nodejs and npm),
# called by in-container-build.sh; tests/security/test_image_assembly.py runs it against a scratch directory with a
# stand-in npm.
#
# usage: build-frontend.sh <frontend-dir> <output-dir>
#   <frontend-dir>  the repository's frontend/ directory. Mounted read-only by build-iso.sh and never written to: the
#                   build runs in a copy, so no node_modules or dist ever appears in the source tree.
#   <output-dir>    receives the CONTENTS of the build's dist/ directory (index.html, assets/, ...). Nothing else
#                   from the build, in particular no node_modules and no sources, ever reaches the image.
#
# `npm ci` installs exactly what package-lock.json pins and checks every package against its recorded integrity hash
# (threat T12), so a changed lockfile or a tampered package fails the build instead of changing the image. Install
# scripts are not run (--ignore-scripts): the build needs none, and a package's install hook must not run code during
# an image build. The host's node_modules (built for another platform) and a stale dist/ are left out of the copy.
set -euo pipefail
export LC_ALL=C

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <frontend-dir> <output-dir>" >&2
    exit 2
fi
FRONTEND_DIR=$1
OUTPUT_DIR=$2

[ -d "$FRONTEND_DIR" ] || fail "frontend directory not found: $FRONTEND_DIR"
[ -f "$FRONTEND_DIR/package.json" ] || fail "no package.json in $FRONTEND_DIR"
[ -f "$FRONTEND_DIR/package-lock.json" ] || fail "no package-lock.json in $FRONTEND_DIR: npm ci needs the lockfile"
[ ! -e "$OUTPUT_DIR" ] || [ -z "$(ls -A "$OUTPUT_DIR")" ] || fail "output directory is not empty: $OUTPUT_DIR"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/src"
tar -C "$FRONTEND_DIR" --exclude=./node_modules --exclude=./dist -cf - . | tar -C "$work/src" -xf -
# The source is mounted read-only and tar keeps those modes; the build must be able to create node_modules and dist here,
# and the cleanup trap must be able to remove the copy. (Root never noticed: it ignores the missing write bit.)
chmod -R u+rwX "$work/src"

cd "$work/src"
npm ci --ignore-scripts --no-audit --no-fund --cache "$work/npm-cache"
npm run build

[ -f dist/index.html ] || fail "the build produced no dist/index.html"
mkdir -p "$OUTPUT_DIR"
cp -a dist/. "$OUTPUT_DIR/"
echo "Built the frontend into $OUTPUT_DIR"
