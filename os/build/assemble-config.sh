#!/usr/bin/env bash
# Assembles the live-build "config" tree from the repository: package lists, root-filesystem overlays, chroot hooks
# and the backend code. in-container-build.sh runs it between `lb config` and `lb build`. It takes only paths, so
# tests/security/test_image_assembly.py runs the very same script on its own against a scratch directory.
#
# usage: assemble-config.sh <os-dir> <backend-dir> <config-dir>
#   <os-dir>       the repository's os/ directory. Every component os/<name>/ may hold package-lists/ (copied to
#                  config/package-lists), rootfs/ (the image root overlay, config/includes.chroot) and hooks/
#                  (chroot hooks, config/hooks/live). Components are discovered, never listed here.
#   <backend-dir>  the repository's backend/ directory, installed at /opt/pai/backend
#   <config-dir>   the live-build config directory to fill
#
# Rules this script enforces for every component, so none has to repeat them:
#   * Two components may not ship the same file: the later one would silently replace the earlier one.
#   * Ownership: what lands in the image is owned by the user running the build (root in the builder container),
#     whoever owns the source tree. On a Linux host that is the developer's uid, which on the live image is a login.
#   * Modes: the source tree's modes say nothing reliable (a Windows checkout reports every file as 0777 or 0755).
#     Directories become 0755, files 0644, and a file that starts with "#!" is a script and becomes 0755. Nothing is
#     group- or world-writable, and a unit file or configuration is never executable. A component that needs
#     other modes (a secret, a private directory) sets them in its own chroot hook, which runs after this.
set -euo pipefail
export LC_ALL=C

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <os-dir> <backend-dir> <config-dir>" >&2
    exit 2
fi
OS_DIR=$1
BACKEND_DIR=$2
CONFIG_DIR=$3

# Where the backend lives in the image. pai-backend.service runs `python3 -m backend` from the parent directory
# (WorkingDirectory=/opt/pai); tests/security/test_image_assembly.py keeps the two equal.
BACKEND_IMAGE_DIR=opt/pai/backend

# What stays out of the image, matched by name at any depth: the tests, bytecode caches and documentation. Everything
# else ships, including the SQL migrations the code reads at run time and any package or data a later milestone adds.
BACKEND_EXCLUDE_DIRS=(tests __pycache__)
BACKEND_EXCLUDE_FILES=('README*' '*.pyc' '*.pyo')

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

# merge_tree <component> <source-dir> <destination-dir>: copies the contents of source into destination, as the
# user running the build owns them, and refuses to replace a file or link another component already put there.
merge_tree() {
    local component=$1 src=$2 dest=$3 entry
    mkdir -p "$dest"
    while IFS= read -r -d '' entry; do
        if [ -e "$dest/${entry#"$src"/}" ] || [ -L "$dest/${entry#"$src"/}" ]; then
            fail "component '$component' ships ${entry#"$src"/}, which another component already provides"
        fi
    done < <(find "$src" \( -type f -o -type l \) -print0)
    cp -a --no-preserve=ownership "$src/." "$dest/"
}

# normalise_modes <dir>: the mode rule in the header. Symbolic links are left alone (find -type d / -type f skip them).
normalise_modes() {
    local file
    find "$1" -type d -exec chmod 0755 {} +
    find "$1" -type f -exec chmod 0644 {} +
    while IFS= read -r -d '' file; do
        if [ "$(head -c 2 "$file")" = '#!' ]; then
            chmod 0755 "$file"
        fi
    done < <(find "$1" -type f -print0)
}

# install_backend <destination-dir>: the backend's code and data, minus BACKEND_EXCLUDE_*, as root-owned files nobody
# else can write: the service account runs this code, so it must not be able to change it.
install_backend() {
    local dest=$1 name
    [ -d "$BACKEND_DIR" ] || fail "backend directory not found: $BACKEND_DIR"
    [ ! -e "$dest" ] || fail "a component already ships /${BACKEND_IMAGE_DIR}, which is where the backend is installed"
    # A link could point anywhere in the image (or nowhere), and the service imports whatever it finds here.
    if [ -n "$(find "$BACKEND_DIR" -type l -print -quit)" ]; then
        fail "$BACKEND_DIR contains a symbolic link; the backend tree may hold only files and directories"
    fi
    mkdir -p "$dest"
    cp -a --no-preserve=ownership "$BACKEND_DIR/." "$dest/"
    for name in "${BACKEND_EXCLUDE_DIRS[@]}"; do
        find "$dest" -type d -name "$name" -prune -exec rm -rf {} +
    done
    for name in "${BACKEND_EXCLUDE_FILES[@]}"; do
        find "$dest" -type f -name "$name" -delete
    done
    find "$dest" -depth -mindepth 1 -type d -empty -delete # directories that only held an excluded file
    # Python modules are imported, never executed, so none needs an exec bit whatever its first line says.
    find "$dest" -type d -exec chmod 0755 {} +
    find "$dest" -type f -exec chmod 0644 {} +
}

[ -d "$OS_DIR" ] || fail "os directory not found: $OS_DIR"
mkdir -p "$CONFIG_DIR/package-lists" "$CONFIG_DIR/includes.chroot" "$CONFIG_DIR/hooks/live"

components=0
for component_dir in "$OS_DIR"/*/; do
    [ -d "$component_dir" ] || continue
    component=$(basename "$component_dir")
    shipped=0
    for part in "package-lists:package-lists" "rootfs:includes.chroot" "hooks:hooks/live"; do
        if [ -d "$component_dir${part%%:*}" ]; then
            merge_tree "$component" "$component_dir${part%%:*}" "$CONFIG_DIR/${part#*:}"
            shipped=1
        fi
    done
    components=$((components + shipped))
done

normalise_modes "$CONFIG_DIR/includes.chroot"
# live-build skips a hook that is not executable, silently, so every hook is: a hook without a script header fails
# the build here instead of being ignored.
while IFS= read -r -d '' hook; do
    [ "$(head -c 2 "$hook")" = '#!' ] || fail "hook ${hook#"$CONFIG_DIR"/} does not start with a #! line"
    chmod 0755 "$hook"
done < <(find "$CONFIG_DIR/hooks/live" -type f -print0)

install_backend "$CONFIG_DIR/includes.chroot/$BACKEND_IMAGE_DIR"

echo "Assembled $components component(s) and the backend into $CONFIG_DIR"
