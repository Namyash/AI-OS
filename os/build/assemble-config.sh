#!/usr/bin/env bash
# Assembles the live-build "config" tree from the repository: package lists, root-filesystem overlays, chroot hooks
# and the code under /opt/pai (the backend, the kiosk launcher, the installer engine, the built frontend). in-container-build.sh runs it
# between `lb config` and `lb build`. It takes only paths, so tests/security/test_image_assembly.py runs the very same
# script on its own against a scratch directory.
#
# usage: assemble-config.sh <os-dir> <backend-dir> <kiosk-dir> <installer-dir> <frontend-dist-dir> <config-dir>
#   <os-dir>             the repository's os/ directory. Every component os/<name>/ may hold package-lists/ (copied to
#                        config/package-lists), rootfs/ (the image root overlay, config/includes.chroot) and hooks/
#                        (chroot hooks, config/hooks/live). Components are discovered, never listed here.
#   <backend-dir>        the repository's backend/ directory, installed at /opt/pai/backend
#   <kiosk-dir>          the repository's kiosk/ directory, installed at /opt/pai/kiosk
#   <installer-dir>      the repository's installer/ directory (the install engine), installed at /opt/pai/installer
#   <frontend-dist-dir>  the PRODUCTION BUILD of the frontend (build-frontend.sh makes it), installed at
#                        /opt/pai/frontend. Never the sources: no node_modules, no TypeScript.
#   <config-dir>         the live-build config directory to fill
#
# Rules this script enforces for every component, so none has to repeat them:
#   * Two components may not ship the same file: the later one would silently replace the earlier one.
#   * Ownership: what lands in the image is owned by the user running the build (root in the builder container),
#     whoever owns the source tree. On a Linux host that is the developer's uid, which on the live image is a login.
#   * Modes: the source tree's modes say nothing reliable (a Windows checkout reports every file as 0777 or 0755).
#     Directories become 0755, files 0644, and a file that starts with "#!" is a script and becomes 0755. This holds
#     for the image overlay and the package lists; hooks are always 0755 (see below). Nothing is group- or
#     world-writable, and a unit file or configuration is never executable. A component that needs other modes (a
#     secret, a private directory) sets them in its own chroot hook, which runs after this.
set -euo pipefail
export LC_ALL=C
# Directories this script creates must not depend on the caller's umask (0002 would leave them group-writable).
umask 022

if [ "$#" -ne 6 ]; then
    echo "usage: $0 <os-dir> <backend-dir> <kiosk-dir> <installer-dir> <frontend-dist-dir> <config-dir>" >&2
    exit 2
fi
OS_DIR=$1
BACKEND_DIR=$2
KIOSK_DIR=$3
INSTALLER_DIR=$4
FRONTEND_DIST_DIR=$5
CONFIG_DIR=$6

# Where each tree lives in the image. pai-backend.service and pai-kiosk.service run `python3 -m backend` / `-m kiosk`
# from the parent directory (WorkingDirectory=/opt/pai), pai-install-auto.service runs `python3 -m installer` from there
# too, and the backend serves the UI from its default static
# directory; tests/security/test_image_assembly.py keeps all of these equal to what the units and the settings say.
BACKEND_IMAGE_DIR=opt/pai/backend
KIOSK_IMAGE_DIR=opt/pai/kiosk
INSTALLER_IMAGE_DIR=opt/pai/installer
FRONTEND_IMAGE_DIR=opt/pai/frontend

# What stays out of the image from a Python tree, matched by name at any depth: the tests, bytecode caches and
# documentation. Everything else ships, including the SQL migrations the code reads at run time and any package or
# data a later milestone adds. The built frontend is not filtered: it holds exactly what the build wrote.
CODE_EXCLUDE_DIRS=(tests __pycache__)
CODE_EXCLUDE_FILES=('README*' '*.pyc' '*.pyo')

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

# install_tree <label> <source-dir> <image-dir> <prune|keep>: a tree of code or data for /opt/pai, as root-owned files
# nobody else can write: the service accounts run this code, so they must not be able to change it. "prune" leaves out
# what CODE_EXCLUDE_* names.
install_tree() {
    local label=$1 src=$2 image_dir=$3 prune=$4
    local dest="$CONFIG_DIR/includes.chroot/$image_dir" name
    [ -d "$src" ] || fail "$label directory not found: $src"
    [ ! -e "$dest" ] || fail "a component already ships /${image_dir}, which is where the $label is installed"
    # A link could point anywhere in the image (or nowhere), and the services read whatever they find here.
    if [ -n "$(find "$src" -type l -print -quit)" ]; then
        fail "$src contains a symbolic link; the $label tree may hold only files and directories"
    fi
    mkdir -p "$dest"
    cp -a --no-preserve=ownership "$src/." "$dest/"
    if [ "$prune" = prune ]; then
        for name in "${CODE_EXCLUDE_DIRS[@]}"; do
            find "$dest" -type d -name "$name" -prune -exec rm -rf {} +
        done
        for name in "${CODE_EXCLUDE_FILES[@]}"; do
            find "$dest" -type f -name "$name" -delete
        done
        find "$dest" -depth -mindepth 1 -type d -empty -delete # directories that only held an excluded file
    fi
    # Python modules are imported and web assets are served, never executed, so none needs an exec bit whatever its
    # first line says.
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
normalise_modes "$CONFIG_DIR/package-lists"
# live-build skips a hook that is not executable, silently, so every hook is: a hook without a script header fails
# the build here instead of being ignored.
while IFS= read -r -d '' hook; do
    [ "$(head -c 2 "$hook")" = '#!' ] || fail "hook ${hook#"$CONFIG_DIR"/} does not start with a #! line"
    chmod 0755 "$hook"
done < <(find "$CONFIG_DIR/hooks/live" -type f -print0)
# The hook directories take the source directory's mode (0777 on a Windows-backed checkout): same rule as everywhere else.
find "$CONFIG_DIR/hooks" -type d -exec chmod 0755 {} +

install_tree backend "$BACKEND_DIR" "$BACKEND_IMAGE_DIR" prune
install_tree kiosk "$KIOSK_DIR" "$KIOSK_IMAGE_DIR" prune
install_tree installer "$INSTALLER_DIR" "$INSTALLER_IMAGE_DIR" prune
install_tree "frontend build output" "$FRONTEND_DIST_DIR" "$FRONTEND_IMAGE_DIR" keep
# The backend answers "/" with this file; a build that produced none must stop the image build, not ship a blank UI.
[ -f "$CONFIG_DIR/includes.chroot/$FRONTEND_IMAGE_DIR/index.html" ] ||
    fail "frontend build output has no index.html: $FRONTEND_DIST_DIR"

echo "Assembled $components component(s), the backend, the kiosk, the installer and the frontend build into $CONFIG_DIR"
