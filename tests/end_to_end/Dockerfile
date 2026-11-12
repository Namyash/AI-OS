# QEMU runner for the boot tests. The guest is emulated in software (TCG) because the development machine has no
# hypervisor and Docker exposes no KVM (docs/architecture/RISKS.md, R1). Nothing here talks to the network at run time.
#
# Everything this image contains is pinned (threat T12): the base image by digest, the packages by a
# snapshot.debian.org timestamp. QEMU emulates the devices an untrusted ISO talks to, so what it is built from must
# not change underneath the test: the same text builds the same image on every machine. The harness tags the image
# with a hash of this file (boot_harness.image_tag), so editing a pin builds a new image on the next run.
# To pick up newer QEMU fixes, move both pins together (docs/development/BOOT_TESTING.md, "Updating the pins").
ARG DEBIAN_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
FROM ${DEBIAN_IMAGE}

# The timestamp the base image was itself built from (its /etc/apt/sources.list.d/debian.sources records it): the same
# snapshot keeps every installed package consistent with the base.
ARG SNAPSHOT=20261104T212339Z

ENV DEBIAN_FRONTEND=noninteractive
# The sources are switched to the snapshot archives (main, updates and security at that timestamp). The grep fails the
# build if the switch did not take, so a changed sources layout can never fall back to the moving mirror unnoticed.
# qemu-system-x86: the emulator; xorriso: lists the ISO and extracts the kernel and initrd without mounting it
# (no privileges needed); python3: runs container_boot.py and container_install.py; ovmf: UEFI firmware for the install
# test's boot of the installed disk (its descriptor in /usr/share/qemu/firmware tells container_install.py which files to
# use). --no-install-recommends keeps GUI/audio/USB stacks out. /disks, owned by the account, is where the install test
# mounts its throwaway volume: a new volume takes its owner from the image, so it is writable.
RUN sed -i \
        -e "s|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}|" \
        -e "s|http://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/${SNAPSHOT}|" \
        /etc/apt/sources.list.d/debian.sources \
    && ! grep -q 'deb\.debian\.org' /etc/apt/sources.list.d/debian.sources \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/50snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends qemu-system-x86 xorriso python3 ovmf \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin pai-e2e \
    && mkdir /disks \
    && chown pai-e2e /disks

USER pai-e2e
WORKDIR /work
