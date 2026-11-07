# Pinned-by-tag builder image for the Private AI OS live ISO. Release builds should pin the base by digest
# (see docs/development/DEVELOPMENT.md) and set PAI_SNAPSHOT for reproducible package sets.
ARG DEBIAN_TAG=trixie-slim
FROM debian:${DEBIAN_TAG}

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        live-build debootstrap squashfs-tools xorriso mtools dosfstools cpio rsync zstd xz-utils \
        isolinux syslinux-common syslinux-utils grub-pc-bin grub-efi-amd64-bin \
        ca-certificates debian-archive-keyring \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
