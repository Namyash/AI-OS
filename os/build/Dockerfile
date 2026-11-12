# Pinned-by-tag builder image for the Private AI OS live ISO. Release builds should pin the base by digest
# (see docs/development/DEVELOPMENT.md) and set PAI_SNAPSHOT for reproducible package sets.
# nodejs and npm are Debian's own (Node 20.19 and npm 9.2 on Debian 13, which the frontend is verified against): they
# build the production UI (build-frontend.sh) and are not part of the image.
ARG DEBIAN_TAG=trixie-slim
FROM debian:${DEBIAN_TAG}

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        live-build debootstrap squashfs-tools xorriso mtools dosfstools cpio rsync zstd xz-utils \
        isolinux syslinux-common syslinux-utils grub-pc-bin grub-efi-amd64-bin \
        ca-certificates debian-archive-keyring \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
