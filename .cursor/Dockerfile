# Cursor Cloud base image for coffre.
#
# Provides the system-level toolchain the repo needs: Node 26 (via nvm),
# pnpm 12.17.0 (its native executable, npm's tarball of it, no Corepack), and a Docker engine
# configured to run inside the Cloud Agent VM (fuse-overlayfs, no containerd
# snapshotter, legacy iptables) so the Postgres service in docker-compose.yml
# works. Repo dependencies are
# installed later by the environment `install` command, after checkout.
#
# Everything it fetches is pinned: the base by its index digest, Docker's
# signing key, nvm, Node and pnpm by their SHA-256 (`ADD --checksum`, which BuildKit
# checks before the file reaches a layer). Ubuntu's and Docker's apt packages
# are not: an apt archive serves its current versions only, each checked
# against the archive's signed index. Rebuilding the image takes the security
# fixes of the day.

# Node 26.13.0, the workspace's (.node-version), for each architecture: its
# tarball and the SHA-256 nodejs.org's SHASUMS256.txt gives. Only the stage
# of the platform being built is fetched.
ARG TARGETARCH
FROM scratch AS node-amd64
ADD --chmod=644 --checksum=sha256:d28a96af6c38596f6d9d97c0ee531c13d238d757742387d1928de822d959e997 \
    https://nodejs.org/dist/v26.13.0/node-v26.13.0-linux-x64.tar.xz /node.tar.xz
FROM scratch AS node-arm64
ADD --chmod=644 --checksum=sha256:406fe3fbde1c054adff8b297c16fdb5af6659db327c1ac8acd46b56ef1af9a92 \
    https://nodejs.org/dist/v26.13.0/node-v26.13.0-linux-arm64.tar.xz /node.tar.xz
# unpinned: one of the two stages above, the platform's.
FROM node-${TARGETARCH} AS node

# pnpm 12.17.0, the workspace's packageManager, for each architecture: its
# native executable, the tarball npm serves as @pnpm/exe.linux-<arch> (what
# the pnpm package's install script would fetch), held to its SHA-256.
FROM scratch AS pnpm-amd64
ADD --chmod=644 --checksum=sha256:6c1c71d00f82765d8f7488df6d1a94533fd1ad5d47c86da41211b1da1093c9d4 \
    https://registry.npmjs.org/@pnpm/exe.linux-x64/-/exe.linux-x64-12.17.0.tgz /pnpm.tgz
FROM scratch AS pnpm-arm64
ADD --chmod=644 --checksum=sha256:017e0264aac3a955e34d82f5d94c100504a791c0dd387f111b7a984024115d50 \
    https://registry.npmjs.org/@pnpm/exe.linux-arm64/-/exe.linux-arm64-12.17.0.tgz /pnpm.tgz
# unpinned: one of the two stages above, the platform's.
FROM pnpm-${TARGETARCH} AS pnpm

FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ENV DEBIAN_FRONTEND=noninteractive

# Base tooling. git + curl are required in fully custom images; lsof is used by
# dev/start.sh, gnupg by the Docker apt repo, sudo by the start hook,
# libatomic1 by Node 26's binary.
# unpinned: Ubuntu's archive, above.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl git gnupg lsof sudo openssh-client xz-utils procps iproute2 libatomic1 \
    && rm -rf /var/lib/apt/lists/*

# Docker engine + compose plugin (docker-in-docker) and fuse-overlayfs. The
# archive's signing key is pinned by its SHA-256: key 9DC8 5822 9FC7 DD38 854A
# E2D8 8D81 803C 0EBF CD88, "Docker Release (CE deb)".
ADD --checksum=sha256:1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570 \
    https://download.docker.com/linux/ubuntu/gpg /etc/apt/keyrings/docker.asc
RUN gpg --dearmor -o /etc/apt/keyrings/docker.gpg /etc/apt/keyrings/docker.asc \
    && rm /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.gpg
# unpinned: Docker's apt archive, above; its index is checked against the key.
RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
        fuse-overlayfs iptables \
    && rm -rf /var/lib/apt/lists/*

# Docker daemon config for the nested VM: overlay2 is unavailable on the
# overlay rootfs, and Docker 29's containerd snapshotter does not support
# fuse-overlayfs, so pin the classic fuse-overlayfs graph driver.
RUN mkdir -p /etc/docker \
    && printf '%s\n' \
        '{' \
        '  "storage-driver": "fuse-overlayfs",' \
        '  "features": { "containerd-snapshotter": false }' \
        '}' > /etc/docker/daemon.json

# Docker 29 bridge networking needs legacy iptables on this kernel.
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# The agent runs as the stock `ubuntu` user (uid 1000). Docker group +
# passwordless sudo so `.cursor/start.sh` can run `sudo service docker start`
# (SysV /etc/init.d/docker — PID 1 is tini, not systemd).
RUN usermod -aG docker ubuntu \
    && echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ubuntu \
    && chmod 0440 /etc/sudoers.d/90-ubuntu

USER ubuntu
WORKDIR /home/ubuntu
ENV NVM_DIR=/home/ubuntu/.nvm

# Node 26 via nvm, and pnpm beside it. nvm is v0.40.3's nvm.sh, at its commit
# and held to its SHA-256; Node is the tarball above, unpacked where nvm keeps
# the versions it installs, so that nvm finds it; pnpm is the executable in
# its tarball above, put in Node's bin. The Cloud runtime injects its
# own Node 22 ahead of us on PATH, so we must prepend the nvm-managed Node 26
# bin. The runtime sources ~/.bashrc even for non-interactive shells (via
# BASH_ENV), so put the prepend ABOVE the stock interactive-guard early return,
# and also in /etc/profile.d for login shells. A resolved absolute path (baked
# at build time from `nvm which`) avoids sourcing nvm on every command. Node 24 or later
# is required because the CLI, dev IdP, migrations, and test runner execute .ts
# files directly via node (native type-stripping, Node 23.6+/24 only).
ARG NODE_VERSION=26.13.0
RUN mkdir -p "$NVM_DIR"
ADD --chown=ubuntu:ubuntu --checksum=sha256:390260ab9eb1da20e8bc0ebea2ee90f528d53e5e9f6e13b16717db4af454df9d \
    https://raw.githubusercontent.com/nvm-sh/nvm/977563e97ddc66facf3a8e31c6cff01d236f09bd/nvm.sh /home/ubuntu/.nvm/nvm.sh
RUN --mount=type=bind,from=node,source=/node.tar.xz,target=/tmp/node.tar.xz \
    --mount=type=bind,from=pnpm,source=/pnpm.tgz,target=/tmp/pnpm.tgz \
    mkdir -p "$NVM_DIR/versions/node/v$NODE_VERSION" \
    && tar -xJf /tmp/node.tar.xz -C "$NVM_DIR/versions/node/v$NODE_VERSION" --strip-components=1 \
    && tar -xzf /tmp/pnpm.tgz -C "$NVM_DIR/versions/node/v$NODE_VERSION/bin" --strip-components=1 package/pnpm \
    && printf '%s\n' 'export NVM_DIR="$HOME/.nvm"' '[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"' >> "$HOME/.bashrc" \
    && . "$NVM_DIR/nvm.sh" \
    && nvm alias default "$NODE_VERSION" \
    && nvm use default \
    && NODE_BIN="$(dirname "$(nvm which default)")" \
    && printf '%s\n' "export PATH=\"$NODE_BIN:\$PATH\"" | cat - "$HOME/.bashrc" > "$HOME/.bashrc.new" \
    && mv "$HOME/.bashrc.new" "$HOME/.bashrc" \
    && printf '%s\n' "export PATH=\"$NODE_BIN:\$PATH\"" | sudo tee /etc/profile.d/00-coffre-node.sh >/dev/null
