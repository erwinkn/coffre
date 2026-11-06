# Cursor Cloud base image for coffre.
#
# Provides the system-level toolchain the repo needs: Node 24 (via nvm),
# pnpm 11.28.9 (npm's tarball of it, no Corepack), and a Docker engine
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

# Node 24.22.2, the workspace's (.node-version), for each architecture: its
# tarball and the SHA-256 nodejs.org's SHASUMS256.txt gives. Only the stage
# of the platform being built is fetched.
ARG TARGETARCH
FROM scratch AS node-amd64
ADD --chmod=644 --checksum=sha256:48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75 \
    https://nodejs.org/dist/v24.22.2/node-v24.22.2-linux-x64.tar.xz /node.tar.xz
FROM scratch AS node-arm64
ADD --chmod=644 --checksum=sha256:eb187837a2230d4047161ac0be008584e16b46f726e9c9490ee35dc6b17d9ba8 \
    https://nodejs.org/dist/v24.22.2/node-v24.22.2-linux-arm64.tar.xz /node.tar.xz
# unpinned: one of the two stages above, the platform's.
FROM node-${TARGETARCH} AS node

# pnpm 11.28.9, the workspace's packageManager: npm's tarball of it, which
# runs on any architecture, held to its SHA-256.
FROM scratch AS pnpm
ADD --chmod=644 --checksum=sha256:e54b07e5634b7bf4352153e0c8c25bcef2930a29e3d1bdc42a9eaf2ffd4436df \
    https://registry.npmjs.org/pnpm/-/pnpm-11.28.9.tgz /pnpm.tgz

FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ENV DEBIAN_FRONTEND=noninteractive

# Base tooling. git + curl are required in fully custom images; lsof is used by
# dev/start.sh, gnupg by the Docker apt repo, sudo by the start hook.
# unpinned: Ubuntu's archive, above.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl git gnupg lsof sudo openssh-client xz-utils procps iproute2 \
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

# Node 24 via nvm, and pnpm beside it. nvm is v0.40.3's nvm.sh, at its commit
# and held to its SHA-256; Node is the tarball above, unpacked where nvm keeps
# the versions it installs, so that `nvm use 24` finds it; pnpm is its
# tarball above, unpacked where `npm install -g` would put it, its command
# linked in Node's bin. The Cloud runtime injects its
# own Node 22 ahead of us on PATH, so we must prepend the nvm-managed Node 24
# bin. The runtime sources ~/.bashrc even for non-interactive shells (via
# BASH_ENV), so put the prepend ABOVE the stock interactive-guard early return,
# and also in /etc/profile.d for login shells. A resolved absolute path (baked
# at build time from `nvm which`) avoids sourcing nvm on every command. Node 24
# is required because the CLI, dev IdP, migrations, and test runner execute .ts
# files directly via node (native type-stripping, Node 23.6+/24 only).
ARG NODE_VERSION=24.22.2
RUN mkdir -p "$NVM_DIR"
ADD --chown=ubuntu:ubuntu --checksum=sha256:390260ab9eb1da20e8bc0ebea2ee90f528d53e5e9f6e13b16717db4af454df9d \
    https://raw.githubusercontent.com/nvm-sh/nvm/977563e97ddc66facf3a8e31c6cff01d236f09bd/nvm.sh /home/ubuntu/.nvm/nvm.sh
RUN --mount=type=bind,from=node,source=/node.tar.xz,target=/tmp/node.tar.xz \
    --mount=type=bind,from=pnpm,source=/pnpm.tgz,target=/tmp/pnpm.tgz \
    mkdir -p "$NVM_DIR/versions/node/v$NODE_VERSION" \
    && tar -xJf /tmp/node.tar.xz -C "$NVM_DIR/versions/node/v$NODE_VERSION" --strip-components=1 \
    && mkdir "$NVM_DIR/versions/node/v$NODE_VERSION/lib/node_modules/pnpm" \
    && tar -xzf /tmp/pnpm.tgz -C "$NVM_DIR/versions/node/v$NODE_VERSION/lib/node_modules/pnpm" --strip-components=1 \
    && ln -s ../lib/node_modules/pnpm/bin/pnpm.mjs "$NVM_DIR/versions/node/v$NODE_VERSION/bin/pnpm" \
    && printf '%s\n' 'export NVM_DIR="$HOME/.nvm"' '[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"' >> "$HOME/.bashrc" \
    && . "$NVM_DIR/nvm.sh" \
    && nvm alias default "$NODE_VERSION" \
    && nvm use default \
    && NODE_BIN="$(dirname "$(nvm which default)")" \
    && printf '%s\n' "export PATH=\"$NODE_BIN:\$PATH\"" | cat - "$HOME/.bashrc" > "$HOME/.bashrc.new" \
    && mv "$HOME/.bashrc.new" "$HOME/.bashrc" \
    && printf '%s\n' "export PATH=\"$NODE_BIN:\$PATH\"" | sudo tee /etc/profile.d/00-coffre-node.sh >/dev/null
