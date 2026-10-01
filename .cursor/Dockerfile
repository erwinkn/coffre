# Cursor Cloud base image for coffre.
#
# Provides the system-level toolchain the repo needs: Node 24 (via nvm),
# pnpm 11.8.0 (via corepack), and a Docker engine configured to run inside the
# Cloud Agent VM (fuse-overlayfs, no containerd snapshotter, legacy iptables) so
# the Postgres service in docker-compose.yml works. Repo dependencies are
# installed later by the environment `install` command, after checkout.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Base tooling. git + curl are required in fully custom images; lsof is used by
# dev/start.sh, gnupg by the Docker apt repo, sudo by the start hook.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl git gnupg lsof sudo openssh-client xz-utils procps iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Docker engine + compose plugin (docker-in-docker) and fuse-overlayfs.
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl --retry 3 -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" \
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

# Node 24 via nvm + pinned pnpm through corepack. The Cloud runtime injects its
# own Node 22 ahead of us on PATH, so we must prepend the nvm-managed Node 24
# bin. The runtime sources ~/.bashrc even for non-interactive shells (via
# BASH_ENV), so put the prepend ABOVE the stock interactive-guard early return,
# and also in /etc/profile.d for login shells. A resolved absolute path (baked
# at build time from `nvm which`) avoids sourcing nvm on every command. Node 24
# is required because the CLI, dev IdP, migrations, and test runner execute .ts
# files directly via node (native type-stripping, Node 23.6+/24 only).
RUN curl --retry 3 -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash \
    && . "$NVM_DIR/nvm.sh" \
    && nvm install 24 \
    && nvm alias default 24 \
    && corepack enable \
    && corepack prepare pnpm@11.8.0 --activate \
    && NODE_BIN="$(dirname "$(nvm which default)")" \
    && printf '%s\n' "export PATH=\"$NODE_BIN:\$PATH\"" | cat - "$HOME/.bashrc" > "$HOME/.bashrc.new" \
    && mv "$HOME/.bashrc.new" "$HOME/.bashrc" \
    && printf '%s\n' "export PATH=\"$NODE_BIN:\$PATH\"" | sudo tee /etc/profile.d/00-coffre-node.sh >/dev/null
