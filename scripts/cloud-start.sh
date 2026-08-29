#!/usr/bin/env bash
# Cursor Cloud boot hook: start the Docker daemon.
#
# The Cloud Agent VM has no systemd, and the Postgres service in
# docker-compose.yml (:55432) that the app and tests depend on needs Docker
# running. Wire this to the environment's `start` command so agents don't have
# to start Docker by hand. Idempotent: safe to run more than once.
set -euo pipefail

if docker info >/dev/null 2>&1; then
    exit 0
fi

sudo dockerd >/tmp/dockerd.log 2>&1 &

for _ in $(seq 1 30); do
    # A fresh daemon creates the socket root:docker 0660; make sure the
    # unprivileged agent user can reach it even if its docker-group membership
    # is not active in this shell yet.
    if [ -S /var/run/docker.sock ]; then
        sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
    fi
    if docker info >/dev/null 2>&1; then
        exit 0
    fi
    sleep 1
done

echo "dockerd did not become ready; see /tmp/dockerd.log" >&2
exit 1
