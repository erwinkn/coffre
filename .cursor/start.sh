#!/usr/bin/env bash
# Cursor Cloud boot: Docker daemon + local Postgres.
#
# PID 1 is tini, not systemd, so `systemctl start docker` is a no-op.
# `sudo service docker start` uses docker-ce's SysV script. Snapshot compose
# containers exit (commonly 255) because the daemon is gone; recreate them.
# Idempotent: safe to run more than once.
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"

# /var/run is a real directory (not a symlink to /run). Snapshots leave it
# 0700, and `service docker start` can recreate it that way, which hides
# docker.sock from ubuntu. The start shell also often lacks group docker.
expose_docker() {
    sudo chmod 755 /var/run /run 2>/dev/null || true
    sudo chmod a+rw /var/run/docker.sock 2>/dev/null || true
}

if ! sudo docker info >/dev/null 2>&1; then
    sudo service docker start || true
    for _ in $(seq 1 30); do
        expose_docker
        sudo docker info >/dev/null 2>&1 && break
        sleep 1
    done
fi
expose_docker
if ! docker info >/dev/null 2>&1; then
    echo "docker did not become ready" >&2
    sudo service docker status >&2 || true
    ls -ld /var/run /var/run/docker.sock >&2 || true
    exit 1
fi

# Over TCP, as in scripts/ensure-postgres.sh: a fresh volume's first server
# answers on the socket only, and stops.
postgres_ready() {
    docker compose exec -T postgres pg_isready -h 127.0.0.1 -U coffre_owner -d coffre >/dev/null 2>&1
}

docker compose up -d postgres >/dev/null
for _ in $(seq 1 20); do
    if postgres_ready; then
        break
    fi
    sleep 1
done
if ! postgres_ready; then
    docker compose up -d --force-recreate postgres >/dev/null
    for _ in $(seq 1 60); do
        if postgres_ready; then
            break
        fi
        sleep 1
    done
fi
if ! postgres_ready; then
    echo "postgres did not become ready" >&2
    docker compose ps >&2 || true
    exit 1
fi

if ! docker compose exec -T postgres psql -U coffre_owner -d postgres -tAc \
    "SELECT 1 FROM pg_roles WHERE rolname = 'coffre_runtime'" | grep -q 1; then
    docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U coffre_owner -d postgres \
        -c "CREATE ROLE coffre_runtime LOGIN PASSWORD 'local-runtime-only'" >/dev/null
fi
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U coffre_owner -d postgres \
    -c "ALTER ROLE coffre_runtime LOGIN PASSWORD 'local-runtime-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" >/dev/null

DATABASE_URL='postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre' \
    pnpm --dir packages/server run db:migrate >/dev/null
