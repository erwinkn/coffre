#!/usr/bin/env bash
# Start the compose Postgres only when nothing answers yet.
#
# Several worktrees share one container. `docker compose up` compares the
# running container with this checkout's compose config and recreates it on
# any difference, which drops every other checkout's connections mid-test.
# A container that already answers, or is still initializing, is reused.
# Cold starts are serialized across worktrees. --no-recreate also protects
# a container started outside this script while a caller waits for the lock.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$script")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"

# Over TCP, not the socket: on a fresh volume the image first runs a
# temporary server on the socket alone, to create the database, then stops
# it and starts the real one. A socket check can pass in between, and the
# next psql finds nothing there.
ready() {
    local published
    published="$(docker compose port postgres 5432 2>/dev/null)" || return 1
    [[ -n "$published" ]] || return 1
    docker compose exec -T postgres pg_isready -h 127.0.0.1 -U coffre_owner -d postgres >/dev/null 2>&1
}

ready && exit 0

# Use the host's advisory lock: the kernel releases it even if a caller is
# killed. The file stays in place so every waiter locks the same inode.
# flock is provided by util-linux on Linux; macOS supplies BSD lockf.
if [[ "${1:-}" != --locked ]]; then
    lock="${TMPDIR:-/tmp}/coffre-postgres-${UID}-${COMPOSE_PROJECT_NAME}.lock"
    if command -v flock >/dev/null; then
        exec flock -w 120 "$lock" bash "$script" --locked
    elif command -v lockf >/dev/null; then
        exec lockf -k -t 120 "$lock" bash "$script" --locked
    else
        echo 'Postgres startup requires flock (Linux) or lockf (macOS).' >&2
        exit 1
    fi
fi

running() {
    local container
    container="$(docker compose ps -aq postgres)"
    [[ -n "$container" && "$(docker inspect --format '{{.State.Running}}' "$container")" == true ]]
}

# A socket allocated before CI reserves 55432 may remain in TIME_WAIT for
# 60 seconds. Allow that plus the image's 60-second initialization budget.
deadline=$((SECONDS + 120))
last_error=''
while ((SECONDS < deadline)); do
    if ready; then exit 0; fi
    if ! running; then
        if node "$(dirname "$script")/postgres-port-available.mjs" 55432; then
            :
        else
            status=$?
            if ((status != 1)); then exit "$status"; fi
            if [[ -z "$last_error" ]]; then
                last_error='Postgres port 55432 is occupied; waiting for the socket to close.'
                printf '%s\n' "$last_error" >&2
            fi
            sleep 1
            continue
        fi
        if ! output="$(docker compose up -d --no-recreate postgres 2>&1)"; then
            # Another caller may have started it while this one asked.
            if ready; then exit 0; fi
            if running; then
                sleep 1
                continue
            fi
            # These can clear when an outgoing socket closes, or a competing
            # compose call finishes creating the named container. Anything
            # else is a real startup failure and must be reported at once.
            if [[ "$output" != *'address already in use'* && "$output" != *'already in use by container'* ]]; then
                printf '%s\n' "$output" >&2
                exit 1
            fi
            if [[ -z "$last_error" ]]; then
                printf '%s\nWaiting for Postgres startup contention to clear.\n' "$output" >&2
            fi
            last_error="$output"
        fi
    fi
    sleep 1
done

echo 'Postgres did not become ready within 120 seconds.' >&2
[[ -z "$last_error" ]] || printf '%s\n' "$last_error" >&2
docker compose ps -a >&2 || true
# A non-listening outgoing socket can block Docker's bind too. Include all
# TCP states so the next failure names the socket rather than only the port.
if command -v ss >/dev/null; then ss -tan '( sport = :55432 )' >&2 || true; fi
exit 1
