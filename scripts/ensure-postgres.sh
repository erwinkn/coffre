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
# Another port is another container: give it its own COMPOSE_PROJECT_NAME.
port="${COFFRE_POSTGRES_PORT:-55432}"
# Its own subnet for this project's network, when the one Docker picks is a
# route the host sends elsewhere (see route_guard).
if [[ -n "${COFFRE_POSTGRES_SUBNET:-}" ]]; then
    # Naming the files turns off compose's own discovery of an override file,
    # so name that one too, and join with compose's own separator.
    files="${COMPOSE_FILE:-}"
    if [[ "$files" == *docker-compose.subnet.yml ]]; then
        : # Already added: this is the re-exec under the lock.
    elif [[ -z "$files" ]]; then
        files=docker-compose.yml
        [[ ! -f docker-compose.override.yml ]] || files="$files${COMPOSE_PATH_SEPARATOR:-:}docker-compose.override.yml"
    fi
    [[ "$files" == *docker-compose.subnet.yml ]] || files="$files${COMPOSE_PATH_SEPARATOR:-:}docker-compose.subnet.yml"
    export COMPOSE_FILE="$files"
fi

# Over TCP, not the socket: on a fresh volume the image first runs a
# temporary server on the socket alone, to create the database, then stops
# it and starts the real one. A socket check can pass in between, and the
# next psql finds nothing there.
ready() {
    local published
    published="$(docker compose port postgres 5432 2>/dev/null)" || return 1
    [[ -n "$published" ]] || return 1
    # The project's container, on another port: never the one this caller asked for.
    if [[ "${published##*:}" != "$port" ]]; then
        printf 'Compose project %s publishes Postgres on :%s, not :%s. Run that port as a project of its own: COMPOSE_PROJECT_NAME=<another> COFFRE_POSTGRES_PORT=%s.\n' \
            "$COMPOSE_PROJECT_NAME" "${published##*:}" "$port" "$port" >&2
        exit 1
    fi
    docker compose exec -T postgres pg_isready -h 127.0.0.1 -U coffre_owner -d postgres >/dev/null 2>&1
}

# A reused container keeps the image it was created from: a compose file that
# moved on (Alpine to Debian, R62) changes nothing for it, and a benchmark on
# it would measure the old one. Say so; recreating is its owner's call.
warn_stale_image() {
    local wanted container have
    wanted="$(docker compose config --images postgres 2>/dev/null)" || return 0
    container="$(docker compose ps -aq postgres 2>/dev/null)" || return 0
    [[ -n "$wanted" && -n "$container" ]] || return 0
    have="$(docker inspect --format '{{.Config.Image}}' "$container" 2>/dev/null)" || return 0
    if [[ -n "$have" && "$have" != "$wanted" ]]; then
        printf 'Postgres on :%s runs %s, but docker-compose.yml names %s; it is reused as it is. Recreate it when no checkout is using it: COMPOSE_PROJECT_NAME=%s docker compose up -d --force-recreate postgres\n' \
            "$port" "$have" "$wanted" "$COMPOSE_PROJECT_NAME" >&2
    fi
    return 0
}

# Host connections to 127.0.0.1:<port> are forwarded (docker-proxy or DNAT) to
# the container's IP. If
# the host routes that IP anywhere but the project's bridge (Cloudflare WARP
# claims hosts of 192.168.0.0/20, Docker's first default subnet), they reach
# some other machine, and the first psql sends the dev password to it. So,
# before any caller connects over the port, ask the kernel where the packets go.
# Only on Linux with `ip`, and only where the bridge exists on this host:
# Docker Desktop and rootless Docker have no route to a container at all.
started=0
route_guard() {
    command -v ip >/dev/null || return 0
    local container addresses address network bridge dev option
    # Past this point a failed lookup refuses: an unchecked route is no pass.
    if ! container="$(docker compose ps -aq postgres 2>/dev/null)" || [[ -z "$container" ]] ||
        ! addresses="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.NetworkID}}{{"\n"}}{{end}}' "$container" 2>/dev/null)"; then
        refuse_route "Could not inspect the Postgres container of project $COMPOSE_PROJECT_NAME, so where the host routes its address is unknown." no
    fi
    while read -r address network; do
        [[ -n "$address" && -n "$network" ]] || continue
        bridge="br-${network:0:12}"
        dev="$(ip -o route get "$address" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')" || dev=''
        [[ "$dev" != "$bridge" ]] || continue
        # A network can name its bridge (a custom compose driver option).
        option="$(docker network inspect --format '{{index .Options "com.docker.network.bridge.name"}}' "$network" 2>/dev/null)" || option=''
        if [[ -n "$option" ]]; then
            bridge="$option"
            [[ "$dev" != "$bridge" ]] || continue
        fi
        # No such bridge on this host: Docker Desktop, rootless, a remote daemon.
        ip link show "$bridge" >/dev/null 2>&1 || continue
        refuse_route "Postgres container $COMPOSE_PROJECT_NAME is at $address, but this host routes $address through ${dev:-no device}, not its bridge $bridge: connections to 127.0.0.1:$port would reach another machine, not this container (Cloudflare WARP does this to some hosts of 192.168.0.0/20, Docker's first default subnet)."
    done <<<"$addresses"
    return 0
}

refuse_route() {
    printf '%s\n' "$1" >&2
    if ((started)); then
        docker compose down >/dev/null 2>&1 || true
        printf 'This script started it, so it is removed again (its data volume is kept).\n' >&2
    else
        printf 'It was already running, so it is left alone. Remove it yourself: COMPOSE_PROJECT_NAME=%s docker compose down\n' "$COMPOSE_PROJECT_NAME" >&2
    fi
    [[ "${2:-}" != no ]] || exit 1
    printf 'Give the project a subnet that no VPN or route claims, then run this again:\n  "default-address-pools" in /etc/docker/daemon.json, for every project (restart Docker), or\n  COFFRE_POSTGRES_SUBNET=10.<n>.0.0/24, one no other Docker network uses (docker network ls), exported for every run, after the down.\n' >&2
    exit 1
}

ready_and_done() {
    route_guard
    warn_stale_image
    exit 0
}

if ready; then ready_and_done; fi

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

# A socket allocated before CI reserves the port may remain in TIME_WAIT for
# 60 seconds. Allow that plus the image's 60-second initialization budget.
deadline=$((SECONDS + 120))
last_error=''
while ((SECONDS < deadline)); do
    if ready; then ready_and_done; fi
    if ! running; then
        if node "$(dirname "$script")/postgres-port-available.mjs" "$port"; then
            :
        else
            status=$?
            if ((status != 1)); then exit "$status"; fi
            if [[ -z "$last_error" ]]; then
                last_error="Postgres port $port is occupied; waiting for the socket to close."
                printf '%s\n' "$last_error" >&2
            fi
            sleep 1
            continue
        fi
        if ! output="$(docker compose --progress plain up -d --no-recreate postgres 2>&1)"; then
            # Another caller may have started it while this one asked.
            if ready; then ready_and_done; fi
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
        else
            # Refuse a bad route at once, not after a wait for readiness. Only
            # a container compose says it started is this script's to remove:
            # another caller may have started it since `running` looked.
            if [[ "$output" == *' Started'* ]]; then started=1; fi
            route_guard
        fi
    fi
    sleep 1
done

echo 'Postgres did not become ready within 120 seconds.' >&2
[[ -z "$last_error" ]] || printf '%s\n' "$last_error" >&2
docker compose ps -a >&2 || true
# A non-listening outgoing socket can block Docker's bind too. Include all
# TCP states so the next failure names the socket rather than only the port.
if command -v ss >/dev/null; then ss -tan "( sport = :$port )" >&2 || true; fi
exit 1
