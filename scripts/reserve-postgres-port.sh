#!/usr/bin/env bash
# CI only: keep dependency downloads from selecting Postgres's listening
# port as an outgoing source port. Preserve every pre-existing reservation.
# https://docs.kernel.org/networking/ip-sysctl.html#ip-local-reserved-ports
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
    echo 'This port reservation is only for GitHub Actions runners.' >&2
    exit 1
fi

reserved="$(sysctl -n net.ipv4.ip_local_reserved_ports)"
IFS=',' read -r -a ranges <<< "$reserved"
for range in "${ranges[@]}"; do
    [[ -n "$range" ]] || continue
    low="${range%-*}"
    high="${range#*-}"
    if ((low <= 55432 && 55432 <= high)); then exit 0; fi
done
sudo sysctl -w "net.ipv4.ip_local_reserved_ports=${reserved:+$reserved,}55432" >/dev/null
