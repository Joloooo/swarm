#!/usr/bin/env bash
# setup_loopback_pool.sh — manage a pool of loopback aliases on macOS so each
# concurrently-running XBEN benchmark can be bound to its OWN host IP
# (127.0.0.2, 127.0.0.3, …) at the container's REAL ports (80, 22, …).
#
# Why this exists
# ---------------
# Docker Desktop on macOS publishes container ports onto the shared host
# `localhost`. With N benchmarks up at once they all land on one
# undifferentiated `127.0.0.1` with random host ports, so:
#   * the agent cannot tell which host port belongs to *its* target, and
#   * `nmap localhost` bleeds across every running benchmark (and is a scope
#     violation — it touches other targets).
# Giving each VM its own loopback IP restores realistic, isolated recon: the
# agent is handed `127.0.0.5` and scans only that one target, finding its real
# ports (e.g. 80 web + 22 ssh) exactly like a real engagement.
#
# Validated on this host: Docker Desktop honours `-p 127.0.0.X:80:80` and binds
# ONLY to that alias (a probe of 127.0.0.1:80 stays closed) — so two VMs can
# both serve real port 80 because 127.0.0.5:80 ≠ 127.0.0.6:80.
#
# macOS does NOT auto-route 127.0.0.0/8 to lo0 (unlike Linux), so the aliases
# must be added explicitly, and they do NOT survive a reboot. Run this once per
# boot before a sweep.
#
# Usage:
#   sudo bash benchmarks/setup_loopback_pool.sh [N]            # add 127.0.0.2 .. 127.0.0.(N+1)  (default N=20)
#   sudo bash benchmarks/setup_loopback_pool.sh --remove [N]   # tear the pool back down
#        bash benchmarks/setup_loopback_pool.sh --list         # show lo0 addresses (no sudo)
set -euo pipefail

BASE="127.0.0"
START=2                 # first alias octet (127.0.0.2); .1 is the real localhost
DEFAULT_COUNT=20

mode="add"
count="$DEFAULT_COUNT"
for arg in "$@"; do
    case "$arg" in
        --remove) mode="remove" ;;
        --list)   mode="list" ;;
        ''|*[!0-9]*) ;;     # ignore flags / non-numeric tokens
        *) count="$arg" ;;
    esac
done
end=$(( START + count - 1 ))

if [ "$mode" = "list" ]; then
    echo "lo0 addresses:"
    ifconfig lo0 | awk '/inet /{print "  " $2}'
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "error: adding/removing lo0 aliases needs root — run: sudo bash $0 $*" >&2
    exit 1
fi

for i in $(seq "$START" "$end"); do
    ip="${BASE}.${i}"
    have=$(ifconfig lo0 | grep -c "inet ${ip} " || true)
    if [ "$mode" = "add" ]; then
        if [ "$have" -eq 0 ]; then
            ifconfig lo0 alias "$ip" up && echo "  added   $ip"
        else
            echo "  exists  $ip"
        fi
    else
        if [ "$have" -gt 0 ]; then
            ifconfig lo0 -alias "$ip" && echo "  removed $ip"
        else
            echo "  absent  $ip"
        fi
    fi
done
echo "done (${mode}, ${BASE}.${START}..${BASE}.${end})."
