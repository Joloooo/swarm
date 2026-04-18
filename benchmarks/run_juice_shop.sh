#!/usr/bin/env bash
# Start OWASP Juice Shop locally for SwarmAttacker testing.
#
# Use this as the first target when debugging the agent — it's deliberately
# vulnerable, so the model doesn't refuse, and it has a wide variety of
# bug classes (SQLi, XSS, IDOR, SSRF, JWT issues, etc.) to exercise the
# whole swarm.
#
# Usage:
#   bash benchmarks/run_juice_shop.sh          # start (default port 3000)
#   bash benchmarks/run_juice_shop.sh stop     # tear down
#   bash benchmarks/run_juice_shop.sh logs     # tail container logs

set -euo pipefail

CONTAINER_NAME="swarmattacker-juice-shop"
PORT="${JUICE_SHOP_PORT:-3000}"
IMAGE="bkimminich/juice-shop:latest"

case "${1:-start}" in
  start)
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
      echo "Juice Shop already running on http://localhost:${PORT}"
      exit 0
    fi
    echo "Starting Juice Shop on http://localhost:${PORT} ..."
    docker run --rm -d \
      --name "${CONTAINER_NAME}" \
      -p "${PORT}:3000" \
      "${IMAGE}" >/dev/null
    echo "Started. Use target_url=http://localhost:${PORT} in Studio."
    ;;
  stop)
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    echo "Stopped ${CONTAINER_NAME}."
    ;;
  logs)
    docker logs -f "${CONTAINER_NAME}"
    ;;
  *)
    echo "Usage: $0 [start|stop|logs]"
    exit 1
    ;;
esac
