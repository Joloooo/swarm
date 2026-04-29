#!/usr/bin/env bash
# Run the SwarmAttacker daily XBOW set unattended.
#
# This is the command to use when leaving the computer on overnight. It keeps
# macOS awake with caffeinate when available, streams output to the terminal,
# and also saves a timestamped run log under logs/.
#
# Usage:
#   bash benchmarks/run_xbow_daily.sh
#   bash benchmarks/run_xbow_daily.sh --skip-build
#   bash benchmarks/run_xbow_daily.sh --resume
#   bash benchmarks/run_xbow_daily.sh --resume --retry-errors --skip-build
#   bash benchmarks/run_xbow_daily.sh --list-file benchmarks/daily_15_buildable.txt

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

mkdir -p logs
STAMP="$(date +%Y%m%dT%H%M%S)"
OUT="logs/xbow-daily-${STAMP}.log"

MODE_ARGS=(--daily)
for arg in "$@"; do
  case "${arg}" in
    --bench|--list-file)
      MODE_ARGS=()
      break
      ;;
  esac
done

CMD=(uv run python -m benchmarks.xbow_runner "${MODE_ARGS[@]}" "$@")

echo "[xbow-daily] cwd: ${ROOT}"
echo "[xbow-daily] log: ${OUT}"
echo "[xbow-daily] cmd: ${CMD[*]}"

if command -v caffeinate >/dev/null 2>&1; then
  caffeinate -dimsu "${CMD[@]}" 2>&1 | tee "${OUT}"
else
  "${CMD[@]}" 2>&1 | tee "${OUT}"
fi
