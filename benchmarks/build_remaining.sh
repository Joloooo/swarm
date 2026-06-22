#!/usr/bin/env bash
# build_remaining.sh — build (and health-check) every XBEN-*-24 benchmark
# that has no `.xben_build_done` guard yet, so its Docker image is cached
# locally and is never re-pulled/re-built during evaluation runs.
#
# WHY THIS SCRIPT (and not one subagent per benchmark):
#   - The Docker Desktop VM on this host has only ~8 GB RAM. Concurrent
#     heavy builds (mysql via Rosetta, multi-service stacks) OOM it, so
#     builds run at BOUNDED parallelism (default 4).
#   - A cold build of a buster/archive.debian.org benchmark can take far
#     longer than any single interactive shell call, so this runs
#     unattended in the background.
#   - `make run` creates an `xben-NNN_default` network and Docker's
#     default bridge address pool caps at ~31 networks (see CLAUDE.md),
#     so health checks run SERIALLY and ALWAYS `docker compose down`
#     afterwards to free the network + RAM.
#
# Run patch_bitrot.sh FIRST (this script does not patch) so known
# bit-rot is already fixed before building.
#
# Outputs (under benchmarks/build_logs/):
#   <id>.build.log    full `make build` output
#   <id>.health.log   full `docker compose up --wait` output
#   <id>.result       one TSV line: id  build  secs  health  note
#   results.tsv       concatenation of all <id>.result lines
#   summary.txt       human-readable roll-up written at the end
#
# Usage:
#   bash benchmarks/build_remaining.sh                  # all unbuilt: build + health
#   bash benchmarks/build_remaining.sh --build-only     # skip the health pass
#   bash benchmarks/build_remaining.sh XBEN-067-24 ...   # only the listed ids
#   PARALLEL=3 bash benchmarks/build_remaining.sh        # change build concurrency

set -uo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
XBOW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../xbow-validation" && pwd)"
BENCH_ROOT="$XBOW_ROOT/benchmarks"
LOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/build_logs"

PARALLEL="${PARALLEL:-4}"
BUILD_TIMEOUT="${BUILD_TIMEOUT:-1800}"   # 30 min per build (archive.debian.org is slow)
UP_TIMEOUT="${UP_TIMEOUT:-180}"          # 3 min for `up --wait`

# Portable timeout: GNU coreutils ships `timeout`; macOS/homebrew ships
# `gtimeout`; if neither exists we run without a hard cap.
TIMEOUT_BIN=""
command -v timeout  >/dev/null 2>&1 && TIMEOUT_BIN="timeout"
command -v gtimeout >/dev/null 2>&1 && TIMEOUT_BIN="gtimeout"
run_capped() {  # run_capped SECONDS cmd...
    local secs="$1"; shift
    if [ -n "$TIMEOUT_BIN" ]; then "$TIMEOUT_BIN" "$secs" "$@"; else "$@"; fi
}

# ---------------------------------------------------------------------------
# Hidden re-entry: `bash build_remaining.sh __build_one XBEN-NNN-24`
# (invoked by xargs -P so builds run in parallel). Writes one .result line.
# ---------------------------------------------------------------------------
build_one() {
    local id="$1"
    local dir="$BENCH_ROOT/$id"
    local blog="$LOG_DIR/$id.build.log"
    local res="$LOG_DIR/$id.result"
    local t0 t1
    t0="$(date +%s)"

    if [ ! -d "$dir" ]; then
        printf '%s\tfail\t0\t-\tdir-not-found\n' "$id" > "$res"; return 0
    fi
    # Require a NON-EMPTY guard: an empty .xben_build_done (e.g. a guard
    # regenerated from a since-pruned image) means the build never really
    # finished, so fall through and build for real.
    if [ -s "$dir/.xben_build_done" ]; then
        printf '%s\tok\t0\tprebuilt\t-\n' "$id" > "$res"
        echo "[build] $id: already built (guard present) — skipped"
        return 0
    fi

    echo "[build] $id: starting ..."
    if ( cd "$dir" && run_capped "$BUILD_TIMEOUT" make build ) > "$blog" 2>&1; then
        t1="$(date +%s)"
        printf '%s\tok\t%s\t-\t-\n' "$id" "$((t1 - t0))" > "$res"
        echo "[build] $id: OK in $((t1 - t0))s"
    else
        local rc=$?
        t1="$(date +%s)"
        local tail3
        tail3="$(tail -n 4 "$blog" 2>/dev/null | tr '\t\n' '  ' | cut -c1-240)"
        printf '%s\tfail\t%s\t-\trc=%s | %s\n' "$id" "$((t1 - t0))" "$rc" "$tail3" > "$res"
        echo "[build] $id: FAIL (rc=$rc) after $((t1 - t0))s"
    fi
}

if [ "${1:-}" = "__build_one" ]; then
    build_one "$2"
    exit 0
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
mkdir -p "$LOG_DIR"

DO_HEALTH=1
ARGS=()
for a in "$@"; do
    case "$a" in
        --build-only) DO_HEALTH=0 ;;
        --help|-h) sed -n '2,40p' "$0"; exit 0 ;;
        *) ARGS+=("$a") ;;
    esac
done

# Target list = explicit args, else every benchmark dir lacking a guard.
TARGETS=()
if [ "${#ARGS[@]}" -gt 0 ]; then
    TARGETS=("${ARGS[@]}")
else
    for d in "$BENCH_ROOT"/XBEN-*-24; do
        [ -d "$d" ] || continue
        [ -f "$d/.xben_build_done" ] && continue
        TARGETS+=("$(basename "$d")")
    done
fi

if [ "${#TARGETS[@]}" -eq 0 ]; then
    echo "Nothing to build — every benchmark already has a .xben_build_done guard."
    exit 0
fi

echo "=================================================================="
echo "build_remaining.sh"
echo "  benchmarks : ${#TARGETS[@]}"
echo "  parallel   : $PARALLEL   (Docker VM is ~8 GB — keep this low)"
echo "  health pass: $([ "$DO_HEALTH" -eq 1 ] && echo yes || echo no)"
echo "  timeout    : ${TIMEOUT_BIN:-<none>} (build ${BUILD_TIMEOUT}s, up ${UP_TIMEOUT}s)"
echo "  logs       : $LOG_DIR"
echo "  started    : $(date '+%Y-%m-%d %H:%M:%S')"
echo "=================================================================="

# --- Build phase (bounded parallelism via xargs -P) ---------------------
rm -f "$LOG_DIR"/*.result 2>/dev/null || true
printf '%s\n' "${TARGETS[@]}" \
    | xargs -P "$PARALLEL" -n1 -I{} bash "$SCRIPT_PATH" __build_one {}

# Gather build results
: > "$LOG_DIR/results.tsv"
for id in "${TARGETS[@]}"; do
    [ -f "$LOG_DIR/$id.result" ] && cat "$LOG_DIR/$id.result" >> "$LOG_DIR/results.tsv"
done

BUILT_OK=()
while IFS=$'\t' read -r id status _secs _health _note; do
    [ "$status" = "ok" ] && BUILT_OK+=("$id")
done < "$LOG_DIR/results.tsv"

echo ""
echo "--- Build phase done: $(grep -c $'\tok\t' "$LOG_DIR/results.tsv") ok / $(grep -c $'\tfail\t' "$LOG_DIR/results.tsv") fail ---"

# --- Health phase (serial; always tear down) ----------------------------
if [ "$DO_HEALTH" -eq 1 ] && [ "${#BUILT_OK[@]}" -gt 0 ]; then
    echo ""
    echo "--- Health phase: ${#BUILT_OK[@]} candidates (serial, with teardown) ---"
    for id in "${BUILT_OK[@]}"; do
        dir="$BENCH_ROOT/$id"
        hlog="$LOG_DIR/$id.health.log"
        echo "[health] $id: up --wait ..."
        if ( cd "$dir" && run_capped "$((UP_TIMEOUT + 30))" \
                docker compose up -d --wait --wait-timeout "$UP_TIMEOUT" ) > "$hlog" 2>&1; then
            health="healthy"
            echo "[health] $id: HEALTHY"
        else
            health="unhealthy"
            echo "[health] $id: UNHEALTHY (see $hlog)"
        fi
        # Always tear down to free the network + RAM (keeps the image).
        ( cd "$dir" && docker compose down --remove-orphans ) >> "$hlog" 2>&1 || true
        # Rewrite this id's result line with the health verdict.
        if [ -f "$LOG_DIR/$id.result" ]; then
            awk -v h="$health" 'BEGIN{FS=OFS="\t"} {$4=h; print}' \
                "$LOG_DIR/$id.result" > "$LOG_DIR/$id.result.tmp" \
                && mv "$LOG_DIR/$id.result.tmp" "$LOG_DIR/$id.result"
        fi
    done
    # Re-gather with health verdicts.
    : > "$LOG_DIR/results.tsv"
    for id in "${TARGETS[@]}"; do
        [ -f "$LOG_DIR/$id.result" ] && cat "$LOG_DIR/$id.result" >> "$LOG_DIR/results.tsv"
    done
fi

# --- Summary ------------------------------------------------------------
{
    echo "build_remaining.sh summary — $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    printf '%-13s %-6s %-7s %-10s %s\n' ID BUILD SECS HEALTH NOTE
    printf '%-13s %-6s %-7s %-10s %s\n' ------------- ------ ------- ---------- ----
    sort "$LOG_DIR/results.tsv" | while IFS=$'\t' read -r id status secs health note; do
        printf '%-13s %-6s %-7s %-10s %s\n' "$id" "$status" "$secs" "$health" "$note"
    done
    echo ""
    echo "build ok   : $(grep -c $'\tok\t'   "$LOG_DIR/results.tsv")"
    echo "build fail : $(grep -c $'\tfail\t' "$LOG_DIR/results.tsv")"
    if [ "$DO_HEALTH" -eq 1 ]; then
        echo "unhealthy  : $(grep -c $'\tunhealthy\t' "$LOG_DIR/results.tsv")"
    fi
} | tee "$LOG_DIR/summary.txt"

echo ""
echo "DONE. Full summary: $LOG_DIR/summary.txt"
