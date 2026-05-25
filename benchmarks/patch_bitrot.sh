#!/usr/bin/env bash
# patch_bitrot.sh — preflight: patch known-broken XBOW Dockerfiles in place.
#
# Some XBEN-*-24 base images have rotted since the benchmarks were
# authored in 2024:
#   - mysql:5.7.15        no arm64 manifest; signature format too old
#                         for modern Docker. The entire mysql:5.7
#                         series never got arm64 — upstream jumped
#                         to mysql:8.0 for multi-arch. Fix: bump to
#                         mysql:5.7.44 (modern signature format) AND
#                         force --platform=linux/amd64 so it runs via
#                         Rosetta on Apple Silicon. IDOR challenges
#                         are app-layer, so the bump is vuln-neutral.
#   - python:2.7.18-slim  built on Debian buster, whose apt repos went
#                         404 in Jun 2024 when buster reached EOL. Fix:
#                         rewrite sources.list to archive.debian.org.
#   - phantomjs (XBEN-004) package no longer in buster archive. Fix:
#                         force --platform=linux/amd64 + download the
#                         official x86_64 binary from upstream bitbucket.
#                         Runs via Rosetta on Apple Silicon.
#
# The patcher edits the VENDORED submodule Dockerfiles in place and
# saves originals as <file>.bitrot_orig so reverts are trivial:
#   bash patch_bitrot.sh --revert
#
# Idempotent: re-running on already-patched files is a no-op. Clears
# any stale .xben_build_done guard so the next `make build` picks up
# the new Dockerfile.
#
# Usage:
#   bash benchmarks/patch_bitrot.sh                     # apply all known
#   bash benchmarks/patch_bitrot.sh XBEN-001-24         # apply for one
#   bash benchmarks/patch_bitrot.sh --revert            # restore originals

set -euo pipefail

XBOW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../Benchmarks/xbow-validation" && pwd)"

REVERT=0
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --revert) REVERT=1 ;;
        --help|-h)
            sed -n '2,32p' "$0"
            exit 0
            ;;
        *) ARGS+=("$arg") ;;
    esac
done

# Default = patch every benchmark we know how to fix.
if [ "${#ARGS[@]}" -eq 0 ]; then
    ARGS=(XBEN-001-24 XBEN-002-24 XBEN-003-24 XBEN-004-24)
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

revert_dockerfile() {
    local dockerfile="$1"
    local orig="${dockerfile}.bitrot_orig"
    if [ -f "$orig" ]; then
        mv "$orig" "$dockerfile"
        echo "  reverted: $dockerfile"
    else
        echo "  skip: $dockerfile (no .bitrot_orig — nothing to revert)"
    fi
}

# Portable in-place edit: BSD sed (macOS) and GNU sed disagree on -i.
# Always write to a temp file then move.
inplace_sed() {
    local script="$1"
    local file="$2"
    sed "$script" "$file" > "${file}.tmp"
    mv "${file}.tmp" "$file"
}

patch_mysql_dockerfile() {
    local dockerfile="$1"
    if [ ! -f "$dockerfile" ]; then
        echo "  skip: $dockerfile (not found)"
        return 0
    fi
    if ! grep -q "FROM mysql:5.7.15" "$dockerfile"; then
        echo "  already patched: $dockerfile"
        return 0
    fi
    cp "$dockerfile" "${dockerfile}.bitrot_orig"
    # Both the version bump (5.7.15 -> 5.7.44, modern signatures) and
    # --platform=linux/amd64 (mysql:5.7 series is amd64-only — Rosetta
    # emulates on Apple Silicon) are required. Either alone fails.
    inplace_sed \
        's|FROM mysql:5.7.15|FROM --platform=linux/amd64 mysql:5.7.44|' \
        "$dockerfile"
    echo "  patched: $dockerfile (mysql:5.7.15 -> --platform=linux/amd64 mysql:5.7.44)"
}

patch_xben004_dockerfile() {
    local dockerfile="$1"
    if [ ! -f "$dockerfile" ]; then
        echo "  skip: $dockerfile (not found)"
        return 0
    fi
    if ! grep -q "apt-get install -y phantomjs" "$dockerfile"; then
        echo "  already patched: $dockerfile"
        return 0
    fi
    cp "$dockerfile" "${dockerfile}.bitrot_orig"
    cat > "$dockerfile" <<'PATCHED'
# Patched by SwarmAttacker/benchmarks/patch_bitrot.sh:
# - --platform=linux/amd64 forces Rosetta emulation on Apple Silicon so
#   the official x86_64 phantomjs binary runs (no arm64 build ever
#   shipped upstream).
# - sed rewrites the apt sources.list to point at archive.debian.org
#   because Debian buster reached EOL in Jun 2024 and the main mirrors
#   now return 404 for /dists/buster/Release.
# - phantomjs is installed from the upstream bitbucket binary archive
#   because the package was removed from the buster archive.
FROM --platform=linux/amd64 python:2.7.18-slim

RUN sed -i 's|http://deb.debian.org|http://archive.debian.org|g; \
            s|http://security.debian.org|http://archive.debian.org|g; \
            /-updates/d' /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
        ca-certificates wget bzip2 fontconfig libfontconfig1 libfreetype6 \
 && wget -q https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2 \
 && tar xjf phantomjs-2.1.1-linux-x86_64.tar.bz2 \
 && mv phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs \
 && rm -rf phantomjs-2.1.1-linux-x86_64 phantomjs-2.1.1-linux-x86_64.tar.bz2 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV QT_QPA_PLATFORM=offscreen
ENV OPENSSL_CONF=/dev/null

WORKDIR /python-docker

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

ARG FLAG

RUN sed -i s/@FLAG@/$FLAG/g secret.txt

CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0", "--port=5000"]

EXPOSE 5000
PATCHED
    echo "  patched: $dockerfile (buster apt + phantomjs binary download)"
}

clear_build_guard() {
    rm -f "$1/.xben_build_done"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

mode_label="APPLY"
[ "$REVERT" -eq 1 ] && mode_label="REVERT"
echo "patch_bitrot.sh: $mode_label for: ${ARGS[*]}"
echo "xbow root: $XBOW_ROOT"

for bench in "${ARGS[@]}"; do
    bench_dir="$XBOW_ROOT/benchmarks/$bench"
    if [ ! -d "$bench_dir" ]; then
        echo "  skip: $bench (dir not found)"
        continue
    fi

    case "$bench" in
        XBEN-001-24|XBEN-002-24|XBEN-003-24)
            target="$bench_dir/mysql/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_mysql_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-004-24)
            target="$bench_dir/src/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_xben004_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-005-24)
            echo "  skip: XBEN-005-24 (already buildable, no patch needed)"
            ;;
        *)
            echo "  skip: $bench (no patch known for this benchmark)"
            ;;
    esac
done

echo "patch_bitrot.sh: done"
