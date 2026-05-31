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
#   - phantomjs (the 23 Dalgona XSS benchmarks: XBEN-004 + 008/010/011/
#                         012/013/015/016/017/018/046/047/048/049/050/051/
#                         059/062/064/065/070/074/087) package no longer in
#                         buster archive. Their original Dockerfiles are
#                         byte-identical. Fix:
#                         force --platform=linux/amd64 + download the
#                         official x86_64 binary from upstream bitbucket.
#                         Runs via Rosetta on Apple Silicon. NOTE: that
#                         binary bundles its own Qt that only ships the
#                         "phantom" QPA platform, so QT_QPA_PLATFORM must
#                         be "phantom" — the original "offscreen" value
#                         (valid for Debian's system-Qt phantomjs package)
#                         makes this binary abort on startup, which
#                         silently breaks the server-side XSS oracle.
#   - httpd:2.4.49/2.4.50 (XBEN-031, XBEN-026) are buster-based and
#                         their apt mirrors went 404. We MUST keep the
#                         httpd version unchanged — those exact
#                         versions ARE the vulnerability (CVE-2021-41773
#                         / CVE-2021-42013). Fix: rewrite sources.list
#                         to archive.debian.org before apt-get update.
#   - python:3.8-slim (XBEN-032) — base image is fine, but the lxml
#                         transitive dep of zeep needs libxml2/libxslt
#                         dev headers + gcc to build the wheel. Fix:
#                         add those packages to the existing apt-get
#                         install line. No version bumps; vuln (XXE in
#                         the SOAP handler) is app-layer.
#   - php:7.1-apache (XBEN-041) is stretch-based, EOL since Jul 2022,
#                         and the stretch archive is now also offline
#                         in practice. Fix: bump to php:7.4-apache
#                         (bullseye, multi-arch). Vuln is app-layer
#                         (arbitrary file upload + command injection
#                         in the PHP source), no `cve` tag, so the
#                         PHP minor bump is vuln-neutral.
#   - composer audit (XBEN-044) refuses to install twig 1.19.0 because
#                         of 12 published advisories. The pinned old
#                         twig IS the vulnerability (SSTI). Fix: pass
#                         --no-audit to composer install. twig stays at
#                         1.19.0 exactly.
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
    ARGS=(
        XBEN-001-24 XBEN-002-24 XBEN-003-24 XBEN-004-24
        XBEN-026-24 XBEN-031-24 XBEN-032-24 XBEN-041-24 XBEN-044-24
        # phantomjs Dalgona XSS family (byte-identical Dockerfiles)
        XBEN-008-24 XBEN-010-24 XBEN-011-24 XBEN-012-24 XBEN-013-24
        XBEN-015-24 XBEN-016-24 XBEN-017-24 XBEN-018-24 XBEN-046-24
        XBEN-047-24 XBEN-048-24 XBEN-049-24 XBEN-050-24 XBEN-051-24
        XBEN-059-24 XBEN-062-24 XBEN-064-24 XBEN-065-24 XBEN-070-24
        XBEN-074-24 XBEN-087-24
        # mysql / buster / compose-platform bit-rot (first-50 sweep)
        XBEN-007-24 XBEN-022-24 XBEN-023-24 XBEN-027-24 XBEN-039-24
        XBEN-040-24 XBEN-043-24
    )
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

# Applies to ALL phantomjs-based Dalgona XSS benchmarks — their original
# Dockerfiles are byte-identical (FROM python:2.7.18-slim, apt phantomjs,
# @FLAG@ -> secret.txt, flask run). XBEN-004 serves /xss25; the other 22
# serve /page. The replacement template is structure-identical, only the
# rotted bits change (archive apt mirror, bitbucket phantomjs binary,
# QT_QPA_PLATFORM=phantom for that binary's bundled Qt).
patch_phantomjs_xss_dockerfile() {
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

# The upstream bitbucket phantomjs binary bundles its own Qt that only
# ships the "phantom" QPA platform plugin (its built-in headless mode).
# The original Dockerfile's "offscreen" value came from Debian's
# system-Qt phantomjs package and does NOT exist in this binary: setting
# it makes phantomjs abort on startup ("could not find or load the Qt
# platform plugin offscreen"), so check.js never runs and the XSS oracle
# silently returns "Failed!" to every submission, including the correct
# one. Must be "phantom" for this binary.
ENV QT_QPA_PLATFORM=phantom
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

patch_httpd_buster_apt_dockerfile() {
    # XBEN-026 (httpd:2.4.50) and XBEN-031 (httpd:2.4.49). Both base
    # images sit on Debian buster (EOL Jun 2024), so any `apt-get
    # update` 404s. CRITICAL: the httpd version IS the vuln
    # (CVE-2021-42013 / CVE-2021-41773) — DO NOT bump. We only rewrite
    # the apt sources to the archive mirror, then re-emit the rest of
    # the original Dockerfile verbatim.
    local dockerfile="$1"
    if [ ! -f "$dockerfile" ]; then
        echo "  skip: $dockerfile (not found)"
        return 0
    fi
    if grep -q "archive.debian.org" "$dockerfile"; then
        echo "  already patched: $dockerfile"
        return 0
    fi
    if ! grep -q "^FROM httpd:" "$dockerfile"; then
        echo "  skip: $dockerfile (not an httpd base image)"
        return 0
    fi
    cp "$dockerfile" "${dockerfile}.bitrot_orig"
    # Insert the sources rewrite immediately after the FROM line, and
    # add Acquire::Check-Valid-Until=false to every subsequent
    # `apt-get update` (archive snapshots have stale Valid-Until
    # timestamps that the default apt rejects).
    awk '
        BEGIN { injected = 0 }
        /^FROM httpd:/ && !injected {
            print
            print ""
            print "# Patched by patch_bitrot.sh: buster apt mirrors went 404 in 2024."
            print "# Rewrite to archive.debian.org so apt-get works; httpd version is"
            print "# left UNCHANGED because that exact version is the vulnerability."
            print "RUN sed -i \\"
            print "        -e \"s|http://deb.debian.org|http://archive.debian.org|g\" \\"
            print "        -e \"s|http://security.debian.org|http://archive.debian.org|g\" \\"
            print "        -e \"/-updates/d\" \\"
            print "        /etc/apt/sources.list"
            injected = 1
            next
        }
        /apt-get update/ && $0 !~ /Acquire::Check-Valid-Until/ {
            gsub(/apt-get update/, "apt-get -o Acquire::Check-Valid-Until=false update")
        }
        { print }
    ' "${dockerfile}.bitrot_orig" > "$dockerfile"
    echo "  patched: $dockerfile (buster apt -> archive.debian.org, httpd version preserved)"
}

patch_lxml_deps_dockerfile() {
    # XBEN-032 (python:3.8-slim) — zeep pulls lxml; building the lxml
    # wheel needs libxml2/libxslt headers AND zlib (the linker step
    # passes -lz). Base image is fine; we just extend the existing
    # apt-get install list. Vuln (XXE in the SOAP handler) is
    # app-layer, untouched.
    local dockerfile="$1"
    if [ ! -f "$dockerfile" ]; then
        echo "  skip: $dockerfile (not found)"
        return 0
    fi
    if grep -q "zlib1g-dev" "$dockerfile"; then
        echo "  already patched: $dockerfile"
        return 0
    fi
    if ! grep -q "apt-get install -y --no-install-recommends curl" "$dockerfile"; then
        echo "  skip: $dockerfile (apt-get install line not in expected form)"
        return 0
    fi
    cp "$dockerfile" "${dockerfile}.bitrot_orig"
    inplace_sed \
        's|apt-get install -y --no-install-recommends curl|apt-get install -y --no-install-recommends curl libxml2-dev libxslt-dev zlib1g-dev gcc|' \
        "$dockerfile"
    echo "  patched: $dockerfile (added libxml2-dev libxslt-dev zlib1g-dev gcc for lxml wheel)"
}

patch_php71_to_74_dockerfile() {
    # XBEN-041 — bump php:7.1-apache (stretch, EOL, archive offline) to
    # php:7.4-apache (bullseye, multi-arch). Vuln is app-layer
    # (arbitrary file upload + command injection in the PHP code);
    # no `cve` tag — so the PHP minor bump does not affect the vuln.
    local dockerfile="$1"
    if [ ! -f "$dockerfile" ]; then
        echo "  skip: $dockerfile (not found)"
        return 0
    fi
    if ! grep -q "^FROM php:7.1-apache" "$dockerfile"; then
        echo "  already patched: $dockerfile"
        return 0
    fi
    cp "$dockerfile" "${dockerfile}.bitrot_orig"
    inplace_sed 's|^FROM php:7.1-apache|FROM php:7.4-apache|' "$dockerfile"
    echo "  patched: $dockerfile (php:7.1-apache -> php:7.4-apache, app-layer vuln preserved)"
}

patch_composer_no_audit_dockerfile() {
    # XBEN-044 — composer's security audit refuses twig 1.19.0 (12 CVEs).
    # That pinned old twig IS the vulnerability (SSTI). The flag that
    # actually disables the blocking behaviour on `composer install` is
    # --no-security-blocking (composer >= 2.4). --no-audit is a
    # `composer audit` subcommand flag and is rejected by `install`.
    # Do NOT bump twig.
    local dockerfile="$1"
    if [ ! -f "$dockerfile" ]; then
        echo "  skip: $dockerfile (not found)"
        return 0
    fi
    if grep -q "composer install --no-security-blocking" "$dockerfile"; then
        echo "  already patched: $dockerfile"
        return 0
    fi
    if ! grep -qE "^RUN composer install[[:space:]]*$" "$dockerfile"; then
        echo "  skip: $dockerfile (composer install line not in expected form)"
        return 0
    fi
    cp "$dockerfile" "${dockerfile}.bitrot_orig"
    inplace_sed 's|^RUN composer install[[:space:]]*$|RUN composer install --no-security-blocking|' "$dockerfile"
    echo "  patched: $dockerfile (composer install --no-security-blocking, twig 1.19.0 preserved)"
}

patch_buster_apt_dockerfile() {
    # Generic buster apt-mirror rescue for non-httpd buster images
    # (XBEN-007: python:3.8-slim-buster). Debian buster reached EOL in
    # Jun 2024 and deb.debian.org now 404s; rewrite the apt sources to
    # archive.debian.org and disable Valid-Until on apt-get update so
    # the existing `apt-get install` step works again. App-layer vuln
    # (IDOR/GraphQL) is untouched — only the apt mirror changes.
    local dockerfile="$1"
    if [ ! -f "$dockerfile" ]; then
        echo "  skip: $dockerfile (not found)"
        return 0
    fi
    if grep -q "archive.debian.org" "$dockerfile"; then
        echo "  already patched: $dockerfile"
        return 0
    fi
    if ! grep -qiE "buster" "$dockerfile"; then
        echo "  skip: $dockerfile (not buster-based)"
        return 0
    fi
    cp "$dockerfile" "${dockerfile}.bitrot_orig"
    awk '
        BEGIN { injected = 0 }
        /^FROM / && !injected {
            print
            print ""
            print "# Patched by patch_bitrot.sh: buster apt mirrors 404 after EOL (Jun 2024)."
            print "RUN sed -i \\"
            print "        -e \"s|http://deb.debian.org|http://archive.debian.org|g\" \\"
            print "        -e \"s|http://security.debian.org|http://archive.debian.org|g\" \\"
            print "        -e \"/-updates/d\" \\"
            print "        /etc/apt/sources.list"
            injected = 1
            next
        }
        /apt-get update/ && $0 !~ /Acquire::Check-Valid-Until/ {
            gsub(/apt-get update/, "apt-get -o Acquire::Check-Valid-Until=false update")
        }
        { print }
    ' "${dockerfile}.bitrot_orig" > "$dockerfile"
    echo "  patched: $dockerfile (buster apt -> archive.debian.org)"
}

patch_compose_mysql_platform() {
    # XBEN-039/040: the db service is `image: mysql:5.7` with no
    # platform. The mysql:5.7 tag has no linux/arm64 manifest, so the
    # pull fails on Apple Silicon before any container starts. Pin
    # platform: linux/amd64 so it runs via Rosetta (same approach as the
    # build-based mysql bump). DB version unchanged; app-layer vuln
    # (SQLi) untouched.
    local compose="$1"
    if [ ! -f "$compose" ]; then
        echo "  skip: $compose (not found)"
        return 0
    fi
    if grep -q "platform: linux/amd64" "$compose"; then
        echo "  already patched: $compose"
        return 0
    fi
    if ! grep -qE "image: *mysql:5\.7" "$compose"; then
        echo "  skip: $compose (no mysql:5.7 image service)"
        return 0
    fi
    cp "$compose" "${compose}.bitrot_orig"
    awk '
        { print }
        /image: *mysql:5\.7/ {
            match($0, /^[ ]*/)
            print substr($0, RSTART, RLENGTH) "platform: linux/amd64"
        }
    ' "${compose}.bitrot_orig" > "$compose"
    echo "  patched: $compose (db service pinned platform: linux/amd64)"
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
        XBEN-001-24|XBEN-002-24|XBEN-003-24|XBEN-022-24|XBEN-023-24|XBEN-027-24|XBEN-043-24)
            target="$bench_dir/mysql/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_mysql_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-004-24|XBEN-008-24|XBEN-010-24|XBEN-011-24|XBEN-012-24|XBEN-013-24|\
        XBEN-015-24|XBEN-016-24|XBEN-017-24|XBEN-018-24|XBEN-046-24|XBEN-047-24|\
        XBEN-048-24|XBEN-049-24|XBEN-050-24|XBEN-051-24|XBEN-059-24|XBEN-062-24|\
        XBEN-064-24|XBEN-065-24|XBEN-070-24|XBEN-074-24|XBEN-087-24)
            target="$bench_dir/src/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_phantomjs_xss_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-005-24)
            echo "  skip: XBEN-005-24 (already buildable, no patch needed)"
            ;;
        XBEN-007-24)
            target="$bench_dir/app/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_buster_apt_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-039-24|XBEN-040-24)
            target="$bench_dir/docker-compose.yml"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_compose_mysql_platform "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-026-24)
            target="$bench_dir/app/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_httpd_buster_apt_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-031-24)
            target="$bench_dir/apache/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_httpd_buster_apt_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-032-24)
            target="$bench_dir/app/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_lxml_deps_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-041-24)
            target="$bench_dir/php/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_php71_to_74_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        XBEN-044-24)
            target="$bench_dir/app/Dockerfile"
            if [ "$REVERT" -eq 1 ]; then
                revert_dockerfile "$target"
            else
                patch_composer_no_audit_dockerfile "$target"
                clear_build_guard "$bench_dir"
            fi
            ;;
        *)
            echo "  skip: $bench (no patch known for this benchmark)"
            ;;
    esac
done

echo "patch_bitrot.sh: done"
