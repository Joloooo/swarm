#!/usr/bin/env bash
# SwarmAttacker setup script.
#
# Installs the external pentesting tools that SwarmAttacker's agents call.
#
# Required (setup fails if these can't be installed):
#   - tmux      (used for agent session isolation)
#   - nmap      (port scanning, service detection)
#   - gobuster  (directory/endpoint brute-forcing)
#   - sqlmap    (SQL injection testing)
#   - nikto     (web-server vulnerability sweep)
#   - curl      (HTTP requests — usually pre-installed)
#
# Recommended (best-effort — the agent runs without them but loses
# capability; each needs a non-uniform installer, hence the separate path):
#   - php          (build/run PHP exploit payloads, e.g. PHAR deserialization)
#   - nuclei       (template-based CVE / known-vuln scanner)
#   - ffuf         (fast content & parameter fuzzing)
#   - feroxbuster  (recursive content discovery)
#   - wpscan       (WordPress plugin/theme enumeration + version->CVE; Ruby gem)
#   - wafw00f      (WAF / input-filter fingerprinting; Python package)
#
# Plus the Playwright Chromium browser binary (~150 MB, used by
# src/tools/crawler.py when raw HTTP fails). The Playwright Python
# wrapper itself is already installed via `uv sync`.
#
# Technology fingerprinting (was: whatweb) is now handled via `curl -sI`
# plus the homepage HTML that fetch_page already pulls — whatweb was
# dropped from Homebrew and added little over a header probe on our
# target workload.
#
# Supports macOS (Homebrew) and Linux (apt / dnf / pacman).
# Idempotent: safe to run multiple times.
#
# Usage:
#   ./scripts/setup.sh                  # install missing tools + Playwright
#   ./scripts/setup.sh --check          # just check what's missing
#   ./scripts/setup.sh --with-seclists  # ALSO clone SecLists (~1 GB) to
#                                       # ~/.swarmattacker/seclists for the
#                                       # gobuster "medium"/"big" presets

set -euo pipefail

# --- Colors (only if outputting to a terminal) ---
if [ -t 1 ]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED="" GREEN="" YELLOW="" BLUE="" BOLD="" RESET=""
fi

info()    { printf "%s[+]%s %s\n" "$BLUE" "$RESET" "$1"; }
success() { printf "%s[✓]%s %s\n" "$GREEN" "$RESET" "$1"; }
warn()    { printf "%s[!]%s %s\n" "$YELLOW" "$RESET" "$1"; }
error()   { printf "%s[✗]%s %s\n" "$RED" "$RESET" "$1"; }

# Repo root — used to install Python-package tools into the project venv
# and to look up their executables under .venv/bin.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Required tools. Format: "command_name:description". These install with the
# command name == package name on every supported package manager, so they go
# through the uniform bulk-install path. Missing one aborts setup.
REQUIRED_TOOLS=(
    "tmux:agent session isolation (CRITICAL)"
    "nmap:port scanning and service detection"
    "gobuster:directory and endpoint brute-forcing"
    "sqlmap:SQL injection testing"
    "nikto:web-server vulnerability sweep"
    "curl:HTTP requests"
)

# Recommended tools — higher capability, but the agent degrades gracefully
# without them, so install is BEST-EFFORT (a failure never aborts setup).
# They live here, not in REQUIRED_TOOLS, because each needs a non-uniform
# installer (Ruby gem / pip / Go) or a package name that differs from the
# command, which the bulk path cannot express.
RECOMMENDED_TOOLS=(
    "php:build/run PHP exploit payloads (e.g. PHAR for deserialization)"
    "nuclei:template-based CVE / known-vuln scanner"
    "ffuf:fast content & parameter fuzzing"
    "feroxbuster:recursive content discovery"
    "wpscan:WordPress plugin/theme enumeration + version->CVE"
    "wafw00f:WAF / input-filter fingerprinting"
)

# SecLists clone target — user-home cache, not in the repo. Mirrors how
# Playwright Chromium is handled (~/Library/Caches/...). Only populated
# when the operator passes --with-seclists.
SECLISTS_DIR="$HOME/.swarmattacker/seclists"
SECLISTS_URL="https://github.com/danielmiessler/SecLists.git"

# Playwright cache directory — Microsoft uses different paths per OS.
# `playwright install chromium` writes the headless-shell + chromium build
# subdirs here; we look for any `chromium*` dir to decide if it's installed.
case "$(uname -s)" in
    Darwin) PLAYWRIGHT_CACHE="$HOME/Library/Caches/ms-playwright" ;;
    *)      PLAYWRIGHT_CACHE="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}" ;;
esac

# --- OS detection ---

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)
            if command -v apt-get >/dev/null 2>&1; then
                echo "linux-apt"
            elif command -v dnf >/dev/null 2>&1; then
                echo "linux-dnf"
            elif command -v pacman >/dev/null 2>&1; then
                echo "linux-pacman"
            else
                echo "linux-unknown"
            fi
            ;;
        *) echo "unknown" ;;
    esac
}

# --- Tool status check ---

check_tools() {
    local missing=()
    printf "\n%sChecking required tools:%s\n" "$BOLD" "$RESET"
    for entry in "${REQUIRED_TOOLS[@]}"; do
        local tool="${entry%%:*}"
        local desc="${entry#*:}"
        if command -v "$tool" >/dev/null 2>&1; then
            success "$(printf "%-10s %s" "$tool" "$desc")"
        else
            error "$(printf "%-10s %s" "$tool" "$desc  [MISSING]")"
            missing+=("$tool")
        fi
    done

    # Return missing tools via stdout (one per line) after a separator
    printf "\n---MISSING---\n"
    for tool in "${missing[@]}"; do
        printf "%s\n" "$tool"
    done
}

# --- Package manager installers ---

install_macos() {
    local tools=("$@")
    if ! command -v brew >/dev/null 2>&1; then
        error "Homebrew is not installed."
        warn "Install it from https://brew.sh, then re-run this script."
        exit 1
    fi
    info "Installing via Homebrew: ${tools[*]}"
    brew install "${tools[@]}"
}

install_apt() {
    local tools=("$@")
    info "Installing via apt: ${tools[*]}"
    sudo apt-get update
    sudo apt-get install -y "${tools[@]}"
}

install_dnf() {
    local tools=("$@")
    info "Installing via dnf: ${tools[*]}"
    sudo dnf install -y "${tools[@]}"
}

install_pacman() {
    local tools=("$@")
    info "Installing via pacman: ${tools[*]}"
    sudo pacman -S --needed --noconfirm "${tools[@]}"
}

# --- Recommended-tool presence + per-tool installers ---

# Is a tool available? Most resolve on PATH; wafw00f is a Python package that
# lives in the project venv (not on the global PATH), so check there too.
tool_present() {
    local tool="$1"
    case "$tool" in
        wafw00f)
            command -v wafw00f >/dev/null 2>&1 || [ -x "$REPO_ROOT/.venv/bin/wafw00f" ]
            ;;
        *)
            command -v "$tool" >/dev/null 2>&1
            ;;
    esac
}

# wafw00f is a Python package — install it into the project venv via uv.
install_wafw00f() {
    ( cd "$REPO_ROOT" && uv pip install wafw00f )
}

# nuclei / ffuf are Go binaries and feroxbuster is Rust; Homebrew ships all
# three, but apt/dnf/pacman usually don't. On Linux fall back to the language
# toolchain (go install / cargo) and symlink the result onto PATH.
install_go_tool() {
    local tool="$1" src=""
    case "$tool" in
        nuclei) src="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
        ffuf)   src="github.com/ffuf/ffuf/v2@latest" ;;
        feroxbuster)
            if command -v cargo >/dev/null 2>&1; then cargo install feroxbuster; return; fi
            warn "feroxbuster: install manually (https://github.com/epi052/feroxbuster)"
            return 1
            ;;
    esac
    if command -v go >/dev/null 2>&1 && [ -n "$src" ]; then
        go install "$src" || return 1
        local gobin; gobin="$(go env GOBIN)"; [ -z "$gobin" ] && gobin="$(go env GOPATH)/bin"
        [ -x "$gobin/$tool" ] && sudo ln -sf "$gobin/$tool" "/usr/local/bin/$tool" 2>/dev/null || true
    else
        warn "$tool: needs Go on this platform (or grab the release binary)"
        return 1
    fi
}

# wpscan is a Ruby gem (it was dropped from Homebrew and is not packaged in
# apt). Current releases need Ruby >= 3, so on macOS use a Homebrew ruby
# rather than the old system ruby. The gem's executable lands in the keg-only
# brew-ruby exec dir, so symlink it onto PATH afterward.
install_wpscan() {
    local os="$1"
    local gem_cmd="gem"
    if [ "$os" = "macos" ]; then
        command -v brew >/dev/null 2>&1 || { warn "wpscan needs Homebrew"; return 1; }
        if [ ! -x "$(brew --prefix)/opt/ruby/bin/gem" ]; then
            info "Installing Homebrew ruby (wpscan needs Ruby >= 3)..."
            brew install ruby || return 1
        fi
        gem_cmd="$(brew --prefix)/opt/ruby/bin/gem"
    fi
    "$gem_cmd" install --no-document wpscan || return 1
    if ! command -v wpscan >/dev/null 2>&1; then
        local execdir
        execdir="$("$gem_cmd" environment | awk -F': ' '/EXECUTABLE DIRECTORY/{print $NF}' | tr -d ' ')"
        if [ -n "$execdir" ] && [ -x "$execdir/wpscan" ]; then
            ln -sf "$execdir/wpscan" "$(brew --prefix 2>/dev/null || echo /usr/local)/bin/wpscan" 2>/dev/null \
                || sudo ln -sf "$execdir/wpscan" "/usr/local/bin/wpscan" 2>/dev/null || true
        fi
    fi
}

# Dispatch one recommended tool to its correct installer for this OS.
install_recommended_tool() {
    local tool="$1" os="$2"
    case "$tool" in
        wpscan)  install_wpscan "$os" ;;
        wafw00f) install_wafw00f ;;
        nuclei|ffuf|feroxbuster)
            if [ "$os" = "macos" ]; then brew install "$tool"; else install_go_tool "$tool"; fi
            ;;
        php)
            case "$os" in
                macos)        brew install php ;;
                linux-apt)    sudo apt-get install -y php-cli ;;
                linux-dnf)    sudo dnf install -y php-cli ;;
                linux-pacman) sudo pacman -S --needed --noconfirm php ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

# Install the RECOMMENDED_TOOLS set. Best-effort: warns on any failure but
# never aborts setup (these are capability boosters, not hard requirements).
install_recommended_tools() {
    local os="$1" check_only="$2"
    printf "\n%sChecking recommended tools (best-effort):%s\n" "$BOLD" "$RESET"
    local entry tool desc
    for entry in "${RECOMMENDED_TOOLS[@]}"; do
        tool="${entry%%:*}"; desc="${entry#*:}"
        if tool_present "$tool"; then
            success "$(printf "%-12s %s" "$tool" "$desc")"
            continue
        fi
        if [ "$check_only" = "true" ]; then
            warn "$(printf "%-12s %s" "$tool" "$desc  [MISSING]")"
            continue
        fi
        info "Installing $tool ($desc)..."
        if install_recommended_tool "$tool" "$os" && tool_present "$tool"; then
            success "$tool installed"
        else
            warn "$tool could not be auto-installed — the agent will run without it."
        fi
    done
}

# --- Playwright Chromium ---

check_playwright_browser() {
    # Returns 0 if a Chromium build exists in the Playwright cache.
    if [[ -d "$PLAYWRIGHT_CACHE" ]] && \
       find "$PLAYWRIGHT_CACHE" -maxdepth 2 -type d -name 'chromium*' 2>/dev/null | grep -q .; then
        return 0
    fi
    return 1
}

install_playwright_browser() {
    info "Installing Playwright Chromium (~150 MB, downloads from Microsoft CDN)..."
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    (cd "$repo_root" && uv run playwright install chromium)
}

# --- SecLists (opt-in, --with-seclists) ---

check_seclists() {
    # 0 if a SecLists checkout exists at our cache path. We look for the
    # Discovery/Web-Content folder specifically because that's what
    # gobuster_dir actually reads — a partial / empty clone wouldn't.
    [[ -d "$SECLISTS_DIR/Discovery/Web-Content" ]]
}

install_seclists() {
    info "Cloning SecLists into $SECLISTS_DIR (~1 GB, shallow clone)..."
    mkdir -p "$(dirname "$SECLISTS_DIR")"
    if [[ -d "$SECLISTS_DIR/.git" ]]; then
        info "SecLists checkout already present — pulling latest"
        git -C "$SECLISTS_DIR" pull --ff-only --depth=1 || \
            warn "git pull failed; leaving existing checkout in place"
    else
        git clone --depth=1 "$SECLISTS_URL" "$SECLISTS_DIR"
    fi
}

# --- Main ---

main() {
    local check_only=false
    local with_seclists=false
    for arg in "$@"; do
        case "$arg" in
            --check)         check_only=true ;;
            --with-seclists) with_seclists=true ;;
            -h|--help)
                grep '^# ' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
                exit 0 ;;
            *)  error "Unknown flag: $arg"; exit 2 ;;
        esac
    done

    printf "%sSwarmAttacker setup%s\n" "$BOLD" "$RESET"

    local os
    os=$(detect_os)
    info "Detected OS: $os"

    # ---- CLI tools ----
    local missing=()
    local in_missing=false
    while IFS= read -r line; do
        if [[ "$line" == "---MISSING---" ]]; then
            in_missing=true
            continue
        fi
        if $in_missing && [[ -n "$line" ]]; then
            missing+=("$line")
        fi
        if ! $in_missing; then
            printf "%s\n" "$line"
        fi
    done < <(check_tools)

    if [[ ${#missing[@]} -gt 0 ]]; then
        if $check_only; then
            printf "\n"
            warn "Missing CLI tools: ${missing[*]}"
            warn "Re-run without --check to install."
        else
            printf "\n"
            info "Missing CLI tools: ${missing[*]}"
            case "$os" in
                macos)         install_macos "${missing[@]}" ;;
                linux-apt)     install_apt "${missing[@]}" ;;
                linux-dnf)     install_dnf "${missing[@]}" ;;
                linux-pacman)  install_pacman "${missing[@]}" ;;
                *)
                    error "Unsupported OS or package manager. Install these manually: ${missing[*]}"
                    exit 1
                    ;;
            esac

            printf "\n"
            info "Verifying installation..."
            local failed=()
            for tool in "${missing[@]}"; do
                if command -v "$tool" >/dev/null 2>&1; then
                    success "$tool installed"
                else
                    error "$tool still missing after install"
                    failed+=("$tool")
                fi
            done

            if [[ ${#failed[@]} -gt 0 ]]; then
                printf "\n"
                error "Some tools failed to install: ${failed[*]}"
                exit 1
            fi
        fi
    fi

    # ---- Recommended tools (best-effort) ----
    install_recommended_tools "$os" "$check_only"

    # ---- Playwright Chromium ----
    printf "\n%sChecking Playwright browser:%s\n" "$BOLD" "$RESET"
    local pw_missing=false
    if check_playwright_browser; then
        success "$(printf "%-10s %s" "chromium" "Playwright browser binary (crawler fallback)")"
    else
        error "$(printf "%-10s %s" "chromium" "Playwright browser binary  [MISSING]")"
        pw_missing=true
        if $check_only; then
            warn "Re-run without --check to install."
        else
            printf "\n"
            install_playwright_browser
            if check_playwright_browser; then
                success "Playwright Chromium installed"
                pw_missing=false
            else
                error "Playwright Chromium install reported success but binary not found in $PLAYWRIGHT_CACHE"
                exit 1
            fi
        fi
    fi

    # ---- SecLists (opt-in) ----
    printf "\n%sChecking SecLists (gobuster medium/big presets):%s\n" "$BOLD" "$RESET"
    local seclists_missing=false
    if check_seclists; then
        success "$(printf "%-10s %s" "seclists" "SecLists at $SECLISTS_DIR")"
    elif $with_seclists; then
        error "$(printf "%-10s %s" "seclists" "SecLists missing  [MISSING]")"
        seclists_missing=true
        if ! $check_only; then
            printf "\n"
            install_seclists
            if check_seclists; then
                success "SecLists installed at $SECLISTS_DIR"
                seclists_missing=false
            else
                error "SecLists clone reported success but Discovery/Web-Content/ not found"
                exit 1
            fi
        fi
    else
        info "$(printf "%-10s %s" "seclists" "not installed (optional; pass --with-seclists to add ~1 GB)")"
        info "       gobuster_dir(wordlist=\"common\") still works via the bundled wordlist"
    fi

    # ---- Final ----
    if $check_only; then
        if [[ ${#missing[@]} -gt 0 ]] || $pw_missing || ($with_seclists && $seclists_missing); then
            exit 1
        fi
        printf "\n"
        success "Everything is in place."
        exit 0
    fi

    printf "\n"
    success "Setup complete. SwarmAttacker is ready to run."
    printf "\nNext steps:\n"
    printf "  1. Authenticate Codex (one time):  %scodex%s\n" "$BOLD" "$RESET"
    printf "  2. Start the dev server:           %slanggraph dev --no-browser --no-reload%s\n" "$BOLD" "$RESET"
    printf "  3. Open Studio:                    https://smith.langchain.com/studio/?baseUrl=http://127.0.0.1:2024\n"
}

main "$@"
