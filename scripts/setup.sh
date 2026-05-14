#!/usr/bin/env bash
# SwarmAttacker setup script.
#
# Installs the external pentesting tools that SwarmAttacker's agents call:
#   - tmux      (required — used for agent session isolation)
#   - nmap      (port scanning, service detection)
#   - gobuster  (directory/endpoint brute-forcing)
#   - sqlmap    (SQL injection testing)
#   - nikto     (web-server vulnerability sweep)
#   - curl      (HTTP requests — usually pre-installed)
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

# Tools SwarmAttacker needs. Format: "command_name:description"
REQUIRED_TOOLS=(
    "tmux:agent session isolation (CRITICAL)"
    "nmap:port scanning and service detection"
    "gobuster:directory and endpoint brute-forcing"
    "sqlmap:SQL injection testing"
    "nikto:web-server vulnerability sweep"
    "curl:HTTP requests"
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
