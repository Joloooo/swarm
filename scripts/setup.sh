#!/usr/bin/env bash
# SwarmAttacker setup script.
#
# Installs the external pentesting tools that SwarmAttacker's agents call:
#   - tmux      (required — used for agent session isolation)
#   - nmap      (port scanning, service detection)
#   - gobuster  (directory/endpoint brute-forcing)
#   - sqlmap    (SQL injection testing)
#   - whatweb   (technology fingerprinting)
#   - nikto     (web-server vulnerability sweep)
#   - curl      (HTTP requests — usually pre-installed)
#
# Supports macOS (Homebrew) and Linux (apt / dnf / pacman).
# Idempotent: safe to run multiple times.
#
# Usage:
#   ./scripts/setup.sh          # install missing tools
#   ./scripts/setup.sh --check  # just check what's missing, don't install

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
    "whatweb:technology fingerprinting"
    "nikto:web-server vulnerability sweep"
    "curl:HTTP requests"
)

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

# --- Main ---

main() {
    local check_only=false
    if [[ "${1:-}" == "--check" ]]; then
        check_only=true
    fi

    printf "%sSwarmAttacker setup%s\n" "$BOLD" "$RESET"

    local os
    os=$(detect_os)
    info "Detected OS: $os"

    # Check what's missing (parse the output)
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

    # Nothing missing — done
    if [[ ${#missing[@]} -eq 0 ]]; then
        printf "\n"
        success "All required tools are installed. You're good to go."
        exit 0
    fi

    # Check-only mode: report and exit
    if $check_only; then
        printf "\n"
        warn "Missing: ${missing[*]}"
        warn "Re-run without --check to install."
        exit 1
    fi

    # Install missing tools using the right package manager
    printf "\n"
    info "Missing tools: ${missing[*]}"

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

    # Verify installation
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

    printf "\n"
    success "All tools installed. SwarmAttacker is ready to run."
    printf "\nNext steps:\n"
    printf "  1. Authenticate Codex (one time):  %scodex%s\n" "$BOLD" "$RESET"
    printf "  2. Start the dev server:           %slanggraph dev --no-browser --no-reload%s\n" "$BOLD" "$RESET"
    printf "  3. Open Studio:                    https://smith.langchain.com/studio/?baseUrl=http://127.0.0.1:2024\n"
}

main "$@"
