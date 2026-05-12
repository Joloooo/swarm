"""macOS Docker bootstrap for the ``swarm`` TUI.

Single public entry: :func:`ensure_ready`. It runs once at TUI start
(before the menu appears) and walks through these states:

  1. ``docker info`` works → done, return immediately.
  2. ``docker`` CLI missing → offer ``brew install --cask docker`` (or
     a manual-download link if Homebrew is also missing). On install
     success, recurse.
  3. ``Docker.app`` is in ``/Applications`` but the daemon is down →
     ``open -a Docker`` then poll ``docker info`` for up to 120s with
     a rich spinner. Cold boots after a macOS restart can take ~90s,
     hence the generous timeout.
  4. Active ``docker context`` is NOT ``default``/``desktop-linux`` →
     leave it alone (the user is on colima / Rancher Desktop /
     orbstack; we don't hijack their setup, just bail with a clear
     message asking them to start their own daemon).

The function exits the process via ``sys.exit(...)`` on unrecoverable
failure rather than raising, because the calling code in
:mod:`src.cli.__init__` shouldn't need to know the difference between
"user said no to install" and "Docker never came up after 120s" —
both end the same way.

Linux/Windows support is explicitly out of scope (the user said
"only for mac for now"); on those platforms ``ensure_ready`` falls
back to a passive check + manual instructions.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Polling settings — tuned for Docker Desktop cold-start on Apple Silicon.
_CHECK_TIMEOUT_S = 5      # `docker info` round-trip when daemon is up = <1s
_POLL_INTERVAL_S = 2.0    # avoid hammering the socket; daemon takes seconds
_GATEKEEPER_HINT_AT_S = 30.0  # first-launch macOS dialog hint threshold


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

def ensure_ready(timeout_s: int = 120) -> None:
    """Make Docker usable, or exit with a clear error.

    No-op when Docker is already up. Otherwise tries to start
    Docker.app (macOS only); offers a Homebrew install if absent.
    """
    if _is_running():
        return

    if platform.system() != "Darwin":
        # Non-macOS: we only checked, we don't auto-start. Bail with a
        # message rather than spinning forever.
        _bail(
            "Docker daemon is not reachable.\n"
            "This auto-start path is macOS-only. Please start Docker manually."
        )

    # macOS-specific path from here on.
    ctx = _active_context()
    if ctx and ctx not in ("default", "desktop-linux", ""):
        _bail(
            f"Active Docker context is '{ctx}' (not Docker Desktop).\n"
            "Please start whichever daemon backs this context (colima / "
            "Rancher / orbstack) and re-run `swarm`."
        )

    if not _cli_installed() or not _desktop_app_installed():
        _offer_install()
        # _offer_install either succeeds (Docker.app now exists) or
        # exits. If it returns, fall through to start the daemon.

    _start_desktop_and_wait(timeout_s)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _is_running() -> bool:
    """Is the Docker daemon reachable via ``docker info``?"""
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_CHECK_TIMEOUT_S,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _cli_installed() -> bool:
    """Is the ``docker`` binary on PATH?"""
    return shutil.which("docker") is not None


def _desktop_app_installed() -> bool:
    """Is Docker Desktop installed in /Applications?"""
    return Path("/Applications/Docker.app").exists()


def _active_context() -> str:
    """Output of ``docker context show`` (or empty on error).

    Used to detect colima / Rancher / orbstack users so we don't
    hijack their setup with ``open -a Docker``.
    """
    if not _cli_installed():
        return ""
    try:
        proc = subprocess.run(
            ["docker", "context", "show"],
            capture_output=True,
            text=True,
            timeout=_CHECK_TIMEOUT_S,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


# ---------------------------------------------------------------------------
# Install (interactive)
# ---------------------------------------------------------------------------

def _offer_install() -> None:
    """Prompt the user to install Docker Desktop via Homebrew.

    On 'yes' we install and return. On 'no' or missing Homebrew we
    exit with a manual-download link.
    """
    from rich.console import Console
    console = Console(stderr=True)

    console.print(
        "[yellow]Docker Desktop is not installed.[/yellow]"
    )

    if not shutil.which("brew"):
        _bail(
            "Homebrew is not installed either.\n"
            "Install it from https://brew.sh, then re-run `swarm`.\n"
            "(Or download Docker Desktop directly from "
            "https://www.docker.com/products/docker-desktop/.)"
        )

    # We can't use questionary here because that module is heavier and
    # the docker bootstrap runs before the TUI fully starts. A simple
    # input() is fine for one yes/no question.
    answer = input("Install Docker Desktop via `brew install --cask docker`? [Y/n] ").strip().lower()
    if answer and answer not in ("y", "yes"):
        _bail("Install declined. Re-run `swarm` after installing Docker.")

    console.print("[cyan]Running `brew install --cask docker`…[/cyan]")
    proc = subprocess.run(
        ["brew", "install", "--cask", "docker"],
        check=False,
    )
    if proc.returncode != 0:
        _bail(
            f"`brew install --cask docker` failed (rc={proc.returncode}).\n"
            "Install Docker Desktop manually from "
            "https://www.docker.com/products/docker-desktop/."
        )

    if not _desktop_app_installed():
        _bail(
            "Install completed but /Applications/Docker.app still not found.\n"
            "Open Docker Desktop manually once to finish setup."
        )


# ---------------------------------------------------------------------------
# Start + wait
# ---------------------------------------------------------------------------

def _start_desktop_and_wait(timeout_s: int) -> None:
    """``open -a Docker`` then poll until the daemon is up.

    On the first-ever launch macOS may pop a Gatekeeper dialog that
    blocks until the user clicks "Open". We can't dismiss it, so
    after 30s of no progress we print a hint suggesting the user
    check for one.
    """
    from rich.console import Console
    from rich.spinner import Spinner

    console = Console(stderr=True)

    try:
        subprocess.run(["open", "-a", "Docker"], check=False, timeout=10)
    except subprocess.TimeoutExpired:
        # `open` should be instant; if it hangs we just fall through
        # to polling and let the timeout catch us.
        pass

    # Manual spinner so we can update the label past the 30s mark to
    # mention the macOS Gatekeeper dialog. rich.progress would also
    # work but is overkill for a one-step waiter.
    started = time.monotonic()
    hint_shown = False

    with console.status("[cyan]Starting Docker Desktop…[/cyan]", spinner="dots") as status:
        while True:
            elapsed = time.monotonic() - started
            if _is_running():
                console.print("[green]Docker is ready.[/green]")
                return
            if elapsed >= timeout_s:
                break
            if elapsed >= _GATEKEEPER_HINT_AT_S and not hint_shown:
                status.update(
                    "[cyan]Starting Docker Desktop… "
                    "(check for a macOS dialog asking you to allow Docker)[/cyan]"
                )
                hint_shown = True
            time.sleep(_POLL_INTERVAL_S)

    _bail(
        f"Docker Desktop did not become ready within {timeout_s}s.\n"
        "Try opening Docker.app manually, accept any macOS dialogs, "
        "then re-run `swarm`."
    )


# ---------------------------------------------------------------------------
# Error helper
# ---------------------------------------------------------------------------

def _bail(message: str) -> None:
    """Print a red error panel and exit with status 3.

    Exit code 3 mirrors ``xbow_runner.py``'s "docker unavailable" code
    so downstream callers see consistent rc.
    """
    from rich.console import Console
    from rich.panel import Panel

    Console(stderr=True).print(
        Panel(message, title="Docker bootstrap failed", border_style="red")
    )
    sys.exit(3)
