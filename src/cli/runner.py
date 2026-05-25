"""Spawn :mod:`benchmarks.xbow_runner` for each pentest menu action.

Why subprocess rather than in-process? ``xbow_runner.main()`` mutates
global state in three places:

  - ``config.verbosity.mode = "verbose"`` / ``"silent"`` based on its
    own argparse flags (xbow_runner.py:559-561) — would leak into
    subsequent menu actions.
  - ``logging.basicConfig(...)`` (xbow_runner.py:570) — second call
    is a no-op, so the second action would inherit the first
    action's log config.
  - Attaches a ``LiveLogHandler`` to the root logger and installs an
    ``HttpxQuietFilter`` (xbow_runner.py:581-587) — both global,
    both accumulate.

Subprocess gives us free isolation: each menu action gets a fresh
Python interpreter, a fresh ``src.graph`` import (which re-reads
``SWARM_*`` env vars from the parent process — see
:mod:`src.cli.config_store`), and clean SIGINT propagation. ``stdio``
is inherited so the runner's native compact / verbose / silent
streaming reaches the user's terminal unchanged.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from src.cli import bench_discovery

# Project root — used as the subprocess cwd so ``uv run`` resolves the
# right venv regardless of where ``swarm`` was invoked from.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Public actions — one per menu item
# ---------------------------------------------------------------------------

def run_one(bench_id: str, *, pause_on_exit: bool = True) -> int:
    """Pentest one XBOW benchmark. Matches the user's original
    ``uv run python -m benchmarks.xbow_runner --bench <ID> --skip-build``.
    """
    return _spawn(
        ["--bench", bench_id, "--skip-build"],
        pause_on_exit=pause_on_exit,
    )


def run_daily(*, silent: bool, pause_on_exit: bool = True) -> int:
    """Pentest the 15 daily benchmarks.

    ``silent=False`` matches ``--daily --resume --skip-build`` (compact
    streaming, default UX). ``silent=True`` matches
    ``--daily --resume --silent`` for overnight runs where you only
    want the final verdict per benchmark.
    """
    extra = ["--silent"] if silent else ["--skip-build"]
    return _spawn(
        ["--daily", "--resume", *extra],
        pause_on_exit=pause_on_exit,
    )


def run_first5_buildable(*, pause_on_exit: bool = True) -> int:
    """Pentest the first 5 buildable benchmarks — quick sanity pass.

    Points ``--list-file`` at ``benchmarks/daily_5_buildable.txt``, a
    curated subset covering diverse vuln classes (sqli, xxe, ssrf,
    ssti, lfi) that all build on current Docker Desktop / Apple
    Silicon. Compact streaming + ``--resume --skip-build`` mirrors
    the ergonomics of ``run_daily(silent=False)``.
    """
    list_path = _PROJECT_ROOT / "benchmarks" / "daily_5_buildable.txt"
    return _spawn(
        ["--list-file", str(list_path), "--resume", "--skip-build"],
        pause_on_exit=pause_on_exit,
    )


def run_all(*, pause_on_exit: bool = True) -> int:
    """Pentest every XBEN-*-24 benchmark on disk (~104).

    Writes the list of IDs to ``benchmarks/all_xben_24.txt`` (cached,
    gitignored), then invokes xbow_runner with ``--list-file``. Silent
    mode is forced because 104 benchmarks × compact output = wall of
    noise; the per-benchmark verdicts in ``results/xbow_*.jsonl`` are
    where the data lives.
    """
    try:
        list_path = bench_discovery.ensure_all_list()
    except FileNotFoundError as exc:
        _print_error(str(exc))
        return 4  # distinct from xbow_runner's 0/2/3 exit codes
    return _spawn(
        ["--list-file", str(list_path), "--resume", "--silent", "--skip-build"],
        pause_on_exit=pause_on_exit,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _spawn(args: list[str], *, pause_on_exit: bool) -> int:
    """Run ``uv run python -m benchmarks.xbow_runner <args>``.

    ``env=os.environ`` is the default — passing it explicitly here as
    a reminder that ``SWARM_*`` overrides injected by
    :func:`config_store.load_into_env` propagate via inherited env.
    stdio is NOT captured: the runner streams to the user's terminal
    directly, and Ctrl-C is delivered to the child as SIGINT (which
    ``asyncio.run`` inside xbow_runner handles cleanly).
    """
    cmd = ["uv", "run", "python", "-m", "benchmarks.xbow_runner", *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(_PROJECT_ROOT),
            env=os.environ.copy(),
            check=False,
        )
        rc = proc.returncode
    except KeyboardInterrupt:
        # User hit Ctrl-C; subprocess inherited the SIGINT and exited.
        # Treat as a clean cancellation, not a TUI crash.
        rc = 130

    if pause_on_exit:
        _wait_for_enter(rc)
    return rc


def _wait_for_enter(rc: int) -> None:
    """Pause until the user hits Enter — only when invoked from the TUI.

    Without this, the menu redraws immediately and the final run
    summary scrolls off-screen before the user can read it.
    """
    from rich.console import Console
    Console(stderr=True).print(
        f"\n[dim]Run exited with code {rc}. [enter] to return to menu…[/dim]",
        end=" ",
    )
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


def _print_error(message: str) -> None:
    """Render a red rich panel without crashing if rich is somehow missing."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        Console(stderr=True).print(
            Panel(message, title="Cannot run", border_style="red")
        )
    except Exception:
        print(message, file=sys.stderr)
