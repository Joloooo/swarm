"""SwarmAttacker CLI — single entry point for ``swarm`` and ``swarmattacker``.

This module is the dispatcher. It parses the shared argparse surface
and routes to one of three handlers:

  1. ``runner.run_<action>()`` — when a benchmark shortcut flag is
     given (``--bench``, ``--daily``, ``--daily-silent``, ``--all``).
     Docker is auto-started first, persistent config from
     ``swarm-config.toml`` is injected into the environment, and
     ``benchmarks.xbow_runner`` is spawned as a subprocess.

  2. ``oneshot.main(args)`` — when a positional ``user_input`` is
     given. Same behaviour as the legacy ``swarmattacker example.com``
     one-shot natural-language flow (preserved verbatim from
     ``src/cli.py`` before the package restructure).

  3. ``tui.main_loop(args)`` — when no positional and no shortcut
     flags are given. Bootstraps Docker (unless ``--no-docker``),
     loads persistent config, then opens the questionary menu.

Why a dispatcher and not separate entry points: the user wanted ONE
command (``swarm``) that does everything, with ``swarmattacker`` kept
as an alias for backwards compatibility. Both ``[project.scripts]``
entries in ``pyproject.toml`` point at this ``main()``.

The ``run`` symbol is re-exported below so anything still doing
``from src.cli import run`` (the old direct API in ``src/cli.py:81``)
keeps working unchanged.
"""

from __future__ import annotations

import argparse
import sys

# Re-export the legacy ``run`` async helper so external callers and
# tests that did ``from src.cli import run`` still find it. The
# oneshot module is import-cheap — it does NOT pull in src.graph at
# import time (the graph import is lazy, inside ``run()``), so this
# re-export is safe for the env-vars-before-graph dance the TUI
# relies on.
from src.cli.oneshot import run  # noqa: F401


def _build_parser() -> argparse.ArgumentParser:
    """Single argparse surface covering all three CLI modes.

    The benchmark shortcut flags are mutually exclusive with each
    other (only one mode can run at a time) but NOT with positional
    ``user_input`` — argparse can't express that elegantly, so we
    enforce it manually in ``main()``.
    """
    parser = argparse.ArgumentParser(
        prog="swarm",
        description=(
            "SwarmAttacker — interactive menu for benchmark runs and "
            "configuration, plus the legacy natural-language one-shot mode."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes:\n"
            "  swarm                              → interactive TUI (Docker bootstrap + menu)\n"
            "  swarm --bench XBEN-006-24          → run one XBOW benchmark, no menu\n"
            "  swarm --daily                      → run the 15 daily benchmarks (compact)\n"
            "  swarm --daily-silent               → run the 15 daily benchmarks (silent)\n"
            "  swarm --all                        → run every XBEN-*-24 benchmark on disk\n"
            "  swarm \"test example.com for sqli\"  → legacy one-shot natural-language pentest\n"
        ),
    )

    # ── Legacy one-shot positional + flags (preserved from src/cli.py) ──
    parser.add_argument(
        "user_input",
        nargs="?",
        default=None,
        help=(
            "Free-form natural-language pentest request "
            "(legacy one-shot mode). Omit to open the TUI menu."
        ),
    )
    parser.add_argument(
        "--scope",
        default="",
        help="Scope restriction (e.g. '*.example.com'). One-shot mode only.",
    )
    parser.add_argument(
        "--experiment",
        default=None,
        help="Ablation experiment label (e.g. 'no_rag'). One-shot mode only.",
    )
    parser.add_argument(
        "--provider",
        default="anthropic",
        choices=["anthropic", "openai", "openrouter"],
        help="LLM provider for one-shot mode (default: anthropic).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name override for one-shot mode.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose logging in one-shot mode.",
    )

    # ── New benchmark shortcuts (skip the menu) ──
    bench_group = parser.add_mutually_exclusive_group()
    bench_group.add_argument(
        "--bench",
        metavar="BENCH_ID",
        default=None,
        help="Run ONE XBOW benchmark by ID (e.g. XBEN-006-24). Skips the menu.",
    )
    bench_group.add_argument(
        "--daily",
        action="store_true",
        help="Run the 15 daily benchmarks in compact mode. Skips the menu.",
    )
    bench_group.add_argument(
        "--daily-silent",
        action="store_true",
        help="Run the 15 daily benchmarks in silent mode. Skips the menu.",
    )
    bench_group.add_argument(
        "--all",
        action="store_true",
        help="Run every XBEN-*-24 benchmark on disk (~104). Skips the menu.",
    )

    # ── TUI / global flags ──
    parser.add_argument(
        "--no-docker",
        action="store_true",
        help="Skip the Docker check / auto-start. Useful on remote VMs.",
    )

    return parser


def _is_benchmark_mode(args: argparse.Namespace) -> bool:
    """Did the user pass any of the benchmark shortcut flags?"""
    return bool(args.bench or args.daily or args.daily_silent or args.all)


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Manually reject the ambiguous combination of positional + shortcut.
    if args.user_input and _is_benchmark_mode(args):
        parser.error(
            "Pass either a free-form request OR a benchmark shortcut "
            "(--bench / --daily / --daily-silent / --all), not both."
        )

    # ── Mode 1: benchmark shortcut → Docker + config + spawn xbow_runner ──
    if _is_benchmark_mode(args):
        # Lazy imports keep startup cheap for --help and one-shot mode.
        from src.cli import config_store, docker_boot, runner

        if not args.no_docker:
            docker_boot.ensure_ready()
        config_store.load_into_env(override=True)

        if args.bench:
            rc = runner.run_one(args.bench, pause_on_exit=False)
        elif args.daily:
            rc = runner.run_daily(silent=False, pause_on_exit=False)
        elif args.daily_silent:
            rc = runner.run_daily(silent=True, pause_on_exit=False)
        elif args.all:
            rc = runner.run_all(pause_on_exit=False)
        else:  # unreachable — guarded by _is_benchmark_mode
            rc = 2
        sys.exit(rc)

    # ── Mode 2: legacy one-shot natural-language flow ──
    if args.user_input:
        from src.cli import oneshot
        oneshot.main(args)
        return

    # ── Mode 3: interactive TUI ──
    from src.cli import tui
    tui.main_loop(args)
