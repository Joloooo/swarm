"""Enumerate every XBEN-*-24 benchmark on disk for the "Run all" action.

Why this module exists rather than just hard-coding ``--daily``:
``benchmarks/daily_15.txt`` ships exactly 15 benchmarks, but the
XBOW submodule on disk currently has 104 of them. The TUI's "Run
all" option needs to discover the full set and write it to a
list-file that ``xbow_runner --list-file`` can consume.

The path is hard-coded (rather than imported from
``benchmarks.xbow_runner``) on purpose: importing that module
triggers ``from src.graph import build_graph, config`` at line 35,
which would freeze the config singleton in the TUI's parent process
and break the env-var-before-import dance that lets edited config
flow into subprocess runs. Keeping this module graph-free preserves
that ordering. The path itself is stable — it has not moved since
the submodule was added — see ``benchmarks/xbow_runner.py:59`` for
the source-of-truth definition we're mirroring.
"""

from __future__ import annotations

from pathlib import Path

# ``parents[3]`` from src/cli/bench_discovery.py:
#   parents[0] = src/cli
#   parents[1] = src
#   parents[2] = SwarmAttacker
#   parents[3] = Thesis
# Mirrors ``benchmarks/xbow_runner.py:59``:
#   XBOW_ROOT = Path(__file__).resolve().parents[2] / "Benchmarks" / "xbow-validation"
XBOW_BENCH_DIR = (
    Path(__file__).resolve().parents[3]
    / "Benchmarks"
    / "xbow-validation"
    / "benchmarks"
)

# Where we cache the generated list. Gitignored — see .gitignore.
_LIST_FILE = (
    Path(__file__).resolve().parents[2]
    / "benchmarks"
    / "all_xben_24.txt"
)


def ensure_all_list() -> Path:
    """Write every XBEN-*-24 directory name to ``all_xben_24.txt``.

    Returns the path so the caller can pass it to
    ``xbow_runner --list-file``. Regenerates on every call — globbing
    104 directories costs <1ms and keeps the list in sync if the
    submodule is updated.

    Raises :class:`FileNotFoundError` with a fix-it message when the
    submodule is uninitialised.
    """
    if not XBOW_BENCH_DIR.is_dir():
        raise FileNotFoundError(
            f"XBOW benchmarks not found at:\n  {XBOW_BENCH_DIR}\n\n"
            "Fix: cd into the parent Thesis repo and run\n"
            "  git submodule update --init Benchmarks/xbow-validation"
        )

    ids = sorted(
        p.name
        for p in XBOW_BENCH_DIR.glob("XBEN-*-24")
        if p.is_dir()
    )

    if not ids:
        raise FileNotFoundError(
            f"No XBEN-*-24 directories found under:\n  {XBOW_BENCH_DIR}\n"
            "The submodule may be checked out at an empty commit."
        )

    _LIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LIST_FILE.write_text("\n".join(ids) + "\n", encoding="utf-8")
    return _LIST_FILE


def count_all() -> int:
    """Return how many XBEN-*-24 benchmarks are available — for menu labels."""
    if not XBOW_BENCH_DIR.is_dir():
        return 0
    return sum(1 for p in XBOW_BENCH_DIR.glob("XBEN-*-24") if p.is_dir())
