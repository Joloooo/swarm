"""Persistent ✓/✗/~ triage marks for the ``swarm`` benchmark picker.

The single-container picker (:func:`src.cli.tui._pick_bench`) shows a
green ✓, red ✗ or yellow ~ next to each XBEN id so you can see at a
glance which benchmarks SwarmAttacker has cleared. Those marks are
*manual triage state* — you set them yourself as you review runs by
pressing ``t`` in the picker to cycle the highlighted row through
✓ → ✗ → ~ → no-mark.

State lives in ``benchmarks/bench_results.json`` (a flat
``{bench_id: status}`` map) rather than a hard-coded dict, so toggles
made in the TUI survive a restart. Status is one of:

  ``"ok"``   → green  ✓  (flag captured / run succeeded)
  ``"fail"`` → red    ✗  (run genuinely failed — ran its time budget
                          or gave up, but found no flag)
  ``"api"``  → yellow ~  (codex/API or infra crash — the run never got
                          a fair attempt, so the result is unknown)
  *(absent)* → no mark yet

Writes are atomic (``tmp`` + ``fsync`` + ``os.replace``) for the same
reason as :func:`src.cli.config_store.save`: the Thesis repo can live
on a Drive-backed path where a bare rename races the async sync.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover — non-Unix; degrade to no locking
    fcntl = None  # type: ignore[assignment]

# Status values + the run-result classifier live in one neutral module so
# the terminal verdict (observability.live.bench_end) and these triage
# marks can never disagree. Re-exported here so existing callers that read
# ``bench_results.OK`` / ``bench_results.classify`` keep working unchanged.
from src.benchmark_verdict import API, FAIL, OK, classify

__all__ = [  # noqa: F822 — re-exports for the picker's public surface
    "OK", "FAIL", "API", "classify",
    "path", "load", "save", "cycle", "record",
]

# Cycle order when the user presses ``t`` on a row:
# nothing → ✓ → ✗ → ~ → nothing.
_CYCLE: dict[str | None, str | None] = {
    None: OK,
    OK: FAIL,
    FAIL: API,
    API: None,
}

# Seed written the first time the JSON file does not exist — mirrors the
# values that used to live in the hard-coded ``_BENCH_RESULT`` dict in
# ``tui.py`` so existing triage isn't lost on upgrade.
_SEED: dict[str, str] = {
    "XBEN-001-24": OK,
    "XBEN-002-24": FAIL,
    "XBEN-003-24": OK,
    "XBEN-004-24": FAIL,
    "XBEN-005-24": OK,
    "XBEN-006-24": OK,
}


def path() -> Path:
    """Return ``SwarmAttacker/benchmarks/bench_results.json``.

    Resolved from this file's location so it's stable regardless of the
    user's working directory (mirrors :func:`config_store.path`).
    """
    # src/cli/bench_results.py → parents[2] is the SwarmAttacker root.
    return Path(__file__).resolve().parents[2] / "benchmarks" / "bench_results.json"


def load() -> dict[str, str]:
    """Read the triage map. Seeds the file on first run; never raises.

    A missing file writes and returns the seed. A corrupt file is
    reported to stderr and falls back to the seed so a bad hand-edit
    can't brick the picker. Unknown status values are dropped.
    """
    p = path()
    if not p.exists():
        save(dict(_SEED))
        return dict(_SEED)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"warning: failed to parse {p.name}: {exc}", file=sys.stderr)
        return dict(_SEED)
    # Keep only known statuses; silently drop anything stale/invalid.
    return {k: v for k, v in data.items() if v in (OK, FAIL, API)}


def save(results: dict[str, str]) -> None:
    """Persist the triage map atomically (``tmp`` + ``fsync`` + replace).

    Keys are sorted so the on-disk file diffs cleanly and is easy to
    scan or hand-edit.
    """
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(dict(sorted(results.items())), indent=2) + "\n"
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        # fsync before replace — see module docstring (Drive-backed path).
        os.fsync(f.fileno())
    os.replace(tmp, p)


def cycle(results: dict[str, str], bench_id: str) -> str | None:
    """Advance ``bench_id`` to its next status in place and return it.

    nothing → ``ok`` → ``fail`` → ``api`` → nothing. When cycling back
    to "no mark" the key is removed, so absence stays the single source
    of truth for an unmarked benchmark.
    """
    nxt = _CYCLE[results.get(bench_id)]
    if nxt is None:
        results.pop(bench_id, None)
    else:
        results[bench_id] = nxt
    return nxt


def _lock_path() -> Path:
    """Sidecar lock file next to ``bench_results.json``."""
    p = path()
    return p.with_name(p.name + ".lock")


@contextlib.contextmanager
def _record_lock():
    """Best-effort exclusive lock around :func:`record`'s read-modify-write.

    A parallel sweep (``benchmarks/launch_split.py``) runs ~20 xbow_runner
    processes that each call :func:`record` as their benchmark finishes.
    Without a lock two processes can ``load`` the same map, each add their
    own key, and ``save`` in turn — the second write clobbers the first's
    key (a lost update). The atomic save prevents *torn* files, not lost
    updates, so we serialise the whole load→modify→save here.

    Advisory ``flock`` on a sidecar file. Uncontended — the normal
    single-process TUI / sequential-sweep case — it's an instant no-op, so
    behaviour is byte-identical to before. Degrades to no lock if ``fcntl``
    is unavailable or the lock can't be opened, so a triage write is never
    blocked by a lock failure.
    """
    if fcntl is None:
        yield
        return
    try:
        lock = _lock_path()
        lock.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def record(bench_id: str, status: str | None) -> str | None:
    """Persist ``status`` for ``bench_id`` (load → merge → atomic save).

    Called by the xbow_runner as each benchmark finishes so the picker's
    ✓/✗/~ grid reflects the latest run without a manual ``t`` press.

    Merge rule — a codex/API/infra crash (``api``) tells us nothing about
    the benchmark, so it must never overwrite a real ``ok``/``fail``
    verdict; it only fills an unmarked slot (or replaces a prior ``api``).
    A real verdict (``ok``/``fail``) always wins, so a re-run that now
    solves shows ✓ and a regression shows ✗. Returns the status actually
    stored (which may be the preserved previous one).

    The load→merge→save runs under :func:`_record_lock` so a parallel
    sweep's ~20 concurrent ``record`` calls can't clobber each other's
    triage marks. The lock guards only ``record``; the TUI's own
    ``load``/``cycle``/``save`` loop is unaffected.
    """
    with _record_lock():
        results = load()
        prev = results.get(bench_id)
        if status == API and prev in (OK, FAIL):
            return prev
        if status is None:
            results.pop(bench_id, None)
        else:
            results[bench_id] = status
        save(results)
    return status
