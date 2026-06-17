"""Persistent ✓/✗/~ triage marks for the ``swarm`` benchmark picker.

The single-container picker (:func:`src.cli.tui._pick_bench`) shows a
green ✓, red ✗ or yellow ~ next to each XBEN id so you can see at a
glance which benchmarks SwarmAttacker has cleared. Those marks are
*manual triage state* — you set them yourself as you review runs by
pressing ``t`` in the picker to cycle the highlighted row through
✓ → ✗ → ~ → no-mark.

State lives in ``benchmarks/bench_results.json`` as a map of
``bench_id → {"status": ..., "duration_s": ...}`` so a benchmark's
verdict and the time its last run took live together in one entry —
they describe the *same run*, so deleting the entry drops both (the
TUI mark **and** its ``(Xm Ys)`` annotation) at once. ``duration_s``
is optional: a mark set by hand before any run has a status but no
time. Status is one of:

  ``"ok"``   → green  ✓  (flag captured / run succeeded)
  ``"fail"`` → red    ✗  (run genuinely failed — ran its time budget
                          or gave up, but found no flag)
  ``"api"``  → yellow ~  (codex/API or infra crash — the run never got
                          a fair attempt, so the result is unknown)
  *(absent)* → no mark yet

Legacy files that stored a bare ``"ok"`` string per id (no duration)
are still read transparently — :func:`_read_raw` coerces them — so an
old ``bench_results.json`` keeps working and gains a time the next run.

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
    "load_durations", "backfill_durations_from_logs",
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


def _normalize_entry(value: object) -> dict | None:
    """Coerce one stored value into ``{"status", "duration_s"?}`` or ``None``.

    Accepts both the new per-id object (``{"status": "ok",
    "duration_s": 1201.0}``) and the legacy bare string (``"ok"``) so an
    old file is read without a migration step. Returns ``None`` for an
    unknown status so stale/invalid entries are silently dropped.
    """
    if isinstance(value, str):
        status, dur = value, None
    elif isinstance(value, dict):
        status, dur = value.get("status"), value.get("duration_s")
    else:
        return None
    if status not in (OK, FAIL, API):
        return None
    entry: dict = {"status": status}
    if isinstance(dur, (int, float)):
        entry["duration_s"] = round(float(dur), 1)
    return entry


def _read_raw() -> dict[str, dict]:
    """Read the file → ``{bench_id: {"status", "duration_s"?}}``.

    Seeds the file on first run; never raises. A missing file writes and
    returns the seed. A corrupt file is reported to stderr and falls back
    to the seed so a bad hand-edit can't brick the picker.
    """
    p = path()
    if not p.exists():
        seeded = {k: {"status": v} for k, v in _SEED.items()}
        _write_raw(seeded)
        return seeded
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"warning: failed to parse {p.name}: {exc}", file=sys.stderr)
        return {k: {"status": v} for k, v in _SEED.items()}
    out: dict[str, dict] = {}
    for bid, val in data.items():
        entry = _normalize_entry(val)
        if entry is not None:
            out[bid] = entry
    return out


def _write_raw(entries: dict[str, dict]) -> None:
    """Persist ``{bench_id: {"status", "duration_s"?}}`` atomically.

    Keys are sorted so the on-disk file diffs cleanly and is easy to
    scan or hand-edit. Each entry is re-normalised on the way out, so a
    duration is only written when it is a real number and an invalid
    status is never persisted. Atomic (``tmp`` + ``fsync`` + replace) for
    the Drive-backed-path reason in the module docstring.
    """
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    clean: dict[str, dict] = {}
    for bid in sorted(entries):
        entry = _normalize_entry(entries[bid])
        if entry is not None:
            clean[bid] = entry
    text = json.dumps(clean, indent=2) + "\n"
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        # fsync before replace — see module docstring (Drive-backed path).
        os.fsync(f.fileno())
    os.replace(tmp, p)


def load() -> dict[str, str]:
    """Read the triage map ``{bench_id: status}``. Seeds on first run.

    The ✓/✗/~ marks only — durations are read with :func:`load_durations`
    from the same file. Never raises; see :func:`_read_raw`.
    """
    return {bid: entry["status"] for bid, entry in _read_raw().items()}


def load_durations() -> dict[str, float]:
    """Read the last-run time (seconds) per benchmark from the same file.

    Powers the picker's dim ``(Xm Ys)`` annotation next to each ✓/✗/~
    mark. Only benchmarks whose entry carries a ``duration_s`` are
    returned, so a mark set by hand (no run yet) and a wiped/absent entry
    both simply get no time — the time is bound to the result, not read
    from a separate log scan. To pull times for old runs into the file,
    see :func:`backfill_durations_from_logs`.
    """
    return {
        bid: entry["duration_s"]
        for bid, entry in _read_raw().items()
        if "duration_s" in entry
    }


def save(results: dict[str, str], durations: dict[str, float] | None = None) -> None:
    """Persist the triage map, keeping each benchmark's run time attached.

    ``results`` is the ``{bench_id: status}`` map the TUI edits. Durations
    are preserved across a save: for every kept id the time comes from
    ``durations`` when supplied (a fresh run), else from whatever is
    already on disk. An id absent from ``results`` is dropped entirely —
    both its mark and its time — which is what makes a TUI cycle-to-blank
    or a hand-delete remove the ``(Xm Ys)`` annotation too.
    """
    existing = _read_raw()
    out: dict[str, dict] = {}
    for bid, status in results.items():
        if status not in (OK, FAIL, API):
            continue
        entry: dict = {"status": status}
        dur: float | None = None
        if durations and isinstance(durations.get(bid), (int, float)):
            dur = durations[bid]
        elif bid in existing and "duration_s" in existing[bid]:
            dur = existing[bid]["duration_s"]
        if dur is not None:
            entry["duration_s"] = round(float(dur), 1)
        out[bid] = entry
    _write_raw(out)


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


def record(
    bench_id: str, status: str | None, duration_s: float | None = None
) -> str | None:
    """Persist ``status`` (and the run's ``duration_s``) for ``bench_id``.

    Called by the xbow_runner as each benchmark finishes so the picker's
    ✓/✗/~ grid — and its ``(Xm Ys)`` time — reflect the latest run without
    a manual ``t`` press. ``duration_s`` is stored in the same entry as
    the status: the verdict and the time describe the one run, so they are
    written together and later cleared together.

    The mark always reflects the **latest run's outcome** — a fresh verdict
    (``ok`` / ``fail`` / ``api``) overwrites whatever was there before. So a
    re-run that now solves shows ✓, a regression shows ✗, and a run that
    crashed on a codex/infra error shows ~ even if it had previously passed
    or failed. That last case is the point: a rate-limit crash invalidates
    the run, and you need to see ~ to know it must be re-run rather than
    have the stale ✓/✗ hide it. ``status=None`` clears the mark.

    The load→set→save runs under :func:`_record_lock` so a parallel sweep's
    ~20 concurrent ``record`` calls can't clobber each other's marks (the
    lock prevents lost updates to *other* benchmarks' keys; each id itself
    is only ever written by the one window that ran it). The lock guards
    only ``record``; the TUI's own ``load``/``cycle``/``save`` loop is
    unaffected.
    """
    with _record_lock():
        results = load()
        durations: dict[str, float] = {}
        if status is None:
            results.pop(bench_id, None)
        else:
            results[bench_id] = status
            if duration_s is not None:
                durations[bench_id] = duration_s
        save(results, durations)
    return status


def _scan_log_durations() -> dict[str, float]:
    """Best-effort: most-recent run duration (seconds) per benchmark id.

    Read straight from the result files the runner already writes — the
    campaign per-benchmark files (``logs/<campaign>/results/<id>.json``) and
    the shared sequential log (``benchmarks/results/xbow_*.jsonl``) — taking
    the most recently written value per benchmark (by file mtime; later lines
    win within one jsonl).

    Best-effort: any unreadable file is skipped, and a benchmark with no
    recorded run simply gets no time. Returns ``{}`` on any trouble. Used by
    :func:`backfill_durations_from_logs` to migrate historical times into the
    unified file; it is not read by the live picker.
    """
    bench_dir = path().parent                  # SwarmAttacker/benchmarks
    logs_root = bench_dir.parent / "logs"      # SwarmAttacker/logs
    local_results = bench_dir / "results"      # benchmarks/results
    best: dict[str, tuple[float, float]] = {}  # id -> (mtime, duration)

    def _consider(bench_id, dur, mtime) -> None:  # noqa: ANN001
        if not bench_id or not isinstance(dur, (int, float)):
            return
        if bench_id not in best or mtime > best[bench_id][0]:
            best[bench_id] = (mtime, float(dur))

    # Campaign per-benchmark json files — each is exactly one run.
    try:
        for p in logs_root.glob("*/results/*.json"):
            try:
                mt = p.stat().st_mtime
                row = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            _consider(row.get("benchmark_id") or p.stem, row.get("duration_s"), mt)
    except OSError:
        pass

    # Shared sequential jsonl — one file may hold many runs; the last line per
    # id is the newest, and the file mtime stands in for "when".
    try:
        for p in local_results.glob("xbow_*.jsonl"):
            try:
                mt = p.stat().st_mtime
                lines = p.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            per_file: dict[str, float] = {}
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                bid, dur = row.get("benchmark_id"), row.get("duration_s")
                if bid and isinstance(dur, (int, float)):
                    per_file[bid] = float(dur)   # later line wins within file
            for bid, dur in per_file.items():
                _consider(bid, dur, mt)
    except OSError:
        pass

    return {bid: dur for bid, (_mt, dur) in best.items()}


def backfill_durations_from_logs() -> int:
    """One-shot: pull historical run times from the logs into the file.

    Times used to be read live from the run logs; they now live in the same
    ``bench_results.json`` entry as the verdict. This migrates the old times
    in **without** resurrecting marks: a duration is only attached to a
    benchmark that already has a status entry and does not yet carry a time.
    A benchmark whose entry was deleted has no status, so it is left blank —
    keeping mark and time deleted together, as intended.

    Returns the number of entries that gained a time. Safe to run repeatedly.
    """
    scanned = _scan_log_durations()
    if not scanned:
        return 0
    with _record_lock():
        entries = _read_raw()
        filled = 0
        for bid, entry in entries.items():
            if "duration_s" not in entry and bid in scanned:
                entry["duration_s"] = round(float(scanned[bid]), 1)
                filled += 1
        if filled:
            _write_raw(entries)
    return filled
