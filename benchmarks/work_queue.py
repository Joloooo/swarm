"""Shared work-queue for a concurrent campaign — dynamic, not pre-sliced.

The old fan-out (:func:`benchmarks.launch_split.split_contiguous`) cut the
benchmark list into N fixed contiguous slices, one per terminal, decided up
front and blind to difficulty — so a session that drew easy benches finished
early and idled while a slow lane ground on for hours. This module replaces that
with one shared queue all N sessions PULL from: the moment a session is free it
claims the next pending benchmark, so fast workers do more and nobody idles
until the whole queue is drained. Load balances by itself.

State — one JSON file, atomically updated under an ``flock`` (the same pattern
as :func:`src.cli.bench_results._record_lock`)::

    campaign/queue.json
      {
        "pending": [id, ...],                       # not yet claimed, dispatch order
        "running": {id: {"pid", "worker", "claimed_at"}},
        "done":    [id, ...],                        # finished (any verdict)
      }

Race safety. :func:`claim_next_pending` pops one id ``pending → running``
*inside the lock*, so even if ten freed sessions race at the same instant the
``flock`` serialises them and each id goes to exactly ONE winner — the losers
just get the next id. The sessions never coordinate timing; only the claim is
atomic, and that is the whole story. (A lock-free atomic-rename design would work
too, but one JSON file gives a glanceable pending/running/done view.)

Crash recovery. :func:`requeue_dead` moves any ``running`` entry whose owning
process is gone back to ``pending``, so a crashed session's in-flight benchmark
is retried rather than lost. It keys on PID liveness, NOT a time threshold — a
benchmark may legitimately run for hours (a 40-min budget plus a usage-cap
hibernation, see :mod:`src.llm.hibernation`), and a living process must never be
reaped as "stale".

Stdlib-only and import-light (like ``bench_results``) so any campaign tool can
use it without pulling in the agent stack.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover — non-Unix; degrade to no locking
    fcntl = None  # type: ignore[assignment]


def queue_path(campaign: Path) -> Path:
    """``campaign/queue.json`` — the shared pending/running/done state."""
    return Path(campaign) / "queue.json"


def _lock_path(campaign: Path) -> Path:
    return Path(campaign) / "queue.json.lock"


@contextlib.contextmanager
def _queue_lock(campaign: Path):
    """Exclusive advisory ``flock`` around a queue read-modify-write.

    Mirrors :func:`src.cli.bench_results._record_lock`: serialises the
    load→modify→save so two sessions can't both claim the same id (or clobber
    each other's ``done`` append). Degrades to no lock if ``fcntl`` is missing
    or the lock can't be opened — a claim is never blocked by a lock failure.
    """
    if fcntl is None:
        yield
        return
    try:
        lp = _lock_path(campaign)
        lp.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lp, os.O_CREAT | os.O_RDWR, 0o644)
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


def _blank() -> dict:
    return {"pending": [], "running": {}, "done": []}


def _load(campaign: Path) -> dict:
    """Read the queue (callers already hold the lock). Never raises."""
    p = queue_path(campaign)
    if not p.exists():
        return _blank()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return _blank()
    # Defensive: tolerate a hand-edited / partial file.
    return {
        "pending": list(data.get("pending") or []),
        "running": dict(data.get("running") or {}),
        "done": list(data.get("done") or []),
    }


def _save_atomic(campaign: Path, q: dict) -> None:
    """Persist atomically (``tmp`` + ``fsync`` + ``os.replace``).

    Same durability rationale as :func:`bench_results.save`: the repo can live
    on a Drive-backed path where a bare rename races the async sync.
    """
    p = queue_path(campaign)
    p.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(q, indent=2) + "\n"
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


def _pid_alive(pid: int | None) -> bool:
    """True if ``pid`` is a live process on this host.

    Local-only check (the campaign's sessions all run on one machine).
    ``os.kill(pid, 0)`` signals nothing; it just probes existence.
    """
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another user — still alive
    except (OSError, ValueError):
        return False
    return True


def init_queue(
    campaign: Path,
    ids: list[str],
    *,
    done_ids: list[str] | None = None,
) -> dict:
    """Create (or reset) the campaign queue with ``ids`` pending.

    ``done_ids`` (e.g. benchmarks a ``--resume`` already has results for) are
    excluded from ``pending`` and seeded into ``done`` so a resumed campaign
    picks up exactly where it left off. Any prior ``running`` state is dropped —
    a fresh launch owns the queue.
    """
    done = list(done_ids or [])
    done_set = set(done)
    pending = [i for i in ids if i not in done_set]
    q = {"pending": pending, "running": {}, "done": done}
    with _queue_lock(campaign):
        _save_atomic(campaign, q)
    return q


def claim_next_pending(
    campaign: Path,
    *,
    pid: int | None = None,
    worker: str = "",
) -> str | None:
    """Atomically move the next pending id to ``running`` and return it.

    Returns ``None`` when nothing is pending. The whole pop runs under the
    ``flock`` so concurrent callers each get a DISTINCT id (or ``None``) — this
    is the race guarantee.
    """
    pid = pid if pid is not None else os.getpid()
    with _queue_lock(campaign):
        q = _load(campaign)
        if not q["pending"]:
            return None
        bid = q["pending"].pop(0)
        q["running"][bid] = {
            "pid": pid,
            "worker": worker or socket.gethostname(),
            "claimed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        _save_atomic(campaign, q)
        return bid


def mark_done(campaign: Path, bid: str) -> None:
    """Move ``bid`` out of ``running`` into ``done`` (idempotent)."""
    with _queue_lock(campaign):
        q = _load(campaign)
        q["running"].pop(bid, None)
        if bid not in q["done"]:
            q["done"].append(bid)
        _save_atomic(campaign, q)


def requeue_dead(campaign: Path) -> int:
    """Move ``running`` entries whose owning process is gone back to ``pending``.

    Keys on PID liveness only (never a time threshold) so a benchmark that is
    legitimately hibernating on a usage cap for hours is left alone. Returns the
    number requeued. Safe to call from any session: a free worker that finds the
    queue empty calls this to reclaim a crashed peer's work before exiting.
    """
    with _queue_lock(campaign):
        q = _load(campaign)
        dead = [bid for bid, info in q["running"].items()
                if not _pid_alive(info.get("pid"))]
        for bid in dead:
            q["running"].pop(bid, None)
            if bid not in q["pending"]:
                q["pending"].append(bid)
        if dead:
            _save_atomic(campaign, q)
        return len(dead)


def list_pending(campaign: Path) -> list[str]:
    """Snapshot of the currently-pending ids (for a startup banner / preview)."""
    with _queue_lock(campaign):
        return list(_load(campaign)["pending"])


def stats(campaign: Path) -> dict[str, int]:
    """``{"pending", "running", "done", "total"}`` counts for the dashboard."""
    with _queue_lock(campaign):
        q = _load(campaign)
    p, r, d = len(q["pending"]), len(q["running"]), len(q["done"])
    return {"pending": p, "running": r, "done": d, "total": p + r + d}
