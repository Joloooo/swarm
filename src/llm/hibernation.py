"""Process-global rate-limit hibernation for benchmark runs.

When a Codex call hits the ChatGPT-subscription usage cap
(``usage_limit_reached``), the cap is a multi-hour wait, not a failure. In
benchmark mode this module parks the in-flight agent **in place** until the
cap's reset window, then lets the SAME call retry. The whole conversation —
messages, graph state, the Docker target — stays live in RAM, so the agent
resumes at the exact step with no re-priming and therefore **no extra tokens**
(this is the cheap alternative to checkpoint/restore).

Two responsibilities:

* :func:`hibernate_until_reset` — the park itself: sleep (in chunks, anchored on
  the absolute ``resets_at`` so it survives the machine sleeping) until the cap
  resets, with a small wake jitter so N concurrent workers don't stampede the
  per-minute limit on resume.
* :func:`paused_seconds` — total time parked this bench, **including any park in
  progress**, so :func:`benchmarks.xbow_runner.run_one` can extend its
  wall-clock budget by that amount and the 40-minute agent timer genuinely
  *freezes* during a park instead of eating the budget.

Disabled by default — a real engagement must never silently hang for hours.
``xbow_runner`` enables it per benchmark.

Concurrency. Within one benchmark, workers fan out on a single asyncio loop, so
several may hit the cap at once. They share one hold: the union interval is
counted once (first worker in → start, last worker out → bank it), and the
deadline is the latest ``resets_at`` any of them saw. The bookkeeping mutates
module globals only between ``await``s, so asyncio's cooperative scheduling
makes those sections atomic — no lock needed.

Process-scope, like :mod:`src.nodes.base.flag_watcher` /
:mod:`src.llm.rate_limit_signal`: each ``launch_split`` slice is its own process
running benches sequentially, so one accumulator per process is unambiguous.
:func:`reset_hibernation` MUST run at the start of every bench.
"""

from __future__ import annotations

import asyncio
import os
import random
import time

# Knobs (env-overridable for a one-off run).
_CHUNK_S = float(os.getenv("SWARM_HIBERNATE_CHUNK_S", "120"))   # wake cadence for logging
_BUFFER_S = float(os.getenv("SWARM_HIBERNATE_BUFFER_S", "45"))  # wait past resets_at to be safe
_WAKE_JITTER_S = float(os.getenv("SWARM_HIBERNATE_JITTER_S", "5"))
_FALLBACK_S = float(os.getenv("SWARM_HIBERNATE_FALLBACK_S", "300"))  # if the error gave no reset

_ENABLED: bool = False
_total_paused: float = 0.0   # banked park time this bench (completed holds)
_holders: int = 0            # workers currently parked
_hold_started: float = 0.0   # monotonic when the FIRST current holder entered
_deadline: float = 0.0       # latest absolute (wall-clock) reset deadline seen


def enable_hibernation(on: bool = True) -> None:
    """Turn hibernation on (benchmark mode) or off (real audits). Off by default."""
    global _ENABLED
    _ENABLED = bool(on)


def hibernation_enabled() -> bool:
    """True when a usage-cap hit should park-and-retry instead of crashing."""
    return _ENABLED


def reset_hibernation() -> None:
    """Clear the per-bench park accumulator + hold state. Run at each bench start.

    Does NOT touch the enabled flag — that is set once for the process.
    """
    global _total_paused, _holders, _hold_started, _deadline
    _total_paused = 0.0
    _holders = 0
    _hold_started = 0.0
    _deadline = 0.0


def paused_seconds() -> float:
    """Total seconds parked this bench, including a park currently in progress.

    The in-progress term is what lets the run timer freeze smoothly: while a
    park is open it grows in real time, so a deadline computed as
    ``RUN_TIMEOUT_S + paused_seconds()`` advances in lockstep with elapsed time
    and never expires mid-park.
    """
    extra = (time.monotonic() - _hold_started) if _holders > 0 else 0.0
    return _total_paused + extra


def _fmt(seconds: float) -> str:
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    return f"{m}m{sec:02d}s" if m else f"{sec}s"


async def hibernate_until_reset(
    resets_at: float | int | None = None,
    resets_in_seconds: float | int | None = None,
    *,
    agent_id: str = "",
    log=None,
) -> None:
    """Park until the usage cap resets, then return so the caller can retry.

    Anchored on the absolute ``resets_at`` (+ a buffer) when available, so a
    machine that sleeps mid-park recomputes the correct remaining time on wake.
    Falls back to ``resets_in_seconds`` and then a short default. Sleeps in
    chunks for progress logging; another concurrent worker may push the shared
    deadline later, which this loop re-reads each chunk.
    """
    now = time.time()
    if resets_at:
        deadline = float(resets_at) + _BUFFER_S
    elif resets_in_seconds:
        deadline = now + float(resets_in_seconds) + _BUFFER_S
    else:
        deadline = now + _FALLBACK_S + _BUFFER_S

    # Enter the shared hold (synchronous → atomic between awaits).
    global _holders, _hold_started, _deadline
    _deadline = max(_deadline, deadline)
    if _holders == 0:
        _hold_started = time.monotonic()
    _holders += 1

    try:
        while True:
            remaining = _deadline - time.time()   # _deadline may have moved out
            if remaining <= 0:
                break
            if log is not None:
                try:
                    log.warning(
                        "Codex usage cap reached — hibernating ~%s "
                        "(agent=%s); run timer is frozen until reset",
                        _fmt(remaining), agent_id or "?",
                    )
                except Exception:  # noqa: BLE001 — logging must never break the park
                    pass
            await asyncio.sleep(min(remaining, _CHUNK_S))
    finally:
        _holders -= 1
        if _holders <= 0:
            _holders = 0
            global _total_paused
            _total_paused += time.monotonic() - _hold_started

    # Stagger resumes so concurrent holders don't all fire at once and trip the
    # *per-minute* limit (a different 429) the instant the window opens.
    if _WAKE_JITTER_S > 0:
        await asyncio.sleep(random.uniform(0, _WAKE_JITTER_S))
