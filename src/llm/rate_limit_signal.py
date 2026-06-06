"""Process-global "a Codex rate-limit / quota error happened" signal.

Mirrors the captured-flag signal in :mod:`src.nodes.base.flag_watcher`: a plain
module-level variable visible to ALL code in the process, so the moment any LLM
call exhausts its retries on a Codex rate-limit (429) or hits an
``insufficient_quota`` error, the whole run can know — even a node that caught
the exception locally.

Why it exists
-------------
When the selected Codex account crosses its 5-hour limit mid-benchmark, the
error surfaces deep inside a worker's ``agent.astream``. The worker-crash
handler (:mod:`src.nodes.base.skill_runner`) would normally salvage a partial
result and let the run continue — so the run burns its whole time budget and
ends up looking like an ordinary ``fail`` instead of a crash. That's wrong: a
rate-limited run never got a fair attempt.

So the pieces work together:

  * :mod:`src.llm.codex` sets this signal when it raises a rate-limit / quota
    error (the single choke point every Codex call passes through).
  * :mod:`src.nodes.base.skill_runner` re-raises those errors instead of
    salvaging, so the run aborts promptly.
  * :func:`benchmarks.xbow_runner.run_one` uses it as a safety net to mark the
    benchmark crashed (``~``) regardless of where the error was caught, and the
    usage guard (default 90%) then pauses before the next benchmark until the
    5-hour window resets.

Bench isolation
---------------
Process-scope, so the daily-sweep loop (many benches per process) MUST call
:func:`reset_rate_limited` at the start of each bench — otherwise bench N+1
would inherit bench N's signal and be marked crashed before it even ran. Wired
into :func:`benchmarks.xbow_runner.run_one`, next to ``reset_captured``.

Stdlib-only and import-light (like flag_watcher) so the LLM core can import it
with no risk of a cycle.
"""

from __future__ import annotations

# The first rate-limit / quota error seen this bench (empty string = none).
_RATE_LIMIT_ERROR: str = ""


def signal_rate_limited(error: str) -> None:
    """Record that a Codex rate-limit / quota error is propagating.

    Idempotent — keeps the FIRST error seen this bench (the root cause that
    started the cascade), so later secondary failures don't overwrite it.
    """
    global _RATE_LIMIT_ERROR
    if not _RATE_LIMIT_ERROR:
        _RATE_LIMIT_ERROR = (error or "Codex rate limit").strip()


def is_rate_limited() -> bool:
    """True if a Codex rate-limit / quota error has fired this bench."""
    return bool(_RATE_LIMIT_ERROR)


def get_rate_limit_error() -> str:
    """The recorded rate-limit error string (empty if none fired)."""
    return _RATE_LIMIT_ERROR


def reset_rate_limited() -> None:
    """Clear the signal. MUST run at the start of every benchmark — see the
    module docstring's "Bench isolation" note."""
    global _RATE_LIMIT_ERROR
    _RATE_LIMIT_ERROR = ""
