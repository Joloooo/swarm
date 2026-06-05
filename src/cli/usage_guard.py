"""Pace a benchmark sweep against a Codex account's 5-hour usage limit.

Before each benchmark in a multi-benchmark sweep, :mod:`benchmarks.xbow_runner`
asks this module whether the *selected* Codex account still has 5-hour
headroom. If usage has reached the threshold (default 70%), the guard sleeps
until the 5-hour window resets (plus a safety margin) and re-checks — so the
sweep never starts a benchmark that would immediately hit a hard rate-limit
(429 / ``insufficient_quota``).

Only the 5-hour window (``primary_window``) matters here; the weekly window
(``secondary_window``) is ignored by design.

The usage snapshot comes from :func:`src.cli.codex_usage.fetch`, which hits
the same read-only ``/wham/usage`` status endpoint the Codex CLI uses — it
consumes no model quota and reads the same default ``~/.codex`` login the run
will spend on.

Timezone safety
---------------
The usage API expresses the 5-hour reset two ways, both absolute and
timezone-free (verified live 2026-06-01):

  * ``reset_after_seconds`` — a relative duration (seconds from *now*),
    e.g. ``11716``.
  * ``reset_at``            — a Unix epoch timestamp (seconds since the
    1970 UTC epoch), e.g. ``1780332942``. ``reset_at - now`` equals
    ``reset_after_seconds`` to the second.

We sleep on the **duration**, so the wait never depends on the wall clock,
AM/PM, or DST. ``reset_at`` is only ever turned into a human string via
``time.localtime`` (epoch → local time), which is correct by construction.
There is no time-*string* parsing anywhere, so there is no AM/PM gap to get
wrong. See ``tests/test_usage_guard.py`` for the invariance tests.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

# ── Tunables ────────────────────────────────────────────────────────────────
# The user-facing defaults. ``xbow_runner`` may override threshold / margin
# from its CLI flags or the SWARM_USAGE_* env vars.
DEFAULT_THRESHOLD_PCT = 70.0
DEFAULT_MARGIN_SECONDS = 5 * 60          # safety margin added after the reset

# Each usage check gets ``FETCH_ATTEMPTS`` total tries before the guard gives
# up and aborts the sweep (the user's choice: retry, then stop rather than run
# blind). ``FETCH_BACKOFF_S[i]`` is slept after the i-th failed attempt; the
# tuple must have at least ``FETCH_ATTEMPTS - 1`` entries (the last is reused
# if attempts is raised above its length).
FETCH_ATTEMPTS = 3
FETCH_BACKOFF_S = (3.0, 6.0)

# Safety net for the re-check loop. After sleeping past a full window reset
# usage MUST drop to ~0%, so one cycle normally clears; we allow a few in case
# of clock skew, then abort rather than park forever.
MAX_WAIT_CYCLES = 4

# Used only if the API omits BOTH reset fields (never observed, but we must
# not sleep 0s and busy-loop if it ever happens).
FALLBACK_WAIT_SECONDS = 10 * 60


# Log sink: ``log(message, level)`` where level ∈ {"info","warn","error"}.
# Default is a no-op so the module is import-safe and unit-testable.
LogFn = Callable[..., None]


class UsageGuardAbort(Exception):
    """The usage check could not be completed (or never cleared).

    Raised when a usage check fails ``FETCH_ATTEMPTS`` times in a row, or when
    usage is still over threshold after ``MAX_WAIT_CYCLES`` reset waits. The
    sweep caller catches this and stops launching new benchmarks rather than
    risk running blind into a hard rate-limit.
    """


@dataclass
class GuardDecision:
    """Outcome of evaluating one usage snapshot against the threshold."""

    should_wait: bool
    used_percent: float
    threshold_percent: float
    wait_seconds: int          # 0 when should_wait is False
    reset_epoch: int | None    # Unix epoch of the 5h reset, or None
    reset_local: str           # "HH:MM TZ" for display, or "" when clear


def _reset_seconds(primary: Any, now: float) -> int:
    """Seconds until the 5-hour window resets, timezone-free.

    Prefers the relative ``reset_after_seconds`` (DST/clock-immune); falls
    back to ``reset_at - now`` (epoch arithmetic, still absolute); finally to
    a fixed constant if the API omitted both (never observed live).
    """
    relative = int(getattr(primary, "reset_after_seconds", 0) or 0)
    if relative > 0:
        return relative
    epoch = int(getattr(primary, "reset_at", 0) or 0)
    if epoch > 0:
        return max(0, epoch - int(now))
    return FALLBACK_WAIT_SECONDS


def evaluate(
    primary: Any,
    *,
    threshold_percent: float,
    margin_seconds: int,
    now: float,
) -> GuardDecision:
    """Decide whether to run now or wait, from one 5-hour-window snapshot.

    ``primary`` is anything exposing ``used_percent`` / ``reset_after_seconds``
    / ``reset_at`` (a :class:`src.cli.codex_usage.Window`, or a stub in tests).
    ``now`` is an injected ``time.time()`` so the math is deterministic.

    The returned ``wait_seconds`` is pure integer arithmetic on the duration —
    it does NOT depend on the local timezone. ``reset_local`` is the only
    timezone-aware value, and it is derived by ``time.localtime`` on an epoch,
    which is correct in every zone.
    """
    used = float(getattr(primary, "used_percent", 0) or 0)
    if used < threshold_percent:
        return GuardDecision(False, used, threshold_percent, 0, None, "")

    secs = _reset_seconds(primary, now)
    epoch = int(getattr(primary, "reset_at", 0) or 0) or int(now + secs)
    reset_local = time.strftime("%H:%M %Z", time.localtime(epoch))
    return GuardDecision(
        should_wait=True,
        used_percent=used,
        threshold_percent=threshold_percent,
        wait_seconds=int(secs) + int(margin_seconds),
        reset_epoch=epoch,
        reset_local=reset_local,
    )


def _fmt_duration(seconds: int) -> str:
    """``12016`` → ``"3h 20m"`` / ``540`` → ``"9m"`` — for the wait notice."""
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, _ = divmod(rem, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m"


def _default_fetch(_label: str) -> Any:
    """Fetch live usage for the default ``~/.codex`` login. Lazy-imports
    :mod:`src.cli.codex_usage` so importing this module stays cheap and never
    drags ``httpx`` / the LLM stack into ``xbow_runner``'s import-order dance.

    ``_label`` (the display name the guard threads into its log lines) is
    ignored here — there is exactly one Codex login to read.
    """
    from src.cli import codex_usage
    return codex_usage.fetch()


def _fetch_with_retries(
    name: str,
    *,
    attempts: int,
    log: LogFn,
    sleep: Callable[[float], None],
    fetch: Callable[[str], Any],
) -> Any:
    """Fetch usage, retrying transient failures up to ``attempts`` times.

    Raises :class:`UsageGuardAbort` if every attempt fails — the caller turns
    that into "stop the sweep". Any exception (network blip, 401, parse error)
    is treated as retryable here; a real revoked token will simply fail all
    attempts and abort, which is the safe outcome.
    """
    last: Exception | None = None
    for i in range(1, attempts + 1):
        try:
            return fetch(name)
        except Exception as exc:  # noqa: BLE001 — every failure is retryable here
            last = exc
            log(
                f"usage check for {name} failed "
                f"(attempt {i}/{attempts}): {type(exc).__name__}: {exc}",
                "warn",
            )
            if i < attempts:
                sleep(FETCH_BACKOFF_S[min(i - 1, len(FETCH_BACKOFF_S) - 1)])
    raise UsageGuardAbort(
        f"could not read {name} 5-hour usage after {attempts} attempts: "
        f"{type(last).__name__}: {last}"
    )


def wait_until_clear(
    name: str,
    *,
    threshold_percent: float = DEFAULT_THRESHOLD_PCT,
    margin_seconds: int = DEFAULT_MARGIN_SECONDS,
    attempts: int = FETCH_ATTEMPTS,
    max_cycles: int = MAX_WAIT_CYCLES,
    log: LogFn = lambda *a, **k: None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.time,
    fetch: Callable[[str], Any] = _default_fetch,
) -> None:
    """Block until account ``name``'s 5-hour usage is under ``threshold_percent``.

    Loop: read usage (with retries) → if under threshold, return immediately →
    else sleep until the 5-hour window resets + ``margin_seconds`` and re-check.

    Raises :class:`UsageGuardAbort` if a usage read fails all ``attempts``, or
    if usage is somehow still over threshold after ``max_cycles`` waits.

    ``sleep`` / ``now`` / ``fetch`` are injectable for tests. ``log`` is
    ``log(message, level)`` — wait and failure notices are emitted at
    ``"warn"`` so they stay visible even in a silent sweep.
    """
    for _cycle in range(max_cycles):
        usage = _fetch_with_retries(
            name, attempts=attempts, log=log, sleep=sleep, fetch=fetch,
        )
        primary = getattr(usage, "primary", None)
        if primary is None:
            # No 5-hour window in the response — can't reason about it; proceed
            # rather than block the sweep on an unexpected shape.
            log(f"usage for {name} had no 5-hour window — proceeding", "warn")
            return

        decision = evaluate(
            primary,
            threshold_percent=threshold_percent,
            margin_seconds=margin_seconds,
            now=now(),
        )
        if not decision.should_wait:
            log(
                f"{name} 5h usage {decision.used_percent:g}% "
                f"< {threshold_percent:g}% — clear to run",
                "info",
            )
            return

        log(
            f"{name} 5h usage {decision.used_percent:g}% ≥ {threshold_percent:g}% "
            f"— pausing {_fmt_duration(decision.wait_seconds)} until the 5h "
            f"window resets (~{decision.reset_local}) + "
            f"{margin_seconds // 60}m margin, then re-checking",
            "warn",
        )
        sleep(decision.wait_seconds)

    raise UsageGuardAbort(
        f"{name} 5h usage still ≥ {threshold_percent:g}% after "
        f"{max_cycles} reset waits — aborting to avoid running blind"
    )
