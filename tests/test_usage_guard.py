"""Tier-1 unit tests for the Codex 5-hour usage guard (``src.cli.usage_guard``).

No network, no LLM — every test injects a fake ``fetch`` / ``sleep`` / ``now``.

The headline concern these lock down (per the feature request): the wait
duration is computed from the API's numeric reset fields ONLY, so it can never
drift with the local timezone, AM/PM, or DST — and the human-readable reset
clock is derived from a Unix epoch via ``time.localtime``, which is correct in
every zone. The live API shape was confirmed 2026-06-01:

    primary_window = {used_percent: 70, limit_window_seconds: 18000,
                      reset_after_seconds: 11716, reset_at: 1780332942}

where ``reset_at`` is a UTC epoch and ``reset_at - now == reset_after_seconds``.
"""

from __future__ import annotations

import os
import time
import types
from contextlib import contextmanager

import pytest

from src.cli import usage_guard
from src.cli.usage_guard import GuardDecision, UsageGuardAbort, evaluate


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #

def _win(used, *, reset_after=0, reset_at=0):
    """A stand-in for ``codex_usage.Window`` (only the read attributes)."""
    return types.SimpleNamespace(
        used_percent=used,
        reset_after_seconds=reset_after,
        reset_at=reset_at,
    )


def _usage(primary):
    return types.SimpleNamespace(primary=primary)


class _Sleeps:
    """Records sleep durations instead of actually sleeping."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@contextmanager
def _tz(name: str):
    """Temporarily force a timezone (Unix only — uses ``time.tzset``)."""
    old = os.environ.get("TZ")
    os.environ["TZ"] = name
    time.tzset()
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
        time.tzset()


# Real values pulled from the live API on 2026-06-01 (see module docstring).
LIVE_NOW = 1780321226          # 2026-06-01 13:40:26 UTC
LIVE_RESET_AT = 1780332942     # 2026-06-01 16:55:42 UTC  == 18:55:42 CEST
LIVE_RESET_AFTER = LIVE_RESET_AT - LIVE_NOW   # 11716


# --------------------------------------------------------------------------- #
# evaluate() — the pure decision
# --------------------------------------------------------------------------- #

def test_under_threshold_runs_immediately():
    d = evaluate(_win(16, reset_after=LIVE_RESET_AFTER, reset_at=LIVE_RESET_AT),
                 threshold_percent=70, margin_seconds=300, now=LIVE_NOW)
    assert d.should_wait is False
    assert d.wait_seconds == 0
    assert d.used_percent == 16


def test_at_threshold_waits():
    # 70 >= 70 → wait (conservative; avoids starting a run that may 429).
    d = evaluate(_win(70, reset_after=LIVE_RESET_AFTER, reset_at=LIVE_RESET_AT),
                 threshold_percent=70, margin_seconds=300, now=LIVE_NOW)
    assert d.should_wait is True


def test_over_threshold_wait_is_reset_after_plus_margin():
    d = evaluate(_win(72, reset_after=LIVE_RESET_AFTER, reset_at=LIVE_RESET_AT),
                 threshold_percent=70, margin_seconds=300, now=LIVE_NOW)
    assert d.should_wait is True
    assert d.wait_seconds == LIVE_RESET_AFTER + 300        # 11716 + 300 = 12016
    assert d.reset_epoch == LIVE_RESET_AT


def test_falls_back_to_reset_at_when_relative_missing():
    # reset_after_seconds absent → derive duration from reset_at - now.
    d = evaluate(_win(99, reset_after=0, reset_at=LIVE_NOW + 1000),
                 threshold_percent=70, margin_seconds=300, now=LIVE_NOW)
    assert d.wait_seconds == 1000 + 300


def test_falls_back_to_constant_when_no_reset_fields():
    d = evaluate(_win(99, reset_after=0, reset_at=0),
                 threshold_percent=70, margin_seconds=300, now=LIVE_NOW)
    assert d.wait_seconds == usage_guard.FALLBACK_WAIT_SECONDS + 300


# --------------------------------------------------------------------------- #
# Timezone safety — the headline guarantee
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not hasattr(time, "tzset"), reason="tzset is Unix-only")
def test_wait_seconds_is_timezone_invariant():
    """The SLEEP duration must be identical in every timezone — it is pure
    integer arithmetic on the API's numeric fields, never a parsed clock time.
    """
    w = _win(85, reset_after=LIVE_RESET_AFTER, reset_at=LIVE_RESET_AT)
    waits = []
    for zone in ("UTC", "Europe/Berlin", "America/New_York", "Asia/Kolkata"):
        with _tz(zone):
            d = evaluate(w, threshold_percent=70, margin_seconds=300, now=LIVE_NOW)
            waits.append(d.wait_seconds)
    assert len(set(waits)) == 1, f"wait drifted across timezones: {waits}"
    assert waits[0] == LIVE_RESET_AFTER + 300


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="tzset is Unix-only")
def test_reset_local_renders_correct_clock_per_zone():
    """The SAME epoch must render to the right local wall-clock in each zone,
    in 24-hour form — proving the epoch→local conversion has no AM/PM gap.

    reset_at = 1780332942 == 16:55:42 UTC, i.e.
        Europe/Berlin (CEST, UTC+2) → 18:55
        America/New_York (EDT, UTC-4) → 12:55
        Asia/Kolkata (IST, UTC+5:30)  → 22:25
    """
    w = _win(85, reset_after=LIVE_RESET_AFTER, reset_at=LIVE_RESET_AT)
    expected = {
        "Europe/Berlin": "18:55",
        "America/New_York": "12:55",
        "Asia/Kolkata": "22:25",
    }
    for zone, hhmm in expected.items():
        with _tz(zone):
            d = evaluate(w, threshold_percent=70, margin_seconds=300, now=LIVE_NOW)
        assert d.reset_local.startswith(hhmm), (
            f"{zone}: expected {hhmm}, got {d.reset_local!r}"
        )


# --------------------------------------------------------------------------- #
# _fetch_with_retries — retry, then abort
# --------------------------------------------------------------------------- #

def test_fetch_retries_then_succeeds():
    calls = {"n": 0}

    def flaky(_name):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionError("network blip")
        return _usage(_win(10))

    sleeps = _Sleeps()
    out = usage_guard._fetch_with_retries(
        "jolocorp", attempts=3, log=lambda *a, **k: None, sleep=sleeps, fetch=flaky,
    )
    assert out.primary.used_percent == 10
    assert calls["n"] == 3
    assert len(sleeps.calls) == 2          # backoff after attempts 1 and 2


def test_fetch_aborts_after_all_attempts_fail():
    def always_fails(_name):
        raise ConnectionError("down")

    sleeps = _Sleeps()
    with pytest.raises(UsageGuardAbort):
        usage_guard._fetch_with_retries(
            "jolocorp", attempts=3, log=lambda *a, **k: None,
            sleep=sleeps, fetch=always_fails,
        )
    assert len(sleeps.calls) == 2          # slept between the 3 attempts, not after


# --------------------------------------------------------------------------- #
# wait_until_clear — the full loop
# --------------------------------------------------------------------------- #

def test_wait_until_clear_returns_without_sleeping_when_under():
    sleeps = _Sleeps()
    usage_guard.wait_until_clear(
        "jolocorp", threshold_percent=70, margin_seconds=300,
        sleep=sleeps, now=lambda: LIVE_NOW,
        fetch=lambda _n: _usage(_win(16, reset_after=LIVE_RESET_AFTER)),
    )
    assert sleeps.calls == []


def test_wait_until_clear_sleeps_then_clears():
    # First check over threshold → sleep(reset+margin) → second check clear.
    seq = iter([
        _usage(_win(72, reset_after=LIVE_RESET_AFTER, reset_at=LIVE_RESET_AT)),
        _usage(_win(3, reset_after=18000)),
    ])
    sleeps = _Sleeps()
    usage_guard.wait_until_clear(
        "jolocorp", threshold_percent=70, margin_seconds=300,
        sleep=sleeps, now=lambda: LIVE_NOW, fetch=lambda _n: next(seq),
    )
    assert sleeps.calls == [LIVE_RESET_AFTER + 300]


def test_wait_until_clear_aborts_if_never_clears():
    sleeps = _Sleeps()
    with pytest.raises(UsageGuardAbort):
        usage_guard.wait_until_clear(
            "jolocorp", threshold_percent=70, margin_seconds=300,
            max_cycles=3, sleep=sleeps, now=lambda: LIVE_NOW,
            fetch=lambda _n: _usage(_win(95, reset_after=600)),
        )
    assert len(sleeps.calls) == 3          # slept once per cycle, then gave up


def test_wait_until_clear_aborts_if_fetch_keeps_failing():
    sleeps = _Sleeps()
    with pytest.raises(UsageGuardAbort):
        usage_guard.wait_until_clear(
            "jolocorp", threshold_percent=70, margin_seconds=300,
            sleep=sleeps, now=lambda: LIVE_NOW,
            fetch=lambda _n: (_ for _ in ()).throw(ConnectionError("down")),
        )


def test_no_primary_window_proceeds():
    # Defensive: an unexpected response shape with no 5h window → proceed,
    # don't block the sweep.
    sleeps = _Sleeps()
    usage_guard.wait_until_clear(
        "jolocorp", threshold_percent=70, margin_seconds=300,
        sleep=sleeps, now=lambda: LIVE_NOW, fetch=lambda _n: _usage(None),
    )
    assert sleeps.calls == []
