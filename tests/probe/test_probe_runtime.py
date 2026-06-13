"""Offline tests for between-replay process-state isolation (Phase 2).

Proves the property the N-sampling loop depends on: two in-process replays are
INDEPENDENT — replay K+1 does not inherit replay K's captured-flag signal (the
poison that would otherwise cancel K+1's first LLM call). No LLM, no network.
"""

from __future__ import annotations

from tests.probe.runtime import fresh_run_id, reset_process_state


def test_reset_clears_captured_flag_between_replays():
    from src.nodes.base.flag_watcher import is_captured, signal_captured

    signal_captured("FLAG{poison-from-replay-K}")
    assert is_captured(), "precondition: replay K captured a flag"
    reset_process_state()
    assert not is_captured(), "replay K+1 must start with a clean captured-flag signal"


def test_reset_is_idempotent():
    reset_process_state()
    reset_process_state()  # must not raise on a second call


def test_fresh_run_id_is_unique_and_labelled():
    a = fresh_run_id("063-x")
    b = fresh_run_id("063-x")
    assert "probe-063-x" in a and "probe-063-x" in b
    assert a != b, "each replay must get a distinct run dir even within one second"
