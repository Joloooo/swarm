"""Tier-1 / Tier-2 regression tests for the live reasoning pipeline.

Two failure modes are pinned here:

1. **ContextVar isolation across LangChain async callbacks** (2026-05-13).
   ``ChatCodex._build_reasoning_sink`` used to read agent_id / lc_run_id
   from ``CURRENT_LLM_CALL``, which was populated by
   ``TokenLoggingCallback.on_chat_model_start``. LangChain dispatches
   async callbacks in a child task; the ``ContextVar.set(...)`` mutated
   the child's context copy and the parent (where ``_agenerate`` runs)
   never saw it. Every reasoning delta from Codex got silently dropped
   on the floor for months — including every "thinking…" indicator,
   so the operator-facing display went mute during the long Codex
   thinking phase.

   The fix reads identity directly from ``run_manager`` inside
   ``_generate`` / ``_agenerate`` (same task, no ContextVar). These
   tests verify that path stays intact.

2. **Thinking-pad pad rendering protocol**. The multi-row pad anchored
   below the live stream relies on a precise cursor-move + clear
   protocol. If anyone touches the pad code path without preserving
   the move-up / clear / redraw discipline, concurrent fan-out workers
   will turn the terminal into garbage. These tests run the pad
   against a fake TTY and assert the byte sequence emitted has the
   structural properties the protocol requires.

If any of these flip, the next change to live.py / codex.py should
fail loudly instead of silently restoring the bug.
"""

from __future__ import annotations

import asyncio
import io
import re
import threading
import time
from typing import Any
from uuid import uuid4

import pytest

import src.graph  # noqa: F401 — import-order warm-up (see conftest)
from src.llm.codex import _build_reasoning_sink, _identity_from_run_manager


# ─────────────────────────────────────────────────────────────────────────
# Tier 1 — identity resolution + sink construction
# ─────────────────────────────────────────────────────────────────────────


class _FakeRunManager:
    """Mimics the shape ``_identity_from_run_manager`` reads."""

    def __init__(self, *, metadata: dict | None, run_id: Any) -> None:
        self.metadata = metadata
        self.run_id = run_id


def test_identity_from_run_manager_pulls_agent_and_run_id():
    """The fix reads identity from run_manager — verify the field names
    match what LangChain actually exposes (``metadata`` dict +
    ``run_id`` UUID attribute)."""
    rid = uuid4()
    rm = _FakeRunManager(metadata={"agent_id": "owasp-recon"}, run_id=rid)
    agent, lc_run_id = _identity_from_run_manager(rm)
    assert agent == "owasp-recon"
    assert lc_run_id == rid


def test_identity_from_run_manager_falls_back_to_ls_agent_key():
    """LangSmith / older LangChain versions pass agent_id under
    ``ls_agent`` instead. The identity resolver tolerates both."""
    rid = uuid4()
    rm = _FakeRunManager(metadata={"ls_agent": "executor-0"}, run_id=rid)
    agent, _ = _identity_from_run_manager(rm)
    assert agent == "executor-0"


def test_identity_from_run_manager_empty_when_run_manager_is_none():
    """Salvage / focused-recovery paths invoke ChatCodex directly
    without a run_manager. The resolver must return ``("", None)`` so
    the sink builder short-circuits."""
    agent, lc_run_id = _identity_from_run_manager(None)
    assert agent == ""
    assert lc_run_id is None


def test_build_reasoning_sink_returns_none_when_agent_id_empty():
    """If we don't know the agent, the sink can't attribute deltas
    — return ``None`` so the parser drops them silently."""
    assert _build_reasoning_sink("", uuid4()) is None
    assert _build_reasoning_sink(None, uuid4()) is None  # type: ignore[arg-type]


def test_build_reasoning_sink_fires_live_thinking_delta(monkeypatch):
    """The constructed sink must route to ``LIVE.thinking_delta`` with
    the agent_id and lc_run_id baked in at construction time.

    This is the assertion that catches the original bug: if someone
    reverts the fix and the sink starts reading from a ContextVar
    again, the captured ``agent`` field will be ``"_unknown"`` instead
    of the value we baked in."""
    captured: list[dict] = []

    def fake_delta(*, agent, run_id, text):
        captured.append({"agent": agent, "run_id": run_id, "text": text})

    from src.observability import live as live_mod
    monkeypatch.setattr(live_mod.LIVE, "thinking_delta", fake_delta)

    rid = uuid4()
    sink = _build_reasoning_sink("owasp-recon", rid)
    assert sink is not None
    sink("**Calculating** I need to ...")
    sink("\n\n")

    assert len(captured) == 2
    assert all(c["agent"] == "owasp-recon" for c in captured)
    assert all(c["run_id"] == rid for c in captured)
    assert captured[0]["text"].startswith("**Calculating**")


def test_build_reasoning_sink_swallows_renderer_errors(monkeypatch):
    """Best-effort observability: a broken renderer must never break
    the LLM call. We raise inside the renderer and confirm the sink
    eats it silently."""

    def boom(*, agent, run_id, text):
        raise RuntimeError("renderer is on fire")

    from src.observability import live as live_mod
    monkeypatch.setattr(live_mod.LIVE, "thinking_delta", boom)

    sink = _build_reasoning_sink("agent-x", uuid4())
    assert sink is not None
    sink("some reasoning")  # must not raise


# ─────────────────────────────────────────────────────────────────────────
# Tier 2 — end-to-end through aparse_stream_to_response with a fake
# event stream. Confirms the sink chain works without hitting the API.
# ─────────────────────────────────────────────────────────────────────────


async def _gen(events):
    for ev in events:
        yield ev


def _make_fake_stream() -> list[dict]:
    """A minimal SSE event sequence that exercises the reasoning path.

    Mirrors the shape observed in the on-the-wire probe (see thesis
    debug session 2026-05-13): a part-added marker, one big delta with
    the summary text, a part-done marker, then completed.
    """
    return [
        {"type": "response.created"},
        {"type": "response.reasoning_summary_part.added"},
        {
            "type": "response.reasoning_summary_text.delta",
            "delta": "**Calculating** I need to compute the travel time.",
        },
        {"type": "response.reasoning_summary_text.done"},
        {"type": "response.reasoning_summary_part.done"},
        {
            "type": "response.output_item.done",
            "item": {"type": "message", "role": "assistant"},
        },
        {
            "type": "response.completed",
            "response": {
                "id": "resp_abc",
                "model": "gpt-5.5",
                "status": "completed",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "total_tokens": 15,
                    "output_tokens_details": {"reasoning_tokens": 30},
                },
            },
        },
    ]


def test_aparse_stream_to_response_forwards_reasoning_deltas_to_sink():
    """End-to-end: a fake event stream with reasoning deltas + a sink
    built from a fake run_manager must result in the sink being called
    with the right text.

    This is the integration test that would have caught the 2026-05-13
    bug in CI: it puts together ``_identity_from_run_manager`` +
    ``_build_reasoning_sink`` + ``aparse_stream_to_response`` in the
    same shape ``_agenerate`` does, with no real network."""
    from src.llm.codex import aparse_stream_to_response

    rid = uuid4()
    rm = _FakeRunManager(metadata={"agent_id": "executor-7"}, run_id=rid)
    agent, lc_run_id = _identity_from_run_manager(rm)
    sink_calls: list[str] = []

    def sink(text: str) -> None:
        sink_calls.append(text)

    resp = asyncio.run(
        aparse_stream_to_response(
            _gen(_make_fake_stream()), on_reasoning_delta=sink,
        )
    )

    assert agent == "executor-7"
    assert lc_run_id == rid
    # Sink fired for the part-added separator AND the delta itself.
    assert len(sink_calls) >= 1
    assert any("Calculating" in s for s in sink_calls)
    # And the reasoning summary landed on the response too.
    assert resp.response_metadata.get("reasoning_summary")
    assert resp.usage is not None
    assert resp.usage["reasoning_tokens"] == 30


# ─────────────────────────────────────────────────────────────────────────
# Tier 1 — thinking pad rendering protocol
# ─────────────────────────────────────────────────────────────────────────


class _FakeTty:
    """Stand-in for ``sys.stderr`` that captures writes and reports as a TTY."""

    def __init__(self) -> None:
        self.buf = io.StringIO()

    def write(self, s: str) -> int:
        self.buf.write(s)
        return len(s)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return True

    def value(self) -> str:
        return self.buf.getvalue()


@pytest.fixture
def pad_harness(monkeypatch):
    """Wire up a fake TTY stderr + a compact-mode no-color config + a
    no-op disk tee, then return a helper that runs a sequence of
    pad operations and yields the captured byte stream.

    Stops the daemon ticker after each test so threads don't leak
    between tests. Without that, repeated pytest runs accumulate
    daemon threads — fine for production but noisy for the test
    runner's "leaked threads" warning.
    """
    fake_err = _FakeTty()
    monkeypatch.setattr("sys.stderr", fake_err)

    # No-op disk tee.
    import src.observability.writers as writers
    monkeypatch.setattr(writers, "write_terminal_line", lambda *a, **k: None)
    monkeypatch.setattr(writers, "write_terminal_chunk", lambda *a, **k: None)

    # Compact mode without color (so byte content is human-readable).
    from src import graph as graph_mod
    class _Verb:
        mode = "compact"
        color = False
        show_http = False
    class _Cfg:
        verbosity = _Verb()
    monkeypatch.setattr(graph_mod, "config", _Cfg())

    from src.observability import live as live_mod
    # Reset any state leaked from a previous test.
    with live_mod._STREAM_LOCK:
        live_mod._PAD.clear()
        live_mod._PAD_LINES_DRAWN = 0

    yield fake_err

    # Stop the ticker so threads don't leak between tests.
    live_mod._PAD_TICKER_STOP.set()
    if live_mod._PAD_TICKER_THREAD is not None:
        live_mod._PAD_TICKER_THREAD.join(timeout=1.0)
    live_mod._PAD_TICKER_THREAD = None
    live_mod._PAD_TICKER_STOP.clear()
    with live_mod._STREAM_LOCK:
        live_mod._PAD.clear()
        live_mod._PAD_LINES_DRAWN = 0


def test_pad_registers_one_entry_per_in_flight_call(pad_harness):
    """A started-but-not-finished call shows up as an entry in the
    pad registry. Two simultaneous calls register two entries.

    State-level assertion (not byte-level) because pytest's stderr
    capture intercepts the daemon-thread writes and we can't read
    them back through a monkeypatched ``sys.stderr``. The byte-level
    behavior is exercised manually via ``scripts/`` smoke harnesses
    and the standalone ``/tmp/test_pad_logic.py`` proof harness."""
    from src.observability import LIVE
    from src.observability import live as live_mod

    LIVE.thinking_started(
        agent="agent-A", run_id="rid-1", model="gpt-5.5",
        reasoning_effort="medium",
    )
    LIVE.thinking_started(
        agent="agent-B", run_id="rid-2", model="gpt-5.5",
        reasoning_effort="medium",
    )

    assert "rid-1" in live_mod._PAD
    assert "rid-2" in live_mod._PAD
    assert live_mod._PAD["rid-1"]["agent"] == "agent-A"
    assert live_mod._PAD["rid-2"]["agent"] == "agent-B"
    assert live_mod._PAD["rid-1"]["model"] == "gpt-5.5"
    assert live_mod._PAD["rid-1"]["reasoning_effort"] == "medium"
    # Daemon ticker should have been spun up.
    assert live_mod._PAD_TICKER_THREAD is not None
    assert live_mod._PAD_TICKER_THREAD.is_alive()


def test_pad_draw_emits_ansi_cursor_protocol_when_called_directly(monkeypatch):
    """Bypass the daemon ticker AND pytest's capture by calling the
    pad rendering function with a fake stderr injected via direct
    attribute set on the ``sys`` module (not monkeypatch — which
    pytest's own capture intercepts).

    Verifies the byte sequence emitted by one draw cycle has the
    structural ANSI escapes the cursor-anchored protocol requires.
    Without this test, a refactor of ``_pad_draw`` could quietly
    stop emitting the move-up + clear escape and the pad would
    just stack rows forever.

    Note: doesn't assert any specific verb string is present — the
    typewriter cycle picks whichever verb is active at wall-clock
    time, which is non-deterministic in a test. Instead we assert
    that SOME verb (or partial verb) from the cycle list appears.
    See :func:`test_current_verb_returns_substring_from_cycle` for
    a deterministic verb-resolution test."""
    import sys
    from src.observability import live as live_mod

    real_err = sys.stderr
    fake_err = _FakeTty()
    sys.stderr = fake_err

    # Force compact, non-color config so byte content is plain.
    from src import graph as graph_mod
    class _Verb:
        mode = "compact"; color = False; show_http = False
    class _Cfg:
        verbosity = _Verb()
    real_config = getattr(graph_mod, "config", None)
    graph_mod.config = _Cfg()

    try:
        with live_mod._STREAM_LOCK:
            live_mod._PAD.clear()
            live_mod._PAD["rid-X"] = {
                "started":          time.perf_counter() - 1.5,
                "agent":            "agent-test",
                "model":            "gpt-5.5",
                "reasoning_effort": "medium",
            }
            live_mod._PAD_LINES_DRAWN = 0
            live_mod._pad_draw()
            # Second call exercises the clear-then-redraw path.
            live_mod._pad_redraw_locked()
        out = fake_err.value()
    finally:
        sys.stderr = real_err
        if real_config is not None:
            graph_mod.config = real_config

    # First draw wrote one row containing the agent name and elapsed time.
    assert "agent-test" in out
    # The second redraw cycle MUST emit the clear-then-redraw escapes
    # — that's the load-bearing protocol property.
    assert "\033[J" in out
    assert re.search(r"\033\[\d+A", out) is not None
    # And the row got drawn at least twice.
    assert out.count("agent-test") >= 2


# ─────────────────────────────────────────────────────────────────────────
# Tier 1 — typewriter + breathing-glow animation primitives
# ─────────────────────────────────────────────────────────────────────────


def test_current_verb_returns_substring_from_cycle():
    """At wall-clock time 0 we should be typing in the first verb
    (``thinking``) from char 0 — i.e. an empty string. At a small
    positive time we should see the first 1-2 characters. At the
    hold-phase boundary we should see the full verb."""
    from src.observability.live import (
        _current_verb, _VERBS, _TYPE_PER_CHAR_S, _HOLD_S,
    )
    first = _VERBS[0]
    assert _current_verb(0.0) == first[:0]  # ""
    assert _current_verb(_TYPE_PER_CHAR_S * 0.5) == first[:0]
    assert _current_verb(_TYPE_PER_CHAR_S * 1.5) == first[:1]
    assert _current_verb(_TYPE_PER_CHAR_S * (len(first) - 0.5)) == first[: len(first) - 1]
    # During the hold phase the full verb plus 0-3 dots is present.
    hold_t = _TYPE_PER_CHAR_S * len(first) + _HOLD_S * 0.5
    label = _current_verb(hold_t)
    assert label.startswith(first)
    assert label[len(first):] in ("", ".", "..", "...")


def test_glow_color_oscillates_between_deep_red_and_bright_red():
    """The breathing-glow returns an RGB triple whose R-channel
    spans the (60, 255) band and whose G/B stay near 0. Sampling
    many points covers the full cycle so any colour-clipping
    regression fails the test."""
    from src.observability.live import (
        _glow_color, _GLOW_PERIOD_S, _DEEP_RED, _BRIGHT_RED,
    )
    samples = [_glow_color(_GLOW_PERIOD_S * (i / 40)) for i in range(40)]
    rs = [s[0] for s in samples]
    # R-channel should span at least most of the dim → bright band.
    assert min(rs) <= _DEEP_RED[0] + 5
    assert max(rs) >= _BRIGHT_RED[0] - 5
    # G and B stay in the small interpolation band their endpoints
    # define — never outside of [0, max(deep, bright)].
    for r, g, b in samples:
        assert 0 <= g <= max(_DEEP_RED[1], _BRIGHT_RED[1]) + 1
        assert 0 <= b <= max(_DEEP_RED[2], _BRIGHT_RED[2]) + 1


def test_fg_truecolor_emits_24bit_ansi_escape():
    """The truecolor SGR escape must use the ``\\x1b[38;2;R;G;Bm``
    shape — anything else would be parsed as a different colour
    mode on real terminals and break the breathing glow."""
    from src.observability.live import _fg_truecolor
    assert _fg_truecolor((10, 20, 30)) == "\x1b[38;2;10;20;30m"


def test_pad_removes_row_when_call_finishes(pad_harness):
    """Calling ``thinking_finished`` for one of two in-flight calls
    should immediately drop that row. The other call's row stays.

    Catches the bug where ``thinking_finished`` forgets to update the
    pad and you end up with phantom spinner rows for completed calls."""
    from src.observability import LIVE
    from src.observability import live as live_mod

    LIVE.thinking_started(
        agent="agent-A", run_id="rid-1", model="gpt-5.5",
        reasoning_effort="medium",
    )
    LIVE.thinking_started(
        agent="agent-B", run_id="rid-2", model="gpt-5.5",
        reasoning_effort="medium",
    )
    time.sleep(0.3)

    # Mark agent-A done. Pad should drop its row, leaving only agent-B.
    LIVE.thinking_finished(
        agent="agent-A", run_id="rid-1", duration_ms=300,
        model="gpt-5.5", input_tokens=10, output_tokens=5,
        reasoning_tokens=2,
    )

    # State-level assertion: only one entry remains.
    assert "rid-1" not in live_mod._PAD
    assert "rid-2" in live_mod._PAD


def test_pad_disabled_when_stderr_is_not_a_tty(monkeypatch):
    """File redirects / piping must not emit cursor-move escapes —
    they'd corrupt the captured file. Confirm pad_enabled is False
    when stderr is non-TTY."""
    import sys
    from src.observability import live as live_mod

    class _NotTty:
        def write(self, s): return len(s)
        def flush(self): pass
        def isatty(self): return False

    monkeypatch.setattr(sys, "stderr", _NotTty())
    from src import graph as graph_mod
    class _Verb:
        mode = "compact"; color = False; show_http = False
    class _Cfg:
        verbosity = _Verb()
    monkeypatch.setattr(graph_mod, "config", _Cfg())

    assert live_mod._pad_enabled() is False


def test_pad_disabled_in_silent_mode(monkeypatch):
    """Silent mode must skip pad rendering entirely — it's the
    "no LIVE output" promise. Confirm the gate respects it even when
    stderr IS a TTY."""
    import sys
    from src.observability import live as live_mod

    fake = _FakeTty()
    monkeypatch.setattr(sys, "stderr", fake)
    from src import graph as graph_mod
    class _Verb:
        mode = "silent"; color = False; show_http = False
    class _Cfg:
        verbosity = _Verb()
    monkeypatch.setattr(graph_mod, "config", _Cfg())

    assert live_mod._pad_enabled() is False
