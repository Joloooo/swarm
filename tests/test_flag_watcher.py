"""Tier 1 — FlagWatcherCallback short-circuit behaviour.

Pins the contract introduced 2026-05-25 after the XBEN-006-24 retro:
a worker that produces the expected flag literal in tool output must
stop immediately, not run another 60-90 s of Codex reasoning before
its agent loop notices it's "done". The callback fires on
``on_tool_end`` and raises :class:`FlagCapturedSignal`, which the
skill runner catches and converts into a normal captured-flag update.

These tests pin five behaviours:

  1. Match → raises FlagCapturedSignal with the captured value.
  2. No match (well-formed but wrong flag) → does NOT raise.
  3. No flag-shaped string in output → does NOT raise.
  4. Empty ``expected_flag`` (real-pentest mode) → callback is a
     no-op regardless of output.
  5. ToolMessage-wrapped output (some agent shapes wrap the bash
     return value in a ToolMessage) is handled, not skipped.

Strategy: invoke the callback's ``on_tool_end`` directly with the
arguments LangChain would pass at runtime. No real LangChain agent,
no real LLM — pure Tier 1.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from langchain_core.messages import ToolMessage

from src.nodes.base.flag_watcher import (
    FlagCapturedSignal,
    FlagWatcherCallback,
    _coerce_to_text,
)


EXPECTED = "flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"
WRONG = "flag{aaaaaaaa-1111-2222-3333-444444444444}"


# ── Helpers ──────────────────────────────────────────────────────────────


def _run(coro):
    """Run an awaitable synchronously in a test."""
    return asyncio.get_event_loop().run_until_complete(coro) \
        if asyncio.get_event_loop().is_running() is False \
        else asyncio.new_event_loop().run_until_complete(coro)


async def _call(cb: FlagWatcherCallback, output, *, tool_name: str = "bash"):
    """Invoke on_tool_end with the kwargs LangChain passes at runtime."""
    return await cb.on_tool_end(
        output,
        run_id=uuid4(),
        parent_run_id=uuid4(),
        name=tool_name,
    )


# ── 1. Match → raises with captured value ────────────────────────────────


@pytest.mark.asyncio
async def test_raises_on_strict_equality_match():
    """The exact case the watcher targets — bash output contains the
    flag literal that strict-equals expected_flag. Must raise so the
    worker loop short-circuits."""
    cb = FlagWatcherCallback(expected_flag=EXPECTED, agent_id="vulntype-sqli")
    output = (
        '### "private\'--" -> 200 len 106 [{"id":3,"name":"Hidden job",'
        f'"type":"private","description":"{EXPECTED}"}}]'
    )
    with pytest.raises(FlagCapturedSignal) as exc_info:
        await _call(cb, output)
    sig = exc_info.value
    assert sig.flag == EXPECTED
    assert sig.agent_id == "vulntype-sqli"
    assert sig.tool_name == "bash"


@pytest.mark.asyncio
async def test_case_insensitive_match_still_raises():
    """Strict equality is case-insensitive (see flags_match in
    src/edges/flag_match.py). FLAG{...} and flag{...} match."""
    cb = FlagWatcherCallback(expected_flag=EXPECTED.upper())
    output = f"got it: {EXPECTED}"  # lowercase in output, upper in expected
    with pytest.raises(FlagCapturedSignal) as exc_info:
        await _call(cb, output)
    assert exc_info.value.flag == EXPECTED  # what we extracted from output


# ── 2. No match — well-formed but wrong flag → no raise ─────────────────


@pytest.mark.asyncio
async def test_does_not_raise_on_wrong_flag():
    """A well-formed flag{...} string that does NOT match expected
    must not trigger the watcher — this is the case for placeholder
    flags in swagger schemas, README examples, or the agent's own
    script literals. Strict equality is the false-positive filter."""
    cb = FlagWatcherCallback(expected_flag=EXPECTED)
    output = f"some unrelated context: {WRONG} (probably a placeholder)"
    # Should return None (not raise).
    result = await _call(cb, output)
    assert result is None


# ── 3. No flag-shaped string at all → no raise ──────────────────────────


@pytest.mark.asyncio
async def test_does_not_raise_when_output_has_no_flag():
    """Recon output, gobuster output, curl headers — most tool calls
    in a run produce no flag-shaped substring at all. The watcher
    must fast-path through them without overhead."""
    cb = FlagWatcherCallback(expected_flag=EXPECTED)
    output = "HTTP/1.1 200 OK\nServer: uvicorn\nContent-Length: 42\n\n{...}"
    result = await _call(cb, output)
    assert result is None


@pytest.mark.asyncio
async def test_does_not_raise_when_output_is_empty():
    """Empty / None / weird tool outputs must be tolerated. The
    watcher is observability-grade — it must never crash a worker."""
    cb = FlagWatcherCallback(expected_flag=EXPECTED)
    for output in ("", None, 0, []):
        result = await _call(cb, output)
        assert result is None


# ── 4. Empty expected_flag → no-op regardless of output ─────────────────


@pytest.mark.asyncio
async def test_noop_when_expected_flag_is_empty():
    """Real-pentest mode → no oracle → no auto-capture. Even if a
    perfectly-shaped flag appears in tool output, the watcher must
    not raise. Capture in that mode is planner-driven via
    ``submit_flag`` over Findings the worker explicitly emitted."""
    cb = FlagWatcherCallback(expected_flag="")
    output = f"surprise: {EXPECTED}"
    result = await _call(cb, output)
    assert result is None


@pytest.mark.asyncio
async def test_noop_when_expected_flag_is_whitespace():
    """Whitespace-only expected_flag is equivalent to empty — same
    semantics as ``flags_match`` (which strips both sides)."""
    cb = FlagWatcherCallback(expected_flag="   \n   ")
    result = await _call(cb, f"hit: {EXPECTED}")
    assert result is None


# ── 5. ToolMessage-wrapped output is handled ────────────────────────────


@pytest.mark.asyncio
async def test_handles_toolmessage_wrapped_output():
    """LangChain's agent loop sometimes passes a ToolMessage to
    on_tool_end rather than a bare string (depends on agent shape).
    The watcher must recurse into ``.content`` and still match."""
    cb = FlagWatcherCallback(expected_flag=EXPECTED)
    wrapped = ToolMessage(
        content=f"output line 1\nflag captured: {EXPECTED}\nexit=0",
        tool_call_id="x",
        name="bash",
    )
    with pytest.raises(FlagCapturedSignal):
        await _call(cb, wrapped)


@pytest.mark.asyncio
async def test_handles_content_block_list_output():
    """Some providers wrap tool output in a list of content blocks
    (``[{"type":"text","text":"..."}, ...]``). Defensive flattening
    must find the flag inside."""
    cb = FlagWatcherCallback(expected_flag=EXPECTED)
    blocks = [
        {"type": "text", "text": "preamble"},
        {"type": "text", "text": f"the flag is {EXPECTED}!"},
    ]
    with pytest.raises(FlagCapturedSignal):
        await _call(cb, blocks)


# ── 6. _coerce_to_text helper (unit) ────────────────────────────────────


def test_coerce_to_text_handles_common_shapes():
    """Direct unit test on the helper so a coverage gap in the
    callback paths doesn't hide a regression in the flattener."""
    assert _coerce_to_text("hello") == "hello"
    assert _coerce_to_text(None) == ""
    assert _coerce_to_text(["a", "b"]) == "a\nb"
    assert _coerce_to_text({"text": "x"}) == "x"
    msg = ToolMessage(content="msg-content", tool_call_id="x", name="t")
    assert _coerce_to_text(msg) == "msg-content"
