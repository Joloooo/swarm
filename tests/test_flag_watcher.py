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
from operator import add
from typing import Annotated, TypedDict
from uuid import uuid4

import pytest
from langchain_core.messages import ToolMessage

from src.nodes.base.flag_watcher import (
    FlagCapturedSignal,
    FlagWatcherCallback,
    GraphTerminatedByCapture,
    _coerce_to_text,
)


# Module-scope so LangGraph's type-hint resolver (which evaluates
# annotations via globals()) can find Annotated. Defining the
# TypedDict inside a test function breaks under
# ``typing.get_type_hints`` because the function's locals aren't
# visible to LangGraph's runtime introspection.
class _CancellationState(TypedDict):
    siblings_cancelled: Annotated[list[str], add]


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


# ── 7. raise_error semantics — load-bearing for LangChain dispatch ────


def test_raise_error_class_attribute_is_true():
    """The 2026-05-25 XBEN-006-24 run at 18:11:10 captured the flag
    via the FlagWatcher but the worker did NOT short-circuit — the
    operator saw ``⚠ Error in FlagWatcherCallback.on_tool_end
    callback: FlagCapturedSignal(...)`` and the worker kept running.

    LangChain's :class:`BaseCallbackManager` swallows callback
    exceptions by default (``raise_error=False`` on the class).
    Setting ``raise_error = True`` on the handler subclass is what
    makes the exception propagate up through ``agent.astream``. This
    test exists so a future refactor that drops the override can't
    silently re-introduce the early-exit bug."""
    from langchain_core.callbacks import AsyncCallbackHandler
    # Sanity: the LangChain default is False (the bug substrate).
    assert AsyncCallbackHandler.raise_error is False
    # Our subclass overrides it.
    assert FlagWatcherCallback.raise_error is True
    # The override survives instantiation.
    cb = FlagWatcherCallback(expected_flag="flag{x}")
    assert cb.raise_error is True


@pytest.mark.asyncio
async def test_exception_propagates_through_callback_manager():
    """End-to-end regression for the LangChain-swallows-callback bug.

    Dispatches ``on_tool_end`` through an actual
    :class:`AsyncCallbackManager` (the same path
    ``agent.astream`` uses) and asserts the signal escapes.

    With ``raise_error=False`` (the LangChain default), this would
    log the exception and return normally — the original 2026-05-25
    failure mode. With ``raise_error=True`` on our subclass, the
    manager re-raises and the worker loop aborts."""
    from langchain_core.callbacks import AsyncCallbackManager

    cb = FlagWatcherCallback(expected_flag=EXPECTED, agent_id="t")
    mgr = AsyncCallbackManager(handlers=[cb])
    # AsyncCallbackManager.on_tool_start returns a per-call run manager
    # whose on_tool_end is what the agent loop invokes after a tool
    # returns. We mimic that pathway here.
    run_mgr = await mgr.on_tool_start(
        serialized={"name": "bash"},
        input_str="curl ...",
    )
    with pytest.raises(FlagCapturedSignal):
        await run_mgr.on_tool_end(
            output=f"bash output containing {EXPECTED}",
        )


# ── 8. GraphTerminatedByCapture — escapes the graph + cancels siblings ──


def test_graph_terminated_carries_flag_agent_and_findings():
    """The exception is the sole channel that survives the
    ``ainvoke`` cancellation chain — graph state is discarded when an
    unhandled exception propagates, so every field xbow_runner needs
    for the verdict path must be present on the exception itself."""
    findings = [object(), object()]  # placeholders; runner just len()s
    exc = GraphTerminatedByCapture(
        flag=EXPECTED, agent_id="owasp-auth", findings=findings,
    )
    assert exc.flag == EXPECTED
    assert exc.agent_id == "owasp-auth"
    assert exc.findings == findings
    # Default findings → empty list (not None) so callers can len() safely.
    bare = GraphTerminatedByCapture(flag=EXPECTED)
    assert bare.findings == []


def test_graph_terminated_str_includes_diagnostic_info():
    """The ``str()`` form ends up in tracebacks, error logs, and the
    ``result["error"]`` field on benches that fall through to the
    generic ``except Exception`` handler. Must identify the flag and
    the agent so post-mortem is one ``grep`` away."""
    exc = GraphTerminatedByCapture(flag=EXPECTED, agent_id="owasp-auth")
    s = str(exc)
    assert EXPECTED in s
    assert "owasp-auth" in s


@pytest.mark.asyncio
async def test_raising_from_one_branch_cancels_sibling_tasks():
    """End-to-end pin for the cancellation mechanism we rely on.

    This is the load-bearing behaviour discovered empirically against
    LangGraph 1.1.6: ``Command(goto=END)`` from a fan-out branch does
    NOT cancel siblings (they run to completion, the summarizer still
    fires), but RAISING an exception from one branch DOES — asyncio's
    ``CancelledError`` propagates to in-flight sibling coroutines at
    their next ``await`` point.

    If a future LangGraph upgrade breaks this contract, this test will
    fail loudly — and the fix is no longer to raise, it is to add a
    process-global captured flag + ``on_llm_start`` callback check.
    The presence of this test is the trigger for that pivot."""
    import time

    from langgraph.graph import StateGraph, END, START
    from langgraph.types import Send

    async def planner_node(state):
        return {"siblings_cancelled": []}

    def fan_out(state):
        # One winner that raises fast, two slow siblings that should
        # be cancelled before completing their sleep.
        return [
            Send("worker", {"wid": "winner", "delay": 0.05, "raises": True}),
            Send("worker", {"wid": "sib1", "delay": 3.0, "raises": False}),
            Send("worker", {"wid": "sib2", "delay": 3.0, "raises": False}),
        ]

    async def worker(state):
        try:
            await asyncio.sleep(state["delay"])
        except asyncio.CancelledError:
            # Record that we were cancelled. This is the load-bearing
            # assertion — if siblings ran to completion, this branch
            # never fires and the list stays empty.
            return {"siblings_cancelled": [state["wid"]]}
        if state["raises"]:
            raise GraphTerminatedByCapture(flag=EXPECTED, agent_id="winner")
        return {"siblings_cancelled": []}

    g = StateGraph(_CancellationState)
    g.add_node("planner", planner_node)
    g.add_node("worker", worker)
    g.add_edge(START, "planner")
    g.add_conditional_edges("planner", fan_out, ["worker"])
    g.add_edge("worker", END)
    compiled = g.compile()

    t0 = time.time()
    with pytest.raises(GraphTerminatedByCapture) as exc_info:
        await compiled.ainvoke({"siblings_cancelled": []})
    elapsed = time.time() - t0

    # The full graph took less than the slow siblings' 3 s sleep,
    # which proves they didn't run to completion.
    assert elapsed < 1.0, (
        f"siblings were not cancelled — graph took {elapsed:.2f}s "
        "(expected < 1.0s if cancellation worked)"
    )
    assert exc_info.value.flag == EXPECTED
    assert exc_info.value.agent_id == "winner"
