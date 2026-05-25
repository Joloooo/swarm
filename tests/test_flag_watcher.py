"""Tier 1 — FlagWatcherCallback cooperative-cancel behaviour.

Pins the contract introduced 2026-05-25 after the XBEN-006-24 retros:
when ANY worker matches the expected flag in tool output, the WINNING
worker exits immediately AND every other in-flight sibling exits
cleanly at its next LLM-call boundary. The graph terminates via the
normal routing edge ``route_after_summarizer → END`` — no exception
escapes the graph.

Two channels make this work:

  * State.captured_flag (LangGraph state) → routing decisions
  * Module-global ``_CAPTURED_FLAG`` → in-flight sibling cancellation
    (callbacks can't reach LangGraph state, so a process-scope
    variable is the only way for callbacks to see "the other guy
    captured" while we're mid-LLM-call)

These tests pin both channels:

  Own-match path:
    1. Match → raises FlagCapturedSignal AND sets module-global.
    2. No match (well-formed but wrong flag) → does NOT raise.
    3. No flag-shaped string in output → does NOT raise.
    4. Empty ``expected_flag`` (real-pentest mode) → no-op.
    5. ToolMessage-wrapped output is handled, not skipped.

  Sibling-cancel path:
    6. Module-global flips True when own-match fires.
    7. ``on_chat_model_start`` raises SiblingCapturedSignal when
       global is set.
    8. ``on_llm_start`` raises SiblingCapturedSignal when global is set.
    9. ``reset_captured`` clears the global (bench-isolation).
   10. Sibling hooks no-op when ``expected_flag`` is empty.

Strategy: invoke the callback's hooks directly with the arguments
LangChain would pass at runtime. No real LangChain agent, no real
LLM — pure Tier 1. The fixture ``reset_module_global`` ensures one
test's capture doesn't leak into another.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from langchain_core.messages import ToolMessage

from src.nodes.base.flag_watcher import (
    FlagCapturedSignal,
    FlagWatcherCallback,
    SiblingCapturedSignal,
    _coerce_to_text,
    is_captured,
    get_captured_flag,
    reset_captured,
    signal_captured,
)


@pytest.fixture(autouse=True)
def reset_module_global():
    """Reset the captured-flag module-global before AND after each test.

    Without this, a test that signals capture would leak into every
    subsequent test in the same process — siblings would raise
    SiblingCapturedSignal on first hook and the test assumptions
    would shift. autouse=True so every test in this file gets the
    isolation automatically.
    """
    reset_captured()
    yield
    reset_captured()


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


# ── 8. Module-global captured flag — bench isolation + read/set ──────


def test_module_global_starts_clean():
    """The autouse fixture resets the global before each test, so
    the global must start empty regardless of prior test state."""
    assert is_captured() is False
    assert get_captured_flag() == ""


def test_signal_captured_flips_the_global():
    """Once any worker calls signal_captured, every subsequent
    is_captured() call (including from a different worker's callback)
    returns True. This is the load-bearing primitive — sibling
    workers' on_chat_model_start hooks read it to decide whether to
    abort their next LLM call."""
    signal_captured(EXPECTED)
    assert is_captured() is True
    assert get_captured_flag() == EXPECTED


def test_signal_captured_is_first_writer_wins():
    """If two parallel workers happen to match the same flag at
    almost the same moment (rare but possible), only the first call
    sticks. The exact value matters less than the consistency — both
    workers raise FlagCapturedSignal with the same flag string from
    their own scan, so either's value is correct."""
    signal_captured(EXPECTED)
    signal_captured("flag{some-other-value}")  # ignored
    assert get_captured_flag() == EXPECTED


def test_reset_clears_the_global():
    """xbow_runner.run_one calls reset_captured() at the start of each
    bench so the daily-sweep loop doesn't leak bench N's flag into
    bench N+1. Without this reset, every worker on bench N+1 would
    raise SiblingCapturedSignal on its first LLM call and the run
    would terminate with no work done."""
    signal_captured(EXPECTED)
    assert is_captured() is True
    reset_captured()
    assert is_captured() is False
    assert get_captured_flag() == ""


# ── 9. Own-match path sets the module-global ────────────────────────


@pytest.mark.asyncio
async def test_own_match_sets_module_global():
    """When FlagWatcher fires for the WINNING worker, the global must
    be set BEFORE the exception is raised — otherwise sibling
    workers checking on_chat_model_start race against the
    skill_runner catching the signal and miss the window."""
    cb = FlagWatcherCallback(expected_flag=EXPECTED, agent_id="winner")
    output = f"got it: {EXPECTED}"
    with pytest.raises(FlagCapturedSignal):
        await _call(cb, output)
    # Side effect: global is now set.
    assert is_captured() is True
    assert get_captured_flag() == EXPECTED


# ── 10. Sibling-cancel path — on_chat_model_start ───────────────────


@pytest.mark.asyncio
async def test_on_chat_model_start_raises_when_sibling_captured():
    """The load-bearing sibling-cancel hook. A worker is mid-loop
    when another worker captures; on the next on_chat_model_start
    (fires before each LLM call), this hook checks the global and
    raises so we don't burn another 60-90 s Codex call."""
    signal_captured(EXPECTED)
    cb = FlagWatcherCallback(expected_flag=EXPECTED, agent_id="sibling")
    with pytest.raises(SiblingCapturedSignal) as exc_info:
        await cb.on_chat_model_start(
            serialized={"name": "ChatCodex"},
            messages=[[]],
            run_id=uuid4(),
        )
    assert exc_info.value.captured_flag == EXPECTED
    assert exc_info.value.agent_id == "sibling"


@pytest.mark.asyncio
async def test_on_chat_model_start_noop_when_no_capture():
    """Before any worker captures, on_chat_model_start must be a
    no-op — otherwise every LLM call would raise on every worker
    and no work would ever happen. The global starts empty (autouse
    fixture); this verifies the guard."""
    cb = FlagWatcherCallback(expected_flag=EXPECTED, agent_id="any")
    # Should return None (not raise).
    result = await cb.on_chat_model_start(
        serialized={"name": "ChatCodex"},
        messages=[[]],
        run_id=uuid4(),
    )
    assert result is None


@pytest.mark.asyncio
async def test_on_chat_model_start_noop_in_real_pentest_mode():
    """No oracle (expected_flag empty) → callback never fires the
    sibling check. Capture in real-pentest mode is planner-driven
    via submit_flag, so process-global wouldn't be set anyway, but
    we belt-and-brace the guard at the callback level too."""
    signal_captured(EXPECTED)  # simulate stale state from prior run
    cb = FlagWatcherCallback(expected_flag="", agent_id="any")
    result = await cb.on_chat_model_start(
        serialized={"name": "ChatCodex"},
        messages=[[]],
        run_id=uuid4(),
    )
    assert result is None


# ── 11. Sibling-cancel path — on_llm_start (non-chat models) ────────


@pytest.mark.asyncio
async def test_on_llm_start_raises_when_sibling_captured():
    """Some agents use on_llm_start instead of on_chat_model_start
    (depends on the model wrapper). We hook both for completeness —
    a future provider switch shouldn't silently break the
    sibling-cancel path."""
    signal_captured(EXPECTED)
    cb = FlagWatcherCallback(expected_flag=EXPECTED, agent_id="sibling")
    with pytest.raises(SiblingCapturedSignal):
        await cb.on_llm_start(
            serialized={"name": "BaseLLM"},
            prompts=["..."],
            run_id=uuid4(),
        )


# ── 12. on_tool_end also notices sibling capture ────────────────────


@pytest.mark.asyncio
async def test_on_tool_end_raises_sibling_when_global_already_set():
    """Defense in depth: if the global was set by another worker
    during our tool execution (between the LLM call and the tool
    return), we surface that as SiblingCapturedSignal rather than
    going through our own match scan. Prevents racing two workers
    trying to write captured_flag to state at the same moment."""
    signal_captured(EXPECTED)
    cb = FlagWatcherCallback(expected_flag=EXPECTED, agent_id="sibling")
    # Tool output that DOESN'T contain the flag — sibling check
    # fires first regardless.
    with pytest.raises(SiblingCapturedSignal):
        await _call(cb, "some output without a flag")


# ── 13. SiblingCapturedSignal carries diagnostic info ───────────────


def test_sibling_captured_str_includes_agent_and_flag():
    """The exception's str() ends up in logger.info output and may
    appear in error tracebacks. It must identify both the cancelled
    worker and the captured flag so a post-mortem operator can
    correlate the abort with the matching capture."""
    exc = SiblingCapturedSignal(captured_flag=EXPECTED, agent_id="sibling")
    s = str(exc)
    assert EXPECTED in s
    assert "sibling" in s
