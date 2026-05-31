"""Worker-side LangChain callbacks for cooperative flag-capture cancellation.

In benchmark mode (``state.expected_flag`` set), workers run tool after
tool until the agent itself decides it's done. The 2026-05-25 XBEN-006-24
post-mortems showed two coupled problems:

  1. **Wasted Codex spend after capture.** A worker that runs the SQLi
     payload ``private'--`` and gets ``flag{...}`` back in its tool
     output will happily spend another 3–10 LLM calls "confirming" the
     finding, drafting a write-up, and emitting a structured FINDING
     block. Each call is 60–90 s of gpt-5.5 reasoning.

  2. **Fan-in deadlock for siblings.** ``executor`` is a fan-out node;
     the ``summarizer`` is its sync point. LangGraph won't fire the
     summarizer until EVERY parallel ``executor`` branch returns.
     When one worker captures the flag, the OTHER 4 are still mid-
     ``agent.astream`` doing 60–90 s LLM calls. Without intervention,
     each will run for its full iteration budget (minutes per sibling)
     before the fan-in completes.

## The two-channel design

LangGraph state (``state.captured_flag``) is the "official decision":
the routing edges (:func:`src.edges.routing.route_after_planner`,
:func:`src.edges.routing.route_after_summarizer`) read it after a node
returns and route to ``END``. But state inside a running node is a
FROZEN SNAPSHOT taken at node entry — sibling workers mid-loop cannot
see ``captured_flag`` being set by another branch.

So this module also maintains a **process-global captured flag** — a
plain module-level variable visible to ALL Python code in the process,
including LangChain callbacks running inside in-flight workers. The
two channels work in concert:

  * ``state.captured_flag``  → routing decisions (post-node)
  * module-global ``_CAPTURED_FLAG`` → in-flight worker cancellation

The callback in this module hooks three LangChain events:

  * ``on_tool_end`` — scan the tool's output. If it strict-equals
    ``expected_flag``, set the module-global AND raise
    :class:`FlagCapturedSignal` so the WINNING worker exits cleanly.

  * ``on_llm_start`` / ``on_chat_model_start`` — check the module-
    global. If another worker captured while we were mid-LLM-call,
    raise :class:`SiblingCapturedSignal` BEFORE the next call burns
    another 60–90 s of Codex time.

:func:`src.nodes.base.skill_runner._run_skill_agent_impl` catches both
signals. ``FlagCapturedSignal`` becomes a normal worker-result dict
with ``captured_flag`` set; ``SiblingCapturedSignal`` becomes a normal
empty-update dict (the sibling didn't capture, it just exited early).
No exception escapes the executor node — the graph terminates via the
normal routing edge ``route_after_summarizer → END``.

## Bench isolation

``_CAPTURED_FLAG`` is process-scope, so the daily-sweep loop in
``xbow_runner`` MUST reset it between benches via :func:`reset_captured`
— otherwise bench N+1 would start with bench N's captured flag still
set, every worker would raise ``SiblingCapturedSignal`` on its first
LLM call, and the run would terminate immediately with no work done.

Real-pentest mode (``expected_flag`` empty) → all hooks are no-ops.
No oracle exists; capture remains a planner-driven ``submit_flag``
decision over Findings the worker explicitly emitted.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler

from src.edges.flag_match import extract_flags, flags_match


# ────────────────────────────────────────────────────────────────────────────
# Module-global captured-flag signal — the "live emergency light" that
# in-flight sibling workers check via callback hooks. See module docstring.
#
# Plain module-level variable (not threading.Event or asyncio.Event)
# because LangGraph workers run as asyncio coroutines on a single thread
# — no inter-thread synchronisation is needed. A read-then-raise race
# between two workers matching the same flag simultaneously is harmless:
# both call ``signal_captured`` with the same value, both raise.
# ────────────────────────────────────────────────────────────────────────────


_CAPTURED_FLAG: str = ""


def signal_captured(flag: str) -> None:
    """Mark the run as captured. Idempotent if called with the same value.

    Called from :class:`FlagWatcherCallback.on_tool_end` the instant a
    worker's tool output matches ``expected_flag``. Subsequent calls
    from other workers (parallel match on the same flag) are no-ops.
    """
    global _CAPTURED_FLAG
    if not _CAPTURED_FLAG:
        _CAPTURED_FLAG = (flag or "").strip()


def is_captured() -> bool:
    """True if any worker in this process has already captured the flag."""
    return bool(_CAPTURED_FLAG)


def get_captured_flag() -> str:
    """The captured flag value (empty string if no capture yet)."""
    return _CAPTURED_FLAG


def reset_captured() -> None:
    """Clear the captured-flag signal. MUST be called at the start of
    every benchmark in the daily sweep — otherwise bench N+1 starts
    with bench N's flag still set and every worker exits immediately.

    Wired into :func:`benchmarks.xbow_runner.run_one` at the top of
    each bench invocation.
    """
    global _CAPTURED_FLAG
    _CAPTURED_FLAG = ""


# ────────────────────────────────────────────────────────────────────────────
# Signals — raised by callbacks, caught by skill_runner
# ────────────────────────────────────────────────────────────────────────────


class FlagCapturedSignal(Exception):
    """Raised by :class:`FlagWatcherCallback.on_tool_end` on own match.

    Carries the matched flag value so the caller can surface it via
    ``state.captured_flag`` and ``state.submission_attempts`` without
    re-scanning a (possibly truncated) snapshot. :mod:`skill_runner`
    catches this signal and converts it into a normal worker-result
    dict — the exception does NOT escape the executor node.

    Scope is the **single worker** that raised. Sibling workers learn
    about the capture via the module-global ``_CAPTURED_FLAG`` and
    raise :class:`SiblingCapturedSignal` on their next LLM-call hook.

    NOT a subclass of the Codex refusal exceptions caught in
    :func:`src.refusals.retry.astream_with_refusal_retry` — that loop's
    ``except REFUSAL_EXCS`` clause must NOT swallow this signal, or
    the worker would retry and the captured value would be lost.
    """

    def __init__(self, *, flag: str, agent_id: str = "", tool_name: str = ""):
        self.flag = flag
        self.agent_id = agent_id
        self.tool_name = tool_name
        super().__init__(
            f"flag captured by {agent_id or 'worker'} "
            f"via {tool_name or 'tool'}: {flag}"
        )


class SiblingCapturedSignal(Exception):
    """Raised by sibling workers' callbacks once any worker has captured.

    Fires from :meth:`FlagWatcherCallback.on_llm_start` or
    :meth:`FlagWatcherCallback.on_chat_model_start` when the module-
    global ``_CAPTURED_FLAG`` is set but THIS worker isn't the one
    that captured. The worker exits cleanly — skill_runner catches
    and returns a minimal update so the fan-in can complete fast and
    ``route_after_summarizer`` can route to ``END``.

    Carries the captured flag value (read from the module-global) for
    diagnostic logging only — the routing decision reads from
    ``state.captured_flag`` (written by the WINNING worker's
    ``FlagCapturedSignal`` handler), not from this exception.

    NOT a subclass of the Codex refusal exceptions for the same
    reason as :class:`FlagCapturedSignal`.
    """

    def __init__(self, *, captured_flag: str = "", agent_id: str = ""):
        self.captured_flag = captured_flag
        self.agent_id = agent_id
        super().__init__(
            f"sibling worker {agent_id or '?'} stopping early — "
            f"flag was captured by another worker: {captured_flag}"
        )


# ────────────────────────────────────────────────────────────────────────────
# The callback — owns both the own-match scan and the sibling-cancel check
# ────────────────────────────────────────────────────────────────────────────


class FlagWatcherCallback(AsyncCallbackHandler):
    """Hooks tool / LLM events to drive cooperative capture cancellation.

    Attach via the worker's ``call_config["callbacks"]`` list. The
    handler is stateless beyond its constructor arguments, so one
    instance per worker is sufficient (and the natural pattern, since
    ``agent_id`` and ``expected_flag`` are per-worker).

    Three hooks, two purposes:

      * ``on_tool_end`` — OWN-MATCH path. Scans the tool's output for
        flag-shaped substrings; on a strict-equality match against
        ``expected_flag``, marks the module-global and raises
        :class:`FlagCapturedSignal`.

      * ``on_llm_start`` / ``on_chat_model_start`` — SIBLING-CANCEL
        path. Checks the module-global. If set (and we're not the
        worker that set it), raises :class:`SiblingCapturedSignal`
        BEFORE the next Codex call queues — saves the 60–90 s of
        reasoning that call would have cost.

    ``raise_error = True`` is load-bearing — LangChain's
    :class:`langchain_core.callbacks.BaseCallbackManager` swallows
    callback exceptions by default (logging them as
    ``Error in <Handler>.<method> callback: ...`` and continuing the
    parent call). The 2026-05-25 XBEN-006-24 run at 18:11:10 showed
    this exact failure mode — FlagWatcher fired and raised, the
    operator saw the swallowed-error log, but the worker kept
    iterating until its own loop completed. With ``raise_error=True``
    set, the exception propagates through ``agent.astream`` to
    :mod:`skill_runner`, which is the entire point of the design.
    """

    # See class docstring — without this, LangChain's callback
    # dispatcher logs the exception and continues. With it, the
    # exception propagates through ``agent.astream`` and reaches
    # ``skill_runner`` where we catch it intentionally.
    raise_error: bool = True

    def __init__(
        self,
        *,
        expected_flag: str | Iterable[str],
        agent_id: str = "",
    ):
        """Accepts either a single expected flag (back-compat) or an
        iterable of expected candidates. See
        :func:`src.edges.flag_match.flags_match` for why benchmarks
        can legitimately have multiple expected values.
        """
        super().__init__()
        if isinstance(expected_flag, str):
            raw_candidates: tuple[str, ...] = (expected_flag,)
        else:
            raw_candidates = tuple(expected_flag or ())
        # Keep a normalized non-empty tuple — used by both the
        # callback hooks and (rare) external introspection.
        self.expected_flag_candidates: tuple[str, ...] = tuple(
            c.strip() for c in raw_candidates if (c or "").strip()
        )
        # Back-compat alias: the first candidate (or empty string).
        # Older callers and tests may still reach for ``expected_flag``.
        self.expected_flag: str = (
            self.expected_flag_candidates[0]
            if self.expected_flag_candidates
            else ""
        )
        self.agent_id = agent_id

    # ── Own-match path ───────────────────────────────────────────────

    async def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        # Real-pentest mode → no oracle, nothing to match against.
        if not self.expected_flag_candidates:
            return
        # Defence in depth: if a sibling captured the EXACT same flag
        # while we were running this tool, surface that as a sibling
        # signal so we don't double-write state.
        if is_captured():
            raise SiblingCapturedSignal(
                captured_flag=get_captured_flag(),
                agent_id=self.agent_id,
            )
        text = _coerce_to_text(output)
        # Cheap pre-filter — extract_flags compiles a regex and walks
        # the string; skipping when no ``{`` is present avoids the
        # cost on the dominant case (tool outputs with no flag at
        # all — recon, gobuster output, curl headers, …).
        if not text or "{" not in text:
            return
        tool_name = kwargs.get("name") or ""
        for candidate in extract_flags(text):
            if flags_match(
                submitted=candidate,
                expected=self.expected_flag_candidates,
            ):
                # Mark process-globally BEFORE raising, so sibling
                # workers can see it at their next callback hook.
                signal_captured(candidate)
                raise FlagCapturedSignal(
                    flag=candidate,
                    agent_id=self.agent_id,
                    tool_name=tool_name,
                )

    # ── Sibling-cancel path ──────────────────────────────────────────

    async def on_llm_start(
        self,
        serialized: Any = None,
        prompts: Any = None,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Fires before a (non-chat) LLM call. Most agents use
        ``on_chat_model_start`` instead, but we hook both for
        defensive completeness — a future provider switch shouldn't
        silently break the sibling-cancel path."""
        if not self.expected_flag_candidates:
            return
        if is_captured():
            raise SiblingCapturedSignal(
                captured_flag=get_captured_flag(),
                agent_id=self.agent_id,
            )

    async def on_chat_model_start(
        self,
        serialized: Any = None,
        messages: Any = None,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Fires before each chat-model call (Codex, OpenAI, Anthropic,
        all chat models). This is the **load-bearing** sibling-cancel
        hook in practice — gpt-5.5 calls are 60–90 s each, and this
        is the earliest moment a sibling can abort before that cost
        is paid."""
        if not self.expected_flag_candidates:
            return
        if is_captured():
            raise SiblingCapturedSignal(
                captured_flag=get_captured_flag(),
                agent_id=self.agent_id,
            )


def _coerce_to_text(output: Any) -> str:
    """Flatten an arbitrary tool-output value into a searchable string.

    The ``bash`` tool returns ``str`` directly under the ``@tool``
    decorator, which is the only shape we hit today. But LangChain
    can wrap outputs in :class:`langchain_core.messages.ToolMessage`
    or a list of content blocks under non-default agent shapes, so
    we flatten defensively. Failure modes (unrepresentable objects)
    return ``""`` rather than raising — observability must never
    break a worker loop.
    """
    if output is None:
        return ""
    if isinstance(output, str):
        return output
    # ToolMessage / AIMessage / any message-like object.
    content = getattr(output, "content", None)
    if content is not None and content is not output:
        return _coerce_to_text(content)
    if isinstance(output, list):
        return "\n".join(_coerce_to_text(x) for x in output)
    if isinstance(output, dict):
        # Common content-block shape: {"type": "text", "text": "..."}.
        if "text" in output:
            return _coerce_to_text(output.get("text"))
        return "\n".join(_coerce_to_text(v) for v in output.values())
    try:
        return str(output)
    except Exception:  # noqa: BLE001
        return ""
