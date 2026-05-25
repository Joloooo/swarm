"""Worker-side LangChain callback that aborts the agent loop on flag capture.

In benchmark mode (``state.expected_flag`` set), workers run tool after
tool until the agent itself decides it's done. The 2026-05-25 XBEN-006-24
post-mortem showed two problems with that:

  1. **Wasted Codex spend after capture.** A worker that runs the SQLi
     payload ``private'--`` and gets ``flag{...}`` back in its tool
     output will happily spend another 3–10 LLM calls "confirming" the
     finding, drafting a write-up, and emitting a structured FINDING
     block. Each call is 60–90 s of gpt-5.5 reasoning. The flag is
     already in our hands; the extra calls add nothing.

  2. **Fan-in deadlock.** The graph wiring is
     ``executor (fan-out N) → summarizer → planner``. The summarizer
     is the fan-in sync point. LangGraph won't fire it until EVERY
     parallel ``executor`` branch returns. On 2026-05-25, one worker
     captured the flag in 13 minutes; two others were still grinding
     through Codex calls. The global 900 s timeout snapped before
     either of them finished, so the summarizer never fired, so
     ``route_after_summarizer`` never read ``state.captured_flag``,
     so the graph aborted with a "no capture" verdict despite the
     flag being on disk.

This callback hooks ``on_tool_end`` — fires the instant a tool returns,
before the next LLM call is queued. On a strict-equality match against
``expected_flag``, raises :class:`FlagCapturedSignal`. The signal
propagates up through ``agent.astream`` and is caught in
:func:`src.nodes.base.skill_runner._run_skill_agent_impl`, which
treats it as a successful capture and short-circuits the worker.

This addresses problem (1) directly — the worker stops within
milliseconds of the tool returning. Problem (2) is downstream: the
summarizer fan-in still waits, but it waits for workers that are now
finishing in seconds rather than minutes, because they all stop the
moment any one of them sees the flag.

Real-pentest mode (``expected_flag`` empty) → callback is a no-op.
No oracle exists; capture remains a planner-driven ``submit_flag``
decision over Findings.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler

from src.edges.flag_match import extract_flags, flags_match


class FlagCapturedSignal(Exception):
    """Raised by :class:`FlagWatcherCallback` to short-circuit a worker.

    Carries the matched flag value so the caller can surface it via
    ``state.captured_flag`` and ``state.submission_attempts`` without
    re-scanning a (possibly truncated) snapshot. The skill runner's
    catch block treats this as a successful capture, not an error.

    Scope is the **single worker** that raised. Other parallel workers
    keep running until :class:`GraphTerminatedByCapture` (raised later
    in the same worker) propagates up through ``ainvoke`` and asyncio
    cancels their tasks. See module docstring for the layered design.

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


class GraphTerminatedByCapture(Exception):
    """Raised by ``skill_runner`` after capture to cancel the whole graph.

    Unlike :class:`FlagCapturedSignal` (caught by skill_runner and
    converted into a normal worker-result dict), this exception is
    INTENDED to escape the graph entirely:

      1. Raised at the end of ``_finalize_skill_result`` once
         ``captured_flag_value`` is known.
      2. Propagates out of ``agent.astream`` → executor node return
         → LangGraph runtime.
      3. LangGraph's asyncio-based ``ainvoke`` cancels the in-flight
         sibling parallel branches via ``asyncio.CancelledError`` at
         their next ``await`` point (the standard asyncio cancellation
         semantics, verified empirically against LangGraph 1.1.6 —
         see ``scripts/verify_*_cancellation.py``).
      4. The exception re-raises out of ``ainvoke`` to ``xbow_runner``,
         which catches it and synthesizes the minimum state needed
         for the verdict path (``captured_flag``,
         ``submission_attempts``, ``findings``).

    Why this design instead of ``Command(goto=END)``: verified that
    LangGraph 1.1.6's ``Command(goto=END)`` from a fan-out branch does
    NOT cancel sibling branches — they run to completion, the
    summarizer still fires, and total wall-clock is unaffected. The
    sibling-cancellation we need comes from asyncio task cancellation
    triggered by an unhandled exception during ``ainvoke``. Raising
    is the cleanest way to trigger that path.

    Carries enough state for the runner to reconstruct the verdict
    without re-scanning anything — the graph state at the moment of
    raise is discarded because the exception bypasses the normal
    reducer path.
    """

    def __init__(
        self,
        *,
        flag: str,
        agent_id: str = "",
        findings: list | None = None,
    ):
        self.flag = flag
        self.agent_id = agent_id
        self.findings = findings or []
        super().__init__(
            f"graph terminated by {agent_id or 'worker'}: "
            f"flag captured = {flag}"
        )


class FlagWatcherCallback(AsyncCallbackHandler):
    """Watch tool outputs for ``flag{...}`` matches against ``expected_flag``.

    Attach via the worker's ``call_config["callbacks"]`` list. The
    handler is stateless beyond its constructor arguments, so one
    instance per worker is sufficient (and the natural pattern, since
    ``agent_id`` and ``expected_flag`` are per-worker).

    On match, raises :class:`FlagCapturedSignal`. LangChain will
    propagate the exception out of the active ``agent.astream``,
    short-circuiting the agent loop. The caller catches the signal
    and converts it into a normal worker-result dict.

    Why ``on_tool_end`` and not ``on_tool_start``: the flag literal
    appears in the tool's OUTPUT, not its input. ``on_chain_end`` /
    ``on_llm_end`` would also work but fire later (after the next
    LLM round-trip) — defeating the point of an early-abort hook.

    ``raise_error = True`` is load-bearing — LangChain's
    :class:`langchain_core.callbacks.BaseCallbackManager` swallows
    callback exceptions by default (logging them as
    ``Error in <Handler>.<method> callback: ...`` and continuing the
    parent call). The 2026-05-25 XBEN-006-24 run at 18:11:10 showed
    this exact failure mode — FlagWatcher fired and raised, the
    operator saw the swallowed-error log, but the worker kept
    iterating until its own loop completed and only the end-of-worker
    fallback scan caught the flag. With ``raise_error = True`` set,
    the exception propagates through ``agent.astream`` to the caller
    in :mod:`src.nodes.base.skill_runner`, which is the entire point
    of the early-abort design.
    """

    # See class docstring — without this the exception is swallowed
    # by LangChain's callback dispatcher and the worker never aborts.
    raise_error: bool = True

    def __init__(self, *, expected_flag: str, agent_id: str = ""):
        super().__init__()
        self.expected_flag = (expected_flag or "").strip()
        self.agent_id = agent_id

    async def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        # Real-pentest mode → no oracle, nothing to match against.
        if not self.expected_flag:
            return
        text = _coerce_to_text(output)
        # Cheap pre-filter — extract_flags compiles a regex and walks
        # the string; skipping when no ``{`` is present avoids the
        # cost on the dominant case (tool outputs with no flag at
        # all — recon, gobuster output, curl headers, …).
        if not text or "{" not in text:
            return
        tool_name = kwargs.get("name") or ""
        for candidate in extract_flags(text):
            if flags_match(submitted=candidate, expected=self.expected_flag):
                raise FlagCapturedSignal(
                    flag=candidate,
                    agent_id=self.agent_id,
                    tool_name=tool_name,
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
