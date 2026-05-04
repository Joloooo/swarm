"""LLM call observability — every chat-model invocation captured.

Goal: at the end of a benchmark you should be able to answer four
questions from disk alone, with zero gaps:

    1. **How many LLM calls did each agent make?**
       Useful for debugging "agent did 0 things" — was it 0 calls
       (provider refusal at API edge) or 25 calls that all returned
       refusals?

    2. **How many input tokens went over the wire on each call?**
       Long-running benchmarks accumulate scratchpad. Codex-class
       models advertise 256k windows but quality degrades visibly
       past ~128k ("context rot"). Per-call input-token series lets
       us see the curve, not just the final spike.

    3. **How many output / reasoning tokens did the model burn?**
       gpt-5.x bills reasoning tokens separately from output text.
       The Codex stream parser extracts both (see ``codex.py`` lines
       748-759); this callback shuttles the numbers to disk so the
       per-run cost is visible without re-parsing the SSE stream.

    4. **Did any call error? With what code?**
       Cyber-policy / context-window / quota errors look identical
       in summary.md ("0 findings") but have very different fixes.
       Logging them at the LangChain callback layer captures the
       failure even when an outer try/except swallows the exception.

The callback is wired into every ``agent.ainvoke()`` / ``llm.ainvoke()``
call site in the codebase via the ``config`` parameter. Each call
gets one line in ``logs/run-<id>/llm_calls.jsonl``. Nothing is
truncated — disk is cheap; thesis analysis needs the full record.

A running per-agent total is also published via :data:`TOKEN_TOTALS`
so the live renderer (``src/live.py``) can show "▸ vulntype-sqli
finished — 12 LLM calls, 187k in / 9.4k out / 22k reasoning" when a
worker exits. That makes the context-rot risk visible without having
to grep the log file mid-run.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.outputs import LLMResult

from src.observability import run_dir

logger = logging.getLogger(__name__)


# ── Per-agent running totals ────────────────────────────────────────────
#
# Used by the live renderer to surface "context-rot risk" as a worker
# finishes. Keyed by ``agent_id``; the planner is "_planner" by
# convention, salvage / focused-recovery use "_focused".


@dataclass
class _AgentTokenTotals:
    """Running totals for one logical agent across a single run.

    Fields:
        calls            — number of completed LLM calls
        input_tokens     — sum of input tokens (prompt) across all calls
        output_tokens    — sum of visible output tokens
        reasoning_tokens — sum of separately-billed reasoning tokens
                           (Codex / o-series only; 0 for other providers)
        peak_input       — largest single input_tokens observed; this is
                           the canonical "context rot risk" number
                           because it tracks the worst case, not the
                           average
        errors           — count of LLM calls that ended with an
                           ``on_llm_error`` (exception bubbled out of
                           the model layer)
    """

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    peak_input: int = 0
    errors: int = 0


_TOTALS_LOCK = threading.Lock()
TOKEN_TOTALS: dict[str, _AgentTokenTotals] = {}


def get_running_total(agent_id: str) -> _AgentTokenTotals:
    """Return (a copy of) the running totals for ``agent_id``.

    Reading is lock-free — readers tolerate a slightly-stale snapshot
    rather than blocking the writer in the middle of a hot agent loop.
    """
    t = TOKEN_TOTALS.get(agent_id)
    if t is None:
        return _AgentTokenTotals()
    return _AgentTokenTotals(
        calls=t.calls,
        input_tokens=t.input_tokens,
        output_tokens=t.output_tokens,
        reasoning_tokens=t.reasoning_tokens,
        peak_input=t.peak_input,
        errors=t.errors,
    )


def reset_totals() -> None:
    """Wipe the running totals — call between bench iterations.

    The counts otherwise carry over across benches in the same Python
    process (the ``xbow_runner`` does sweep multiple benches in one
    invocation), which would make per-bench context-rot reports
    misleading.
    """
    with _TOTALS_LOCK:
        TOKEN_TOTALS.clear()


# ── Disk path resolution ────────────────────────────────────────────────


def _llm_log_path(run_id: str) -> "pathlib.Path":  # noqa: F821 — string annot
    """Where ``llm_calls.jsonl`` for ``run_id`` lives.

    Co-located with ``nodes.jsonl`` and ``terminal_events.jsonl`` so the
    three files form a self-contained per-run log bundle that's easy to
    archive or analyze together.
    """
    return run_dir(run_id) / "llm_calls.jsonl"


_LOG_LOCK = threading.Lock()


def _append_llm_event(run_id: str | None, event: dict) -> None:
    """Append one JSON line to ``logs/run-<id>/llm_calls.jsonl``.

    Failures are swallowed — observability must never break a graph
    run. The lock keeps parallel worker calls from interleaving
    half-lines (the executor fans out 4-way for ``custom-attack``).
    """
    if not run_id:
        return
    try:
        path = _llm_log_path(run_id)
        line = json.dumps(event, default=str, ensure_ascii=False) + "\n"
        with _LOG_LOCK, path.open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:  # noqa: BLE001 — observability must not break runs
        pass


# ── Callback handler ────────────────────────────────────────────────────


class TokenLoggingCallback(AsyncCallbackHandler):
    """LangChain async callback that captures every chat-model invocation.

    Hooks
        ``on_chat_model_start``  — record start time, peek at messages
        ``on_llm_end``           — extract usage_metadata, write log
        ``on_llm_error``         — write error log line; still counts
                                   toward the running total so a 0-token
                                   error doesn't masquerade as success

    Per-call event shape (one JSONL line)::

        {
            "ts":               "2026-05-04T08:14:32.117",
            "phase":             "end" | "error",
            "run_id":            "XBEN-006-24__...",
            "agent_id":          "vulntype-sqli" | "_planner" | "_focused",
            "node":              "executor" | "planner" | ...,
            "model":             "gpt-5.4-mini",
            "duration_ms":       1842,
            "input_tokens":      11583,
            "output_tokens":     421,
            "reasoning_tokens":  3104,
            "total_tokens":      15108,
            "running_input":     59210,    // running sum for this agent
            "running_calls":     7,
            "error_type":        "CodexCyberPolicyError",  // only on error
            "error_msg":         "request blocked by …"
        }

    The ``run_id`` and ``agent_id`` fields are read from the
    ``RunnableConfig`` metadata that the call-site passes when invoking
    the agent — that's how the callback can attribute a buried inner
    chat-model call back to the worker agent that triggered it.

    A single instance is safe to share across the whole run; it's
    stateless beyond the global :data:`TOKEN_TOTALS` table.
    """

    # Tracks per-run_id timestamps so on_llm_end can compute duration.
    # Keyed by the LangChain ``run_id`` UUID (not our run_id), which is
    # a unique identifier for *this* model call.
    _starts: dict[UUID, float]

    def __init__(self) -> None:
        super().__init__()
        self._starts = {}

    # Pretend we want to handle every event. LangChain checks this flag
    # in some hot-paths to skip the callback machinery entirely.
    raise_error: bool = False
    run_inline: bool = False

    # ── start hooks ──────────────────────────────────────────────────────

    async def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Record the start time so we can report duration on end."""
        self._starts[run_id] = time.perf_counter()

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Some providers route through ``on_llm_start`` (string prompts)
        instead of ``on_chat_model_start``. Cover both."""
        self._starts[run_id] = time.perf_counter()

    # ── end / error hooks ────────────────────────────────────────────────

    async def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        t0 = self._starts.pop(run_id, None)
        dt_ms = int((time.perf_counter() - t0) * 1000) if t0 else 0

        # Walk the generations to find usage_metadata. ChatCodex puts it
        # on the AIMessage (see codex.py:1127); other providers attach
        # it via LLMResult.llm_output["token_usage"] — try both.
        usage = self._extract_usage(response)
        model = self._extract_model(response, metadata)

        meta = metadata or {}
        agent_id = str(meta.get("agent_id") or meta.get("ls_agent") or "_unknown")
        node = str(meta.get("node") or "")
        run_id_str = meta.get("run_id")

        running = self._update_totals(
            agent_id=agent_id,
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            reasoning_tokens=usage["reasoning_tokens"],
        )

        event = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
                  + f".{int((time.time() % 1) * 1000):03d}",
            "phase": "end",
            "run_id": run_id_str,
            "agent_id": agent_id,
            "node": node,
            "model": model,
            "duration_ms": dt_ms,
            **usage,
            "running_input": running.input_tokens,
            "running_calls": running.calls,
            "running_peak_input": running.peak_input,
        }
        _append_llm_event(run_id_str, event)

        # Surface a one-line LIVE entry for verbose-mode users only —
        # compact mode would drown in these (one per LLM call).
        try:
            from src.live import LIVE  # lazy — avoid import cycle
            LIVE.llm_call(
                agent=agent_id,
                model=model,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                reasoning_tokens=usage["reasoning_tokens"],
                duration_ms=dt_ms,
                running_input=running.input_tokens,
                peak_input=running.peak_input,
            )
        except Exception:  # noqa: BLE001 — never let live rendering break logging
            pass

    async def on_llm_error(
        self,
        error: BaseException | Exception,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        t0 = self._starts.pop(run_id, None)
        dt_ms = int((time.perf_counter() - t0) * 1000) if t0 else 0

        meta = metadata or {}
        agent_id = str(meta.get("agent_id") or meta.get("ls_agent") or "_unknown")
        node = str(meta.get("node") or "")
        run_id_str = meta.get("run_id")

        with _TOTALS_LOCK:
            t = TOKEN_TOTALS.setdefault(agent_id, _AgentTokenTotals())
            t.errors += 1
            running_errors = t.errors

        event = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
                  + f".{int((time.time() % 1) * 1000):03d}",
            "phase": "error",
            "run_id": run_id_str,
            "agent_id": agent_id,
            "node": node,
            "model": meta.get("model") or "?",
            "duration_ms": dt_ms,
            "error_type": type(error).__name__,
            "error_msg": str(error)[:500],
            "running_errors": running_errors,
        }
        _append_llm_event(run_id_str, event)

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _extract_usage(response: LLMResult) -> dict[str, int]:
        """Walk the LLMResult to pull out token counts.

        Prefers per-message ``usage_metadata`` (set by ChatCodex and
        most modern langchain-* packages) and falls back to the
        provider-specific ``llm_output["token_usage"]`` shape used by
        older OpenAI/Anthropic integrations. Returns zeros when neither
        is present so the log row stays well-shaped.
        """
        input_tokens = 0
        output_tokens = 0
        reasoning_tokens = 0
        total_tokens = 0

        # Prefer message-level usage_metadata.
        for gen_list in response.generations:
            for gen in gen_list:
                msg = getattr(gen, "message", None)
                um = getattr(msg, "usage_metadata", None) if msg else None
                if isinstance(um, dict):
                    input_tokens     += int(um.get("input_tokens",     0) or 0)
                    output_tokens    += int(um.get("output_tokens",    0) or 0)
                    reasoning_tokens += int(um.get("reasoning_tokens", 0) or 0)
                    total_tokens     += int(um.get("total_tokens",     0) or 0)

        # Fallback to llm_output (older integrations).
        if not total_tokens and response.llm_output:
            tu = (response.llm_output or {}).get("token_usage") or {}
            input_tokens     = int(tu.get("prompt_tokens",     input_tokens)     or input_tokens)
            output_tokens    = int(tu.get("completion_tokens", output_tokens)    or output_tokens)
            total_tokens     = int(tu.get("total_tokens",      total_tokens)     or total_tokens)

        # Backfill total if missing.
        if not total_tokens:
            total_tokens = input_tokens + output_tokens + reasoning_tokens

        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "reasoning_tokens": reasoning_tokens,
            "total_tokens": total_tokens,
        }

    @staticmethod
    def _extract_model(response: LLMResult, metadata: dict | None) -> str:
        """Best-effort model name from the response metadata."""
        for gen_list in response.generations:
            for gen in gen_list:
                msg = getattr(gen, "message", None)
                rm = getattr(msg, "response_metadata", None) if msg else None
                if isinstance(rm, dict) and rm.get("model"):
                    return str(rm["model"])
        if response.llm_output and "model_name" in response.llm_output:
            return str(response.llm_output["model_name"])
        if metadata and metadata.get("model"):
            return str(metadata["model"])
        return "?"

    @staticmethod
    def _update_totals(
        *,
        agent_id: str,
        input_tokens: int,
        output_tokens: int,
        reasoning_tokens: int,
    ) -> _AgentTokenTotals:
        with _TOTALS_LOCK:
            t = TOKEN_TOTALS.setdefault(agent_id, _AgentTokenTotals())
            t.calls += 1
            t.input_tokens += input_tokens
            t.output_tokens += output_tokens
            t.reasoning_tokens += reasoning_tokens
            if input_tokens > t.peak_input:
                t.peak_input = input_tokens
            return _AgentTokenTotals(
                calls=t.calls,
                input_tokens=t.input_tokens,
                output_tokens=t.output_tokens,
                reasoning_tokens=t.reasoning_tokens,
                peak_input=t.peak_input,
                errors=t.errors,
            )


# ── Module-level singleton ──────────────────────────────────────────────
#
# A single instance is sufficient. The handler is stateless beyond the
# per-call ``_starts`` map (keyed by the unique LangChain run_id) and
# the global TOKEN_TOTALS dict.

TOKEN_LOGGER = TokenLoggingCallback()


def make_call_config(
    *,
    run_id: str | None,
    agent_id: str,
    node: str | None = None,
    recursion_limit: int | None = None,
    extra_metadata: dict | None = None,
) -> dict:
    """Build a ``RunnableConfig`` dict that activates token logging.

    Pass the result as the ``config=`` argument to any ``ainvoke`` /
    ``astream`` call. The metadata fields are read by
    :class:`TokenLoggingCallback` to attribute each LLM call to the
    right agent in ``llm_calls.jsonl``.

    ``recursion_limit`` is forwarded so call-sites that previously
    passed only ``{"recursion_limit": N}`` can switch to this helper
    without losing the iteration cap.
    """
    metadata = {
        "agent_id": agent_id,
        "run_id":   run_id,
    }
    if node:
        metadata["node"] = node
    if extra_metadata:
        metadata.update(extra_metadata)

    cfg: dict = {
        "callbacks": [TOKEN_LOGGER],
        "metadata":  metadata,
    }
    if recursion_limit is not None:
        cfg["recursion_limit"] = recursion_limit
    return cfg
