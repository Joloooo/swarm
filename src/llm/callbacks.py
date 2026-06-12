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
so the live renderer (``src/observability/live.py``) can show "▸ vulntype-sqli
finished — 12 LLM calls, 187k in / 9.4k out / 22k reasoning" when a
worker exits. That makes the context-rot risk visible without having
to grep the log file mid-run.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.outputs import LLMResult

from src.observability.writers import append_event

logger = logging.getLogger(__name__)


# ── Per-call context (legacy — kept for read-only external consumers) ────
#
# NOTE: ChatCodex no longer reads this ContextVar — its reasoning-stream
# sink now pulls agent_id and lc_run_id directly from the run_manager
# parameter of ``_generate`` / ``_agenerate``. The ContextVar route was
# broken because LangChain dispatches async callbacks in a child task,
# so the ``CURRENT_LLM_CALL.set(...)`` below mutates the child's context
# copy and the parent (where ``_agenerate`` runs) never sees the value.
# See ``src/llm/codex.py::_build_reasoning_sink`` docstring and
# ``tests/FAILURES.md`` 2026-05-13 for the full diagnosis.
#
# We still populate the ContextVar at start time and clear it at end /
# error so any external consumer that has come to depend on its
# contents keeps working. It's effectively dead code from the
# perspective of reasoning streaming and can be removed once a search
# confirms no third-party code reads it.
#
# Shape: {"agent_id": str, "run_id": str | None, "node": str | None,
#         "model": str | None, "lc_run_id": UUID}

CURRENT_LLM_CALL: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "swarm_current_llm_call", default=None,
)


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
        cached_tokens    — sum of input tokens served from OpenAI's
                           automatic prompt cache (a subset of
                           ``input_tokens``; ``cached_tokens /
                           input_tokens`` is the cache hit ratio). 0
                           when the provider doesn't report cache
                           hits — see ``src/llm/codex.py`` for the
                           Responses-API parse site.
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
    cached_tokens: int = 0
    peak_input: int = 0
    errors: int = 0


_TOTALS_LOCK = threading.Lock()
TOKEN_TOTALS: dict[str, _AgentTokenTotals] = {}

# Same running totals, but keyed by graph *node* (``planner``, ``recon``,
# ``executor``, ``summarizer``, ``web_search``, …) instead of by agent.
# A node's turn often spans several agents (the summarizer runs one
# ``*__summary`` call per worker plus a ``__consolidate``); the live
# renderer reads this to print a ``▸ node`` rollup that reflects *that
# node's* cost rather than a sum across every agent in the run. Without
# it the no-``active``-marker rollup lines (summarizer, web_search) used
# to fall back to summing all agents and printed run-to-date totals.
NODE_TOTALS: dict[str, _AgentTokenTotals] = {}


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
        cached_tokens=t.cached_tokens,
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
        NODE_TOTALS.clear()


# ── Disk path resolution ────────────────────────────────────────────────
#
# Every LLM event lands in ``logs/run-<id>/full_logs.jsonl`` via
# :func:`src.observability.writers.append_event`. The phase-keyed event
# dicts produced by the start / end / error helpers below get translated
# into ``type="llm_start" | "llm_end" | "llm_error"`` rows.


def _append_llm_event(run_id: str | None, event: dict) -> None:
    """Adapter — translate a phase-keyed event dict into ``append_event``.

    Existing call sites in this file build a dict with ``phase`` plus
    ``run_id`` / ``agent_id`` / ``node`` / token usage / etc. The unified
    writer expects ``type`` and ``run_id`` separately, so we pop those
    out and forward the rest as kwargs.

    Tolerates ``run_id=None`` by no-op'ing (matches the prior writer's
    contract, which mattered for callbacks that fire before the run id
    is propagated).
    """
    if not event:
        return
    phase = event.pop("phase", "end")
    # Drop the locally-stamped ts — append_event adds its own with
    # millisecond precision so we don't double-stamp.
    event.pop("ts", None)
    # Also drop the bare run_id key from the row body (it's the first
    # arg below) so it doesn't appear twice.
    rid = event.pop("run_id", None) or run_id
    type_name = {
        "start": "llm_start",
        "end":   "llm_end",
        "error": "llm_error",
    }.get(phase, f"llm_{phase}")
    append_event(rid, type_name, **event)


# Back-compat alias — the start-side event builder still calls
# ``_append_request_event``; the adapter handles both halves of the call.
_append_request_event = _append_llm_event


# ── Request-side serialization helpers ───────────────────────────────────


def _serialize_message_for_request_log(msg: Any) -> dict:
    """Convert one ``BaseMessage`` to a JSON-safe dict — full content.

    No truncation, by design. The user explicitly asked for "absolutely
    full logs everything" so they can replay exactly what was sent.
    Tool calls (assistant-side) and ``tool_call_id`` (tool-side) are
    preserved so the conversation can be reconstructed in either
    direction.

    Robust to non-message types (e.g. dicts produced by mocks): falls
    back to ``str(msg)`` so the serializer never raises.
    """
    role = {
        "HumanMessage":  "human",
        "AIMessage":     "assistant",
        "SystemMessage": "system",
        "ToolMessage":   "tool",
    }.get(type(msg).__name__, type(msg).__name__.lower())

    content = getattr(msg, "content", None)
    if content is None and isinstance(msg, dict):
        content = msg.get("content")
    if isinstance(content, list):
        # Multi-part content (rare on the request side; common for
        # vision/audio messages). Flatten to a list of part dicts.
        parts = []
        for p in content:
            if isinstance(p, dict):
                parts.append(p)
            else:
                parts.append({"text": str(p)})
        content_value: Any = parts
        chars = sum(len(json.dumps(p, default=str, ensure_ascii=False))
                    for p in parts)
    else:
        content_value = "" if content is None else str(content)
        chars = len(content_value)

    out: dict[str, Any] = {
        "role":  role,
        "content": content_value,
        "chars": chars,
    }

    # Assistant tool calls — present on AIMessage in the prompt history
    # whenever a previous turn invoked a tool. Capture the structured
    # tool_calls list verbatim (LangChain ToolCall TypedDicts) so the
    # full request is reproducible.
    tool_calls = getattr(msg, "tool_calls", None)
    if tool_calls:
        out["tool_calls"] = [
            {
                "name": tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", None),
                "args": tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", None),
                "id":   tc.get("id")   if isinstance(tc, dict) else getattr(tc, "id",   None),
            }
            for tc in tool_calls
        ]

    # ToolMessage carries the call_id binding it back to the
    # assistant-side tool_calls entry; keep the linkage.
    tool_call_id = getattr(msg, "tool_call_id", None)
    if tool_call_id:
        out["tool_call_id"] = tool_call_id

    name = getattr(msg, "name", None)
    if name:
        out["name"] = name

    return out


def _serialize_tools_for_request_log(serialized: dict | None) -> list[dict]:
    """Pull the tools advertised to the model out of the serialized
    callable, if present.

    LangChain's ``bind_tools`` stashes tools under varying paths
    depending on the provider. We probe a couple of common shapes;
    anything unrecognized returns ``[]`` rather than raising. Each
    tool is rendered as ``{name, description, parameters}`` with NO
    truncation — see the design note about full-content logging.
    """
    if not serialized:
        return []
    kwargs = serialized.get("kwargs") or {}
    raw_tools = kwargs.get("tools") or []
    out: list[dict] = []
    for t in raw_tools:
        if not isinstance(t, dict):
            # Unknown shape — best-effort string repr, still no truncation.
            out.append({"raw": str(t)})
            continue
        # OpenAI/Codex shape: {"type": "function", "function": {...}}
        fn = t.get("function") if t.get("type") == "function" else None
        if isinstance(fn, dict):
            out.append({
                "name":        fn.get("name"),
                "description": fn.get("description"),
                "parameters":  fn.get("parameters"),
            })
        else:
            out.append(t)
    return out


def _short_hash(value: Any) -> str:
    if isinstance(value, str):
        raw = value
    else:
        raw = json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _serialized_kwargs(serialized: dict | None) -> dict:
    if not isinstance(serialized, dict):
        return {}
    kwargs = serialized.get("kwargs")
    return kwargs if isinstance(kwargs, dict) else {}


def _build_callback_cache_shape(
    *,
    serialized: dict | None,
    serialized_msgs: list[dict],
    system_prompt: str,
    tools: list[dict],
) -> dict[str, Any]:
    """Compact request-shape fingerprint for prompt-cache diagnostics.

    The full prompt and full tools are already logged next to this block.
    This object gives quick comparable fields for grep/jq without reading
    megabytes of prompt content.
    """
    kwargs = _serialized_kwargs(serialized)
    message_roles: dict[str, int] = {}
    for msg in serialized_msgs:
        role = str(msg.get("role") or "?")
        message_roles[role] = message_roles.get(role, 0) + 1
    message_chars = sum(int(m.get("chars") or 0) for m in serialized_msgs)
    return {
        "serialized_id": (
            serialized.get("id") if isinstance(serialized, dict) else None
        ),
        "serialized_name": (
            serialized.get("name") if isinstance(serialized, dict) else None
        ),
        "bound_kwargs": sorted(kwargs.keys()),
        "model": kwargs.get("model") or kwargs.get("model_name"),
        "tool_choice": kwargs.get("tool_choice"),
        "reasoning_effort": kwargs.get("reasoning_effort"),
        "reasoning_summary": kwargs.get("reasoning_summary"),
        "prompt_cache_key": kwargs.get("prompt_cache_key"),
        "prompt_cache_retention": kwargs.get("prompt_cache_retention"),
        "message_count": len(serialized_msgs),
        "message_roles": message_roles,
        "message_chars": message_chars,
        "message_sha256": _short_hash(serialized_msgs),
        "system_chars": len(system_prompt or ""),
        "system_sha256": _short_hash(system_prompt or ""),
        "tools_count": len(tools),
        "tool_names": [str(t.get("name") or "?") for t in tools[:80]],
        "tools_sha256": _short_hash(tools),
    }


def _build_request_event(
    *,
    lc_run_id: UUID,
    metadata: dict | None,
    serialized: dict | None,
    messages: list[list[Any]] | None,
) -> dict:
    """Assemble the full request-log event for one LLM call start.

    Captures:
      - identity (lc_run_id, run_id, agent_id, node, model)
      - the bound tools advertised to the model
      - every message in the prompt, with role / content / chars /
        tool-call linkage, NO truncation
      - aggregate sizing (n_messages, total_chars, char_breakdown,
        rough estimated_input_tokens via the chars/4 heuristic) so
        post-run analysis can plot growth without re-summing each
        message
    """
    meta = metadata or {}
    ser = serialized or {}
    model = (
        (ser.get("kwargs") or {}).get("model")
        or (ser.get("kwargs") or {}).get("model_name")
        or meta.get("model")
        or "?"
    )

    # ``messages`` arrives as list[list[BaseMessage]] from
    # on_chat_model_start (one inner list per "prompt" — typically
    # length 1 for chat models). Flatten while preserving order.
    flat: list[Any] = []
    for sub in messages or []:
        if isinstance(sub, list):
            flat.extend(sub)
        else:
            flat.append(sub)

    serialized_msgs = [_serialize_message_for_request_log(m) for m in flat]

    # Pull out the first SystemMessage for convenience — often the
    # primary thing a reader wants to see when scrolling jq output.
    system_prompt = None
    for sm in serialized_msgs:
        if sm.get("role") == "system":
            system_prompt = sm.get("content")
            break

    char_breakdown = {"system": 0, "human": 0, "assistant": 0, "tool": 0}
    for sm in serialized_msgs:
        role = str(sm.get("role") or "")
        chars = int(sm.get("chars") or 0)
        if role in char_breakdown:
            char_breakdown[role] += chars
        else:
            char_breakdown.setdefault("other", 0)
            char_breakdown["other"] += chars
    total_chars = sum(char_breakdown.values())
    tools = _serialize_tools_for_request_log(serialized)

    return {
        "ts":         time.strftime("%Y-%m-%dT%H:%M:%S")
                      + f".{int((time.time() % 1) * 1000):03d}",
        "phase":      "start",
        "lc_run_id":  str(lc_run_id),
        "run_id":     meta.get("run_id"),
        "agent_id":   str(meta.get("agent_id") or meta.get("ls_agent")
                          or "_unknown"),
        "node":       meta.get("node"),
        "model":      str(model),
        "request": {
            "system_prompt":  system_prompt,
            "messages":       serialized_msgs,
            "tools":          tools,
            "n_messages":     len(serialized_msgs),
            "total_chars":    total_chars,
            "char_breakdown": char_breakdown,
            "cache_shape":    _build_callback_cache_shape(
                serialized=serialized,
                serialized_msgs=serialized_msgs,
                system_prompt=system_prompt,
                tools=tools,
            ),
            # Char/4 is the standard cheap pre-tokenizer heuristic.
            # Real input_tokens lands later in llm_calls.jsonl from
            # the provider's usage_metadata; the join key
            # ``lc_run_id`` lets you compare estimate vs reality.
            "estimated_input_tokens": total_chars // 4,
        },
    }


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

    # Tracks per-run_id state so on_llm_end can compute duration AND
    # restore the call's identity (agent_id / our run_id / node / model)
    # that was published at start time. We can't trust LangChain to
    # re-pass the parent's metadata to ``on_llm_end`` for nested
    # chat-model calls inside ``create_agent`` — empirically, metadata
    # is dropped on the end event and we'd see ``agent_id="_unknown"``
    # / ``model="?"`` on every "done" line. Stashing it here is the fix.
    #
    # Each entry is a small dict:
    #   {"started_at": perf_counter_float,
    #    "agent_id":   "owasp-recon",
    #    "run_id":     "XBEN-006-24__...",   # our run id (string)
    #    "node":       "executor",
    #    "model":      "gpt-5.4-mini",
    #    "reasoning_effort": "xhigh"}
    _starts: dict[UUID, dict[str, Any]]

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
        """Record the start time, publish the call identity for the
        streaming sink, write the full prompt to llm_requests.jsonl,
        and tell the renderer to draw a "thinking…" header (and start
        a heartbeat task)."""
        self._starts[run_id] = self._resolve_identity(
            metadata=metadata, serialized=serialized,
        )
        self._publish_call_context(run_id, metadata, serialized)
        # Write the request-side log row BEFORE notifying the
        # renderer so a slow disk doesn't delay the stderr header.
        # Failures are swallowed inside _append_request_event.
        request_event = _build_request_event(
            lc_run_id=run_id,
            metadata=metadata,
            serialized=serialized,
            messages=messages,
        )
        _append_request_event(request_event["run_id"], request_event)
        self._notify_render_start(run_id, metadata, serialized)

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
        self._starts[run_id] = self._resolve_identity(
            metadata=metadata, serialized=serialized,
        )
        self._publish_call_context(run_id, metadata, serialized)
        # Wrap the raw prompt strings in a single synthetic ``human``
        # message so the request-log row has a consistent shape across
        # providers. Real chat-model providers route through
        # on_chat_model_start above; this branch is the fallback for
        # text-completion-style providers.
        synthetic = [
            [type("PromptStr", (), {"content": p})() for p in (prompts or [])]
        ]
        request_event = _build_request_event(
            lc_run_id=run_id,
            metadata=metadata,
            serialized=serialized,
            messages=synthetic,
        )
        _append_request_event(request_event["run_id"], request_event)
        self._notify_render_start(run_id, metadata, serialized)

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
        # Pull the identity stashed at start time. LangChain often
        # drops parent metadata on ``on_llm_end`` for nested
        # chat-model calls inside ``create_agent``, which is why we
        # cannot trust the ``metadata`` argument here. The
        # ``_starts`` dict was populated by
        # ``on_chat_model_start`` / ``on_llm_start`` via
        # ``_resolve_identity`` — read everything from there first
        # and only fall back to the (possibly stale) metadata for
        # fields that weren't captured.
        ident = self._starts.pop(run_id, None) or {}
        t0 = ident.get("started_at")
        dt_ms = int((time.perf_counter() - t0) * 1000) if t0 else 0

        # Walk the generations to find usage_metadata. ChatCodex puts it
        # on the AIMessage (see codex.py:1127); other providers attach
        # it via LLMResult.llm_output["token_usage"] — try both.
        usage = self._extract_usage(response)
        # Model: prefer the actual response_metadata.model from the
        # AIMessage (most accurate), fall back to the stash, fall
        # back to the metadata dict, fall back to "?".
        model = (
            self._extract_model(response, metadata)
            or ident.get("model")
            or "?"
        )
        if model == "?" and ident.get("model"):
            model = ident["model"]

        meta = metadata or {}
        agent_id = (
            ident.get("agent_id")
            or str(meta.get("agent_id") or meta.get("ls_agent") or "_unknown")
        )
        node = ident.get("node") or str(meta.get("node") or "")
        run_id_str = ident.get("run_id") or meta.get("run_id")

        running = self._update_totals(
            agent_id=agent_id,
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            reasoning_tokens=usage["reasoning_tokens"],
            cached_tokens=usage.get("cached_tokens", 0),
            node=node or None,
        )

        # Tell the renderer to close the streaming line / cancel the
        # heartbeat. We do this BEFORE writing the disk event so the
        # "🧠 done" line on stderr appears alongside the same fields
        # that just landed in llm_calls.jsonl.
        try:
            from src.observability import LIVE  # lazy — avoid import cycle
            LIVE.thinking_finished(
                agent=agent_id,
                run_id=run_id,
                duration_ms=dt_ms,
                model=model,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                reasoning_tokens=usage["reasoning_tokens"],
                cached_tokens=usage.get("cached_tokens", 0),
                running_input=running.input_tokens,
                peak_input=running.peak_input,
            )
        except Exception:  # noqa: BLE001 — never let live rendering break logging
            pass
        # Clear the per-call ContextVar so a stray reasoning delta
        # arriving after on_llm_end can't be misattributed.
        try:
            CURRENT_LLM_CALL.set(None)
        except Exception:  # noqa: BLE001
            pass

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
            "running_cached": running.cached_tokens,
            "running_calls": running.calls,
            "running_peak_input": running.peak_input,
        }
        _append_llm_event(run_id_str, event)
        # Note: the per-call "done" line on stderr is emitted by
        # ``LIVE.thinking_finished`` above, BEFORE the disk write,
        # so we don't double-print here.

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
        # Same fallback discipline as on_llm_end — read identity
        # from the stash first.
        ident = self._starts.pop(run_id, None) or {}
        t0 = ident.get("started_at")
        dt_ms = int((time.perf_counter() - t0) * 1000) if t0 else 0

        meta = metadata or {}
        agent_id = (
            ident.get("agent_id")
            or str(meta.get("agent_id") or meta.get("ls_agent") or "_unknown")
        )
        node = ident.get("node") or str(meta.get("node") or "")
        run_id_str = ident.get("run_id") or meta.get("run_id")
        model = ident.get("model") or meta.get("model") or "?"

        # Tear down the renderer's heartbeat / streaming state for
        # this call so an error doesn't leave a "🧠 thinking…" header
        # hanging without a closer.
        try:
            from src.observability import LIVE  # lazy — avoid import cycle
            LIVE.thinking_finished(
                agent=agent_id,
                run_id=run_id,
                duration_ms=dt_ms,
                model=model,
                input_tokens=0,
                output_tokens=0,
                reasoning_tokens=0,
                running_input=0,
                peak_input=0,
                error=type(error).__name__,
            )
        except Exception:  # noqa: BLE001
            pass
        try:
            CURRENT_LLM_CALL.set(None)
        except Exception:  # noqa: BLE001
            pass

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
            "model": model,
            "duration_ms": dt_ms,
            "error_type": type(error).__name__,
            "error_msg": str(error)[:500],
            "running_errors": running_errors,
        }
        _append_llm_event(run_id_str, event)

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_identity(
        *,
        metadata: dict | None,
        serialized: dict | None,
    ) -> dict[str, Any]:
        """Best-effort resolution of the call's identity at start time.

        The fields here are what every downstream consumer needs:
        ``agent_id`` for live rendering / running totals,
        ``run_id`` (our run id, not the LangChain UUID) for the JSONL
        path, ``node`` for the disk row, ``model`` and
        ``reasoning_effort`` for the "thinking…" header.

        Why this exists as a single helper: the same identity is
        needed in three places — the CURRENT_LLM_CALL ContextVar (for
        the streaming reasoning sink in ``ChatCodex._build_reasoning_sink``),
        the ``LIVE.thinking_started(...)`` header line, and ``self._starts``
        so ``on_llm_end`` can recover the same fields after LangChain
        drops parent metadata on the end event for nested chat-model
        calls. Resolving once and storing once avoids the divergence
        the user observed in production:

            🧠 _planner   thinking (?)…
            🧠 _unknown   done (...)

        which happens when ``on_llm_end``'s ``metadata`` is stripped
        but ``self._starts[run_id]`` still has the identity from
        ``on_chat_model_start``.

        Lookup order for each field walks: explicit metadata key →
        ``serialized.kwargs`` key → ``serialized.repr`` regex (handles
        Pydantic-v1 BaseChatModel reprs) → starting time / "?" /
        "_unknown" sentinels.
        """
        meta = metadata or {}
        ser = serialized or {}
        kwargs = (ser.get("kwargs") or {}) if isinstance(ser, dict) else {}
        # Pydantic-v1 chat models sometimes serialize the model name only
        # into the ``repr`` string. Cheap regex scan as a final fallback.
        repr_str = ser.get("repr") if isinstance(ser, dict) else ""

        def _from_repr(needle: str) -> str | None:
            if not isinstance(repr_str, str) or not repr_str:
                return None
            m = re.search(rf"{needle}=['\"]?([^\s'\",)]+)", repr_str)
            return m.group(1) if m else None

        model = (
            kwargs.get("model")
            or kwargs.get("model_name")
            or meta.get("model")
            or _from_repr("model")
            or "?"
        )
        reasoning_effort = (
            kwargs.get("reasoning_effort")
            or meta.get("reasoning_effort")
            or _from_repr("reasoning_effort")
            or ""
        )
        agent_id = str(
            meta.get("agent_id") or meta.get("ls_agent") or "_unknown"
        )
        return {
            "started_at":       time.perf_counter(),
            "agent_id":         agent_id,
            "run_id":           meta.get("run_id"),
            "node":             meta.get("node"),
            "model":            str(model),
            "reasoning_effort": str(reasoning_effort),
        }

    @classmethod
    def _publish_call_context(
        cls,
        run_id: UUID,
        metadata: dict | None,
        serialized: dict | None,
    ) -> None:
        """Stash the calling identity on :data:`CURRENT_LLM_CALL`.

        Read by ``ChatCodex._build_reasoning_sink`` to attribute
        reasoning deltas to the right agent_id without plumbing
        kwargs through the parser API.
        """
        ident = cls._resolve_identity(metadata=metadata, serialized=serialized)
        try:
            CURRENT_LLM_CALL.set({
                "agent_id":  ident["agent_id"],
                "run_id":    ident["run_id"],
                "node":      ident["node"],
                "model":     ident["model"],
                "lc_run_id": run_id,
            })
        except Exception:  # noqa: BLE001
            pass

    @classmethod
    def _notify_render_start(
        cls,
        run_id: UUID,
        metadata: dict | None,
        serialized: dict | None,
    ) -> None:
        """Tell the live renderer to draw the "🧠 thinking…" header
        and start a heartbeat. Best-effort; never raises."""
        try:
            from src.observability import LIVE  # lazy — avoid import cycle
        except Exception:  # noqa: BLE001
            return
        ident = cls._resolve_identity(metadata=metadata, serialized=serialized)
        try:
            LIVE.thinking_started(
                agent=ident["agent_id"],
                run_id=run_id,
                model=ident["model"],
                reasoning_effort=ident["reasoning_effort"],
            )
        except Exception:  # noqa: BLE001
            pass

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
        cached_tokens = 0
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
                    cached_tokens    += int(um.get("cached_tokens",    0) or 0)
                    total_tokens     += int(um.get("total_tokens",     0) or 0)

        # Fallback to llm_output (older integrations).
        if not total_tokens and response.llm_output:
            tu = (response.llm_output or {}).get("token_usage") or {}
            input_tokens     = int(tu.get("prompt_tokens",     input_tokens)     or input_tokens)
            output_tokens    = int(tu.get("completion_tokens", output_tokens)    or output_tokens)
            total_tokens     = int(tu.get("total_tokens",      total_tokens)     or total_tokens)
            # Older OpenAI integrations report cache hits at
            # ``prompt_tokens_details.cached_tokens``.
            ptd = tu.get("prompt_tokens_details") or {}
            if isinstance(ptd, dict):
                cached_tokens = int(ptd.get("cached_tokens", cached_tokens) or cached_tokens)

        # Backfill total if missing.
        if not total_tokens:
            total_tokens = input_tokens + output_tokens + reasoning_tokens

        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "reasoning_tokens": reasoning_tokens,
            "cached_tokens": cached_tokens,
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
        cached_tokens: int = 0,
        node: str | None = None,
    ) -> _AgentTokenTotals:
        def _add(t: _AgentTokenTotals) -> None:
            t.calls += 1
            t.input_tokens += input_tokens
            t.output_tokens += output_tokens
            t.reasoning_tokens += reasoning_tokens
            t.cached_tokens += cached_tokens
            if input_tokens > t.peak_input:
                t.peak_input = input_tokens

        with _TOTALS_LOCK:
            t = TOKEN_TOTALS.setdefault(agent_id, _AgentTokenTotals())
            _add(t)
            # Mirror the same call into the per-node rollup so the live
            # renderer can attribute a ``▸ node`` line to that node's own
            # turn instead of summing every agent in the run.
            if node:
                _add(NODE_TOTALS.setdefault(node, _AgentTokenTotals()))
            return _AgentTokenTotals(
                calls=t.calls,
                input_tokens=t.input_tokens,
                output_tokens=t.output_tokens,
                reasoning_tokens=t.reasoning_tokens,
                cached_tokens=t.cached_tokens,
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
    extra_callbacks: list | None = None,
) -> dict:
    """Build a ``RunnableConfig`` dict that activates token logging.

    Pass the result as the ``config=`` argument to any ``ainvoke`` /
    ``astream`` call. The metadata fields are read by
    :class:`TokenLoggingCallback` to attribute each LLM call to the
    right agent in ``llm_calls.jsonl``.

    ``recursion_limit`` is forwarded so call-sites that previously
    passed only ``{"recursion_limit": N}`` can switch to this helper
    without losing the iteration cap.

    ``extra_callbacks`` are appended after :data:`TOKEN_LOGGER`. Use
    this to attach worker-specific handlers — currently the
    :class:`src.nodes.base.flag_watcher.FlagWatcherCallback` that
    short-circuits the worker on flag capture. Order matters only for
    callbacks that mutate the run state; the flag watcher only reads,
    so its position is irrelevant.
    """
    metadata = {
        "agent_id": agent_id,
        "run_id":   run_id,
    }
    if node:
        metadata["node"] = node
    if extra_metadata:
        metadata.update(extra_metadata)

    callbacks: list = [TOKEN_LOGGER]
    if extra_callbacks:
        callbacks.extend(extra_callbacks)

    cfg: dict = {
        "callbacks": callbacks,
        "metadata":  metadata,
    }
    if recursion_limit is not None:
        cfg["recursion_limit"] = recursion_limit
    return cfg
