"""Worker-trace summarisation + per-message size cap.

This module owns the **summarisation primitives** that the
``SummarizerNode`` (``src/nodes/summarizer.py``) drives. It is
deliberately framework-agnostic — pure async functions over
``BaseMessage`` lists, no LangGraph imports — so the same primitives can
be unit-tested in isolation and reused later (e.g. in a manual
``/compact`` flow or in an ablation harness).

The big idea
============

SwarmAttacker hits Codex's 256k input window because every worker's full
``AIMessage`` + ``ToolMessage`` trace was mirrored verbatim into the
global ``state["messages"]``, and the supervisor planner re-read that
list every turn. With ~60 worker iterations × ~4 KB per call × 4
parallel workers per planner turn, the planner crosses 256 K within a
handful of cycles.

The fix: workers' raw traces never enter ``state["messages"]`` at all.
Each worker hands its trace to the summarizer node, which produces ONE
structured report per worker and writes only that report to global
state. The planner's input prompt then carries digests + its own
decisions — never raw tool-call storms.

What lives here
===============

- :data:`WORKER_REPORT_TEMPLATE` — the prompt that turns a trace into
  a structured report. Tuned for security testing (probe enumeration,
  filter inference, what-was-NOT-tried). Vocabulary-policy compliant
  (see ``CLAUDE.md`` "Skill Vocabulary Policy").
- :func:`summarize_worker_trace` — runs the prompt with
  ``BaseNode.ask_focused``-style minimal framing so the summariser does
  not inherit the worker's noisy system prompt.
- :func:`cap_message_size` — Layer 2 defense: head+tail trim any single
  message above ``MAX_MESSAGE_TOKENS``. Pure deterministic, no LLM
  cost. Applied in ``BaseNode.__call__`` and
  ``ChatCodex._build_request_kwargs`` (defense-in-depth).
- :func:`find_prior_worker_report` — reads back a previous summarizer
  report for the same ``agent_id`` so re-dispatched workers see what
  the previous dispatch tried.
- :func:`estimate_total_tokens` — token-count helper (tiktoken with a
  character-count fallback).

Cost model
==========

One LLM call per worker per dispatch (the summarisation). The summariser
runs on a fresh ``ChatModel`` so it doesn't inherit the worker's prompt;
typical input is the trace (~30–60 KB) plus a small framing block,
output is ≤4 K tokens. Cheaper than mirroring 60+ ``ToolMessage``s into
every subsequent planner turn, by ~10×.

When the worker crashed mid-loop or hit its iteration cap without a
clean final ``AIMessage``, this same path runs over the partial trace —
the summariser is the unified report-writer for happy and unhappy
paths alike, so there is no separate fallback summariser to maintain.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

logger = logging.getLogger(__name__)


# ── Tunables (all overridable via env vars for benchmark debugging) ────


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# Cap any single message above this threshold via head+tail trim before
# it hits the LLM. 4 K tokens ≈ 16 KB — well above the typical worker
# ToolMessage (~3.7 K tokens after the existing per-tool head+tail), so
# this rarely fires; it exists to catch outliers (huge HTML responses,
# verbose nmap dumps, an unexpectedly long planner SYSTEM NOTE).
MAX_MESSAGE_TOKENS = _env_int("SWARM_MAX_MESSAGE_TOKENS", 4_000)
MAX_MESSAGE_TARGET_TOKENS = _env_int("SWARM_MAX_MESSAGE_TARGET_TOKENS", 2_000)

# How much output budget we give the summariser per worker report.
# 4 K tokens ≈ a thousand-word structured digest, plenty of room for the
# probe-enumeration sections without bleeding into the planner budget.
REPORT_MAX_OUTPUT_TOKENS = _env_int("SWARM_REPORT_MAX_OUTPUT_TOKENS", 4_000)

# Max characters of trace text we feed to the summariser. The trace can
# legitimately be large (60 iterations × ~4 KB), but at some point we
# hit diminishing returns vs. summary quality. Cap at ~120 K chars
# (~30 K tokens) of input to the summariser; beyond that, head+tail
# trim per-message inside the trace rather than feeding it raw.
MAX_TRACE_CHARS_FOR_SUMMARY = _env_int("SWARM_MAX_TRACE_CHARS", 120_000)


# ── Token counting ─────────────────────────────────────────────────────


def _count_tokens(text: str) -> int:
    """Best-effort token count for a text blob.

    Tries tiktoken (cl100k_base — Codex / GPT-4 family); falls back to
    ``len(text) // 4`` so the module works even when tiktoken isn't
    installed in the dev environment. The fallback overestimates for
    English prose and underestimates for dense JSON / curl output, but
    both errors are within ~30% which is fine for "are we above the
    threshold" decisions.
    """
    if not text:
        return 0
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        return max(1, len(text) // 4)


def _message_text(msg: BaseMessage) -> str:
    """Extract the text content of a message for token-counting / display.

    Handles ``str`` and ``list[dict]`` content shapes (the latter is
    what providers return when an assistant message includes mixed text
    + image / tool blocks).
    """
    content = getattr(msg, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                else:
                    parts.append(f"[{item.get('type', 'block')}]")
            else:
                parts.append(str(item))
        return " ".join(parts)
    return str(content or "")


def estimate_total_tokens(messages: list[BaseMessage]) -> int:
    """Sum of token estimates across every message's text content.

    Does NOT count tool-call argument bytes or message metadata — those
    are small relative to message bodies, and the goal here is a "good
    enough" pre-flight check for compaction decisions, not invoice-grade
    accuracy.
    """
    return sum(_count_tokens(_message_text(m)) for m in messages)


# ── Layer 2: per-message size cap ──────────────────────────────────────


def _head_tail_trim(text: str, target_tokens: int) -> str:
    """Deterministic head+tail trim to roughly ``target_tokens``.

    Splits the text in half by tokens, keeps the first quarter and the
    last quarter, and inserts a marker in the middle. This preserves the
    "what was the start of this output" + "what was the verdict at the
    end" signal — both useful for an LLM trying to reason about a tool
    response — while dropping the middle, which is usually repetition or
    progress chatter.
    """
    # Char-based proxy: 1 token ≈ 4 chars. Cheaper than encoding twice.
    target_chars = max(200, target_tokens * 4)
    if len(text) <= target_chars:
        return text
    head_chars = target_chars // 2
    tail_chars = target_chars - head_chars
    head = text[:head_chars]
    tail = text[-tail_chars:]
    return (
        head
        + f"\n\n... [Layer 2 cap: middle trimmed, ~{len(text) - head_chars - tail_chars} "
        f"chars elided] ...\n\n"
        + tail
    )


def cap_message_size(
    msg: BaseMessage,
    *,
    max_tokens: int = MAX_MESSAGE_TOKENS,
    target_tokens: int = MAX_MESSAGE_TARGET_TOKENS,
) -> BaseMessage:
    """If ``msg.content`` exceeds ``max_tokens``, return a head+tail
    trimmed copy whose content is roughly ``target_tokens`` long. Pure,
    deterministic, no LLM cost. Returns the original ``msg`` unchanged
    when it's already under the cap.

    Used as a pre-LLM hook in ``BaseNode.__call__`` and
    ``ChatCodex._build_request_kwargs`` so a single oversized message
    (huge HTML response, verbose nmap dump, an unexpectedly long
    ``[SYSTEM NOTE]``) cannot blow up the prompt by itself. Doesn't
    mutate state — the original message lives on; only the LLM-feed copy
    is trimmed.
    """
    text = _message_text(msg)
    if not text:
        return msg
    tokens = _count_tokens(text)
    if tokens <= max_tokens:
        return msg

    trimmed = _head_tail_trim(text, target_tokens)
    # Reconstruct a new message of the same type with capped content;
    # preserve additional_kwargs, name, tool_call_id, etc.
    cls = type(msg)
    kwargs: dict[str, Any] = {"content": trimmed}
    for attr in (
        "additional_kwargs",
        "response_metadata",
        "name",
        "id",
        "tool_call_id",
        "tool_calls",
    ):
        v = getattr(msg, attr, None)
        if v is not None:
            kwargs[attr] = v
    try:
        new_msg = cls(**kwargs)
    except Exception:
        # Some message subclasses have stricter __init__ signatures;
        # if reconstruction fails, fall back to the original (the LLM
        # call will then carry the un-trimmed message — defense-in-depth
        # is best-effort, not a hard guarantee).
        return msg
    # Tag so downstream observability can see we trimmed.
    try:
        new_msg.additional_kwargs.setdefault("layer2_capped", True)
        new_msg.additional_kwargs.setdefault("layer2_tokens_before", tokens)
    except Exception:
        pass
    return new_msg


# ── The summarisation prompt ──────────────────────────────────────────


# This is the centerpiece. It demands fine-grained probe enumeration
# because a re-dispatch of the same skill needs to know *exactly* what
# casings / encodings / comment-splices were tried and which families
# remain unexplored. A vague "tried various injections" digest is
# actively harmful — the next dispatch wastes iterations re-probing the
# same families.
#
# Vocabulary policy compliance: this template is grepped by the CI check
# in ``CLAUDE.md`` (Skill Vocabulary Policy section). Use neutral
# test-task vocabulary throughout. Domain technical names
# (SQL injection, CSRF token, SSRF gadget) stay intact — they're
# vocabulary, not framing. See CLAUDE.md for the substitution table.
WORKER_REPORT_TEMPLATE = """\
You are summarizing the work of a security testing worker for the
supervisor planner. The supervisor will read your summary and decide what
to do next. They will NOT see the worker's tool calls, raw outputs, or
intermediate reasoning — they see only your summary.

The supervisor dispatched this worker because:

  {dispatch_reason}

Worker identity:
  agent_id:     {agent_id}
  config_name:  {config_name}
  methodology:  {methodology}
  target:       {target_url}
  status:       {status}{status_note}
  iterations:   {iteration_count}
  findings extracted by worker (already structured): {findings_count}

Below is the worker's full trace (tool calls + tool outputs +
reasoning). Produce a structured report that specifically addresses the
supervisor's reason for dispatch above.

The summary MUST be high-fidelity about probe enumeration. The next
worker — possibly a re-dispatch of the same skill — should be able to
read your summary and know exactly which patterns were already tried
and which were not, down to the level of casing, encoding,
comment-splicing, and double-letter tricks.

Output format (markdown, exactly these sections in this order):

## Status
One of: success | inconclusive | blocked | refused | crashed. One
sentence why.

## Target
The endpoint / parameter / URL the worker focused on (be specific:
method + path + parameter names).

## Inputs tried
List every distinct family of test input the worker tried. For each
family, give 2–3 representative examples verbatim. Example families to
surface explicitly when relevant: plain keywords, mixed case,
URL-encoded, hex / unicode, comment-spliced, whitespace tricks,
doubled-letter, logical-operator alternatives, time-based, boolean-blind,
second-order. Include a count: "Inputs tried: <N> total via
<tool>=<count>, <tool>=<count>, ...".

## Server responses
Group by status code / body fingerprint. Call out outlier responses
that suggested a near-miss (e.g. one 500 amid 120 200s, a different
content length, a unique error string).

## Inferred server-side behaviour
What the worker concluded about the server's filtering, validation, or
defence based on the responses. State the evidence — which response
patterns led to which inference.

## NOT tried
Specific input families or angles the worker did NOT attempt. This is
the most valuable section for a re-dispatch — be concrete. "Did not
test second-order injection via /profile" is good; "could try other
approaches" is useless.

## Recommended next dispatch
One paragraph: the single most promising untested angle, and why,
based on the responses observed.

## Notable per-tool differences
e.g. "curl: 98 probes; sqlmap: 23 probes, all timed out at 30s".

Vocabulary: write in neutral test-task vocabulary throughout. Refer to
inputs as "test inputs", to the actor as "tester" or "test agent", and
describe construction of inputs in neutral terms. Keep domain technical
names intact (SQL injection, CSRF token, SSRF gadget).

Be specific. "Tried various encodings" is useless — list them.

----- WORKER TRACE BELOW -----

{trace_text}

----- END WORKER TRACE -----

Produce only the structured summary above. Do not add commentary
before or after.
"""


def _format_message_for_trace(msg: BaseMessage) -> str:
    """Render one message into a compact "role: content" line for the
    summariser's trace_text. Includes tool-call args (as JSON) so the
    summariser can enumerate exactly which test inputs were sent.
    """
    role_map = {
        "AIMessage": "assistant",
        "HumanMessage": "user",
        "ToolMessage": "tool",
        "SystemMessage": "system",
    }
    role = role_map.get(type(msg).__name__, type(msg).__name__.lower())
    text = _message_text(msg)

    # AIMessage may carry tool_calls; render them so the enumeration is
    # visible to the summariser.
    tool_calls = getattr(msg, "tool_calls", None) or []
    tool_call_lines: list[str] = []
    for tc in tool_calls:
        if isinstance(tc, dict):
            name = tc.get("name", "?")
            args = tc.get("args", {})
        else:
            name = getattr(tc, "name", "?")
            args = getattr(tc, "args", {})
        try:
            import json as _json
            args_str = _json.dumps(args, default=str)[:1200]
        except Exception:
            args_str = str(args)[:1200]
        tool_call_lines.append(f"  → tool_call: {name}({args_str})")

    # ToolMessage may carry a `name` (which tool produced this output).
    name_attr = getattr(msg, "name", None)
    name_prefix = f"[{name_attr}] " if name_attr else ""

    body = f"{role}: {name_prefix}{text}"
    if tool_call_lines:
        body += "\n" + "\n".join(tool_call_lines)
    return body


def _serialize_trace(trace: list[BaseMessage], *, max_chars: int) -> str:
    """Serialize a trace into the text block the summariser reads.

    Caps total chars to ``max_chars`` by trimming the OLDEST messages
    first when over budget — the recent context is what tells the story
    of what the worker was just trying when it terminated.
    """
    if not trace:
        return "(empty trace)"

    rendered = [_format_message_for_trace(m) for m in trace]
    full = "\n\n".join(rendered)
    if len(full) <= max_chars:
        return full

    # Over budget — drop oldest messages until under the cap.
    # Prefer keeping recent messages (the verdict / final reasoning) over
    # ancient setup chatter.
    kept: list[str] = []
    running = 0
    for r in reversed(rendered):
        if running + len(r) + 2 > max_chars:
            break
        kept.append(r)
        running += len(r) + 2
    kept.reverse()
    dropped_count = len(rendered) - len(kept)
    if dropped_count > 0:
        kept.insert(
            0,
            f"... [omitted oldest {dropped_count} message(s); "
            f"~{len(full) - running} chars] ...",
        )
    return "\n\n".join(kept)


# ── The summariser entry point ────────────────────────────────────────


async def summarize_worker_trace(
    *,
    trace: list[BaseMessage],
    agent_id: str,
    config_name: str,
    methodology: str,
    dispatch_reason: str,
    target_url: str,
    findings_count: int,
    iteration_count: int,
    completed: bool,
    error: str | None,
    refused: bool,
    model: BaseChatModel,
    run_id: str | None,
    node_name: str = "summarizer",
    status_note: str = "",
) -> AIMessage:
    """Run one summariser LLM call and return the worker's report
    ``AIMessage``.

    Tags the result with ``additional_kwargs={"agent_id": ...,
    "kind": "worker_report", ...}`` so the seeder
    (``_collect_prior_skill_history``) can find it on re-dispatch and
    so observability can group reports by worker.

    Failure modes:
    - Summariser LLM call raises → fall back to a deterministic stub
      that lists the trace shape ("N messages, X tool calls, status=...")
      so the planner still sees *something* coherent rather than a hole.
    """
    if completed:
        status = "success" if findings_count > 0 else "inconclusive"
    elif refused:
        status = "refused"
    elif error:
        status = "crashed"
    else:
        status = "blocked"

    trace_text = _serialize_trace(trace, max_chars=MAX_TRACE_CHARS_FOR_SUMMARY)

    prompt = WORKER_REPORT_TEMPLATE.format(
        dispatch_reason=dispatch_reason or "(no reason recorded)",
        agent_id=agent_id,
        config_name=config_name,
        methodology=methodology,
        target_url=target_url or "(unset)",
        status=status,
        status_note=f" — {error}" if error else "",
        iteration_count=iteration_count,
        findings_count=findings_count,
        trace_text=trace_text,
    )

    # Lazy import to avoid the circular import path
    # ``digest → callbacks → graph → nodes → digest``.
    from src.llm.callbacks import make_call_config

    call_config = make_call_config(
        run_id=run_id,
        agent_id=f"{agent_id}__summary",  # keep summary tokens distinguishable
        node=node_name,
    )

    try:
        response = await model.ainvoke(
            [
                SystemMessage(
                    content=(
                        "You are a precise technical summariser for a "
                        "security testing platform. Produce only the "
                        "requested structured report. No commentary."
                    )
                ),
                HumanMessage(content=prompt),
            ],
            config=call_config,
        )
        text = response.content
        if not isinstance(text, str):
            text = str(text or "")
        text = text.strip()
        if not text:
            text = _stub_report(
                agent_id=agent_id,
                config_name=config_name,
                status=status,
                iteration_count=iteration_count,
                findings_count=findings_count,
                error=error,
            )
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "[%s] summariser LLM call failed (%s: %s) — using stub report",
            agent_id, type(e).__name__, str(e)[:200],
        )
        text = _stub_report(
            agent_id=agent_id,
            config_name=config_name,
            status=status,
            iteration_count=iteration_count,
            findings_count=findings_count,
            error=error,
        )

    report = AIMessage(
        content=text,
        additional_kwargs={
            "agent_id": agent_id,
            "kind": "worker_report",
            "config_name": config_name,
            "methodology": methodology,
            "status": status,
            "iteration_count": iteration_count,
            "findings_count": findings_count,
        },
    )
    return report


def _stub_report(
    *,
    agent_id: str,
    config_name: str,
    status: str,
    iteration_count: int,
    findings_count: int,
    error: str | None,
) -> str:
    """Deterministic fallback when the summariser LLM call fails.

    Better than nothing: gives the planner a one-block placeholder so it
    knows the worker ran (and roughly what happened) rather than seeing
    nothing at all from the dispatch.
    """
    return (
        f"## Status\n{status}"
        + (f" — {error}" if error else "")
        + f"\n\n## Target\n(summariser failed; trace not available to planner)"
        f"\n\n## Inputs tried\n(summariser unavailable — see "
        f"`logs/run-<id>/worker-{agent_id}-*/trace.jsonl` on disk for "
        f"the full {iteration_count}-step trace)"
        f"\n\n## Server responses\n(unavailable)"
        f"\n\n## Inferred server-side behaviour\n(unavailable)"
        f"\n\n## NOT tried\n(unavailable)"
        f"\n\n## Recommended next dispatch\nRe-dispatch {config_name} or "
        f"pick a different skill; the previous run produced "
        f"{findings_count} structured finding(s)."
    )


# ── Re-dispatch helper: find the previous report for this agent_id ────


def find_prior_worker_report(
    messages: list[BaseMessage],
    agent_id: str,
) -> AIMessage | None:
    """Return the most recent ``worker_report`` ``AIMessage`` whose
    ``additional_kwargs.agent_id`` matches ``agent_id``, or ``None``.

    Used by ``_collect_prior_skill_history`` (in ``src/nodes/base.py``)
    to seed a re-dispatched worker with what the previous dispatch did.
    Walks the list in reverse so the FIRST hit is the most recent — this
    matters because a long benchmark may have many prior reports for the
    same agent_id, and only the latest is useful as next-step context.
    """
    if not messages or not agent_id:
        return None
    for m in reversed(messages):
        if not isinstance(m, AIMessage):
            continue
        akw = getattr(m, "additional_kwargs", None) or {}
        if akw.get("kind") != "worker_report":
            continue
        if akw.get("agent_id") != agent_id:
            continue
        return m
    return None
