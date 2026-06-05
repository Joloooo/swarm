"""Graceful wrap-up — force a clean summary when a worker hits its step budget.

Why this exists
---------------

A worker's per-run budget is its LangGraph ``recursion_limit``
(``config.max_iterations``). When it is exhausted mid-loop, LangGraph
raises ``GraphRecursionError``. Crucially, the model itself is still
perfectly reachable — the worker simply ran out of turns. So the right
recovery is **not** the post-crash *salvage* path: salvage
(:mod:`src.refusals.salvage`) exists for the case the LLM channel is
dead — a Codex ``cyber_policy`` refusal — and can only *guess* a finding
from a tail of the trace with a separate classifier call.

Instead we make ONE more LLM call that hands the worker its own partial
trace and asks it to STOP testing and write a clean summary plus any
findings it had not yet formalized, using the same ``**FINDING:**``
schema the success path already parses. A budget-stopped worker then
contributes exactly what a naturally-finished one would: its own
``**FINDING:**`` blocks (recovered from the partial trace) plus a forced
wrap-up — never a silently discarded run.

The two recovery paths, side by side:

  * **salvage**  → the LLM refused / is unreachable; reconstruct impact
                   from a tail with a *separate* classifier call. A last
                   resort for genuine crashes.
  * **wrap-up**  → the LLM works; the worker just ran out of turns. Ask
                   it to summarize its own work. The first-class recovery
                   for a step-budget stop.

Cost model: one bounded sub-LLM call per budget-stopped worker (the tail
is clipped, like salvage's), and any failure on this call is swallowed so
the stop path stays graceful regardless.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

if TYPE_CHECKING:
    from src.nodes.base import AgentConfig

logger = logging.getLogger(__name__)


_WRAPUP_SYSTEM = (
    "You are a security testing assistant. The trace below is your own "
    "work on an authorized test target. You have reached the step budget "
    "for this pass and must stop testing now — do not request any more "
    "tool calls. Summarize what you did and report any findings you "
    "confirmed, using the **FINDING:** schema for each one. Be concise "
    "and accurate: report only what the trace actually shows, and never "
    "invent impact you did not observe."
)


def _format_tail(messages: list[Any], *, n: int = 16) -> str:
    """Render the trailing N tool/assistant messages as one text block.

    Each ToolMessage is clipped to 1500 chars so a noisy scan output
    cannot blow up the prompt; AIMessage narration is kept (clipped to
    1200) because the "I just confirmed X" thought often lives there.
    Mirrors :func:`src.refusals.salvage._format_tail` but owns its copy
    so the two recovery paths stay decoupled.
    """
    tail: list[str] = []
    seen = 0
    for msg in reversed(messages):
        if isinstance(msg, ToolMessage):
            content = (
                msg.content if isinstance(msg.content, str) else str(msg.content)
            )
            tool_name = getattr(msg, "name", "tool") or "tool"
            tail.append(f"### tool[{tool_name}]\n{content[:1500]}")
            seen += 1
        elif isinstance(msg, AIMessage):
            content = (
                msg.content if isinstance(msg.content, str) else str(msg.content)
            )
            if content.strip():
                tail.append(f"### assistant\n{content[:1200]}")
                seen += 1
        if seen >= n:
            break
    return "\n\n".join(reversed(tail))


async def force_wrapup_summary(
    *,
    config: "AgentConfig",
    partial_messages: list,
    target_url: str = "",
    log: logging.Logger | None = None,
    run_id: str | None = None,
) -> AIMessage | None:
    """Ask a budget-stopped worker to wrap up its own work in one call.

    Returns an ``AIMessage`` containing the worker's forced summary (with
    any ``**FINDING:**`` blocks it chose to emit), or ``None`` when there
    was no partial trace or the call failed. The caller runs
    ``_extract_findings`` over the returned message to pull out findings,
    exactly as it does on the natural-completion path.
    """
    log = log or logger
    if not partial_messages:
        return None
    try:
        from src.llm.provider import get_llm
        from src.llm.callbacks import make_call_config

        llm = get_llm()
        tail = _format_tail(partial_messages)
        user_prompt = (
            "You reached your step budget and must stop now. Do NOT ask "
            "for more tool calls.\n\n"
            "Write two things:\n"
            "1. Any confirmed finding you have not yet written up — each as "
            "a **FINDING:** block (Title / Severity / Category / URL / "
            "Evidence). Only real, observed results.\n"
            "2. A short summary for the lead: what you tested, what worked, "
            "what looked promising but unfinished, and the single most "
            "useful next step.\n\n"
            f"Target (for context): {target_url or 'unknown'}\n\n"
            "## Your work so far (most recent at the bottom)\n\n"
            f"{tail}"
        )
        # Distinct synthetic agent_id so the wrap-up call is visible in
        # llm_calls.jsonl without losing the attribution chain.
        cfg = make_call_config(
            run_id=run_id,
            agent_id=f"{config.agent_id}__wrapup",
            node="wrapup",
        )
        resp = await llm.ainvoke(
            [
                SystemMessage(content=_WRAPUP_SYSTEM),
                HumanMessage(content=user_prompt),
            ],
            config=cfg,
        )
    except Exception as e:  # noqa: BLE001
        # The wrap-up call must never make the stop path worse — a
        # refusal or transport error here just means we fall back to the
        # findings the worker already wrote before the budget ran out.
        log.warning(
            "[%s] forced wrap-up call failed (%s): %s",
            config.agent_id, type(e).__name__, str(e)[:160],
        )
        return None

    text = resp.content if isinstance(resp.content, str) else str(resp.content)
    return AIMessage(
        content=text,
        additional_kwargs={
            "agent_id": config.agent_id,
            "kind": "forced_wrapup",
        },
    )
