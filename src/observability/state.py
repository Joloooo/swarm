"""Pure helpers used by ``BaseNode.__call__`` to render node finishes.

This module used to host a much larger surface — state-shape snapshots,
per-node diffs, JSON serialisation of new messages / findings /
agent_results — used to populate ``logs/run-<run_id>/nodes.jsonl``.
The 2026-05 log consolidation removed that artefact (nobody read it in
practice, the same information is reconstructable from
``full_logs.jsonl``), so the only helpers that survive here are the
two that are still consumed elsewhere:

* :func:`_summarize_node_result` — builds the one-line summary that
  goes into the boundary ``✅ [name] Xms — summary`` AIMessage written
  by :class:`src.nodes.base.BaseNode`.``__call__`` and rendered live by
  :func:`src.observability.live.LIVE.node_finished`.

* :func:`_count_worker_iterations` — counts ``AIMessage`` entries in a
  worker trace that carry tool calls. Used by the summariser node and
  the worker run record to report how many tool-call rounds the worker
  actually attempted.
"""

from __future__ import annotations

from typing import Any


def _summarize_node_result(name: str, result: dict) -> str:
    """One-line summary of what a node returned, for the chat trace.

    ``name`` is kept in the signature for forward compatibility — the
    current implementation does not yet vary the summary by node, but
    future per-node phrasing would route through here.
    """
    del name  # currently unused — see docstring
    if not isinstance(result, dict):
        return "ok"
    parts = []
    if "findings" in result:
        parts.append(f"{len(result['findings'])} findings")
    if "agent_results" in result:
        ars = result["agent_results"] or []
        completed = sum(1 for a in ars if getattr(a, "completed", False))
        parts.append(f"{completed}/{len(ars)} agents ok")
    if result.get("active_agents"):
        parts.append(f"active: {','.join(result['active_agents'])}")
    if result.get("waf_detected"):
        parts.append(f"WAF (level {result.get('stealth_level', 0)})")
    if result.get("next_action"):
        parts.append(f"→ {result['next_action']}")
    if result.get("pending_dispatch"):
        parts.append(f"staged {len(result['pending_dispatch'])} workflow(s)")
    return ", ".join(parts) or "ok"


def _count_worker_iterations(trace: list[Any]) -> int:
    """How many tool-call iterations did the worker actually run?

    Counts ``AIMessage``s that carry tool calls (each one represents the
    worker deciding to invoke a tool). Doesn't count ``AIMessage``s
    without tool calls (the terminal "I'm done" message) or
    ``ToolMessage``s (those are responses, not iterations). Useful
    metadata for the summarizer prompt.
    """
    # Lazy import — keep the module import-light so nothing wants
    # langchain_core at module-load time.
    from langchain_core.messages import AIMessage

    count = 0
    for m in trace:
        if isinstance(m, AIMessage):
            tcs = getattr(m, "tool_calls", None) or []
            if tcs:
                count += 1
    return count
