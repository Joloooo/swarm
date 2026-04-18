"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

Flow:
    START → initialize → recon → [router fans out] → pentest_workflow(s)
        → check_tier2 → report → END

Every node is registered through `traced()`, which wraps it to:
    1. Time the node and append a boundary `[name] Xms — summary` AIMessage
       so the LangGraph Studio chat shows continuous progress instead of a
       blank screen during long-running parallel work.
    2. Catch crashes and surface them as a visible error message instead of
       failing the whole graph silently.

Adding a new node? Register it through `traced(name, fn)` and it inherits
both behaviors — no per-node boilerplate.
"""

from __future__ import annotations

import functools
import logging
import time
from inspect import iscoroutinefunction

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph

from src.edges import route_after_recon, route_tier2
from src.nodes import (
    initialize_node,
    recon_node,
    pentest_workflow_node,
    check_tier2_node,
    report_node,
)
from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


def _route_after_initialize(state: SwarmGraphState) -> str:
    """Skip straight to the report if no target URL was provided."""
    return "recon" if state.get("target_url") else "report"


def _summarize_node_result(name: str, result: dict) -> str:
    """One-line summary of what a node returned, for the chat trace."""
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
    return ", ".join(parts) or "ok"


def traced(name: str, fn):
    """Wrap a node so it emits a boundary AIMessage to state.messages.

    The wrapper is transparent — it returns the same shape the node returned
    plus a single trailing AIMessage tagged ``additional_kwargs={"node": name}``
    so downstream consumers (e.g. ``route_after_recon``) can filter it out
    when looking for actual agent output.
    """

    @functools.wraps(fn)
    async def wrapped(state):
        t0 = time.perf_counter()
        try:
            if iscoroutinefunction(fn):
                result = await fn(state)
            else:
                result = fn(state)
        except Exception as e:  # noqa: BLE001 — visibility > strictness here
            dt_ms = int((time.perf_counter() - t0) * 1000)
            logger.exception(f"[{name}] crashed after {dt_ms}ms")
            return {
                "messages": [
                    AIMessage(
                        content=f"❌ [{name}] crashed after {dt_ms}ms: {e}",
                        additional_kwargs={"node": name, "error": True},
                    )
                ]
            }

        result = result or {}
        dt_ms = int((time.perf_counter() - t0) * 1000)
        summary = _summarize_node_result(name, result)
        msgs = list(result.get("messages") or [])
        msgs.append(
            AIMessage(
                content=f"✅ [{name}] {dt_ms}ms — {summary}",
                additional_kwargs={"node": name},
            )
        )
        return {**result, "messages": msgs}

    wrapped.__name__ = f"traced_{name}"
    return wrapped


def build_graph():
    """Build and compile the SwarmAttacker graph."""
    graph = StateGraph(SwarmGraphState)

    # Every node goes through traced() so chat shows boundary messages.
    # Future nodes registered the same way inherit the behavior automatically.
    graph.add_node("initialize",       traced("initialize",       initialize_node))
    graph.add_node("recon",            traced("recon",            recon_node))
    graph.add_node("pentest_workflow", traced("pentest_workflow", pentest_workflow_node))
    graph.add_node("check_tier2",      traced("check_tier2",      check_tier2_node))
    graph.add_node("report",           traced("report",           report_node))

    # Edges
    graph.add_edge(START, "initialize")
    graph.add_conditional_edges(
        "initialize", _route_after_initialize, ["recon", "report"]
    )
    graph.add_conditional_edges("recon", route_after_recon, ["pentest_workflow", "report"])
    graph.add_edge("pentest_workflow", "check_tier2")
    graph.add_conditional_edges("check_tier2", route_tier2, ["report"])
    graph.add_edge("report", END)

    return graph.compile()


# Compiled graph — imported by langgraph.json for Studio
graph = build_graph()
