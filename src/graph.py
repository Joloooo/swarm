"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

Supervisor-shaped graph: one planner node is the only decision-maker,
every worker node edges back to it. The planner emits a JSON directive
picking the next action — recon, playbook, dynamic, web_search, or
report — and the graph transitions accordingly.

Every node goes through :func:`traced`, which wraps it to:

1. Time the node and append a boundary ``✅ [name] Xms — summary``
   AIMessage so LangGraph Studio chat shows continuous progress
   instead of a blank screen during long-running parallel work.
2. Catch crashes and surface them as a visible ``❌`` error message
   instead of failing the whole graph silently.

Boundary messages are tagged with ``additional_kwargs={"node": name}``
so downstream consumers that scan message history (e.g. the dispatch
nodes picking recon output) can filter them out and look at real agent
output only.

Adding a new node? Register it through ``traced(name, fn)`` and it
inherits both behaviors — no per-node boilerplate.

Flow::

    START → initialize → planner ←─────────────────────────────────────┐
                           │                                           │
          ┌────────────────┼────────────────┬─────────────┬─────────┐  │
          ↓                ↓                ↓             ↓         ↓  │
        recon    playbook_dispatch   dynamic_dispatch  web_search report
          │                │                │            │         │   │
          │                └── pentest_workflow (parallel) ┘        │   │
          └──────────── all worker returns ───────────────────────────┘
                                                            report → END
"""

from __future__ import annotations

import functools
import logging
import time
from inspect import iscoroutinefunction

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph

from src.edges.routing import fanout_pending_dispatch, route_after_planner
from src.nodes import (
    dynamic_dispatch_node,
    initialize_node,
    pentest_workflow_node,
    planner_node,
    playbook_dispatch_node,
    recon_node,
    report_node,
    web_search_node,
)
from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


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
    if result.get("next_action"):
        parts.append(f"→ {result['next_action']}")
    if result.get("pending_dispatch"):
        parts.append(f"staged {len(result['pending_dispatch'])} workflow(s)")
    return ", ".join(parts) or "ok"


def traced(name: str, fn):
    """Wrap a node so it emits a boundary AIMessage to state.messages.

    The wrapper is transparent — it returns the same shape the node
    returned plus a single trailing AIMessage tagged
    ``additional_kwargs={"node": name}`` so downstream consumers that
    read message history can filter it out when looking for actual
    agent output.
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
    graph.add_node("initialize",        traced("initialize",        initialize_node))
    graph.add_node("planner",           traced("planner",           planner_node))
    graph.add_node("recon",             traced("recon",             recon_node))
    graph.add_node("playbook_dispatch", traced("playbook_dispatch", playbook_dispatch_node))
    graph.add_node("dynamic_dispatch",  traced("dynamic_dispatch",  dynamic_dispatch_node))
    graph.add_node("pentest_workflow",  traced("pentest_workflow",  pentest_workflow_node))
    graph.add_node("web_search",        traced("web_search",        web_search_node))
    graph.add_node("report",            traced("report",            report_node))

    # Edges
    graph.add_edge(START, "initialize")
    graph.add_edge("initialize", "planner")

    # Supervisor branches to one of four nodes based on its JSON decision.
    # No separate skip-to-report routing from initialize — the supervisor
    # itself decides "report" on turn 1 if the user gave no usable target.
    graph.add_conditional_edges(
        "planner",
        route_after_planner,
        [
            "recon",
            "playbook_dispatch",
            "dynamic_dispatch",
            "web_search",
            "report",
        ],
    )

    # Workers always return to the supervisor so it can reassess.
    graph.add_edge("recon", "planner")
    graph.add_edge("pentest_workflow", "planner")
    graph.add_edge("web_search", "planner")

    # Dispatch nodes stage a list of configs, then fan out via the shared
    # edge. Empty dispatches route back to the planner so it can replan.
    graph.add_conditional_edges(
        "playbook_dispatch",
        fanout_pending_dispatch,
        ["pentest_workflow", "planner"],
    )
    graph.add_conditional_edges(
        "dynamic_dispatch",
        fanout_pending_dispatch,
        ["pentest_workflow", "planner"],
    )

    graph.add_edge("report", END)

    return graph.compile()


# Compiled graph — imported by langgraph.json for Studio
graph = build_graph()
