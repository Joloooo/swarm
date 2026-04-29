"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

Supervisor-shaped graph: one planner node is the only decision-maker,
every worker node edges back to it. The planner emits a JSON directive
picking the next action — recon, attack (with the list of configs to
fan out), web_search, or report — and the graph transitions accordingly.

Every node goes through :func:`traced`, which wraps it to:

1. Time the node and append a boundary ``✅ [name] Xms — summary``
   AIMessage so LangGraph Studio chat shows continuous progress
   instead of a blank screen during long-running parallel work.
2. Catch crashes and surface them as a visible ``❌`` error message
   instead of failing the whole graph silently.

Boundary messages are tagged with ``additional_kwargs={"node": name}``
so downstream consumers that scan message history can filter them out
and look at real agent output only.

Adding a new node? Register it through ``traced(name, fn)`` and it
inherits both behaviors — no per-node boilerplate.

Flow::

    START → initialize → planner ← ──────────────────────────┐
                          │                                   │
            ┌─────────────┼────────────────┬───────────┐      │
            ↓             ↓                ↓           ↓      │
          recon    pentest_workflow    web_search    report   │
            │      (×N parallel, via                  │       │
            │       Send() fan-out)                   │       │
            └─────── all workers return ──────────────┘       │
                          │                                   │
                          └───────────────────────────────────┘
                                          report → END
"""

from __future__ import annotations

import functools
import logging
import os
import sys
import time
from inspect import iscoroutinefunction

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph

from src.edges.routing import route_after_planner
from src.nodes import (
    initialize_node,
    pentest_workflow_node,
    planner_node,
    recon_node,
    report_node,
    web_search_node,
)
from src.observability import append_node_event, make_run_id
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
    """Wrap a node so it emits a boundary AIMessage and a JSONL event.

    Two side effects per call:
        1. Append an AIMessage to state.messages so Studio shows live
           progress (existing behavior).
        2. Append one line to ``logs/run-<run_id>/nodes.jsonl`` capturing
           the timestamp, node name, duration, summary, and full result
           dict — for thesis-grade post-run analysis.

    The run_id is read from state. If absent (e.g. Studio runs that
    bypass the runner), one is derived on the fly from target_url.
    """

    @functools.wraps(fn)
    async def wrapped(state):
        run_id = (state or {}).get("run_id") or make_run_id(
            target_url=(state or {}).get("target_url"),
        )

        t0 = time.perf_counter()
        try:
            if iscoroutinefunction(fn):
                result = await fn(state)
            else:
                result = fn(state)
        except Exception as e:  # noqa: BLE001 — visibility > strictness here
            dt_ms = int((time.perf_counter() - t0) * 1000)
            logger.exception("[%s] crashed after %dms", name, dt_ms)
            append_node_event(run_id, {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "node": name,
                "duration_ms": dt_ms,
                "error": f"{type(e).__name__}: {e}",
                "summary": "",
                "result": None,
            })
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
        append_node_event(run_id, {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "node": name,
            "duration_ms": dt_ms,
            "summary": summary,
            "result": result,
        })
        if os.getenv("SWARM_VERBOSE"):
            ts_short = time.strftime("%H:%M:%S")
            print(
                f"\n─── [{ts_short}] node `{name}` finished in {dt_ms} ms ───\n"
                f"    {summary}",
                file=sys.stderr, flush=True,
            )
            # Print any new AI messages this node added so the full
            # reasoning stream lives in the same terminal.
            for msg in result.get("messages") or []:
                content = getattr(msg, "content", None)
                if not content:
                    continue
                # Filter out the ✅ boundary messages we ourselves emit
                # (added below) so we don't log them twice.
                kw = getattr(msg, "additional_kwargs", None) or {}
                if kw.get("node") and isinstance(content, str) and (
                    content.startswith("✅ [") or content.startswith("❌ [")
                ):
                    continue
                role = type(msg).__name__
                text = content if isinstance(content, str) else str(content)
                print(
                    f"    └── {role}:",
                    file=sys.stderr, flush=True,
                )
                for line in text.splitlines() or [""]:
                    print(f"        {line}", file=sys.stderr, flush=True)
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
    graph.add_node("planner",          traced("planner",          planner_node))
    graph.add_node("recon",            traced("recon",            recon_node))
    graph.add_node("pentest_workflow", traced("pentest_workflow", pentest_workflow_node))
    graph.add_node("web_search",       traced("web_search",       web_search_node))
    graph.add_node("report",           traced("report",           report_node))

    # Edges
    graph.add_edge(START, "initialize")
    graph.add_edge("initialize", "planner")

    # Supervisor is the only decision-maker. `route_after_planner` returns
    # either a node name (recon / web_search / report) OR a list of Send()
    # calls that fan out to parallel pentest_workflow runs for "attack".
    graph.add_conditional_edges(
        "planner",
        route_after_planner,
        [
            "recon",
            "pentest_workflow",
            "web_search",
            "report",
        ],
    )

    # Workers always return to the supervisor so it can reassess.
    graph.add_edge("recon", "planner")
    graph.add_edge("pentest_workflow", "planner")
    graph.add_edge("web_search", "planner")

    graph.add_edge("report", END)

    return graph.compile()


# Compiled graph — imported by langgraph.json for Studio
graph = build_graph()
