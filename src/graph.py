"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

Supervisor-shaped graph: one planner node is the only decision-maker,
every worker node edges back to it. The planner emits a JSON directive
picking the next action — recon, playbook, dynamic, or report — and
the graph transitions accordingly.

Flow::

    START → initialize → planner ←────────────────────────────┐
                           │                                  │
          ┌────────────────┼────────────────┬─────────────┐   │
          ↓                ↓                ↓             ↓   │
        recon    playbook_dispatch   dynamic_dispatch  report │
          │                │                │            │    │
          │                └── pentest_workflow (parallel) ┘  │
          └──────────── all worker returns ────────────────────┘
                                                     report → END
"""

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
)
from src.state import SwarmGraphState


def build_graph():
    """Build and compile the SwarmAttacker graph."""
    graph = StateGraph(SwarmGraphState)

    # Nodes
    graph.add_node("initialize", initialize_node)
    graph.add_node("planner", planner_node)
    graph.add_node("recon", recon_node)
    graph.add_node("playbook_dispatch", playbook_dispatch_node)
    graph.add_node("dynamic_dispatch", dynamic_dispatch_node)
    graph.add_node("pentest_workflow", pentest_workflow_node)
    graph.add_node("report", report_node)

    # Edges
    graph.add_edge(START, "initialize")
    graph.add_edge("initialize", "planner")

    # Supervisor branches to one of four nodes based on its JSON decision.
    graph.add_conditional_edges(
        "planner",
        route_after_planner,
        ["recon", "playbook_dispatch", "dynamic_dispatch", "report"],
    )

    # Workers always return to the supervisor so it can reassess.
    graph.add_edge("recon", "planner")
    graph.add_edge("pentest_workflow", "planner")

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
