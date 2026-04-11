"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

Flow:
    START → initialize → recon → [router fans out] → swarm_agent(s)
        → check_tier2 → report → END
"""

from langgraph.graph import END, START, StateGraph

from src.edges import route_after_recon, route_tier2
from src.nodes import (
    initialize_node,
    recon_node,
    swarm_agent_node,
    check_tier2_node,
    report_node,
)
from src.state import SwarmGraphState


def build_graph():
    """Build and compile the SwarmAttacker graph."""
    graph = StateGraph(SwarmGraphState)

    # Nodes
    graph.add_node("initialize", initialize_node)
    graph.add_node("recon", recon_node)
    graph.add_node("swarm_agent", swarm_agent_node)
    graph.add_node("check_tier2", check_tier2_node)
    graph.add_node("report", report_node)

    # Edges
    graph.add_edge(START, "initialize")
    graph.add_edge("initialize", "recon")
    graph.add_conditional_edges("recon", route_after_recon, ["swarm_agent", "report"])
    graph.add_edge("swarm_agent", "check_tier2")
    graph.add_conditional_edges("check_tier2", route_tier2, ["report"])
    graph.add_edge("report", END)

    return graph.compile()


# Compiled graph — imported by langgraph.json for Studio
graph = build_graph()
