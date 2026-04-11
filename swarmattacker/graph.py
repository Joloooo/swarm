"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

This is the root graph that:
1. Receives a target URL
2. Runs a reconnaissance agent first
3. Dispatches swarm agents in parallel (OWASP + vuln-type + custom)
4. Aggregates findings
5. Produces a final report

Phase 1 (skeleton): single recon agent only.
Phase 2 will add parallel swarm branches.
"""

from __future__ import annotations

from typing import Any, Literal

from langchain_core.messages import HumanMessage
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from swarmattacker.agents.base import AgentConfig, make_agent_node
from swarmattacker.agents.configs.registry import get_all_configs, get_config
from swarmattacker.llm.provider import LLMConfig, get_llm
from swarmattacker.state import SwarmGraphState
from swarmattacker.tools.terminal import run_command


# ---- Node functions ----

async def initialize(state: SwarmGraphState) -> dict:
    """Set up the run: validate target, set defaults."""
    return {
        "waf_detected": False,
        "stealth_level": 0,
        "tier2_activated": False,
        "messages": [
            HumanMessage(content=f"Starting penetration test against: {state['target_url']}")
        ],
    }


def route_after_recon(state: SwarmGraphState) -> list[Send]:
    """After recon, dispatch all configured swarm agents in parallel.

    Uses LangGraph's Send() to fan out to parallel agent nodes.
    Each Send targets the same 'swarm_agent' node but with different
    config passed via the state.
    """
    configs = get_all_configs()
    # Filter out the recon config (already ran)
    attack_configs = [c for c in configs if c.config_name != "recon"]

    if not attack_configs:
        # No attack agents configured — go straight to report
        return [Send("report", state)]

    return [
        Send("swarm_agent", {
            **state,
            "agent_id": config.agent_id,
            "config_name": config.config_name,
            "methodology": config.methodology,
        })
        for config in attack_configs
    ]


async def swarm_agent(state: dict) -> dict:
    """Generic swarm agent node — loads config by config_name and runs it."""
    config_name = state.get("config_name", "")
    config = get_config(config_name)
    if config is None:
        return {"agent_results": [], "active_agents": []}

    node_fn = make_agent_node(config)
    return await node_fn(state)


async def report(state: SwarmGraphState) -> dict:
    """Aggregate all findings into a final report message."""
    findings = state.get("findings", [])
    results = state.get("agent_results", [])

    completed = [r for r in results if r.completed]
    failed = [r for r in results if r.error]

    summary_lines = [
        f"## SwarmAttacker Report",
        f"**Target:** {state.get('target_url', 'unknown')}",
        f"**Agents completed:** {len(completed)}",
        f"**Agents failed:** {len(failed)}",
        f"**Total findings:** {len(findings)}",
        "",
    ]

    if findings:
        summary_lines.append("### Findings")
        for f in findings:
            summary_lines.append(
                f"- [{f.severity.value.upper()}] {f.title} ({f.category})"
            )

    if failed:
        summary_lines.append("\n### Errors")
        for r in failed:
            summary_lines.append(f"- {r.agent_id}: {r.error}")

    return {
        "messages": [HumanMessage(content="\n".join(summary_lines))],
    }


# ---- Graph construction ----

def build_graph() -> StateGraph:
    """Build the SwarmAttacker LangGraph graph.

    Returns the compiled graph, ready for `.invoke()` or LangGraph Studio.
    """
    # Get the recon config
    recon_config = get_config("recon")
    if recon_config is None:
        raise ValueError("No 'recon' agent config found. Cannot build graph.")

    recon_node = make_agent_node(recon_config)

    graph = StateGraph(SwarmGraphState)

    # Nodes
    graph.add_node("initialize", initialize)
    graph.add_node("recon", recon_node)
    graph.add_node("swarm_agent", swarm_agent)
    graph.add_node("report", report)

    # Edges
    graph.add_edge(START, "initialize")
    graph.add_edge("initialize", "recon")
    graph.add_conditional_edges("recon", route_after_recon, ["swarm_agent", "report"])
    graph.add_edge("swarm_agent", "report")
    graph.add_edge("report", END)

    return graph.compile()


# The compiled graph — imported by langgraph.json for Studio
graph = build_graph()
