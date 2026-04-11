"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

This is the root graph that:
1. Receives a target URL and runtime config
2. Runs a reconnaissance agent first
3. Routes through Tier 1 (deterministic) and optionally Tier 2 (dynamic)
4. Dispatches swarm agents in parallel (OWASP + vuln-type + custom)
5. Runs stealth monitoring across all agent outputs
6. Aggregates findings into a final report
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from src.agents.base import AgentConfig, make_agent_node
from src.agents.configs.registry import get_all_configs, get_config
from src.config import is_enabled, load_config
from src.llm.provider import LLMConfig, get_llm
from src.planning.router import route
from src.state import SwarmGraphState
from src.stealth.monitor import StealthMonitor
from src.tools.terminal import run_command

logger = logging.getLogger(__name__)

# Module-level stealth monitor (shared across all agents in a run)
_stealth_monitor = StealthMonitor()


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


async def recon(state: SwarmGraphState) -> dict:
    """Run the reconnaissance agent."""
    recon_config = get_config("recon")
    if recon_config is None:
        return {"messages": [AIMessage(content="ERROR: No recon config found.")]}

    node_fn = make_agent_node(recon_config)
    return await node_fn(state)


def route_after_recon(state: SwarmGraphState) -> list[Send]:
    """After recon, use Tier 1 router to decide which agents to dispatch.

    Uses LangGraph's Send() to fan out to parallel agent nodes.
    The router analyzes recon output and selects relevant agents.
    """
    # Extract recon output from the last messages
    messages = state.get("messages", [])
    recon_output = ""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content:
            recon_output = msg.content if isinstance(msg.content, str) else str(msg.content)
            break

    # Run Tier 1 router
    decision = route(recon_output)

    logger.info(
        f"Tier 1 router selected {len(decision.agent_configs)} agents: "
        f"{[c.agent_id for c in decision.agent_configs]}"
    )
    for reason in decision.reasoning:
        logger.info(f"  {reason}")

    configs = decision.agent_configs

    if not configs:
        return [Send("report", state)]

    return [
        Send("swarm_agent", {
            **state,
            "agent_id": config.agent_id,
            "config_name": config.config_name,
            "methodology": config.methodology,
        })
        for config in configs
    ]


async def swarm_agent(state: dict) -> dict:
    """Generic swarm agent node — loads config by config_name and runs it.

    This is the target of Send() calls from the router. Each parallel
    invocation gets a different config_name via the state.
    """
    config_name = state.get("config_name", "")
    config = get_config(config_name)
    if config is None:
        logger.warning(f"Config not found: {config_name}")
        return {"agent_results": [], "active_agents": [], "findings": []}

    node_fn = make_agent_node(config)
    result = await node_fn(state)

    # Stealth monitoring: check agent output for WAF/IDS signals
    agent_results = result.get("agent_results", [])
    for ar in agent_results:
        if ar.findings:
            for finding in ar.findings:
                alert = _stealth_monitor.analyze_output(finding.evidence)
                if alert.detected:
                    logger.warning(
                        f"Stealth alert from {config_name}: "
                        f"{alert.waf_name} ({alert.alert_type})"
                    )
                    result["waf_detected"] = True
                    result["stealth_level"] = max(
                        state.get("stealth_level", 0),
                        alert.recommended_level,
                    )

    return result


async def check_tier2(state: SwarmGraphState) -> dict:
    """Check if Tier 2 dynamic planner should activate.

    Runs after the first wave of swarm agents complete.
    If findings are sparse or agents failed, generates dynamic agents.
    """
    results = state.get("agent_results", [])
    findings = state.get("findings", [])
    failed = [r for r in results if r.error]
    completed = [r for r in results if r.completed]

    # Skip Tier 2 if we already have good results
    if len(findings) >= 3 or not completed:
        return {}

    # Skip if Tier 2 is disabled
    try:
        config = load_config()
        if not is_enabled(config, "planning", "tier2_planner"):
            return {}
    except FileNotFoundError:
        pass  # No config file — allow Tier 2 by default

    logger.info("Tier 2 planner activating — few findings from Tier 1 agents")

    # Get recon output
    messages = state.get("messages", [])
    recon_output = ""
    for msg in messages:
        if isinstance(msg, AIMessage) and msg.content:
            recon_output = msg.content if isinstance(msg.content, str) else str(msg.content)
            break

    try:
        from src.planning.planner import dynamic_plan

        dynamic_configs = await dynamic_plan(
            recon_output=recon_output,
            existing_findings=findings,
            failed_agents=[r.agent_id for r in failed],
        )

        if dynamic_configs:
            return {
                "tier2_activated": True,
                "messages": [
                    HumanMessage(
                        content=f"Tier 2 planner generated {len(dynamic_configs)} "
                        f"dynamic agents: {[c.agent_id for c in dynamic_configs]}"
                    )
                ],
            }
    except Exception as e:
        logger.error(f"Tier 2 planner failed: {e}")

    return {}


def route_tier2(state: SwarmGraphState) -> Literal["report"]:
    """After Tier 2 check, always proceed to report.

    Future enhancement: dispatch Tier 2 dynamic agents before report.
    """
    return "report"


async def report(state: SwarmGraphState) -> dict:
    """Aggregate all findings into a final report message."""
    findings = state.get("findings", [])
    results = state.get("agent_results", [])

    completed = [r for r in results if r.completed]
    failed = [r for r in results if r.error]

    # Sort findings by severity
    severity_order = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
    }
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.severity.value, 5),
    )

    summary_lines = [
        "## SwarmAttacker Penetration Test Report",
        f"**Target:** {state.get('target_url', 'unknown')}",
        f"**Scope:** {state.get('target_scope', 'unknown')}",
        f"**Agents completed:** {len(completed)}",
        f"**Agents failed:** {len(failed)}",
        f"**Total findings:** {len(findings)}",
        f"**WAF detected:** {'Yes' if state.get('waf_detected') else 'No'}",
        f"**Stealth level:** {state.get('stealth_level', 0)}",
        f"**Tier 2 activated:** {'Yes' if state.get('tier2_activated') else 'No'}",
        "",
    ]

    if sorted_findings:
        summary_lines.append("### Findings (by severity)")
        for f in sorted_findings:
            lines = [f"#### [{f.severity.value.upper()}] {f.title}"]
            lines.append(f"- **Category:** {f.category}")
            if f.url:
                lines.append(f"- **URL:** {f.url}")
            if f.cwe:
                lines.append(f"- **CWE:** {f.cwe}")
            lines.append(f"- **Found by:** {f.agent_id}")
            if f.evidence:
                lines.append(f"- **Evidence:** {f.evidence[:200]}")
            summary_lines.extend(lines)
            summary_lines.append("")
    else:
        summary_lines.append("### No vulnerabilities found")
        summary_lines.append(
            "The swarm completed testing but did not identify any "
            "vulnerabilities. This could mean the target is well-secured "
            "or that additional testing methodologies are needed."
        )

    if failed:
        summary_lines.append("\n### Agent Errors")
        for r in failed:
            summary_lines.append(f"- **{r.agent_id}:** {r.error}")

    # Agent summary
    summary_lines.append("\n### Agent Summary")
    for r in results:
        status = "completed" if r.completed else f"FAILED: {r.error}"
        finding_count = len(r.findings) if r.findings else 0
        summary_lines.append(
            f"- **{r.agent_id}** ({r.methodology}/{r.config_name}): "
            f"{status}, {finding_count} findings"
        )

    return {
        "messages": [HumanMessage(content="\n".join(summary_lines))],
    }


# ---- Graph construction ----


def build_graph() -> StateGraph:
    """Build the SwarmAttacker LangGraph graph.

    Flow:
        START → initialize → recon → [router fans out] → swarm_agent(s)
            → check_tier2 → report → END
    """
    graph = StateGraph(SwarmGraphState)

    # Nodes
    graph.add_node("initialize", initialize)
    graph.add_node("recon", recon)
    graph.add_node("swarm_agent", swarm_agent)
    graph.add_node("check_tier2", check_tier2)
    graph.add_node("report", report)

    # Edges
    graph.add_edge(START, "initialize")
    graph.add_edge("initialize", "recon")
    graph.add_conditional_edges("recon", route_after_recon, ["swarm_agent", "report"])
    graph.add_edge("swarm_agent", "check_tier2")
    graph.add_conditional_edges("check_tier2", route_tier2, ["report"])
    graph.add_edge("report", END)

    return graph.compile()


# The compiled graph — imported by langgraph.json for Studio
graph = build_graph()
