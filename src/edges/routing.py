"""Routing edges — conditional logic that decides which node runs next."""

import logging
from typing import Literal

from langchain_core.messages import AIMessage
from langgraph.types import Send

from src.planning.router import route
from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


def route_after_recon(state: SwarmGraphState) -> list[Send]:
    """After recon, use Tier 1 router to decide which agents to dispatch.

    Uses LangGraph's Send() to fan out to parallel agent nodes.
    The router analyzes recon output and selects relevant agents.
    """
    # Extract recon output from the last AI message
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

    mode = state.get("mode", "analyze")

    return [
        Send("pentest_workflow", {
            **state,
            "agent_id": config.agent_id,
            "config_name": config.config_name,
            "methodology": config.methodology,
            "mode": mode,
        })
        for config in configs
    ]


def route_tier2(state: SwarmGraphState) -> Literal["report"]:
    """After Tier 2 check, always proceed to report.

    Future enhancement: dispatch Tier 2 dynamic agents before report.
    """
    return "report"
