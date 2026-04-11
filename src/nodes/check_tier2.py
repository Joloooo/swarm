"""Check Tier 2 node — decides if the dynamic planner should activate.

Runs after the first wave of swarm agents complete. If findings are
sparse or agents failed, invokes the LLM-based Tier 2 planner to
generate additional attack strategies.
"""

import logging

from langchain_core.messages import AIMessage, HumanMessage

from src.config import is_enabled, load_config
from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


async def check_tier2_node(state: SwarmGraphState) -> dict:
    """Check if Tier 2 dynamic planner should activate."""
    results = state.get("agent_results", [])
    findings = state.get("findings", [])
    failed = [r for r in results if r.error]
    completed = [r for r in results if r.completed]

    # Skip Tier 2 if we already have good results
    if len(findings) >= 3 or not completed:
        return {}

    # Skip if Tier 2 is disabled in config
    try:
        config = load_config()
        if not is_enabled(config, "planning", "tier2_planner"):
            return {}
    except FileNotFoundError:
        pass  # No config file — allow Tier 2 by default

    logger.info("Tier 2 planner activating — few findings from Tier 1 agents")

    # Get recon output from messages
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
