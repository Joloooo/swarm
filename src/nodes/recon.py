"""Recon node — runs the reconnaissance agent."""

from langchain_core.messages import AIMessage

from src.agents.base import make_agent_node
from src.skills.loader import load_skill
from src.state import SwarmGraphState


async def recon_node(state: SwarmGraphState) -> dict:
    """Run the reconnaissance agent and mark recon as done for the planner."""
    recon_config = load_skill("recon")
    if recon_config is None:
        return {
            "recon_done": True,
            "messages": [AIMessage(content="ERROR: No recon skill found.")],
        }

    node_fn = make_agent_node(recon_config)
    result = await node_fn(state)
    # Flag recon_done so the supervisor can avoid asking for recon
    # again on its next turn unless it explicitly wants a second pass.
    result.setdefault("recon_done", True)
    return result
