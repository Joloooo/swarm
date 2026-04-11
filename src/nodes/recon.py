"""Recon node — runs the reconnaissance agent."""

from langchain_core.messages import AIMessage

from src.agents.base import make_agent_node
from src.agents.configs.registry import get_config
from src.state import SwarmGraphState


async def recon_node(state: SwarmGraphState) -> dict:
    """Run the reconnaissance agent."""
    recon_config = get_config("recon")
    if recon_config is None:
        return {"messages": [AIMessage(content="ERROR: No recon config found.")]}

    node_fn = make_agent_node(recon_config)
    return await node_fn(state)
