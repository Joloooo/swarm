"""Initialize node — sets up the run with target info and defaults."""

from langchain_core.messages import HumanMessage

from src.state import SwarmGraphState


async def initialize_node(state: SwarmGraphState) -> dict:
    """Set up the run: validate target, set defaults."""
    return {
        "waf_detected": False,
        "stealth_level": 0,
        "tier2_activated": False,
        "messages": [
            HumanMessage(content=f"Starting penetration test against: {state['target_url']}")
        ],
    }
