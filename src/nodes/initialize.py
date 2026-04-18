"""Initialize node — seeds defaults before the supervisor takes over.

Runs once at graph start. The target URL is NOT set here — the
supervisor planner populates ``target_url`` / ``target_scope`` on its
first turn, after reading the user's message and calling
``normalize_url``. This node only establishes the stealth baseline and
the supervisor iteration counter.
"""

from langchain_core.messages import AIMessage

from src.state import SwarmGraphState


async def initialize_node(state: SwarmGraphState) -> dict:
    """Seed stealth defaults and the planner iteration counter."""
    return {
        "waf_detected": False,
        "stealth_level": 0,
        "tier2_activated": False,
        "planner_iters": 0,
        "recon_done": False,
        "pending_dispatch": [],
        "messages": [
            AIMessage(
                content=(
                    "Starting SwarmAttacker planning session. Supervisor "
                    "will read the user's request and decide the next step."
                )
            )
        ],
    }
