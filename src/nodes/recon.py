"""Recon node — runs the reconnaissance agent."""

from langchain_core.messages import AIMessage

from src.nodes.base import BaseNode
from src.state import SwarmGraphState


class ReconNode(BaseNode):
    """Run the reconnaissance agent and mark recon as done for the planner."""

    async def execute(self, state: SwarmGraphState) -> dict:
        recon_config = self.load_skill("recon")
        if recon_config is None:
            return {
                "recon_done": True,
                "messages": [AIMessage(content="ERROR: No recon skill found.")],
            }

        result = await self.run_skill_agent(recon_config, state)
        # Flag recon_done so the supervisor can avoid asking for recon
        # again on its next turn unless it explicitly wants a second pass.
        result.setdefault("recon_done", True)
        return result


recon_node = ReconNode()
