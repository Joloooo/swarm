"""Recon node — runs one reconnaissance dimension agent.

Recon fans out into parallel dimension workers, exactly like the attack
phase fans out executors: :func:`src.edges.routing.route_after_planner`
emits one ``Send("recon", {... "config_name": <dim> ...})`` per recon
dimension (currently ``recon`` for the HTTP/app surface and
``recon-ports`` for the network/service surface). This node is therefore
dimension-agnostic — it loads whatever skill the Send carries, the same
way :class:`src.nodes.executor.ExecutorNode` does. The default is the
``recon`` (web/app) skill so a bare invocation still behaves as before.

All branches converge on the summarizer barrier (static ``recon →
summarizer`` edge); the ``recon`` branch's report becomes the canonical
"Application map" (``recon_summary``), and the other dimensions reach the
planner as ordinary worker reports.
"""

import dataclasses

from langchain_core.messages import AIMessage

from src.nodes.base import BaseNode
from src.state import SwarmGraphState


class ReconNode(BaseNode):
    """Run one reconnaissance dimension and mark recon as done."""

    async def execute(self, state: SwarmGraphState) -> dict:
        config_name = state.get("config_name") or "recon"
        recon_config = self.load_skill(config_name)
        if recon_config is None:
            self.log.warning("Recon skill not found: %s", config_name)
            return {
                "recon_done": True,
                "messages": [
                    AIMessage(content=f"ERROR: No recon skill '{config_name}' found.")
                ],
            }

        # The recon node owns the recon framing: force the recon phase on
        # whatever skill it runs, so skills no longer carry a ``phase`` field.
        recon_config = dataclasses.replace(recon_config, phase="recon")

        self.log.info("[%s] Starting recon agent", config_name)
        result = await self.run_skill_agent(recon_config, state)
        # Flag recon_done so the supervisor can avoid asking for recon
        # again on its next turn unless it explicitly wants a second pass.
        # Every parallel dimension writes this; the sticky-True reducer
        # in ``src/state.py`` collapses the concurrent writes.
        result.setdefault("recon_done", True)
        return result


recon_node = ReconNode()
