"""Playbook dispatch node — expands recon output into parallel workflows.

Invoked by the supervisor planner when it picks ``action="playbook"``.
Reads whatever recon text is available in the message history, calls
the deterministic playbook library (``src.planning.playbook_library``)
to pick from ~12 pre-defined attack configs, and stages the resulting
configs in ``state["pending_dispatch"]`` for the shared fan-out edge
(``fanout_pending_dispatch``) to turn into parallel
``pentest_workflow`` invocations via ``Send()``.

This node does not itself call ``Send()`` — that happens in the
conditional edge so the graph topology (which nodes can be targeted)
stays declarative.
"""

from __future__ import annotations

import logging

from langchain_core.messages import AIMessage

from src.planning.playbook_library import route
from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


def _last_ai_text(messages: list) -> str:
    """Return the most recent AIMessage content as a plain string.

    Works across provider formats: some return str content, some return
    a list of content blocks.
    """
    for msg in reversed(messages):
        if not isinstance(msg, AIMessage):
            continue
        content = msg.content
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    parts.append(block.get("text") or block.get("content") or "")
                else:
                    parts.append(str(block))
            return "\n".join(parts)
        return str(content)
    return ""


async def playbook_dispatch_node(state: SwarmGraphState) -> dict:
    """Stage a parallel batch of playbook-library workflows."""
    recon_text = _last_ai_text(state.get("messages", []))
    decision = route(recon_text)

    mode = state.get("mode", "analyze")
    pending = [
        {
            "agent_id": cfg.agent_id,
            "config_name": cfg.config_name,
            "methodology": cfg.methodology,
            "mode": mode,
        }
        for cfg in decision.agent_configs
    ]

    logger.info(
        "playbook_dispatch staged %d workflow(s): %s",
        len(pending),
        [p["config_name"] for p in pending],
    )
    for reason in decision.reasoning:
        logger.info("  %s", reason)

    return {"pending_dispatch": pending}
