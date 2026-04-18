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


def _coerce_content(content) -> str:
    """Flatten a LangChain message content value to a plain string.

    Providers return either a str or a list of content blocks like
    ``[{"type": "text", "text": "..."}]``. Both forms are flattened
    here so downstream consumers don't have to care.
    """
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
    return str(content) if content else ""


def _last_real_agent_text(messages: list) -> str:
    """Find the most recent real *agent* AIMessage in the history.

    We're looking for recon output (or, after a prior attack pass, the
    last attack agent's output). That means skipping:

    - Boundary messages emitted by ``graph.py:traced()`` (tagged with
      ``additional_kwargs["node"]``). These are ``✅ [name] Xms`` chat
      chrome, not actual agent reasoning.
    - Refusal / error messages (``additional_kwargs["refusal"]`` or
      ``["error"]``) produced by ``agents/base.py`` when a model
      refuses or crashes.
    - The supervisor planner's own JSON-decision message — it has no
      ``agent_id`` kwarg because ``planner_node`` uses
      ``create_react_agent`` directly rather than ``make_agent_node``.

    We prefer messages tagged with an ``agent_id`` kwarg (those come
    from ``make_agent_node`` — real agents' output) and return the
    latest such message's content.
    """
    for msg in reversed(messages):
        if not isinstance(msg, AIMessage) or not msg.content:
            continue
        kw = getattr(msg, "additional_kwargs", {}) or {}
        if kw.get("node") or kw.get("refusal") or kw.get("error"):
            continue
        if not kw.get("agent_id"):
            # Untagged: most likely the planner's own output — skip.
            continue
        return _coerce_content(msg.content)
    return ""


async def playbook_dispatch_node(state: SwarmGraphState) -> dict:
    """Stage a parallel batch of playbook-library workflows."""
    recon_text = _last_real_agent_text(state.get("messages", []))
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
