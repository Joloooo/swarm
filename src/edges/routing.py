"""Routing edge — translates supervisor decisions into graph transitions.

One edge function lives here. :func:`route_after_planner` reads the
supervisor's state update and returns either a node name (for
``recon`` / ``web_search`` / ``report``) or a list of :class:`Send`
calls (for ``attack``, which fans out to parallel ``pentest_workflow``
runs — one per entry in ``state["pending_dispatch"]``).

The planner itself is responsible for populating ``pending_dispatch``
when it picks ``action="attack"``; this edge only reads it.
"""

from __future__ import annotations

import logging
from typing import Union

from langgraph.types import Send

from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


def route_after_planner(state: SwarmGraphState) -> Union[str, list[Send]]:
    """Pick the next graph transition based on the supervisor's decision.

    For ``attack``: return a list of Send()s, one per staged dispatch
    item. If the planner wrote an empty list (defensive — it should
    have flipped to report itself), fall back to the report node.

    For every other action: return the node name as a string.
    """
    action = state.get("next_action", "report")

    if action == "attack":
        pending = state.get("pending_dispatch") or []
        if not pending:
            logger.warning(
                "route_after_planner: action=attack but pending_dispatch "
                "is empty; routing to report."
            )
            return "report"
        logger.info(
            "route_after_planner: fanning out %d parallel pentest_workflow(s).",
            len(pending),
        )
        return [
            Send(
                "pentest_workflow",
                {
                    **state,
                    "agent_id": item["agent_id"],
                    "config_name": item["config_name"],
                    "methodology": item["methodology"],
                    "mode": item.get("mode", "analyze"),
                },
            )
            for item in pending
        ]

    if action in {"recon", "web_search", "report"}:
        return action

    logger.warning(
        "route_after_planner: unknown next_action=%r, routing to report.",
        action,
    )
    return "report"
