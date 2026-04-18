"""Routing edges — translate supervisor decisions into graph transitions.

Two edge functions live here:

- :func:`route_after_planner` reads ``state["next_action"]`` (set by
  the supervisor planner) and returns the next node name.
- :func:`fanout_pending_dispatch` is shared by ``playbook_dispatch``
  and ``dynamic_dispatch``. Both dispatch nodes populate
  ``state["pending_dispatch"]`` with the same shape; this edge turns
  that list into parallel :class:`Send` calls against
  ``pentest_workflow``. If the list is empty, the edge routes back to
  the supervisor so it can replan (typical when recon was empty and
  the playbook library picked nothing beyond the always-on set — or
  when the dynamic generator returned no strategies).
"""

from __future__ import annotations

import logging
from typing import Literal

from langgraph.types import Send

from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


_NextNode = Literal[
    "recon", "playbook_dispatch", "dynamic_dispatch", "web_search", "report"
]


def route_after_planner(state: SwarmGraphState) -> _NextNode:
    """Read the supervisor's decision and pick the next node."""
    action = state.get("next_action", "report")

    if action == "recon":
        return "recon"
    if action == "playbook":
        return "playbook_dispatch"
    if action == "dynamic":
        return "dynamic_dispatch"
    if action == "web_search":
        return "web_search"
    if action == "report":
        return "report"

    # Unknown / missing — fail safe by reporting.
    logger.warning(
        "route_after_planner: unknown next_action=%r, routing to report.",
        action,
    )
    return "report"


def fanout_pending_dispatch(state: SwarmGraphState) -> list:
    """Fan out staged dispatch items to parallel pentest_workflow runs.

    Reads ``state["pending_dispatch"]`` — a list of dicts shaped like
    ``{"agent_id", "config_name", "methodology", "mode"}`` — and emits
    one :class:`Send` per item. Empty list routes back to the planner.
    """
    pending = state.get("pending_dispatch", []) or []

    if not pending:
        logger.info(
            "fanout_pending_dispatch: nothing to dispatch, returning to planner."
        )
        return ["planner"]

    logger.info(
        "fanout_pending_dispatch: dispatching %d parallel workflow(s).",
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
