"""Routing edge — translates supervisor decisions into graph transitions.

One edge function lives here. :func:`route_after_planner` reads the
supervisor's state update and returns either a node name (for
``recon`` / ``web_search`` / ``report``) or a list of :class:`Send`
calls (for ``attack``, which fans out to parallel ``executor`` runs —
one per entry in ``state["pending_dispatch"]``).

The planner itself is responsible for populating ``pending_dispatch``
when it picks ``action="attack"``; this edge only reads it. Each entry
runs the same ExecutorNode — whether it's a pre-built skill, a
custom_config, or a generic free-form task is decided upstream by the
loader, which always lands the dispatch as an ``AgentConfig`` in cache.
"""

from __future__ import annotations

import logging
from typing import Union

from langgraph.graph import END
from langgraph.types import Send

from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


# DEBUG-FOCUS MODE: the report node is currently bypassed.
#
# While the agent is being tuned we don't want a 3-5s LLM call producing
# a polished final report; we want to land at END the moment the planner
# decides we're done so the run-folder artifacts (nodes.jsonl,
# terminal_events.jsonl, summary.md, final_state.json) are the source of
# truth for analysis.
#
# To re-enable the report node later, change `_TERMINATE` back to "report".
_TERMINATE: Union[str, type] = END


def route_after_planner(state: SwarmGraphState) -> Union[str, list[Send]]:
    """Pick the next graph transition based on the supervisor's decision.

    For ``attack``: return a list of Send()s, one per staged dispatch
    item. If the planner wrote an empty list (defensive — it should
    have flipped to report itself), terminate.

    For every other action: return the node name (or END if the
    planner picked report and report is currently bypassed).
    """
    action = state.get("next_action", "report")

    if action == "attack":
        pending = state.get("pending_dispatch") or []
        if not pending:
            logger.warning(
                "route_after_planner: action=attack but pending_dispatch "
                "is empty; terminating."
            )
            return _TERMINATE
        logger.info(
            "route_after_planner: fanning out %d parallel executor(s).",
            len(pending),
        )
        return [
            Send(
                "executor",
                {
                    **state,
                    "agent_id": item["agent_id"],
                    "config_name": item["config_name"],
                    "methodology": item["methodology"],
                    "mode": item.get("mode", "analyze"),
                    # Forward the planner's reasoning as the worker's
                    # dispatch_reason so ``run_skill_agent`` can attach
                    # it to ``pending_summary_inputs[*].dispatch_reason``.
                    # The summarizer reads it as the intent anchor when
                    # condensing the trace ("the supervisor dispatched
                    # this worker because: …"). Empty string is a valid
                    # value — the summariser handles missing reason
                    # gracefully.
                    "dispatch_reason": item.get("dispatch_reason", ""),
                },
            )
            for item in pending
        ]

    if action == "report":
        return _TERMINATE  # bypassed — see _TERMINATE comment above
    if action in {"recon", "web_search"}:
        return action

    logger.warning(
        "route_after_planner: unknown next_action=%r, terminating.",
        action,
    )
    return _TERMINATE
