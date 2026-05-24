"""Routing edges — translate the supervisor's decision into a transition.

One edge function:

  :func:`route_after_planner` — reads the supervisor's chosen action
  and returns either a node name (``recon`` / ``web_search`` /
  ``report``) or a list of :class:`Send` calls (for ``attack``, which
  fans out to parallel ``executor`` runs — one per entry in
  ``state["pending_dispatch"]``). Also the flag verifier for explicit
  submissions — on ``action="submit_flag"``, compares
  ``state["submission_attempts"][-1]`` to ``state["expected_flag"]``
  via :func:`src.edges.flag_match.flags_match`. Match → ``END``,
  miss → ``"planner"``.

The summarizer → planner transition used to be conditional (a
``route_after_summarizer`` edge that scanned worker tool outputs for
``flag{...}`` strings and auto-terminated on a hit). Removed
2026-05-24: regex matching over raw HTTP response bodies cannot be
made false-positive-safe — README excerpts, swagger schemas, and the
agent's own ``python3 -c`` script literals all contain ``flag{...}``-
shaped strings. Capture is now an explicit agent decision via
``submit_flag``; the summarizer always routes back to the planner.

The planner is responsible for populating ``pending_dispatch`` when
it picks ``action="attack"`` and for populating ``submission_attempts``
when it picks ``action="submit_flag"``; this edge only reads those
fields.
"""

from __future__ import annotations

import logging
from typing import Union

from langgraph.graph import END
from langgraph.types import Send

from src.edges.flag_match import flags_match
from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


# DEBUG-FOCUS MODE: the report node is currently bypassed.
#
# While the agent is being tuned we don't want a 3-5s LLM call producing
# a polished final report; we want to land at END the moment the planner
# decides we're done so the run-folder artifacts (full_logs.jsonl,
# displayed_terminal_logs.log) are the source of truth for analysis.
#
# To re-enable the report node later, change `_TERMINATE` back to "report".
_TERMINATE: Union[str, type] = END


def route_after_planner(state: SwarmGraphState) -> Union[str, list[Send]]:
    """Pick the next graph transition based on the supervisor's decision.

    For ``attack``: return a list of ``Send()``s, one per staged dispatch
    item. If the planner wrote an empty list (defensive — it should have
    flipped to report itself), terminate.

    For ``submit_flag``: read the last entry of
    ``state["submission_attempts"]`` and compare it to
    ``state["expected_flag"]`` via :func:`src.edges.flag_match.flags_match`. On a
    match → ``END``. On a miss → ``"planner"``. The planner runs again
    with the rejected attempt visible in its state so its system prompt
    can teach it not to re-submit the same string. Real pentest runs
    (no ``expected_flag``) accept any well-formed flag from the agent
    — the agent is the authority outside benchmark mode.

    For every other action: return the node name (or ``END`` if the
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

    if action == "submit_flag":
        attempts = list(state.get("submission_attempts") or [])
        if not attempts:
            logger.warning(
                "route_after_planner: action=submit_flag but "
                "submission_attempts is empty; deferring to planner.",
            )
            return "planner"
        submitted = attempts[-1].strip()
        expected = (state.get("expected_flag") or "").strip()
        if flags_match(submitted=submitted, expected=expected):
            logger.info(
                "route_after_planner: flag verified (%r); routing to END.",
                submitted[:80],
            )
            return END
        logger.info(
            "route_after_planner: submitted flag (%r) did not match "
            "expected — handing control back to planner.",
            submitted[:80],
        )
        return "planner"

    if action == "report":
        return _TERMINATE  # bypassed — see _TERMINATE comment above
    if action in {"recon", "web_search"}:
        return action

    logger.warning(
        "route_after_planner: unknown next_action=%r, terminating.",
        action,
    )
    return _TERMINATE

