"""Routing edges — translate the supervisor's decision into a transition.

The single edge function in this module is :func:`route_after_planner`.
It reads the supervisor's chosen action and returns either a node name
(``recon`` / ``web_search`` / ``report``) or a list of :class:`Send`
calls (for ``attack``, which fans out to parallel ``executor`` runs —
one per entry in ``state["pending_dispatch"]``). It is ALSO the flag
verifier — when the supervisor picks ``action="submit_flag"``, the
edge reads the last entry of ``state["submission_attempts"]`` and
compares it to ``state["expected_flag"]`` via
:func:`src.flag.flags_match`. On a match the graph routes to ``END``;
on a miss the planner runs again (with the rejected attempt visible
in ``submission_attempts``).

The recon / executor / web_search nodes route into the summariser /
planner via plain edges declared in ``src/graph.py``. There used to be
a conditional ``route_after_summarizer`` here that did a
benchmark-mode "scan messages for ``FLAG{...}``" early-exit; that
function got deleted in the 2026-05 refactor after it produced false
positives whenever a placeholder ``FLAG{...}`` appeared in the
planner's narration. Flag verification now lives exclusively in the
explicit submit-flag protocol above.

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

from src.flag import flags_match
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
    ``state["expected_flag"]`` via :func:`src.flag.flags_match`. On a
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


