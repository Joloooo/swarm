"""Routing edges — translate node outputs into graph transitions.

Two edge functions live here:

* :func:`route_after_planner` reads the supervisor's state update and
  returns either a node name (``recon`` / ``web_search`` / ``report``)
  or a list of :class:`Send` calls (for ``attack``, which fans out to
  parallel ``executor`` runs — one per entry in
  ``state["pending_dispatch"]``).
* :func:`route_after_summarizer` is the **benchmark-mode early-exit
  gate**. After every fan-out cycle, it scans ``state`` for a captured
  flag; if one is present and ``expected_flag`` is set (i.e. we're in
  a benchmark), it short-circuits straight to END rather than letting
  the planner spend more turns. This is what makes
  ``uv run python -m benchmarks.xbow_runner`` stop the moment any
  worker has demonstrably won, instead of running until the timeout.
  Outside benchmark mode (real pentest runs leave ``expected_flag``
  empty) the gate is a pass-through to the planner.

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

from src.flag import find_flag_in_state
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


def route_after_summarizer(state: SwarmGraphState) -> str:
    """Benchmark-mode early-exit gate.

    Runs after every summarizer pass (i.e. after every fan-out cycle).
    Returns:

    * ``END`` — only when ``expected_flag`` is set AND a flag pattern
      was captured anywhere in messages / findings / agent_results.
      The captured value is recorded into ``state["flag_captured"]``
      so post-run consumers (xbow_runner, summary writers) can read
      it back.
    * ``"planner"`` — every other case. Real pentest runs (no
      ``expected_flag``) always fall through here, preserving the
      existing supervisor loop.

    Why this lives in the routing layer instead of the planner:
    a routing edge can return ``END`` directly. The planner can only
    suggest ``"report"`` (currently bypassed to ``END``), and even
    then it pays for one extra LLM call before terminating. In a
    benchmark with hard time budgets that one call is wasted, and
    every additional supervisor turn risks a Codex policy refusal on
    an already-solved problem. Short-circuiting here is both cheaper
    and more reliable.
    """
    # Real pentest runs: no benchmark gate, always defer to the
    # supervisor. Test-only short-circuit shouldn't hijack live work.
    expected = (state.get("expected_flag") or "").strip()
    if not expected:
        return "planner"

    # Already captured in a previous turn — fall straight through to
    # END without re-scanning state. Idempotent: keeps later workers
    # from un-capturing if the planner has already scheduled them.
    already = (state.get("flag_captured") or "").strip()
    if already:
        logger.info(
            "route_after_summarizer: flag already captured (%r), "
            "terminating early.", already[:80],
        )
        return END

    found, flag = find_flag_in_state(state, expected=expected)
    if found and flag:
        logger.info(
            "route_after_summarizer: benchmark flag captured (%r); "
            "skipping planner, routing to END.", flag[:80],
        )
        # Stash the captured value into state via the dict-style
        # mutation that LangGraph's TypedDict accepts. The next
        # snapshot the runner sees will contain ``flag_captured``,
        # so xbow_runner can use it as the authoritative answer
        # instead of re-running the substring match.
        try:
            state["flag_captured"] = flag
        except Exception:  # noqa: BLE001 — TypedDict assignment can vary
            pass
        return END

    return "planner"
