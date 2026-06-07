"""Routing edges — translate the supervisor's decision into a transition.

Two edge functions:

  :func:`route_after_planner` — reads the supervisor's chosen action
  and returns either a node name (``recon`` / ``web_search`` /
  ``report``) or a list of :class:`Send` calls (for ``attack``, which
  fans out to parallel ``executor`` runs — one per entry in
  ``state["pending_dispatch"]``). Also the flag verifier for explicit
  submissions — on ``action="submit_flag"``, compares
  ``state["submission_attempts"][-1]`` to ``state["expected_flag"]``
  via :func:`src.edges.flag_match.flags_match`. Match → ``END``,
  miss → ``"planner"``.

  :func:`route_after_summarizer` — reads ``state["captured_flag"]``,
  which is set by the skill runner ONLY when a worker's tool output
  contained a ``flag{...}`` substring that strict-equals
  ``expected_flag``. Truthy → ``END``, empty → ``"planner"``.

Why ``route_after_summarizer`` is back (2026-05-25):

  An earlier version of this edge scanned worker tool outputs for ANY
  ``flag{...}`` substring and terminated on a hit. Removed 2026-05-24
  because regex matching over raw HTTP response bodies is structurally
  false-positive-prone — README excerpts, swagger schemas, and the
  agent's own ``python3 -c`` script literals all contain
  ``flag{...}``-shaped strings.

  The current re-introduction is a DIFFERENT design: the skill runner
  (``src/nodes/base/skill_runner.py``) does the scan, but only
  populates ``state["captured_flag"]`` when the extracted string
  strict-equals ``expected_flag``. So this edge's decision reduces to
  "is there a verified capture?" — a boolean read, not a regex match.
  The strict-equality gate is itself the false-positive filter:
  ``flag{example}`` cannot strict-equal ``FLAG{9c935b35a4f...}``.

  In real-pentest mode (``expected_flag`` empty) the skill runner
  never sets ``captured_flag``, so this edge always routes back to
  the planner — capture remains planner-driven via ``submit_flag``,
  same as before.

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
    # Hard-stop: if any prior worker already captured the flag via
    # FlagWatcher's auto-verify path, terminate immediately regardless
    # of what action the planner chose. Otherwise the planner could
    # waste a turn dispatching more workers that are guaranteed to
    # exit early via the sibling-cancel hook. The summarizer's edge
    # ``route_after_summarizer`` also reads ``captured_flag``, but
    # short-circuiting here keeps the planner from emitting a
    # redundant decision in the first place.
    captured = (state.get("captured_flag") or "").strip()
    if captured:
        logger.info(
            "route_after_planner: captured_flag already set (%r); "
            "routing to END without dispatching further work.",
            captured[:80],
        )
        try:
            from src.observability.writers import append_event
            append_event(
                (state or {}).get("run_id"),
                "routing_decision",
                edge="route_after_planner",
                next="__end__",
                reason="captured_flag_already_set",
                captured_flag=captured,
            )
        except Exception:  # noqa: BLE001
            pass
        return END

    action = state.get("next_action", "report")

    if action == "attack":
        pending = state.get("pending_dispatch") or []
        if not pending:
            logger.warning(
                "route_after_planner: action=attack but pending_dispatch "
                "is empty; terminating."
            )
            return _TERMINATE
        research_query = (state.get("research_query") or "").strip()
        logger.info(
            "route_after_planner: fanning out %d parallel executor(s)%s.",
            len(pending),
            " + 1 web_search" if research_query else "",
        )
        sends = [
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
        # Concurrent research branch: when the planner attached a research
        # query to this attack, fan out a web_search alongside the executors.
        # It joins the same summarizer fan-in (web_search → summarizer), so
        # all branches rejoin the planner together — executors never block
        # waiting on the search, and the search is ready by the next turn.
        if research_query:
            sends.append(Send("web_search", {**state, "search_query": research_query}))
        return sends

    if action == "submit_flag":
        attempts = list(state.get("submission_attempts") or [])
        if not attempts:
            logger.warning(
                "route_after_planner: action=submit_flag but "
                "submission_attempts is empty; deferring to planner.",
            )
            try:
                from src.observability.writers import append_event
                append_event(
                    (state or {}).get("run_id"),
                    "routing_decision",
                    edge="route_after_planner",
                    next="planner",
                    action="submit_flag",
                    reason="no_submission_attempts",
                )
            except Exception:  # noqa: BLE001
                pass
            return "planner"
        submitted = attempts[-1].strip()
        # Match against the FULL candidate set populated by the
        # benchmark runner — see :func:`src.edges.flag_match.flags_match`
        # for why benchmarks can have multiple legitimate expected
        # values. Falls back to the single ``expected_flag`` field
        # when ``expected_flag_candidates`` isn't populated (e.g.
        # non-benchmark driver, ad-hoc invocations).
        candidates: tuple[str, ...] = tuple(
            (state or {}).get("expected_flag_candidates") or ()
        )
        expected: str | tuple[str, ...]
        if candidates:
            expected = candidates
        else:
            expected = (state.get("expected_flag") or "").strip()
        matched = flags_match(submitted=submitted, expected=expected)
        next_node = END if matched else "planner"
        if matched:
            logger.info(
                "route_after_planner: flag verified (%r); routing to END.",
                submitted[:80],
            )
        else:
            logger.info(
                "route_after_planner: submitted flag (%r) did not match "
                "expected — handing control back to planner.",
                submitted[:80],
            )
        try:
            from src.observability.writers import append_event
            append_event(
                (state or {}).get("run_id"),
                "routing_decision",
                edge="route_after_planner",
                next=str(next_node),
                action="submit_flag",
                submitted=submitted,
                expected_flag=expected,
                matched=matched,
            )
        except Exception:  # noqa: BLE001
            pass
        return next_node

    if action == "report":
        # Benchmark-mode hard stop. A VOLUNTARY report does not end the
        # run: capture (handled at the top of this function → END) and the
        # iteration budget are the only terminals, so the planner's own
        # "we're done" decision can't stop the run on a possibly-
        # hallucinated belief. Re-plan instead.
        #
        # The single exception is the iteration-cap path in
        # ``PlannerNode.execute``, which sets ``budget_exhausted`` — that
        # report we DO let through, otherwise the cap could never
        # terminate and we'd loop planner→report→planner forever.
        #
        # This needs NO graph change: "planner" is already a declared
        # destination in the conditional-edge whitelist (src/graph.py), so
        # re-routing there is a legal transition. Real-pentest runs
        # (no ``expected_flag``) fall straight through to END as before.
        benchmark_mode = bool(
            (state.get("expected_flag") or "").strip()
            or state.get("expected_flag_candidates")
        )
        if benchmark_mode and not state.get("budget_exhausted"):
            logger.info(
                "route_after_planner: benchmark-mode report suppressed "
                "(no capture, budget not exhausted) — re-planning instead "
                "of ending the run."
            )
            try:
                from src.observability.writers import append_event
                append_event(
                    (state or {}).get("run_id"),
                    "routing_decision",
                    edge="route_after_planner",
                    next="planner",
                    action="report",
                    reason="benchmark_report_suppressed",
                )
            except Exception:  # noqa: BLE001
                pass
            return "planner"
        return _TERMINATE  # bypassed — see _TERMINATE comment above
    if action == "recon":
        # Recon fans out into parallel dimension workers, exactly like
        # ``attack`` fans out executors above. Each Send lands on the
        # (dimension-agnostic) recon node carrying a different
        # ``config_name``; both branches run concurrently with their own
        # tool budgets and converge on the summarizer barrier (static
        # ``recon → summarizer`` edge). The ``recon`` branch maps the
        # web/app surface and becomes the canonical "Application map"
        # (the summarizer keys ``recon_summary`` on ``config_name ==
        # "recon"``); the ``recon-ports`` branch scans the network/service
        # surface so a co-located non-web service (e.g. an object store on
        # a high port) can't slip past unnoticed. Splitting the budgets is
        # the point: a single recon worker spends its whole budget on HTTP
        # and never reaches the port scan.
        #
        # No graph change needed — ``recon`` is already a declared Send
        # destination in the conditional-edge whitelist (src/graph.py).
        recon_dimensions: tuple[tuple[str, str], ...] = (
            ("recon", "Parallel recon: map the web/app surface — pages, "
                      "forms, API routes, directories, technology."),
            ("recon-ports", "Parallel recon: scan the network/service "
                            "surface for non-web services and extra ports."),
        )
        logger.info(
            "route_after_planner: fanning out %d parallel recon "
            "dimension(s): %s.",
            len(recon_dimensions),
            ", ".join(name for name, _ in recon_dimensions),
        )
        try:
            from src.observability.writers import append_event
            append_event(
                (state or {}).get("run_id"),
                "routing_decision",
                edge="route_after_planner",
                next="recon",
                action="recon",
                dimensions=[name for name, _ in recon_dimensions],
            )
        except Exception:  # noqa: BLE001
            pass
        return [
            Send(
                "recon",
                {
                    **state,
                    "config_name": name,
                    "mode": "analyze",
                    "dispatch_reason": reason,
                },
            )
            for name, reason in recon_dimensions
        ]

    if action == "web_search":
        return action

    logger.warning(
        "route_after_planner: unknown next_action=%r, terminating.",
        action,
    )
    return _TERMINATE


def route_after_summarizer(state: SwarmGraphState) -> str:
    """Terminate the graph on a verified flag capture, else continue.

    Reads ``state["captured_flag"]``, which the skill runner sets
    ONLY when a worker's tool output contained a ``flag{...}``
    substring that strict-equals ``state["expected_flag"]`` (the
    deterministic XBow benchmark target value). The strict equality
    is the false-positive filter — a placeholder ``flag{example}``
    in a swagger schema cannot match ``FLAG{<64-hex>}``.

    Truthy ``captured_flag`` → ``END``. The graph stops; the
    ``xbow_runner`` reads ``submission_attempts[-1]`` (which the
    skill runner also populated) as the authoritative verdict.

    Empty / missing ``captured_flag`` → ``"planner"``. The planner
    runs as normal and decides the next action. In real-pentest mode
    (no ``expected_flag`` configured) this is always the taken
    branch — capture is planner-driven via ``submit_flag``.
    """
    captured = (state.get("captured_flag") or "").strip()
    next_node = END if captured else "planner"
    if captured:
        logger.info(
            "route_after_summarizer: verified capture %r — routing to END.",
            captured[:80],
        )
    # Structured record so post-mortem can answer "did this edge fire
    # at all, and what did state look like when it did". The 2026-05-25
    # XBEN-006-24 incident showed that scan + capture can succeed without
    # this edge ever firing (blocked behind a fan-in waiting for stuck
    # parallel workers), so a missing event here is itself the signal.
    try:
        from src.observability.writers import append_event
        append_event(
            (state or {}).get("run_id"),
            "routing_decision",
            edge="route_after_summarizer",
            next=str(next_node),
            captured_flag=captured,
            expected_flag=(state.get("expected_flag") or "").strip(),
        )
    except Exception:  # noqa: BLE001
        pass
    return next_node

