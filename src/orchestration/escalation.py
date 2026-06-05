"""Dual-planner escalation — race two independent planner lanes.

Why this layer exists
---------------------

The core graph (``src/graph.py``) is a single supervisor planner driving
a swarm of workers. Empirically ~80% of benchmark wins land in recon or
the first attack batch; the losses are the runs where the planner
**fixates** — it re-cycles the same surface and never escapes a decoy
(the canonical case: XBEN-084, where the swarm ground on the `/api/s3`
web proxy and never pivoted to the co-located object store).

A second planner that **cannot see the first's history** can't inherit
that fixation. So when the first lane is still stuck after a few planner
turns, we fork a SECOND, fully independent run of the same graph — its
own state, its own context window, its own recon — steered by a
*divergence persona* (and a one-time brief of what the first lane has
already tried) to deliberately take different angles. The two race; the
first to capture the flag wins and the other is cancelled.

Why a separate graph invocation rather than an in-graph second planner:
the graph's control-state keys (``next_action``, ``pending_dispatch``,
``planner_iters``, …) are single-valued — two planners writing them in
one shared state would raise LangGraph's ``InvalidUpdateError``. Running
two independent ``graph.astream`` invocations gives each planner its own
isolated state for free, which is exactly the "separate context windows,
never merged" property we want. The core graph is untouched, so the
fast-win path that already works is structurally unaffected: lane A runs
solo and identically to a plain ``ainvoke`` right up until the fork — and
the fork only fires on the slow runs that haven't won early.

Contract: :func:`run_with_escalation` is a drop-in for
``graph.ainvoke(state, config=config)`` — it returns the winning lane's
final state dict in the same shape, so the caller's verdict logic
(``submission_attempts`` / ``captured_flag`` / ``findings``) is unchanged.
Lane A's exceptions propagate unchanged (so the runner's timeout-rescue
still works); lane B is best-effort and never propagates.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


# The disposition that makes lane B diverge from lane A. Kept neutral /
# vocab-clean (this reaches the LLM) so it can't trip a cyber_policy
# refusal — see the Skill Vocabulary Policy in CLAUDE.md.
DEFAULT_LANE_B_PERSONA = (
    "You are the SECOND, independent tester on this target, working in "
    "parallel with another tester and racing them to the objective. "
    "Assume the other tester is already grinding the most obvious path — "
    "the main web app's headline issue. Your value is a DIFFERENT route: "
    "co-located services on other ports, authentication and authorization "
    "and business-logic flaws, multi-step or chained sequences, unusual "
    "inputs and encodings, and anything an obvious-first approach skips. "
    "Do not coordinate with or wait for the other tester; run your own "
    "ranked hypotheses to the end. Whoever reaches the objective first "
    "ends the run."
)


def _findings_of(state: dict) -> list:
    return list((state or {}).get("findings") or [])


def _render_brief(a_state: dict) -> str:
    """One-time snapshot of lane A's leads, handed to lane B at fork time.

    Deliberately a SNAPSHOT, not a live link: after the fork the lanes
    never merge. Lane B reads this once to know what to avoid repeating.
    """
    lines: list[str] = []
    for f in _findings_of(a_state)[-12:]:
        title = getattr(f, "title", "") or ""
        url = getattr(f, "url", "") or ""
        if title:
            lines.append(f"- {title}" + (f"  ({url})" if url else ""))
    rs = (a_state or {}).get("relevant_summary")
    if isinstance(rs, dict):
        for key in ("ranked_hypotheses", "hypotheses", "notes", "summary"):
            val = rs.get(key)
            if val:
                lines.append(f"(other tester's {key}): {str(val)[:600]}")
                break
    if not lines:
        return (
            "(The other tester has no confirmed leads yet — you have a "
            "clean field; pursue the full ranked hypothesis space.)"
        )
    return "\n".join(lines)


def build_lane_b_state(
    initial_state: dict,
    a_snapshot: dict,
    *,
    persona: str = DEFAULT_LANE_B_PERSONA,
) -> dict:
    """Build lane B's fresh initial state from the ORIGINAL seed state.

    Lane B starts cold (its own recon, its own empty accumulators) — not
    from lane A's evolved state — so its context window is genuinely
    independent. The only things carried over are the engagement seed
    (target, expected flag) and a one-time divergence steer.
    """
    b = dict(initial_state)
    # Fresh, independent accumulators — do NOT inherit lane A's history.
    b["messages"] = list(initial_state.get("messages") or [])
    for key in (
        "findings",
        "agent_results",
        "active_agents",
        "pending_summary_inputs",
        "pending_dispatch",
        "submission_attempts",
    ):
        b[key] = []
    b["planner_iters"] = 0
    b["forced_recoveries"] = 0
    b["recon_done"] = False
    b["relevant_summary"] = {}
    b["recon_summary"] = ""
    b["captured_flag"] = None
    b["next_action"] = ""
    b["search_query"] = ""
    b["budget_exhausted"] = False
    # Distinct run_id → lane B's events land in their own
    # logs/run-<id>-laneB/ dir (append_event creates it lazily), so the
    # two concurrent planners don't interleave in one event stream and
    # post-mortem metrics stay per-lane.
    rid = initial_state.get("run_id") or "run"
    b["run_id"] = f"{rid}-laneB"
    # The divergence steer (read by _escalation_note in the planner).
    b["planner_persona"] = persona
    b["escalation_brief"] = _render_brief(a_snapshot)
    return b


async def run_with_escalation(
    graph: Any,
    initial_state: dict,
    *,
    config: dict,
    enabled: bool = True,
    fork_after_planner_iters: int = 3,
    lane_b_persona: str = DEFAULT_LANE_B_PERSONA,
    log: logging.Logger | None = None,
) -> dict:
    """Run lane A solo; fork a divergent lane B if A gets stuck; race them.

    Drop-in for ``await graph.ainvoke(initial_state, config=config)``.

    * ``enabled=False`` → plain ``ainvoke`` (zero behavioral change).
    * Lane A streams identically to ``ainvoke`` and its exceptions
      propagate unchanged (the caller's timeout-rescue path still fires).
    * Lane B is forked only once, when lane A has run
      ``fork_after_planner_iters`` planner turns without a capture, and is
      best-effort (its errors never propagate).
    * First lane to set ``captured_flag`` wins; the loser is cancelled.
      If neither captures, the lane with more findings is returned (richer
      report).
    """
    log = log or logger
    if not enabled:
        return await graph.ainvoke(initial_state, config=config)

    b_task: asyncio.Task | None = None
    b_latest: dict = {"state": {}}
    fork_attempted = False

    async def run_lane_b(b_state: dict) -> dict:
        last: dict = {}
        try:
            async for s in graph.astream(b_state, config, stream_mode="values"):
                last = s
                b_latest["state"] = s
                if s.get("captured_flag"):
                    return s
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — lane B is best-effort
            log.warning(
                "escalation lane B ended on error: %s: %s",
                type(e).__name__, str(e)[:200],
            )
        return last

    a_last: dict = {}
    try:
        async for s in graph.astream(initial_state, config, stream_mode="values"):
            a_last = s
            if s.get("captured_flag"):
                if b_task and not b_task.done():
                    b_task.cancel()
                return s
            # Did lane B capture while lane A was still streaming?
            if b_task is not None and b_task.done():
                try:
                    b_res = b_task.result()
                except Exception:  # noqa: BLE001
                    b_res = b_latest["state"]
                if (b_res or {}).get("captured_flag"):
                    return b_res
            # Fork trigger — once, when lane A is stuck.
            if (
                not fork_attempted
                and int(s.get("planner_iters") or 0) >= fork_after_planner_iters
            ):
                fork_attempted = True
                try:
                    b_state = build_lane_b_state(
                        initial_state, s, persona=lane_b_persona,
                    )
                    b_task = asyncio.create_task(run_lane_b(b_state))
                    log.info(
                        "escalation: lane A stuck after %s planner turns — "
                        "forked divergent lane B (run_id=%s)",
                        s.get("planner_iters"), b_state.get("run_id"),
                    )
                except Exception as e:  # noqa: BLE001
                    log.warning("escalation: failed to fork lane B: %s", e)
    except BaseException:
        # Lane A raised or the wall-clock wait_for cancelled us. Preserve
        # today's behavior exactly: tear down lane B and re-raise so the
        # runner's existing handlers (TimeoutError rescue, etc.) run.
        if b_task and not b_task.done():
            b_task.cancel()
        raise

    # Lane A finished WITHOUT a capture.
    if b_task is not None:
        try:
            b_res = await b_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            b_res = b_latest["state"]
        if (b_res or {}).get("captured_flag"):
            return b_res
        # Neither captured — return the richer lane for the report.
        if len(_findings_of(b_res)) > len(_findings_of(a_last)):
            return b_res
    return a_last
