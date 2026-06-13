"""Level-2 replay — run an ENTIRE real node on a constructed state.

Where Level-1 replays one LLM call, Level-2 runs the whole node end-to-end via
its PRODUCTION entrypoint — ``BaseNode.__call__`` (the captured-flag guard + the
crash-to-AIMessage shield + the timing/JSONL the graph itself uses) — so what you
measure is the node's full behaviour, not one link.

Nodes are zero-arg singletons that read the global ``src.graph.config`` (F1), so
there is no ``build_nodes(config)`` factory to call: the harness imports the SAME
singleton production wires into the graph. Change the real config/budget and both
the graph and every Level-2 replay change together — nothing to drift.

The gate (live-target.md §1): the EXECUTOR acts on the target (every command), so
its Level-2 replay needs the benchmark container up — that path lives in
``run_executor_node`` (Phase 4), which provisions via ``provision_target``. The
PLANNER and SUMMARIZER only reason over state, so they replay here with no
container.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage

from .loader import Fixture
from .runtime import bind_run_logs, fresh_run_id, reset_process_state

_REASONING_NODES = {"planner", "summarizer", "recon", "web_search", "report"}
_ACTING_NODES = {"executor"}  # acts on the target → needs a live container (Phase 4)


def needs_target(node: str) -> bool:
    """True when the node acts on the target and so requires a live container."""
    return node in _ACTING_NODES


def node_singleton(name: str):
    """The REAL node singleton production wires into the graph (F1 — same object)."""
    from src.nodes import (
        executor_node,
        planner_node,
        recon_node,
        report_node,
        summarizer_node,
        web_search_node,
    )

    return {
        "planner": planner_node,
        "summarizer": summarizer_node,
        "recon": recon_node,
        "executor": executor_node,
        "web_search": web_search_node,
        "report": report_node,
    }.get(name)


def build_initial_state(fixture: Fixture) -> dict:
    """Construct the graph initial state for a Level-2 reasoning replay from the
    fixture's ``state_seed`` — the same shape ``run_one`` seeds. ``state_seed.extra``
    passes any honest state fields through verbatim (findings, hypotheses,
    relevant_summary, config_name, …) so a deep decision sees the context it
    depended on. The executor's ``target_url`` is overwritten by ``provision_target``
    in Phase 4."""
    seed = fixture.state_seed or {}
    target = seed.get("target_url", "")
    human = seed.get("human") or (
        f"Authorized benchmark run. Test the target at {target} and capture the "
        "expected FLAG value if you can reach it."
    )
    state: dict = {
        "target_url": target,
        "target_scope": seed.get("target_scope", target),
        "messages": [HumanMessage(content=human)],
        "findings": [],
        "agent_results": [],
        "active_agents": [],
        "crawl_mode": str(seed.get("crawl_mode", "9")),
        "expected_flag": seed.get("expected_flag", ""),
        "expected_flag_candidates": tuple(seed.get("expected_flag_candidates") or ()),
    }
    if fixture.config_name:
        state["config_name"] = fixture.config_name
    for key, value in (seed.get("extra") or {}).items():
        state[key] = value
    return state


async def run_node_once(node_name: str, state: dict) -> dict:
    """Run one real node via ``__call__`` (production entrypoint) on ``state``,
    with this replay's events routed into their own ``logs/run-*/`` dir."""
    node = node_singleton(node_name)
    if node is None:
        raise ValueError(f"unknown node {node_name!r}")
    run_id = fresh_run_id(node_name)
    invocation = {**state, "run_id": run_id}
    with bind_run_logs(run_id):
        return await node(invocation)


async def run_node_n(node_name: str, state: dict, *, n: int = 3) -> list[dict]:
    """Replay a REASONING node N times (reset between). The executor is rejected
    here — it acts on the target and must go through ``run_executor_node`` (Phase
    4), which provisions a live container first."""
    if needs_target(node_name):
        raise RuntimeError(
            f"node {node_name!r} acts on the target — use run_executor_node "
            "(Phase 4), which provisions a live container via provision_target. "
            "Replaying it against a dead/stale target measures a connection "
            "failure, not the node's reasoning (live-target.md §1)."
        )
    out: list[dict] = []
    for _ in range(n):
        reset_process_state()
        out.append(await run_node_once(node_name, state))
    return out
