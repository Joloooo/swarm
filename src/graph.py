"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

Supervisor-shaped graph: one planner node is the only decision-maker,
every worker node edges back to it. The planner emits a JSON directive
picking the next action — recon, attack (with the list of configs to
fan out), web_search, or report — and the graph transitions accordingly.

Every node goes through :func:`traced`, which wraps it to:

1. Time the node and append a boundary ``✅ [name] Xms — summary``
   AIMessage so LangGraph Studio chat shows continuous progress
   instead of a blank screen during long-running parallel work.
2. Catch crashes and surface them as a visible ``❌`` error message
   instead of failing the whole graph silently.

Boundary messages are tagged with ``additional_kwargs={"node": name}``
so downstream consumers that scan message history can filter them out
and look at real agent output only.

Adding a new node? Register it through ``traced(name, fn)`` and it
inherits both behaviors — no per-node boilerplate.

Flow::

    START → initialize → planner ← ──────────────────────────┐
                          │                                   │
            ┌─────────────┼────────────────┬───────────┐      │
            ↓             ↓                ↓           ↓      │
          recon    pentest_workflow    web_search    report   │
            │      (×N parallel, via                  │       │
            │       Send() fan-out)                   │       │
            └─────── all workers return ──────────────┘       │
                          │                                   │
                          └───────────────────────────────────┘
                                          report → END
"""

from __future__ import annotations

import functools
import logging
import os
import sys
import time
from dataclasses import dataclass, fields
from inspect import iscoroutinefunction


# ============================================================================
# Centralized budgets — every cap, timeout, and iteration count.
#
# This block exists HERE (top of graph.py, BEFORE any other imports) so that
# transitive imports — planner.py, loop/detection.py, tools/*, llm/* — can
# turn around and `from src.graph import budgets` without hitting an import
# cycle. Python hands them whatever's been bound in this module's namespace
# at the time of the partial import; as long as `budgets` is bound before
# the `from src.nodes import (...)` block below, the partial-import works.
#
# DO NOT MOVE THIS BLOCK BELOW THE NODE/STATE/EDGE IMPORTS or the cycle
# returns and you'll get `ImportError: cannot import name 'budgets'`.
#
# Override any field at runtime with the corresponding SWARM_* env var.
# Useful for debug runs without code edits, e.g.
#     SWARM_PLANNER_MAX_ITERS=200 uv run python -m benchmarks.xbow_runner ...
# ============================================================================


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Budgets:
    """Resource budgets for the agent + runner. One screen, scan-friendly."""

    # --- Graph supervisor / planner ---
    planner_max_iters:             int   = _env_int("SWARM_PLANNER_MAX_ITERS",        50)

    # --- Worker agents (per invocation) ---
    worker_max_tool_calls:         int   = _env_int("SWARM_WORKER_MAX_TOOL_CALLS",    50)
    worker_max_iterations:         int   = _env_int("SWARM_WORKER_MAX_ITERATIONS",    30)

    # --- Planner-invented "custom" attacks ---
    custom_attack_max_tool_calls:  int   = _env_int("SWARM_CUSTOM_MAX_TOOL_CALLS",    40)
    custom_attack_max_iterations:  int   = _env_int("SWARM_CUSTOM_MAX_ITERATIONS",    25)

    # --- Loop detection ---
    loop_max_repeated_calls:       int   = _env_int("SWARM_LOOP_MAX_REPEATED",         3)
    loop_same_tool_threshold:      int   = _env_int("SWARM_LOOP_SAME_TOOL_THRESHOLD",  5)
    loop_budget_warn_critical:     int   = _env_int("SWARM_LOOP_BUDGET_CRITICAL",      5)
    loop_budget_warn_pct:          float = _env_float("SWARM_LOOP_BUDGET_PCT",       0.25)

    # --- Tool execution timeouts ---
    tool_command_timeout_s:        int   = _env_int("SWARM_TOOL_CMD_TIMEOUT",        120)
    tool_url_validate_timeout_s:   float = _env_float("SWARM_URL_VALIDATE_TIMEOUT",  5.0)
    tool_crawler_timeout_ms:       int   = _env_int("SWARM_CRAWLER_TIMEOUT_MS",  300000)

    # --- LLM ---
    llm_max_tokens:                int   = _env_int("SWARM_LLM_MAX_TOKENS",         4096)
    llm_request_timeout_s:         float = _env_float("SWARM_LLM_REQ_TIMEOUT",     120.0)

    # --- Web search node ---
    web_search_max_crawled_chars:  int   = _env_int("SWARM_WEB_MAX_CHARS",          3000)
    web_search_max_tavily_results: int   = _env_int("SWARM_WEB_TAVILY_MAX",           10)

    # --- Benchmark runner (xbow_runner.py) ---
    runner_build_timeout_s:        int   = _env_int("SWARM_RUNNER_BUILD_TIMEOUT",   1500)
    runner_up_timeout_s:           int   = _env_int("SWARM_RUNNER_UP_TIMEOUT",       180)
    runner_down_timeout_s:         int   = _env_int("SWARM_RUNNER_DOWN_TIMEOUT",      90)
    runner_discover_timeout_s:     int   = _env_int("SWARM_RUNNER_DISCOVER_TIMEOUT",  30)
    runner_agent_timeout_s:        int   = _env_int("SWARM_RUNNER_AGENT_TIMEOUT",    900)

    def describe(self) -> str:
        """One-block dump of every field — log at startup for run snapshots."""
        return "Budgets:\n" + "\n".join(
            f"  {f.name:<32s} = {getattr(self, f.name)}" for f in fields(self)
        )


# Module-level singleton. Callers do `from src.graph import budgets`.
budgets = Budgets()


# ============================================================================
# Imports below this line MUST come AFTER the budgets block above so the
# transitive `from src.graph import budgets` resolves correctly.
# ============================================================================

from langchain_core.messages import AIMessage  # noqa: E402
from langgraph.graph import END, START, StateGraph  # noqa: E402

from src.edges.routing import route_after_planner  # noqa: E402
from src.nodes import (  # noqa: E402
    initialize_node,
    pentest_workflow_node,
    planner_node,
    recon_node,
    report_node,
    web_search_node,
)
from src.observability import append_node_event, make_run_id  # noqa: E402
from src.state import SwarmGraphState  # noqa: E402

logger = logging.getLogger(__name__)


def _summarize_node_result(name: str, result: dict) -> str:
    """One-line summary of what a node returned, for the chat trace."""
    if not isinstance(result, dict):
        return "ok"
    parts = []
    if "findings" in result:
        parts.append(f"{len(result['findings'])} findings")
    if "agent_results" in result:
        ars = result["agent_results"] or []
        completed = sum(1 for a in ars if getattr(a, "completed", False))
        parts.append(f"{completed}/{len(ars)} agents ok")
    if result.get("active_agents"):
        parts.append(f"active: {','.join(result['active_agents'])}")
    if result.get("waf_detected"):
        parts.append(f"WAF (level {result.get('stealth_level', 0)})")
    if result.get("next_action"):
        parts.append(f"→ {result['next_action']}")
    if result.get("pending_dispatch"):
        parts.append(f"staged {len(result['pending_dispatch'])} workflow(s)")
    return ", ".join(parts) or "ok"


def traced(name: str, fn):
    """Wrap a node so it emits a boundary AIMessage and a JSONL event.

    Two side effects per call:
        1. Append an AIMessage to state.messages so Studio shows live
           progress (existing behavior).
        2. Append one line to ``logs/run-<run_id>/nodes.jsonl`` capturing
           the timestamp, node name, duration, summary, and full result
           dict — for thesis-grade post-run analysis.

    The run_id is read from state. If absent (e.g. Studio runs that
    bypass the runner), one is derived on the fly from target_url.
    """

    @functools.wraps(fn)
    async def wrapped(state):
        run_id = (state or {}).get("run_id") or make_run_id(
            target_url=(state or {}).get("target_url"),
        )

        t0 = time.perf_counter()
        try:
            if iscoroutinefunction(fn):
                result = await fn(state)
            else:
                result = fn(state)
        except Exception as e:  # noqa: BLE001 — visibility > strictness here
            dt_ms = int((time.perf_counter() - t0) * 1000)
            logger.exception("[%s] crashed after %dms", name, dt_ms)
            append_node_event(run_id, {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "node": name,
                "duration_ms": dt_ms,
                "error": f"{type(e).__name__}: {e}",
                "summary": "",
                "result": None,
            })
            return {
                "messages": [
                    AIMessage(
                        content=f"❌ [{name}] crashed after {dt_ms}ms: {e}",
                        additional_kwargs={"node": name, "error": True},
                    )
                ]
            }

        result = result or {}
        dt_ms = int((time.perf_counter() - t0) * 1000)
        summary = _summarize_node_result(name, result)
        append_node_event(run_id, {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "node": name,
            "duration_ms": dt_ms,
            "summary": summary,
            "result": result,
        })
        if os.getenv("SWARM_VERBOSE"):
            ts_short = time.strftime("%H:%M:%S")
            print(
                f"\n─── [{ts_short}] node `{name}` finished in {dt_ms} ms ───\n"
                f"    {summary}",
                file=sys.stderr, flush=True,
            )
            # Print any new AI messages this node added so the full
            # reasoning stream lives in the same terminal.
            for msg in result.get("messages") or []:
                content = getattr(msg, "content", None)
                if not content:
                    continue
                # Filter out the ✅ boundary messages we ourselves emit
                # (added below) so we don't log them twice.
                kw = getattr(msg, "additional_kwargs", None) or {}
                if kw.get("node") and isinstance(content, str) and (
                    content.startswith("✅ [") or content.startswith("❌ [")
                ):
                    continue
                role = type(msg).__name__
                text = content if isinstance(content, str) else str(content)
                print(
                    f"    └── {role}:",
                    file=sys.stderr, flush=True,
                )
                for line in text.splitlines() or [""]:
                    print(f"        {line}", file=sys.stderr, flush=True)
        msgs = list(result.get("messages") or [])
        msgs.append(
            AIMessage(
                content=f"✅ [{name}] {dt_ms}ms — {summary}",
                additional_kwargs={"node": name},
            )
        )
        return {**result, "messages": msgs}

    wrapped.__name__ = f"traced_{name}"
    return wrapped


def build_graph():
    """Build and compile the SwarmAttacker graph."""
    graph = StateGraph(SwarmGraphState)

    # Every node goes through traced() so chat shows boundary messages.
    # Future nodes registered the same way inherit the behavior automatically.
    graph.add_node("initialize",       traced("initialize",       initialize_node))
    graph.add_node("planner",          traced("planner",          planner_node))
    graph.add_node("recon",            traced("recon",            recon_node))
    graph.add_node("pentest_workflow", traced("pentest_workflow", pentest_workflow_node))
    graph.add_node("web_search",       traced("web_search",       web_search_node))
    graph.add_node("report",           traced("report",           report_node))

    # Edges
    graph.add_edge(START, "initialize")
    graph.add_edge("initialize", "planner")

    # Supervisor is the only decision-maker. `route_after_planner` returns
    # either a node name (recon / web_search / report) OR a list of Send()
    # calls that fan out to parallel pentest_workflow runs for "attack".
    # END is a valid destination too — see `_TERMINATE` in
    # src/edges/routing.py for the report-bypass note.
    graph.add_conditional_edges(
        "planner",
        route_after_planner,
        [
            "recon",
            "pentest_workflow",
            "web_search",
            "report",
            END,
        ],
    )

    #this is like loop every loop combinations recon is allowed to go to planner basically every node is only allowed to talk to planner
    # Workers always return to the supervisor so it can reassess.
    graph.add_edge("recon", "planner")
    graph.add_edge("pentest_workflow", "planner")
    graph.add_edge("web_search", "planner")

    graph.add_edge("report", END)

    return graph.compile()


# Compiled graph — imported by langgraph.json for Studio
graph = build_graph()
