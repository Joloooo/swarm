"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

Supervisor-shaped graph: one planner node is the only decision-maker,
every worker node edges back to it. The planner emits a JSON directive
picking the next action — recon, attack (with the list of configs to
fan out), web_search, or report — and the graph transitions accordingly.

Every node is a :class:`~src.nodes.base.BaseNode` instance, and
``BaseNode.__call__`` itself owns the cross-cutting instrumentation
(timing, boundary AIMessage, JSONL run logging, crash-to-AIMessage
conversion, ``SWARM_VERBOSE`` streaming). The graph just wires
instances in directly — no wrapper, no per-node boilerplate.

Boundary messages are tagged with ``additional_kwargs={"node": name}``
so downstream consumers that scan message history can filter them out
and look at real agent output only.

Adding a new node? Subclass :class:`BaseNode`, expose a singleton
instance from ``src.nodes``, and ``graph.add_node("foo", foo_node)``
here. It inherits all the instrumentation automatically.

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

import logging
import os
from dataclasses import dataclass, fields


# ============================================================================
# Centralized budgets — every cap, timeout, and iteration count.
#
# This block exists HERE (top of graph.py, BEFORE any other imports) so that
# transitive imports — planner.py, tools/*, llm/* — can turn around and
# `from src.graph import budgets` without hitting an import cycle. Python
# hands them whatever's been bound in this module's namespace at the time
# of the partial import; as long as `budgets` is bound before the
# `from src.nodes import (...)` block below, the partial-import works.
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


@dataclass(frozen=True)
class Budgets:
    """Resource budgets for LLM-running nodes only.

    These bound *what an agent can do per invocation* — iterations,
    tool calls, output tokens, context window. Infrastructure timeouts
    (Docker build, HTTP request, tmux command, search-API parameters)
    are NOT budgets and live as local constants in the file that uses
    them. Don't add fields here unless they're directly bounding LLM
    behavior in a node.
    """

    # --- Graph supervisor / planner ---
    planner_max_iters:             int   = _env_int("SWARM_PLANNER_MAX_ITERS",        50)
    # --- Worker agents (per invocation) ---
    worker_max_iterations:         int   = _env_int("SWARM_WORKER_MAX_ITERATIONS",    30)
    # --- Planner-invented "custom" attacks ---
    custom_attack_max_tool_calls:  int   = _env_int("SWARM_CUSTOM_MAX_TOOL_CALLS",    40)
    custom_attack_max_iterations:  int   = _env_int("SWARM_CUSTOM_MAX_ITERATIONS",    25)
    # --- LLM (per-call output cap) ---
    llm_max_tokens:                int   = _env_int("SWARM_LLM_MAX_TOKENS",         4096)
    # --- Web search node (LLM context budget per source) ---
    web_search_max_crawled_chars:  int   = _env_int("SWARM_WEB_MAX_CHARS",          3000)

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
from src.state import SwarmGraphState  # noqa: E402

logger = logging.getLogger(__name__)


def build_graph():
    """Build and compile the SwarmAttacker graph."""
    graph = StateGraph(SwarmGraphState)

    # Every node is a BaseNode instance; BaseNode.__call__ already owns
    # the cross-cutting instrumentation (timing, boundary AIMessage,
    # JSONL run logging, crash-to-AIMessage, SWARM_VERBOSE streaming).
    # Adding a new node? Subclass BaseNode, export a singleton from
    # `src.nodes`, register it here. No wrapper required.
    graph.add_node("initialize",       initialize_node)
    graph.add_node("planner",          planner_node)
    graph.add_node("recon",            recon_node)
    graph.add_node("pentest_workflow", pentest_workflow_node)
    graph.add_node("web_search",       web_search_node)
    graph.add_node("report",           report_node)

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
