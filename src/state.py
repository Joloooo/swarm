"""Shared state schema for the SwarmAttacker LangGraph graph."""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from enum import Enum
from typing import Annotated, Any

from langchain_core.messages import AnyMessage
from langgraph.graph import add_messages


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single vulnerability or observation discovered during testing."""

    title: str
    severity: Severity
    category: str  # e.g. "sqli", "xss", "idor", "info-disclosure"
    description: str
    evidence: str  # raw tool output / proof
    agent_id: str  # which agent found it
    url: str = ""
    cwe: str = ""
    reproduced: bool = False


@dataclass
class AgentResult:
    """Result returned by a single swarm agent when it finishes."""

    agent_id: str
    methodology: str  # "owasp", "vulntype", "custom"
    config_name: str  # e.g. "sqli", "auth-testing", "chain-ssrf-to-rce"
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    completed: bool = False
    phase: str = "analyze"  # "analyze" or "exploit" — which workflow phase produced this


def _merge_findings(left: list[Finding], right: list[Finding]) -> list[Finding]:
    """Reducer: append new findings (dedup by title+url later)."""
    return left + right


def _merge_results(left: list[AgentResult], right: list[AgentResult]) -> list[AgentResult]:
    """Reducer: append agent results."""
    return left + right


def _captured_flag_reducer(
    existing: str | None,
    new: str | None,
) -> str | None:
    """First non-None wins — once captured, stays captured.

    The conditional edge ``route_after_summarizer`` reads this field and
    routes to ``END`` on a truthy value. We use first-wins (rather than
    last-wins) so that:

    1. A second parallel worker that also matches expected_flag can't
       overwrite the first match with the same value (harmless but
       wasteful).
    2. A subsequent ``None`` write from a different node (e.g. a
       follow-up summarizer pass) cannot un-capture the flag.

    Two parallel workers landing flag matches in the same fan-out is
    rare (usually only one worker actually executes the winning probe),
    and if it happens both should match the same ``expected_flag``
    string anyway — so dropping the second is correct.
    """
    return existing or new


def _summary_inputs_reducer(
    left: list[dict] | None, right: list[dict] | None,
) -> list[dict]:
    """Reducer for ``pending_summary_inputs``.

    Plain ``operator.add`` would concatenate forever — and after the
    summarizer node has consumed the list, there is no way to clear it
    because re-emitting ``[]`` reduces to a no-op append. So we use a
    sentinel: when ``right`` is ``None``, the field is **cleared**
    (replaced by ``[]``); otherwise it is appended to the existing list.

    Each parallel worker (executor / recon) returns
    ``{"pending_summary_inputs": [singleton]}``; LangGraph fan-out
    accumulates the writes via this reducer so the synchronization-point
    summarizer node sees one entry per worker. The summarizer then
    returns ``{"pending_summary_inputs": None}`` to clear before
    transitioning to the planner.
    """
    if right is None:
        return []
    return list(left or []) + list(right or [])


class SwarmState:
    """Root state for the SwarmAttacker LangGraph graph.

    Uses LangGraph's annotated reducer pattern so parallel agent branches
    can all write findings/results and they get merged automatically.
    """

    # -- Target info (set once at the start) --
    target_url: str
    target_scope: str  # e.g. "*.example.com" or single URL

    # -- Orchestrator messages (routing / planning decisions) --
    messages: Annotated[list[AnyMessage], add_messages]

    # -- Aggregated results from all swarm agents --
    findings: Annotated[list[Finding], _merge_findings]
    agent_results: Annotated[list[AgentResult], _merge_results]

    # -- Stealth state (shared across all agents) --
    waf_detected: bool
    stealth_level: int  # 0=none, 1=cautious, 2=evasive

    # -- Planning / routing metadata --
    active_agents: Annotated[list[str], operator.add]


# LangGraph needs a TypedDict or dict-like schema.
# We use the class above for documentation, but the actual graph state
# is this TypedDict for LangGraph compatibility.
from typing import TypedDict


class SwarmGraphState(TypedDict, total=False):
    """The actual LangGraph state — TypedDict for graph compatibility."""

    # Run identity. Set once at graph invocation by the runner (or by
    # the initialize node as a fallback for Studio runs). Read by
    # BaseNode.__call__ to route per-node JSONL events into the correct
    # logs/run-<run_id>/ directory.
    run_id: str

    # Target (populated by the supervisor planner on its first turn,
    # not by the CLI). Before the first planner turn these may be empty.
    target_url: str
    target_scope: str

    # Orchestrator conversation
    messages: Annotated[list[AnyMessage], add_messages]

    # Findings & results (reducers merge from parallel branches)
    findings: Annotated[list[Finding], _merge_findings]
    agent_results: Annotated[list[AgentResult], _merge_results]

    # Stealth
    waf_detected: bool
    stealth_level: int

    # Workflow mode
    mode: str  # "analyze" or "full" — controls whether exploit phase runs

    # Planning
    active_agents: Annotated[list[str], operator.add]

    # -- Supervisor planner state (src/nodes/planner.py) --
    # The action the planner chose on its most recent turn. Read by
    # route_after_planner to pick the next node.
    next_action: str  # "attack" | "recon" | "web_search" | "report"
    # How many times the supervisor has been invoked this run. Capped
    # to prevent runaway supervision loops.
    planner_iters: int
    # Configs the planner staged for attack fan-out. Populated by
    # planner_node when it picks action="attack"; read by
    # route_after_planner to emit one Send() per item. Overwritten each
    # turn, not reduced.
    pending_dispatch: list[dict]
    # Convenience flag the planner can check to avoid asking for recon
    # again when it has already run at least once.
    recon_done: bool
    # Query string the planner asked the web_search node to run. Set
    # only when next_action == "web_search"; read by web_search_node.
    search_query: str
    # Counter for the planner's `_maybe_force_recovery` safety net —
    # how many times it has overridden a `report` decision with a
    # forced `web_search` this run. Capped at 1 to prevent loops.
    # See `_maybe_force_recovery` in src/nodes/planner.py for the rule.
    forced_recoveries: int
    # Optional benchmark-mode field. When set (by the xbow_runner or any
    # other benchmark driver), the planner and workers know the run has
    # an explicit success criterion — extracting a string matching this
    # value. Real pentest runs leave this empty, and the benchmark-only
    # behavior (flag-aware planner forcing function) does not fire.
    # Read by:
    #   - src.nodes.planner.PlannerNode.execute (planner prompt addendum
    #     and the `_maybe_force_recovery` safety net)
    #   - src.edges.routing.route_after_planner (compares submitted vs
    #     expected on action="submit_flag")
    expected_flag: str

    # Append-only list of flag strings the planner has explicitly
    # submitted via ``action="submit_flag"``. The routing edge
    # (``src.edges.routing.route_after_planner``) compares the most
    # recent entry against ``expected_flag`` using
    # ``src.edges.flag_match.flags_match`` and routes the graph to ``END`` on a
    # match — otherwise control returns to the planner so it can try a
    # different candidate. The system prompt teaches the planner that
    # re-entering after a submission means the previous attempt was
    # rejected.
    #
    # Two consumers:
    #   * ``route_after_planner`` — reads ``attempts[-1]`` to verify.
    #   * ``benchmarks.xbow_runner.run_one`` — reads the same value
    #     post-run as the authoritative verdict (no more passive regex
    #     scan of free-form messages, no more false-positive on a
    #     ``FLAG{...}`` placeholder in narration).
    #
    # The reducer is plain ``operator.add`` so multiple turns of the
    # planner each appending their own attempt are concatenated rather
    # than overwriting.
    submission_attempts: Annotated[list[str], operator.add]

    # Auto-verified flag capture. Set by ``run_skill_agent`` on the
    # worker success path when ANY ToolMessage in the agent's trace
    # contains a ``flag{...}`` substring that strict-equals
    # ``expected_flag`` via ``src.edges.flag_match.flags_match``. The
    # strict-equality gate is what makes this safe vs. the regex-only
    # auto-terminate that was removed on 2026-05-24: false-positive
    # patterns (swagger schemas, README examples, the agent's own
    # script literals) cannot strict-equal the deterministic
    # ``FLAG{sha256(BENCHMARK_UPPER)}`` value, so they simply don't
    # set this field.
    #
    # Consumed by ``src.edges.routing.route_after_summarizer`` to
    # auto-route the graph to ``END`` without requiring a planner
    # round-trip + ``submit_flag``. The skill runner ALSO pushes the
    # same value onto ``submission_attempts`` so ``xbow_runner``'s
    # existing verdict path (which reads ``submission_attempts``)
    # sees the capture without any new wiring.
    #
    # Only meaningful in benchmark mode (where ``expected_flag`` is
    # set). In real-pentest mode ``expected_flag`` is empty and this
    # field is never written — capture remains a planner-driven
    # explicit ``submit_flag`` decision, since no oracle exists.
    captured_flag: Annotated[str | None, _captured_flag_reducer]

    # ── Worker → Summarizer hand-off (the context-window fix) ──
    # Each worker (executor, recon, salvage) writes a SINGLE-ITEM list
    # here describing its run; LangGraph fan-out accumulates writes via
    # the ``_summary_inputs_reducer`` so the summarizer node — the
    # synchronization point — sees one entry per parallel worker. The
    # summarizer produces one ``AIMessage`` per entry (the worker's
    # report to the supervisor) and clears the list with ``None``.
    #
    # The raw worker trace NEVER enters ``state["messages"]`` — it lives
    # only inside this list while it's pending, and on disk in the
    # consolidated ``logs/run-<id>/worker_traces.jsonl`` file (one shared
    # file per run; rows tagged with ``agent_id`` + ``dispatch_ts`` so
    # individual worker invocations stay distinguishable). This bound the
    # planner's input prompt to digests + planner decisions instead of the
    # full mirrored trace storm.
    #
    # Each entry shape (see ``src/nodes/summarizer.py`` for the canonical
    # definition):
    #   {
    #     "agent_id":         str,
    #     "config_name":      str,
    #     "methodology":      str,
    #     "dispatch_reason":  str,                 # planner's "why"
    #     "trace":            list[BaseMessage],   # not mirrored to messages
    #     "trace_path":       str,                 # disk pointer
    #     "completed":        bool,
    #     "error":            str | None,
    #     "refused":          bool,
    #     "findings_count":   int,
    #   }
    pending_summary_inputs: Annotated[list[dict], _summary_inputs_reducer]


class AgentState(TypedDict, total=False):
    """Per-agent subgraph state — each swarm agent gets its own context."""

    # Inherited from parent
    target_url: str
    target_scope: str

    # Agent's own conversation (isolated context window)
    messages: Annotated[list[AnyMessage], add_messages]

    # Agent identity
    agent_id: str
    config_name: str
    methodology: str

    # Agent's findings (written back to parent via reducer)
    findings: Annotated[list[Finding], _merge_findings]

    # Stealth awareness (read from parent)
    waf_detected: bool
    stealth_level: int

    # Loop detection
    tool_call_count: int
    max_tool_calls: int
