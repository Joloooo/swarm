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


def _merge_findings(left: list[Finding], right: list[Finding]) -> list[Finding]:
    """Reducer: append new findings (dedup by title+url later)."""
    return left + right


def _merge_results(left: list[AgentResult], right: list[AgentResult]) -> list[AgentResult]:
    """Reducer: append agent results."""
    return left + right


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
    tier2_activated: bool


# LangGraph needs a TypedDict or dict-like schema.
# We use the class above for documentation, but the actual graph state
# is this TypedDict for LangGraph compatibility.
from typing import TypedDict


class SwarmGraphState(TypedDict, total=False):
    """The actual LangGraph state — TypedDict for graph compatibility."""

    # Target
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

    # Planning
    active_agents: Annotated[list[str], operator.add]
    tier2_activated: bool


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
