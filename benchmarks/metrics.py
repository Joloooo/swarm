"""Evaluation metrics for SwarmAttacker benchmark runs.

Computes the metrics defined in the thesis methodology:
- Success rate: % of expected vulnerabilities found
- Autonomy: % of test completed without human intervention
- Efficiency: findings per tool call, findings per dollar
- Error rate: % of agents that crashed or looped
- Finding quality: severity-weighted score
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from swarmattacker.state import AgentResult, Finding, Severity


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@dataclass
class BenchmarkMetrics:
    """Computed metrics for a single benchmark run."""

    target_name: str
    experiment: str  # config name (e.g., "default", "no_rag", "single_agent")

    # Success
    expected_vulns: list[str] = field(default_factory=list)
    found_categories: list[str] = field(default_factory=list)
    success_rate: float = 0.0  # |found ∩ expected| / |expected|

    # Autonomy
    total_agents: int = 0
    completed_agents: int = 0
    failed_agents: int = 0
    human_interventions: int = 0  # manual corrections needed
    autonomy_rate: float = 0.0  # completed / total

    # Efficiency
    total_tool_calls: int = 0
    total_findings: int = 0
    findings_per_tool_call: float = 0.0
    total_cost_usd: float = 0.0  # estimated LLM cost
    findings_per_dollar: float = 0.0

    # Errors
    error_rate: float = 0.0  # failed / total
    loop_detections: int = 0

    # Quality
    finding_quality_score: float = 0.0  # severity-weighted
    false_positives: int = 0  # manually verified
    unique_findings: int = 0

    # Timing
    total_duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for JSON/CSV export."""
        return {
            "target": self.target_name,
            "experiment": self.experiment,
            "success_rate": round(self.success_rate, 3),
            "autonomy_rate": round(self.autonomy_rate, 3),
            "error_rate": round(self.error_rate, 3),
            "total_findings": self.total_findings,
            "unique_findings": self.unique_findings,
            "finding_quality_score": round(self.finding_quality_score, 2),
            "findings_per_tool_call": round(self.findings_per_tool_call, 4),
            "total_tool_calls": self.total_tool_calls,
            "total_agents": self.total_agents,
            "completed_agents": self.completed_agents,
            "failed_agents": self.failed_agents,
            "loop_detections": self.loop_detections,
            "duration_seconds": round(self.total_duration_seconds, 1),
            "cost_usd": round(self.total_cost_usd, 4),
        }


def compute_metrics(
    findings: list[Finding],
    agent_results: list[AgentResult],
    expected_vulns: list[str],
    target_name: str = "",
    experiment: str = "default",
    duration_seconds: float = 0.0,
) -> BenchmarkMetrics:
    """Compute all metrics from a completed run."""
    m = BenchmarkMetrics(
        target_name=target_name,
        experiment=experiment,
        expected_vulns=expected_vulns,
    )

    # Findings analysis
    m.total_findings = len(findings)
    m.found_categories = list({f.category for f in findings})
    m.unique_findings = len({(f.title, f.url) for f in findings})

    # Success rate: how many expected vuln categories did we find?
    if expected_vulns:
        found_set = set(m.found_categories)
        expected_set = set(expected_vulns)
        m.success_rate = len(found_set & expected_set) / len(expected_set)

    # Finding quality score (severity-weighted)
    m.finding_quality_score = sum(
        SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings
    )

    # Agent analysis
    m.total_agents = len(agent_results)
    m.completed_agents = sum(1 for r in agent_results if r.completed)
    m.failed_agents = sum(1 for r in agent_results if r.error)

    if m.total_agents > 0:
        m.autonomy_rate = m.completed_agents / m.total_agents
        m.error_rate = m.failed_agents / m.total_agents

    # Efficiency (tool calls estimated from agent results)
    # Actual tool call counts will come from loop detector integration
    m.total_duration_seconds = duration_seconds

    return m
