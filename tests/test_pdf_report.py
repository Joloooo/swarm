"""Tier 1 report-content regression tests, plus the report-skill contract.

The client report must consume the canonical root-cause view instead of the raw
append-only observation feed.  Severity, validation, and confidence are factual
presentation fields, so they are derived deterministically before either the
Markdown or PDF renderer sees the findings.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.nodes.report import REPORTING_SKILL_NAME, ReportNode
from src.reporting.content import build_report_content, confidence_score
from src.reporting.markdown_report import render_markdown
from src.skills.loader import get_skill_description
from src.state import Finding, Severity


def _finding(
    title: str,
    severity: Severity,
    *,
    status: str = "demonstrated",
    reproduced: bool = False,
    description: str = "Observed security weakness",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category="sqli",
        description=description,
        evidence="HTTP/1.1 200 OK returned database error and extracted record",
        agent_id="test-agent",
        url="https://target.example/item?id=1",
        cwe="CWE-89",
        reproduced=reproduced,
        status=status,
    )


def test_report_prefers_canonical_findings_and_preserves_their_totals():
    raw = [
        _finding("Raw duplicate one", Severity.CRITICAL),
        _finding("Raw duplicate two", Severity.HIGH),
        _finding("Raw duplicate three", Severity.HIGH),
        _finding("Raw duplicate four", Severity.LOW),
    ]
    canonical = [
        _finding("Canonical high one", Severity.HIGH),
        _finding("Canonical high two", Severity.HIGH),
        _finding("Canonical medium", Severity.MEDIUM, reproduced=True),
        _finding("Canonical low", Severity.LOW),
        _finding("Canonical info", Severity.INFO),
    ]

    report = build_report_content({
        "target_url": "https://target.example",
        "target_scope": "target.example",
        "findings": raw,
        "canonical_findings": canonical,
    })

    assert [finding.title for finding in report.findings] == [
        "Canonical high one",
        "Canonical high two",
        "Canonical medium",
        "Canonical low",
        "Canonical info",
    ]
    assert report.severity_counts == {
        "critical": 0,
        "high": 2,
        "medium": 1,
        "low": 1,
        "info": 1,
    }
    assert report.raw_observation_count == 4


def test_report_maps_validation_and_separates_unverified_observations():
    report = build_report_content({
        "canonical_findings": [
            _finding("Demonstrated", Severity.HIGH),
            _finding("Confirmed", Severity.MEDIUM, reproduced=True),
            _finding(
                "Needs review",
                Severity.LOW,
                description="Manual review is required before verification",
            ),
        ],
    })

    assert [finding.validation for finding in report.findings] == [
        "Demonstrated",
        "Confirmed",
    ]
    assert [finding.title for finding in report.unverified] == ["Needs review"]
    markdown = render_markdown(report)
    assert "Not reproduced" not in markdown
    assert "| Validation status | Demonstrated |" in markdown
    assert "# Unverified observations" in markdown


@pytest.mark.parametrize(
    ("finding", "expected_score", "expected_label"),
    [
        ({}, 4, "Low"),
        ({"evidence": "x" * 100, "status": "demonstrated"}, 53, "Medium"),
        ({
            "evidence": "x" * 230,
            "status": "demonstrated",
            "url": "https://target.example",
            "agent_id": "agent",
            "category": "sqli",
            "cwe": "CWE-89",
        }, 70, "High"),
        ({
            "evidence": "HTTP/1.1 200 OK " + "x" * 230,
            "reproduced": True,
            "url": "https://target.example",
            "agent_id": "agent",
            "category": "sqli",
            "cwe": "CWE-89",
        }, 99, "Very high"),
        ({
            "evidence": "HTTP/1.1 200 OK " + "x" * 230,
            "attempts": [{"result": "progressed"}] * 3,
            "url": "https://target.example",
            "agent_id": "agent",
            "category": "sqli",
            "cwe": "CWE-89",
        }, 69, "Medium"),
    ],
)
def test_confidence_boundaries_are_deterministic(
    finding: dict,
    expected_score: int,
    expected_label: str,
):
    assert confidence_score(finding) == (expected_score, expected_label)


def test_reporting_skill_metadata_marks_final_reports_as_mandatory():
    description = get_skill_description(REPORTING_SKILL_NAME)
    assert "mandatory" in description.lower()
    assert "always use" in description.lower()
    assert "report-only" in description.lower()


@pytest.mark.asyncio
async def test_report_node_loads_reporting_skill_for_every_report(
    monkeypatch: pytest.MonkeyPatch,
):
    node = ReportNode()
    loaded: list[str] = []

    monkeypatch.setattr(
        node,
        "load_skill",
        lambda name: loaded.append(name) or SimpleNamespace(system_prompt="report rules"),
    )

    async def fake_ask_focused(*args, **kwargs):
        return "{}"

    monkeypatch.setattr(node, "ask_focused", fake_ask_focused)
    populated_result = await node._synthesize({
        "canonical_findings": [_finding("Canonical finding", Severity.HIGH)],
    })
    empty_result = await node._synthesize({"canonical_findings": []})

    assert populated_result == {}
    assert empty_result == {}
    assert loaded == [REPORTING_SKILL_NAME, REPORTING_SKILL_NAME]
