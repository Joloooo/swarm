"""Lossless Markdown companion for the branded PDF report."""

from __future__ import annotations

from .content import ReportContent, ReportFinding


def _bullet_lines(items: list[str], empty: str = "Not recorded") -> list[str]:
    return [f"- {item}" for item in items] if items else [f"- {empty}"]


def _finding_lines(finding: ReportFinding, number: int) -> list[str]:
    lines = [
        f"## F-{number:03d} — {finding.title}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Severity | {finding.severity.title()} ({finding.severity_band}) |",
        f"| Evidence confidence | {finding.confidence}% ({finding.confidence_label}) |",
        f"| Validation status | {finding.validation} |",
        f"| Category | {finding.category} |",
        f"| CWE | {finding.cwe or 'Not mapped'} |",
        f"| Affected target | {finding.url or 'Not recorded'} |",
        "",
        "### What an attacker could achieve",
        "",
        finding.business_impact,
        "",
        "### Systems and data at risk",
        "",
        *_bullet_lines(finding.assets_at_risk),
        "",
        "### Technical description and root cause",
        "",
        finding.description or "No additional technical description was recorded.",
        "",
        f"**Root cause:** {finding.root_cause}",
        "",
        "### Attack narrative",
        "",
    ]
    lines.extend(
        f"{index}. {step}" for index, step in enumerate(finding.attack_narrative, 1)
    )
    if finding.attempts:
        lines.extend([
            "",
            "### Demonstration steps recorded during testing",
            "",
            "| Step | Method | Result | Observation |",
            "|---:|---|---|---|",
        ])
        for index, attempt in enumerate(finding.attempts, 1):
            method = attempt.get("method") or "Not recorded"
            result = attempt.get("result") or "Not recorded"
            note = attempt.get("note") or ""
            lines.append(f"| {index} | {method} | {result} | {note} |")
    if finding.evidence:
        evidence = finding.evidence.replace("```", "''' ")
        lines.extend(["", "### Raw evidence", "", f"```text\n{evidence}\n```"])
    lines.extend([
        "",
        "### Remediation",
        "",
        *_bullet_lines(finding.remediation),
        "",
        f"**How to verify the fix:** {finding.validation_guidance}",
        "",
    ])
    return lines


def render_markdown(report: ReportContent) -> str:
    """Render the full report; unlike the old PDF edition, nothing is clipped."""
    counts = report.severity_counts
    lines = [
        "# SwarmAttacker Penetration Test Report",
        "",
        "## Executive summary",
        "",
        f"**Overall risk: {report.overall_risk} ({report.overall_risk_band})**",
        "",
        report.risk_rationale,
        "",
        "### What an attacker could achieve",
        "",
        *_bullet_lines(report.attacker_outcomes, "No demonstrated attacker outcome"),
        "",
        "### Systems and data at risk",
        "",
        *_bullet_lines(report.assets_at_risk),
        "",
        "### Priority actions",
        "",
        *_bullet_lines(report.priority_actions),
        "",
        f"**Average evidence confidence:** {report.average_confidence}%",
        "",
        f"**Assessment limitation:** {report.limitations}",
        "",
        "## Engagement details",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Target | {report.target} |",
        f"| Authorized scope | {report.scope} |",
        f"| Testing model | Autonomous black-box web application testing |",
        f"| Traffic profile | {report.traffic_profile} |",
        f"| Raw observations | {report.raw_observation_count} |",
        f"| Consolidated actionable findings | {len(report.findings)} |",
        f"| Unverified observations | {len(report.unverified)} |",
        "",
        "### Severity model",
        "",
        "Severity communicates potential technical impact; confidence communicates evidence strength. "
        "The report uses the standard qualitative bands Critical 9.0-10.0, High 7.0-8.9, "
        "Medium 4.0-6.9, Low 0.1-3.9, and Informational.",
        "",
        "| Critical | High | Medium | Low | Informational |",
        "|---:|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['info']} |",
        "",
        "## Findings summary",
        "",
        "| ID | Severity | Confidence | Validation | Finding |",
        "|---|---|---:|---|---|",
    ]
    for index, finding in enumerate(report.findings, 1):
        lines.append(
            f"| F-{index:03d} | {finding.severity.title()} | {finding.confidence}% | "
            f"{finding.validation} | {finding.title} |"
        )
    lines.extend(["", "# Detailed technical findings", ""])
    for index, finding in enumerate(report.findings, 1):
        lines.extend(_finding_lines(finding, index))

    lines.extend([
        "# Remediation roadmap",
        "",
        "Priority follows demonstrated impact and evidence confidence. Application owners should "
        "adjust timing where business context or compensating controls materially change exposure.",
        "",
    ])
    for index, finding in enumerate(report.findings, 1):
        action = finding.remediation[0] if finding.remediation else "Review and remediate the finding."
        lines.append(
            f"- **F-{index:03d} / {finding.severity.title()}:** {action}"
        )

    if report.unverified:
        lines.extend([
            "",
            "# Unverified observations",
            "",
            "These observations require manual review and are excluded from the actionable risk totals.",
            "",
            "| ID | Suspected severity | Confidence | Observation |",
            "|---|---|---:|---|",
        ])
        offset = len(report.findings)
        for index, finding in enumerate(report.unverified, 1):
            lines.append(
                f"| U-{index:03d} | {finding.severity.title()} | {finding.confidence}% | {finding.title} |"
            )
        lines.extend([""])
        for index, finding in enumerate(report.unverified, 1):
            lines.extend(_finding_lines(finding, offset + index))

    lines.extend([
        "# Methodology and limitations",
        "",
        "SwarmAttacker performed autonomous black-box testing against the authorized target. "
        "It mapped reachable functionality, formed evidence-backed hypotheses, dispatched specialist "
        "testing capabilities, and consolidated repeated observations by root cause. Results describe "
        "a point-in-time assessment and do not prove the absence of vulnerabilities in untested or "
        "unreachable functionality.",
        "",
        "Confidence is deterministic rather than model self-confidence. It combines raw evidence "
        "quality (0-40 points), validation status (0-35), successful supporting attempts (0-15), "
        "and traceability metadata (0-10). Unverified observations are capped below 70%.",
        "",
    ])
    if report.testing_areas:
        lines.extend(["### Testing areas exercised", "", *_bullet_lines(report.testing_areas), ""])
    return "\n".join(lines).rstrip() + "\n"


__all__ = ["render_markdown"]
