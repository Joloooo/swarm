# Finding extraction.
# Two parsers run per assistant message: structured **FINDING:** / ## Finding,
# then JSON {"findings": [...]} as fallback. Only Title + Severity are required;
# bounded gaps stop runaway matches across unrelated headings.

from __future__ import annotations

import json
import re

from langchain_core.messages import AIMessage

from src.state import Finding, Severity


FINDING_PATTERN = re.compile(
    r"(?:\*\*FINDING:?\*\*|##\s+FINDING|##\s+Finding)"
    r"[\s\S]{0,40}?"
    r"Title:\s*(.+?)$"
    r"[\s\S]{0,200}?"
    r"Severity:\s*(\w+)"
    r"(?:[\s\S]{0,200}?Category:\s*([\w-]+))?"
    r"(?:[\s\S]{0,400}?URL:\s*(.+?)$)?"
    r"(?:[\s\S]{0,400}?Evidence:\s*(.+?)$)?"
    # Primitive is OPTIONAL, instructed LAST; generous gap tolerates a CWE/Payload
    # line before it. Group 6. Absent → "" → ordinary (non-primitive) finding.
    r"(?:[\s\S]{0,400}?Primitive:\s*([\w-]+))?",
    re.MULTILINE,
)

# JSON object (non-greedy) containing a "findings" key — fallback when the model
# emits {"findings": [...]} instead of the markdown form.
JSON_FINDINGS_PATTERN = re.compile(
    r'\{[^{}]*?"findings"\s*:\s*\[[\s\S]*?\]\s*\}',
)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _findings_from_markdown(content: str, agent_id: str) -> list[Finding]:
    # Parse the structured **FINDING:** / ## Finding format.
    out = []
    for match in FINDING_PATTERN.finditer(content):
        title = match.group(1).strip()
        severity_str = (match.group(2) or "info").strip().lower()
        category = (match.group(3) or "unknown").strip().lower()
        url = (match.group(4) or "").strip()
        evidence = (match.group(5) or "").strip()
        primitive = (match.group(6) or "").strip().lower()
        out.append(Finding(
            title=title,
            severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
            category=category,
            description=title,
            evidence=evidence[:500],
            agent_id=agent_id,
            url=url,
            primitive=primitive,
        ))
    return out


def _findings_from_json(content: str, agent_id: str) -> list[Finding]:
    # Fallback parser for JSON {"findings": [...]} blocks.
    out = []
    for match in JSON_FINDINGS_PATTERN.finditer(content):
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
        for item in data.get("findings", []) or []:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "Untitled finding").strip()
            severity_str = str(item.get("severity") or "info").strip().lower()
            category = str(item.get("category") or "unknown").strip().lower()
            url = str(item.get("url") or "").strip()
            evidence = str(item.get("evidence") or item.get("payload") or "")[:500]
            primitive = str(item.get("primitive") or "").strip().lower()
            out.append(Finding(
                title=title,
                severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
                category=category,
                description=str(item.get("description") or title),
                evidence=evidence,
                agent_id=agent_id,
                url=url,
                primitive=primitive,
            ))
    return out


def _extract_findings(messages: list, agent_id: str) -> list[Finding]:
    # Parse structured findings from agent messages: markdown FINDING first,
    # then JSON {"findings": [...]} fallback. Both run on every AIMessage.
    findings = []
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        findings.extend(_findings_from_markdown(content, agent_id))
        findings.extend(_findings_from_json(content, agent_id))
    return findings
