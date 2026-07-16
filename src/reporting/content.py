"""Normalize report data and derive auditable, presentation-ready content.

The report renderer never reads the append-only raw finding feed directly.  It
prefers the consolidation pass' canonical view, computes validation/confidence
deterministically, and accepts only bounded prose enrichment from the reporting
skill.  This keeps counts, severity, and evidence trustworthy even when the LLM
synthesis call is unavailable or returns malformed output.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Iterable
from enum import Enum
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_BANDS = {
    "critical": "9.0-10.0",
    "high": "7.0-8.9",
    "medium": "4.0-6.9",
    "low": "0.1-3.9",
    "info": "Informational",
}


def _plain(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return _plain(dataclasses.asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _value(obj: Any, name: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _severity(obj: Any) -> str:
    value = _value(obj, "severity", "info")
    severity = str(getattr(value, "value", value) or "info").lower()
    return severity if severity in SEVERITY_ORDER else "info"


def _clean(value: Any, limit: int = 0) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if limit and len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _list(value: Any, *, limit: int, item_limit: int = 280) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = _clean(item, item_limit)
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def select_report_findings(state: dict[str, Any]) -> list[Any]:
    """Return the canonical report feed, falling back only on cold-start runs."""
    canonical = list(state.get("canonical_findings") or [])
    selected = canonical if canonical else list(state.get("findings") or [])
    return sorted(selected, key=lambda item: SEVERITY_ORDER.get(_severity(item), 5))


def validation_status(finding: Any) -> str:
    """Describe what the evidence proves without conflating it with severity."""
    description = _clean(_value(finding, "description")).lower()
    if "unverified" in description or "manual review" in description:
        return "Unverified"
    if bool(_value(finding, "reproduced", False)):
        return "Confirmed"
    status = _clean(_value(finding, "status")).lower()
    if status in {"converted", "confirmed"}:
        return "Confirmed"
    if status == "demonstrated":
        return "Demonstrated"
    if status in {"converting", "intermittent"}:
        return "Intermittent"
    return "Unverified"


def confidence_score(finding: Any) -> tuple[int, str]:
    """Return an auditable 0-100 evidence confidence score.

    Components: evidence quality 0-40, validation 0-35, repeatability 0-15,
    and traceability 0-10.  This is deliberately not model self-confidence.
    """
    evidence = _clean(_value(finding, "evidence"))
    attempts = list(_value(finding, "attempts", []) or [])
    status = validation_status(finding)

    if not evidence:
        evidence_points = 0
    elif len(evidence) < 80:
        evidence_points = 18
    elif len(evidence) < 220:
        evidence_points = 28
    else:
        evidence_points = 35
    concrete_markers = (
        "http/", "status 200", "200 ok", "set-cookie", "response", "request",
        "returned", "output", "error", "extracted", "leaked", "confirmed",
    )
    if evidence and any(marker in evidence.lower() for marker in concrete_markers):
        evidence_points = min(40, evidence_points + 5)

    validation_points = {
        "Confirmed": 35,
        "Demonstrated": 25,
        "Intermittent": 18,
        "Unverified": 4,
    }[status]

    progressed = 0
    for attempt in attempts:
        result = _clean(_value(attempt, "result")).lower()
        if result in {"progressed", "confirmed", "success", "converted"}:
            progressed += 1
    repeatability_points = min(15, progressed * 5)
    if bool(_value(finding, "reproduced", False)):
        repeatability_points = 15

    traceability_points = 0
    traceability_points += 4 if _clean(_value(finding, "url")) else 0
    traceability_points += 3 if _clean(_value(finding, "agent_id")) else 0
    traceability_points += 2 if _clean(_value(finding, "category")) else 0
    traceability_points += 1 if _clean(_value(finding, "cwe")) else 0

    total = max(0, min(99, evidence_points + validation_points
                       + repeatability_points + traceability_points))
    if status == "Unverified":
        total = min(total, 69)
    label = (
        "Very high" if total >= 90 else
        "High" if total >= 70 else
        "Medium" if total >= 50 else
        "Low"
    )
    return total, label


_CATEGORY_CONTENT: dict[str, dict[str, Any]] = {
    "sqli": {
        "assets": ["application database", "business records", "database integrity"],
        "impact": "An attacker may read or alter database-backed information available to the vulnerable application account.",
        "root": "Untrusted input reaches a database query without safe parameter binding.",
        "fix": [
            "Replace dynamic SQL construction with parameterized queries for every affected parameter.",
            "Restrict the application database account to the minimum required permissions.",
            "Review adjacent routes that use the same query-building code.",
        ],
        "verify": "Replay the original payloads and confirm they are treated as data without SQL errors, query changes, or returned records.",
    },
    "auth": {
        "assets": ["user accounts", "authentication credentials", "authenticated sessions"],
        "impact": "An attacker who obtains the exposed authentication material may impersonate an affected user and access that user's privileges.",
        "root": "Authentication material is stored or exposed outside a protected server-side session boundary.",
        "fix": [
            "Remove passwords and reusable authentication secrets from client-side storage.",
            "Use short-lived opaque session identifiers protected with Secure, HttpOnly, and appropriate SameSite attributes.",
            "Invalidate existing exposed credentials and active sessions.",
        ],
        "verify": "Authenticate again and confirm no password or reusable credential is present in cookies, URLs, HTML, or browser storage.",
    },
    "session": {
        "assets": ["authenticated sessions", "user accounts", "authorization boundaries"],
        "impact": "A predictable, reusable, or insufficiently rotated session may let an attacker retain or assume another user's authenticated state.",
        "root": "The application does not enforce a secure session lifecycle at an authentication boundary.",
        "fix": [
            "Rotate the session identifier after login and every privilege change.",
            "Invalidate the prior identifier server-side and enforce secure cookie attributes.",
            "Add regression checks for fixation, logout invalidation, and replay.",
        ],
        "verify": "Confirm that login issues a new session identifier and that the pre-login value cannot access authenticated content.",
    },
    "crypto": {
        "assets": ["encrypted web traffic", "credentials in transit", "session confidentiality"],
        "impact": "Legacy transport settings can weaken protection for sensitive traffic and increase exposure to protocol or cipher attacks.",
        "root": "The TLS endpoint permits obsolete protocol versions or weak cipher suites.",
        "fix": [
            "Disable TLS 1.0, TLS 1.1, 3DES, and other weak cipher suites.",
            "Permit TLS 1.2 and TLS 1.3 with modern server-preferred suites.",
        ],
        "verify": "Repeat TLS enumeration and confirm only approved protocol versions and cipher suites are offered.",
    },
    "default": {
        "assets": ["affected application functionality", "application users", "security controls"],
        "impact": "The weakness may reduce the confidentiality, integrity, or security assurance of the affected functionality.",
        "root": "The affected functionality does not enforce the expected security control consistently.",
        "fix": [
            "Correct the affected control at its server-side enforcement point.",
            "Review equivalent functionality for the same root cause.",
        ],
        "verify": "Repeat the original test and confirm the insecure behavior is no longer observable.",
    },
}


def _fallback_profile(category: str) -> dict[str, Any]:
    key = category.lower()
    if key in _CATEGORY_CONTENT:
        return _CATEGORY_CONTENT[key]
    if "sql" in key:
        return _CATEGORY_CONTENT["sqli"]
    if key in {"idor", "bfla", "access-control"}:
        return {
            "assets": ["other users' records", "authorization boundaries", "protected functions"],
            "impact": "An attacker may access or modify resources outside the permissions of their own account.",
            "root": "Server-side authorization does not consistently verify the caller's ownership or role.",
            "fix": ["Enforce object ownership and role checks on every affected server-side operation.", "Add negative authorization tests for other-user and lower-privilege sessions."],
            "verify": "Repeat the request as an unauthorized user and confirm the server returns 401 or 403 without protected data.",
        }
    if key in {"info", "information-disclosure"}:
        return {
            "assets": ["exposed application data", "internal implementation details", "business information"],
            "impact": "An unauthorised party may obtain information that supports further attacks or directly exposes business data.",
            "root": "Sensitive information is returned to a context that does not require it or is not authorized to receive it.",
            "fix": ["Remove sensitive values from public or client-visible responses.", "Require authorization before serving generated files or sensitive records.", "Expire and invalidate previously exposed artifacts or secrets."],
            "verify": "Request the affected resource without authorization and confirm no sensitive content or reusable secret is returned.",
        }
    return _CATEGORY_CONTENT["default"]


@dataclasses.dataclass
class ReportFinding:
    source_index: int
    title: str
    severity: str
    severity_band: str
    category: str
    description: str
    evidence: str
    url: str
    cwe: str
    agent_id: str
    attempts: list[dict[str, str]]
    validation: str
    confidence: int
    confidence_label: str
    business_impact: str
    assets_at_risk: list[str]
    root_cause: str
    attack_narrative: list[str]
    remediation: list[str]
    validation_guidance: str

    @property
    def verified(self) -> bool:
        return self.validation != "Unverified"


@dataclasses.dataclass
class ReportContent:
    target: str
    scope: str
    traffic_profile: str
    overall_risk: str
    overall_risk_band: str
    risk_rationale: str
    attacker_outcomes: list[str]
    assets_at_risk: list[str]
    priority_actions: list[str]
    limitations: str
    findings: list[ReportFinding]
    unverified: list[ReportFinding]
    raw_observation_count: int
    average_confidence: int
    testing_areas: list[str]

    @property
    def all_findings(self) -> list[ReportFinding]:
        return self.findings + self.unverified

    @property
    def severity_counts(self) -> dict[str, int]:
        return {
            severity: sum(1 for finding in self.findings if finding.severity == severity)
            for severity in SEVERITY_ORDER
        }


def _default_attack_narrative(finding: Any, category: str) -> list[str]:
    steps: list[str] = []
    url = _clean(_value(finding, "url"), 220)
    if url:
        steps.append(f"Reach the affected functionality at {url}.")
    for attempt in list(_value(finding, "attempts", []) or [])[:3]:
        method = _clean(_value(attempt, "method"), 100)
        note = _clean(_value(attempt, "note"), 140)
        if method:
            steps.append(f"Use {method}{': ' + note if note else ''}.")
    if len(steps) < 2:
        description = _clean(_value(finding, "description"), 220)
        if description:
            steps.append(f"Observe the reported behavior: {description}.")
    return steps[:5]


def _normalize_finding(item: Any, index: int, enrichment: dict[str, Any]) -> ReportFinding:
    severity = _severity(item)
    category = _clean(_value(item, "category")) or "unspecified"
    fallback = _fallback_profile(category)
    confidence, confidence_label = confidence_score(item)
    attempts: list[dict[str, str]] = []
    for attempt in list(_value(item, "attempts", []) or [])[:8]:
        attempts.append({
            "method": _clean(_value(attempt, "method"), 120),
            "result": _clean(_value(attempt, "result"), 50),
            "note": _clean(_value(attempt, "note"), 180),
        })
    return ReportFinding(
        source_index=index,
        title=_clean(_value(item, "title"), 240) or "Untitled finding",
        severity=severity,
        severity_band=SEVERITY_BANDS[severity],
        category=category,
        description=_clean(_value(item, "description"), 1000),
        evidence=str(_value(item, "evidence", "") or "").strip()[:8000],
        url=_clean(_value(item, "url"), 500),
        cwe=_clean(_value(item, "cwe"), 80),
        agent_id=_clean(_value(item, "agent_id"), 80),
        attempts=attempts,
        validation=validation_status(item),
        confidence=confidence,
        confidence_label=confidence_label,
        business_impact=_clean(enrichment.get("business_impact"), 600)
        or fallback["impact"],
        assets_at_risk=_list(enrichment.get("assets_at_risk"), limit=6, item_limit=120)
        or list(fallback["assets"]),
        root_cause=_clean(enrichment.get("root_cause"), 500) or fallback["root"],
        attack_narrative=_list(enrichment.get("attack_narrative"), limit=5, item_limit=300)
        or _default_attack_narrative(item, category),
        remediation=_list(enrichment.get("remediation"), limit=5, item_limit=360)
        or list(fallback["fix"]),
        validation_guidance=_clean(enrichment.get("validation_guidance"), 500)
        or fallback["verify"],
    )


def _dedupe(items: Iterable[str], limit: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        value = _clean(item)
        key = value.lower()
        if value and key not in seen:
            seen.add(key)
            result.append(value)
        if len(result) >= limit:
            break
    return result


def _testing_areas(state: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    for result in list(state.get("agent_results") or []):
        name = _clean(_value(result, "config_name") or _value(result, "methodology"))
        if not name:
            continue
        label = name.replace("-", " ").replace("_", " ").title()
        if label not in labels:
            labels.append(label)
    return labels[:16]


def build_report_content(
    state: dict[str, Any],
    synthesis: dict[str, Any] | None = None,
) -> ReportContent:
    selected = select_report_findings(state)
    synthesis = synthesis if isinstance(synthesis, dict) else {}
    enrichments: dict[int, dict[str, Any]] = {}
    for entry in synthesis.get("findings", []) if isinstance(synthesis.get("findings"), list) else []:
        if not isinstance(entry, dict):
            continue
        try:
            source_index = int(entry.get("source_index"))
        except (TypeError, ValueError):
            continue
        enrichments[source_index] = entry

    normalized = [
        _normalize_finding(item, index, enrichments.get(index, {}))
        for index, item in enumerate(selected, 1)
    ]
    findings = [item for item in normalized if item.verified]
    unverified = [item for item in normalized if not item.verified]
    overall = findings[0].severity if findings else "info"
    overall_label = "Informational" if not findings else overall.title()

    executive = synthesis.get("executive")
    executive = executive if isinstance(executive, dict) else {}
    top = findings[:3]
    fallback_rationale = (
        f"The assessment identified {len(findings)} actionable vulnerabilities. "
        f"The highest-risk demonstrated issue, {top[0].title}, may affect "
        f"{', '.join(top[0].assets_at_risk[:3])}."
        if top else
        "No actionable vulnerability was demonstrated during this assessment; this does not prove that the target is free of vulnerabilities."
    )
    attacker_outcomes = _list(executive.get("attacker_outcomes"), limit=4, item_limit=300)
    if not attacker_outcomes:
        attacker_outcomes = _dedupe((item.business_impact for item in top), 4)
    assets = _list(executive.get("assets_at_risk"), limit=6, item_limit=140)
    if not assets:
        assets = _dedupe(
            (asset for item in top for asset in item.assets_at_risk), 6
        )
    priorities = _list(executive.get("priority_actions"), limit=5, item_limit=320)
    if not priorities:
        priorities = _dedupe(
            (action for item in top for action in item.remediation[:1]), 5
        )
    limitations = _clean(executive.get("limitations"), 500)
    if not limitations:
        demonstrated = sum(1 for item in findings if item.validation == "Demonstrated")
        limitations = (
            f"{demonstrated} finding{'s were' if demonstrated != 1 else ' was'} demonstrated from captured evidence but not independently reverified before report generation."
            if demonstrated else
            "Results are a point-in-time assessment limited to the supplied scope, access, runtime, and target availability."
        )
    average = round(sum(item.confidence for item in findings) / len(findings)) if findings else 0
    return ReportContent(
        target=_clean(state.get("target_url")) or "Target from engagement instruction",
        scope=_clean(state.get("target_scope")) or "Scope defined by the operator",
        traffic_profile=_clean(state.get("traffic_profile")) or "not recorded",
        overall_risk=overall_label,
        overall_risk_band=SEVERITY_BANDS[overall],
        risk_rationale=_clean(executive.get("risk_rationale"), 700) or fallback_rationale,
        attacker_outcomes=attacker_outcomes,
        assets_at_risk=assets,
        priority_actions=priorities,
        limitations=limitations,
        findings=findings,
        unverified=unverified,
        raw_observation_count=len(list(state.get("findings") or [])),
        average_confidence=average,
        testing_areas=_testing_areas(state),
    )


def synthesis_input(state: dict[str, Any]) -> str:
    """Return bounded canonical evidence for the reporting skill."""
    payload = {
        "target": state.get("target_url") or "",
        "scope": state.get("target_scope") or "",
        "findings": [],
    }
    for index, finding in enumerate(select_report_findings(state), 1):
        payload["findings"].append({
            "source_index": index,
            "title": _clean(_value(finding, "title"), 240),
            "severity": _severity(finding),
            "category": _clean(_value(finding, "category"), 80),
            "description": _clean(_value(finding, "description"), 900),
            "evidence": str(_value(finding, "evidence", "") or "").strip()[:2500],
            "url": _clean(_value(finding, "url"), 500),
            "cwe": _clean(_value(finding, "cwe"), 80),
            "validation": validation_status(finding),
            "confidence": confidence_score(finding)[0],
            "attempts": _plain(list(_value(finding, "attempts", []) or [])[:6]),
        })
    return json.dumps(payload, ensure_ascii=False, indent=2)


def parse_synthesis(text: str) -> dict[str, Any]:
    """Parse a JSON object, tolerating an accidental Markdown fence."""
    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, count=1, flags=re.I)
        raw = re.sub(r"\s*```$", "", raw, count=1)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        start, end = raw.find("{"), raw.rfind("}")
        if start < 0 or end <= start:
            raise
        parsed = json.loads(raw[start:end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("report synthesis must be a JSON object")
    return parsed


__all__ = [
    "ReportContent",
    "ReportFinding",
    "SEVERITY_BANDS",
    "SEVERITY_ORDER",
    "build_report_content",
    "parse_synthesis",
    "select_report_findings",
    "synthesis_input",
]
