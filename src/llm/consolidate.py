"""Findings consolidation pass — dedup, status, attempts, lead_priority.

This module owns the **consolidation primitive** that the
``SummarizerNode`` (``src/nodes/summarizer.py``) runs once per cycle,
after the per-worker digests are produced. Like ``digest.py`` it is
framework-agnostic — pure async/sync functions over plain data and a
``BaseChatModel`` — so it can be unit-tested in isolation.

The problem it solves
=====================

The raw ``state["findings"]`` list is append-only and deduped only by
*exact* ``title+url`` (``src/state.py:_merge_findings``). Workers reword
the same finding every wave, so the same blind-SQLi observation can
survive 7–13× under slightly different titles; the planner's directive
then carries all of them, and the real signal (a proven primitive, or
the one finding closest to the flag) drowns. The audit (06-10 batch)
measured the findings stream at ~88% noise — duplicated, mis-channelled
(negatives filed as findings), and mis-ranked (severity ≠ proximity to
the objective).

What this pass produces
=======================

One LLM call per summarizer cycle reads the raw findings + the prior
canonical view + the worker digests and proposes a **canonical** list:
deduped/merged, each entry stamped with a conversion ``status``
(``PrimitiveStatus``), a short ``attempts`` log (what was tried to turn a
primitive into the flag, with what outcome), and a ``lead_priority``.
Pure negative/status results ("did not authenticate", "service
unavailable") are routed OUT of the findings channel into a separate
``exhausted_ledger`` so they inform "don't re-try" without diluting the
digest.

Determinism guard
=================

The LLM only *proposes*. Everything consequential is enforced
deterministically afterward:

- ``status`` is **monotonic** — a primitive can only advance
  (suspected → demonstrated → converting → exhausted | converted), never
  regress, enforced against the prior canonical view.
- ``lead_priority`` is recomputed from a deterministic formula
  (:func:`_lead_priority`); the LLM contributes only a bounded ±15
  app-specific nudge, then the score is clamped to 0–100.
- If the LLM call fails or returns junk, a deterministic fallback
  (:func:`_deterministic_consolidate`) still dedups by
  ``(category, url)``, carries prior status/attempts forward, and scores
  — so ``canonical_findings`` is always populated even with no LLM.

Vocabulary policy
=================

All prompt text uses neutral test-task vocabulary (see the Skill
Vocabulary Policy in ``CLAUDE.md``). Domain technical names (SQL
injection, SSRF, CSRF token) stay intact; framing words do not.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import replace
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from src.state import AttemptResult, Finding, PrimitiveStatus, Severity

logger = logging.getLogger(__name__)


# ── Tunables ──────────────────────────────────────────────────────────

# How many of the most recent raw findings we feed the consolidation
# call. Bounds prompt size on long runs; the carried-forward canonical
# view preserves anything older that already mattered.
MAX_RAW_FINDINGS = 60
# Per-finding evidence snippet length fed to the LLM (the full evidence
# stays on the canonical Finding; the LLM only needs enough to judge).
EVIDENCE_SNIPPET_CHARS = 300
# Per-worker digest length fed to the LLM as the source for deriving
# attempts ("what was tried, with what outcome").
DIGEST_SNIPPET_CHARS = 1400
# Keep at most this many attempts per primitive (the freshest).
MAX_ATTEMPTS_PER_FINDING = 5
# Hard cap on the canonical list size so a pathological run can't bloat
# the planner prompt.
MAX_CANONICAL = 40


# ── Deterministic scoring + status machinery ──────────────────────────

# "Proximity to the objective" by primitive class — how many mechanical
# steps a proven primitive of this class is from reading the flag.
_PROXIMITY = {
    "rce": 30,
    "file_read": 30,
    "sqli_read": 20,
    "auth_bypass": 20,
    "ssrf": 15,
}
_PROXIMITY_DEFAULT_PRIMITIVE = 12  # a demonstrated primitive of some other class

_SEV_WEIGHT = {
    "critical": 12,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
}

# Base score by conversion status.
_STATUS_BASE = {
    "demonstrated": 50,
    "converting": 45,
    "suspected": 20,
    "exhausted": 0,
    "converted": 0,  # run ends on capture; ranking is moot
    "": 0,
}

# Monotonic floor — a status may only move to one with floor >= its
# current floor. Lets converting↔exhausted oscillate (both floor 2) while
# forbidding a regression from demonstrated (2) back to suspected (1).
# ``converted`` (3) is terminal.
_STATUS_FLOOR = {
    "": 0,
    "suspected": 1,
    "demonstrated": 2,
    "converting": 2,
    "exhausted": 2,
    "converted": 3,
}

_VALID_STATUSES = {s.value for s in PrimitiveStatus}
_VALID_RESULTS = {r.value for r in AttemptResult}
_VALID_SEVERITIES = {s.value for s in Severity}

# Negative / status phrases that mark a "finding" as a non-finding (a
# tried-and-didn't-work result) — used by the deterministic fallback to
# route entries into the exhausted ledger. Neutral vocabulary.
_NEGATIVE_MARKERS = (
    "did not", "didn't", "not demonstrated", "no sql injection",
    "not exploitable", "no confirmed", "unavailable", "not authenticate",
    "could not", "couldn't", "no open", "found no", "returned empty",
    "appears unsupported", "not vulnerable", "no recoverable",
)

# Content signals for category reconciliation (fix a worker that filed an
# SSRF under its xss skill identity, etc.). Conservative — only the
# strongest, unambiguous markers.
_CATEGORY_SIGNALS = (
    ("ssrf", ("server-side request", "ssrf ", " ssrf", "localhost-only",
              "internal service", "metadata endpoint")),
    ("sqli", ("union select", "sql injection", "information_schema",
              "boolean-based blind", "time-based blind")),
    ("rce", ("command execution", "remote code execution", "code execution")),
)


def _sev_str(value: Any) -> str:
    """Lowercase severity string from a Finding or a raw value."""
    sev = getattr(value, "severity", value)
    return str(getattr(sev, "value", sev) or "").lower()


def _lead_priority(
    *, status: str, primitive: str, severity: str, n_attempts: int,
    nudge: int = 0,
) -> int:
    """Deterministic 0–100 proximity-to-objective score.

    A proven primitive close to the flag with few attempts ranks highest;
    each attempt decays the score (so persistence does not become
    head-banging); an exhausted primitive is driven to the floor. The LLM
    ``nudge`` (clamped ±15 by the caller) adds app-specific judgment at
    the margin only.
    """
    base = _STATUS_BASE.get(status, 0)
    prim = (primitive or "").strip().lower()
    if prim:
        base += _PROXIMITY.get(prim, _PROXIMITY_DEFAULT_PRIMITIVE)
    base += _SEV_WEIGHT.get(severity, 0)
    base -= 5 * min(max(n_attempts, 0), 5)
    if status == PrimitiveStatus.EXHAUSTED.value:
        base -= 100
    return max(0, min(100, base + int(nudge)))


def _advance_status(prior: str, proposed: str) -> str:
    """Monotonic status guard — never let a primitive regress.

    Returns ``proposed`` when it is at least as advanced as ``prior``
    (by ``_STATUS_FLOOR``); otherwise keeps ``prior``. ``converted`` is
    terminal once reached.
    """
    prior = (prior or "").strip().lower()
    proposed = (proposed or "").strip().lower()
    if proposed not in _VALID_STATUSES:
        return prior
    if prior == PrimitiveStatus.CONVERTED.value:
        return prior
    if _STATUS_FLOOR.get(proposed, 0) < _STATUS_FLOOR.get(prior, 0):
        return prior
    return proposed


def _normalize_stem(title: str) -> str:
    """Collapse a title to a coarse stem for dedup: lowercase, drop a
    trailing ``(skill)`` / ``(executor-N)`` parenthetical, strip
    punctuation, collapse whitespace.
    """
    t = (title or "").lower()
    t = re.sub(r"\([^)]*\)\s*$", "", t)  # trailing tag
    t = re.sub(r"[^a-z0-9 ]+", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _dedup_key(f: Finding) -> str:
    """Coarse identity for the deterministic fallback: a primitive/vuln on
    one URL is one lead regardless of wording. Falls back to the title
    stem when there is no URL.
    """
    cat = (getattr(f, "category", "") or "").strip().lower()
    url = (getattr(f, "url", "") or "").strip().lower()
    if url:
        return f"{cat}|{url}"
    return f"{cat}|{_normalize_stem(getattr(f, 'title', ''))}"


def _ledger_key(category: str, url: str) -> str:
    return f"{(category or '').strip().lower()}|{(url or '').strip().lower()}"


# ── Hygiene guards (deterministic) ────────────────────────────────────

_CORE_VERSION_RE = re.compile(
    r"(wordpress|drupal|joomla|apache|nginx|php)\s+core[^0-9]*([0-9]+)\.([0-9]+)",
    re.I,
)
# Highest plausible MAJOR core version per product (anything above is a
# misparse — typically a plugin/module version mislabelled as core).
_MAX_PLAUSIBLE_CORE_MAJOR = {
    "wordpress": 6, "drupal": 11, "joomla": 5, "apache": 2, "nginx": 1,
    "php": 8,
}


def _version_fp_guard(title: str, severity: str) -> tuple[str, bool]:
    """Demote an implausible *core* version claim (e.g. "WordPress core
    7.0" — WP 7.0 does not exist; it is almost always a plugin version
    mislabelled as core). Returns ``(severity, unverified)``.
    """
    m = _CORE_VERSION_RE.search(title or "")
    if not m:
        return severity, False
    product = m.group(1).lower()
    major = int(m.group(2))
    if major > _MAX_PLAUSIBLE_CORE_MAJOR.get(product, 99):
        return Severity.INFO.value, True
    return severity, False


def _reconcile_category(title: str, evidence: str, category: str) -> str:
    """If the title/evidence unambiguously signals a vuln class that
    disagrees with the worker-assigned ``category``, prefer the
    content-derived class. Conservative; only fires on strong markers.
    """
    blob = f"{title} {evidence}".lower()
    cat = (category or "").strip().lower()
    for canon, markers in _CATEGORY_SIGNALS:
        if cat == canon:
            continue
        if any(mk in blob for mk in markers):
            return canon
    return cat


def _clean_attempts(raw: Any, prior: list[dict] | None) -> list[dict]:
    """Validate + merge attempt records; keep the freshest N, dedup by
    (method, result). Each entry: ``{method, result, note}`` with a
    controlled ``result`` and short neutral ``method``/``note``.
    """
    out: list[dict] = list(prior or [])
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method") or "").strip()[:60]
            result = str(item.get("result") or "").strip().lower()
            note = str(item.get("note") or "").strip()[:80]
            if not method or result not in _VALID_RESULTS:
                continue
            out.append({"method": method, "result": result, "note": note})
    # dedup by (method, result), keep last occurrence, cap to last N
    seen: dict[tuple[str, str], dict] = {}
    for a in out:
        seen[(a["method"].lower(), a["result"])] = a
    deduped = list(seen.values())
    return deduped[-MAX_ATTEMPTS_PER_FINDING:]


# ── LLM call ──────────────────────────────────────────────────────────

_CONSOLIDATE_SYSTEM = """\
You organize the evidence log of a black-box web-application security
test so a supervisor can decide the next step. You do NOT run any tests
and you do NOT call any tools — you only restructure findings that other
test agents already recorded.

Two ideas drive your work:

1. A PRIMITIVE is a demonstrated capability that is a means to the
   objective but not yet the objective itself — e.g. a working data-
   leaking SQL injection, a confirmed file read, a held privileged
   session, a reached internal service. A primitive has a conversion
   STATUS:
     - suspected: a lead, not yet proven
     - demonstrated: proven capability, not yet turned into the flag
     - converting: an agent is actively turning it into the flag
     - exhausted: the conversion methods tried so far did not work
     - converted: it reached the objective
   Status only advances; it never goes backward.

2. SEVERITY (how serious the bug is) is SEPARATE from how CLOSE a lead
   is to the objective. Rank by closeness, not by severity.

Use neutral test-task vocabulary. Keep domain names intact (SQL
injection, SSRF, CSRF token). Output ONLY the JSON object specified.
"""


def _finding_brief(i: int, f: Finding) -> dict:
    return {
        "id": i,
        "title": (getattr(f, "title", "") or "")[:160],
        "severity": _sev_str(f),
        "category": (getattr(f, "category", "") or ""),
        "url": (getattr(f, "url", "") or ""),
        "primitive": (getattr(f, "primitive", "") or ""),
        "evidence": (getattr(f, "evidence", "") or "")[:EVIDENCE_SNIPPET_CHARS],
    }


def _prior_brief(f: Finding) -> dict:
    return {
        "key": _dedup_key(f),
        "title": (getattr(f, "title", "") or "")[:120],
        "status": (getattr(f, "status", "") or ""),
        "attempts": list(getattr(f, "attempts", []) or [])[-MAX_ATTEMPTS_PER_FINDING:],
    }


def _build_user_prompt(
    raw: list[Finding], prior: list[Finding], digests: list[str],
) -> str:
    raw_briefs = [_finding_brief(i, f) for i, f in enumerate(raw)]
    prior_briefs = [_prior_brief(f) for f in prior]
    digest_block = "\n\n".join(
        f"[worker digest {i}]\n{d[:DIGEST_SNIPPET_CHARS]}"
        for i, d in enumerate(digests) if d
    )
    return f"""\
RAW FINDINGS (each test agent's recorded observations; many are reworded
duplicates of the same underlying issue):
{json.dumps(raw_briefs, indent=1)}

PRIOR CANONICAL VIEW (status + attempts already established last cycle —
carry these forward; status may only advance):
{json.dumps(prior_briefs, indent=1)}

WORKER DIGESTS (source for deriving what conversion methods were tried
and with what outcome):
{digest_block or "(none this cycle)"}

TASK — produce a JSON object:
{{
  "canonical": [
    {{
      "sources": [<raw-finding ids this entry merges; the first is the
                   strongest/most-evidenced>],
      "title": "<one clear title>",
      "severity": "critical|high|medium|low|info",
      "category": "<vuln class, e.g. sqli/ssrf/idor/ssti>",
      "url": "<endpoint or empty>",
      "primitive": "<rce|file_read|sqli_read|auth_bypass|ssrf|'' if not a primitive>",
      "status": "suspected|demonstrated|converting|exhausted|converted",
      "kind": "signal|negative",
      "attempts": [
        {{"method": "<<=8 words, neutral, e.g. 'union-return auth check'>",
          "result": "no-effect|blocked|partial|error|progressed",
          "note": "<<=10 words, optional>"}}
      ],
      "priority_nudge": <integer -15..15: + if this lead is closer to the
                          flag than its class suggests, - if farther>
    }}
  ]
}}

RULES:
- MERGE every reworded duplicate into ONE canonical entry (list all the
  source ids in "sources"). Collapsing duplicates is the main job.
- kind="negative" for a pure tried-and-did-not-work / status result
  ("no injection confirmed", "service unavailable"). These are NOT
  findings — mark them negative so they leave the findings digest.
- Set "status" honestly. A finding with a real demonstrated capability
  is "demonstrated"; a mere lead is "suspected".
- Derive "attempts" from the worker digests: the conversion methods
  tried on a primitive and their outcome. Empty list if none.
- Output ONLY the JSON object. No prose.
"""


def _extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of an LLM response (tolerating
    ```json fences and trailing prose)."""
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fence.group(1) if fence else None
    if candidate is None:
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        for j in range(start, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:j + 1]
                    break
    if not candidate:
        return None
    try:
        obj = json.loads(candidate)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


async def consolidate_findings(
    *,
    raw_findings: list[Finding],
    prior_canonical: list[Finding],
    prior_ledger: dict | None,
    worker_digests: list[str],
    model: BaseChatModel,
    run_id: str | None,
    node_name: str = "summarizer",
) -> dict:
    """Return ``{"canonical_findings": [...], "exhausted_ledger": {...}}``.

    Tries the LLM consolidation; on any failure falls back to the
    deterministic consolidation so the canonical view is always
    populated. Returns ``{}`` (no state change) when there is nothing to
    consolidate.
    """
    raw = list(raw_findings or [])
    if not raw:
        return {}
    prior = list(prior_canonical or [])
    ledger = dict(prior_ledger or {})
    raw_fed = raw[-MAX_RAW_FINDINGS:]
    prior_by_key = {_dedup_key(f): f for f in prior}

    parsed: dict | None = None
    try:
        from src.llm.callbacks import make_call_config
        call_config = make_call_config(
            run_id=run_id, agent_id="__consolidate", node=node_name,
        )
        messages = [
            SystemMessage(content=_CONSOLIDATE_SYSTEM),
            HumanMessage(content=_build_user_prompt(
                raw_fed, prior, worker_digests)),
        ]
        response = await model.ainvoke(messages, config=call_config)
        text = response.content
        if not isinstance(text, str):
            text = str(text or "")
        parsed = _extract_json(text)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "consolidate: LLM call failed (%s: %s) — deterministic fallback",
            type(e).__name__, str(e)[:200],
        )

    if parsed and isinstance(parsed.get("canonical"), list):
        try:
            return _assemble_from_llm(parsed["canonical"], raw_fed,
                                      prior_by_key, ledger)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "consolidate: assembling LLM output failed (%s) — fallback", e)

    return _deterministic_consolidate(raw_fed, prior_by_key, ledger)


def _assemble_from_llm(
    canonical: list, raw_fed: list[Finding],
    prior_by_key: dict[str, Finding], ledger: dict,
) -> dict:
    """Turn the LLM's proposed canonical list into real ``Finding``s with
    deterministic status (monotonic), attempts (validated/capped),
    lead_priority (formula + clamped nudge), and hygiene guards applied.
    Negative-kind entries go to the ledger instead of the findings list.
    """
    out: list[Finding] = []
    for entry in canonical:
        if not isinstance(entry, dict):
            continue
        src_ids = [i for i in (entry.get("sources") or [])
                   if isinstance(i, int) and 0 <= i < len(raw_fed)]
        primary = raw_fed[src_ids[0]] if src_ids else None

        title = str(entry.get("title") or
                    (getattr(primary, "title", "") if primary else "")).strip()[:200]
        if not title:
            continue
        url = str(entry.get("url") or
                  (getattr(primary, "url", "") if primary else "")).strip()
        sev = str(entry.get("severity") or _sev_str(primary)).strip().lower()
        if sev not in _VALID_SEVERITIES:
            sev = Severity.INFO.value
        category = str(entry.get("category") or
                       (getattr(primary, "category", "") if primary else "")).strip()
        evidence = (getattr(primary, "evidence", "") if primary else "") or ""
        category = _reconcile_category(title, evidence, category)
        sev, unverified = _version_fp_guard(title, sev)

        kind = str(entry.get("kind") or "signal").strip().lower()
        if kind == "negative":
            key = _ledger_key(category, url)
            attempts = _clean_attempts(entry.get("attempts"), None)
            result = attempts[-1]["result"] if attempts else AttemptResult.NO_EFFECT.value
            ledger[key] = {
                "summary": title[:160],
                "category": category,
                "url": url,
                "result": result,
            }
            continue

        primitive = str(entry.get("primitive") or
                        (getattr(primary, "primitive", "") if primary else "")
                        ).strip().lower()
        prior = prior_by_key.get(_ledger_key(category, url)) or \
            prior_by_key.get(f"{category.lower()}|{_normalize_stem(title)}")
        prior_status = getattr(prior, "status", "") if prior else ""
        prior_attempts = list(getattr(prior, "attempts", []) or []) if prior else []

        proposed_status = str(entry.get("status") or "").strip().lower()
        if not proposed_status:
            proposed_status = (PrimitiveStatus.DEMONSTRATED.value
                               if primitive else PrimitiveStatus.SUSPECTED.value)
        status = _advance_status(prior_status, proposed_status)
        attempts = _clean_attempts(entry.get("attempts"), prior_attempts)

        try:
            nudge = int(entry.get("priority_nudge") or 0)
        except (TypeError, ValueError):
            nudge = 0
        nudge = max(-15, min(15, nudge))
        priority = _lead_priority(status=status, primitive=primitive,
                                  severity=sev, n_attempts=len(attempts),
                                  nudge=nudge)

        desc = (getattr(primary, "description", "") if primary else "") or ""
        if unverified and "unverified" not in desc.lower():
            desc = (desc + " [version claim unverified — implausible core "
                    "version]").strip()

        out.append(Finding(
            title=title, severity=Severity(sev), category=category,
            description=desc, evidence=evidence,
            agent_id=(getattr(primary, "agent_id", "") if primary else "") or "",
            url=url, cwe=(getattr(primary, "cwe", "") if primary else "") or "",
            reproduced=bool(getattr(primary, "reproduced", False)) if primary else False,
            primitive=primitive, status=status, attempts=attempts,
            lead_priority=priority,
        ))

    out.sort(key=lambda f: f.lead_priority, reverse=True)
    return {"canonical_findings": out[:MAX_CANONICAL], "exhausted_ledger": ledger}


def _infer_status(f: Finding, prior_status: str) -> str:
    """Deterministic status inference for the fallback path."""
    primitive = (getattr(f, "primitive", "") or "").strip()
    evidence = (getattr(f, "evidence", "") or "").lower()
    title = (getattr(f, "title", "") or "").lower()
    blob = f"{title} {evidence}"
    if primitive or any(m in blob for m in (
            "extracted", "dumped", "executed", "authenticated as",
            "session as", "code execution", "union select", "information_schema")):
        proposed = PrimitiveStatus.DEMONSTRATED.value
    else:
        proposed = PrimitiveStatus.SUSPECTED.value
    return _advance_status(prior_status, proposed)


def _deterministic_consolidate(
    raw_fed: list[Finding], prior_by_key: dict[str, Finding], ledger: dict,
) -> dict:
    """LLM-free consolidation: dedup by coarse key (keeps the highest-
    severity / most-evidenced representative), route obvious negatives to
    the ledger, carry prior status/attempts forward, score deterministically.
    Guarantees a populated canonical view even when the LLM is unavailable.
    """
    best: dict[str, Finding] = {}
    for f in raw_fed:
        title = (getattr(f, "title", "") or "")
        if any(m in title.lower() for m in _NEGATIVE_MARKERS):
            cat = (getattr(f, "category", "") or "")
            url = (getattr(f, "url", "") or "")
            ledger[_ledger_key(cat, url)] = {
                "summary": title[:160], "category": cat, "url": url,
                "result": AttemptResult.NO_EFFECT.value,
            }
            continue
        key = _dedup_key(f)
        cur = best.get(key)
        if cur is None:
            best[key] = f
            continue
        # keep the stronger representative: higher severity, then longer evidence
        if (_SEV_WEIGHT.get(_sev_str(f), 0) > _SEV_WEIGHT.get(_sev_str(cur), 0)
                or len(getattr(f, "evidence", "") or "")
                > len(getattr(cur, "evidence", "") or "")):
            best[key] = f

    out: list[Finding] = []
    for key, f in best.items():
        prior = prior_by_key.get(key)
        prior_status = getattr(prior, "status", "") if prior else ""
        prior_attempts = list(getattr(prior, "attempts", []) or []) if prior else []
        title = getattr(f, "title", "") or ""
        sev = _sev_str(f)
        sev, unverified = _version_fp_guard(title, sev)
        category = _reconcile_category(
            title, getattr(f, "evidence", "") or "", getattr(f, "category", "") or "")
        status = _infer_status(f, prior_status)
        primitive = (getattr(f, "primitive", "") or "").strip().lower()
        priority = _lead_priority(status=status, primitive=primitive,
                                  severity=sev, n_attempts=len(prior_attempts))
        out.append(replace(
            f, severity=Severity(sev if sev in _VALID_SEVERITIES else "info"),
            category=category, status=status, attempts=prior_attempts,
            lead_priority=priority,
        ))

    out.sort(key=lambda f: f.lead_priority, reverse=True)
    return {"canonical_findings": out[:MAX_CANONICAL], "exhausted_ledger": ledger}
