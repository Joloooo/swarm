"""Skill runner — turn a loaded skill config into an executing LangChain agent.

This module is the heart of every worker dispatch. The flow:

  1. The planner picks an action and stages a list of skill configs in
     ``state.pending_dispatch``. The routing edge fans them out across
     parallel ExecutorNode / ReconNode invocations.
  2. Each worker's ``execute`` calls
     :meth:`src.nodes.base.BaseNode.run_skill_agent`, which is a thin
     wrapper that forwards to :func:`run_skill_agent` here.
  3. This module builds the system prompt
     (``src/nodes/base/system_prompt.py:_build_system_message``), seeds
     the agent with cross-turn context (latest web search, prior
     dispatch's report), runs the LangChain ``create_agent`` loop with
     the tier-1/tier-2 refusal-retry ladder
     (``src/refusals/retry.py``), parses out structured findings from
     the trace, and on crash tries to salvage a finding from the
     partial messages (``src/refusals/salvage.py``).
  4. The result is the standard worker-node update dict
     (``messages`` / ``agent_results`` / ``findings`` /
     ``active_agents`` / ``pending_summary_inputs``) the rest of the
     graph already understands.

The ``AgentConfig`` dataclass that carries skill content
(SKILL.md body, tool list, budgets) lives here too because it is the
runner's input contract — it has nowhere else to belong.

NB: skill *loading* (reading SKILL.md from disk, parsing frontmatter,
resolving tool names to LangChain tool instances) lives in
``src/skills/loader.py``. This module consumes the loaded config; it
does not load.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool

from src.llm.callbacks import make_call_config
from src.nodes.base.flag_watcher import (
    FlagCapturedSignal,
    SiblingCapturedSignal,
)
from src.nodes.base.system_prompt import (
    BENCHMARK_PROGRESS_FOOTER,
    _build_system_message,
)
from src.observability import make_run_id
from src.observability.state import _count_worker_iterations
from src.refusals.detect import looks_like_refusal
from src.refusals.recover import recover_from_refusal
from src.refusals.retry import astream_with_refusal_retry
from src.refusals.salvage import try_salvage
from src.state import AgentResult, Finding, Severity, Signal

if TYPE_CHECKING:
    from src.nodes.base import BaseNode


# ────────────────────────────────────────────────────────────────────────────
# AgentConfig — the in-memory carrier produced by ``src.skills.loader``
# ────────────────────────────────────────────────────────────────────────────


@dataclass
class AgentConfig:
    """Everything that makes one swarm agent different from another.

    Skill content (system_prompt + tool list + caps) comes from SKILL.md
    files under ``src/skills/`` parsed by ``src/skills/loader.py``. This
    dataclass is the in-memory carrier the loader produces.
    """

    # Identity
    agent_id: str  # unique name, e.g. "owasp-auth-testing"
    methodology: str  # "owasp" | "vulntype" | "custom" | "skill"
    config_name: str  # primary key for planner dispatch — matches skill folder

    # Prompt body (the SKILL.md body, minus frontmatter)
    system_prompt: str = ""

    # Tools (LangChain tool instances, resolved from SKILL.md tool names)
    tools: list[BaseTool] = field(default_factory=list)

    # Worker budget in REAL tool-using rounds (model decides + a tool runs);
    # the only worker cap, fed by ``budgets.worker_max_iterations``. Converted
    # to a LangGraph super-step ``recursion_limit`` (~3 super-steps/round) where
    # ``call_config`` is built. This dataclass default is only a fallback for
    # configs constructed outside the loader.
    max_iterations: int = 20

    # Prompt assembly opt-out. When True, ``_build_system_message``
    # skips the identity preamble, pentesting-rules block, role
    # framing, and RAG hint — the SKILL.md body is the entire system
    # prompt. Use for skills whose value depends on minimal framing
    # (focused technical Q&A that broad pentest context would taint).
    skip_base_prompt: bool = False

    # Which rule bundle the worker prompt carries.
    #   "executor" (default) — every dispatchable attack skill.
    #     Gets universal blocks + methodology + demonstrated-extraction
    #     + diversity + transformation hypothesis + severity +
    #     finding category guidance.
    #   "recon"             — discovery-phase agents (the recon skill).
    #     Gets universal blocks + a short "what counts as a recon
    #     finding" hint. No payload methodology, no exploit-output
    #     standard — those are exec-phase concerns that empirically
    #     tripped the Codex cyber_policy classifier on recon turns in
    #     ``logs/run-XBEN-006-24__2026-05-13_21h14m49s/``.
    # Set via ``metadata.phase`` in SKILL.md frontmatter.
    phase: str = "executor"


# ────────────────────────────────────────────────────────────────────────────
# Finding extraction from agent output
#
# Two parsers run on every assistant message:
# 1. The structured **FINDING:** / ## Finding format defined in FINDING_FORMAT
# 2. JSON blocks of the form {"findings": [...]} as a forgiving fallback
#
# The structured pattern only requires Title and Severity now (Category, URL,
# Evidence are optional). Bounded `[\s\S]{0,N}?` gaps prevent runaway matches
# across unrelated headings.
# ────────────────────────────────────────────────────────────────────────────


FINDING_PATTERN = re.compile(
    r"(?:\*\*FINDING:?\*\*|##\s+FINDING|##\s+Finding)"
    r"[\s\S]{0,40}?"
    r"Title:\s*(.+?)$"
    r"[\s\S]{0,200}?"
    r"Severity:\s*(\w+)"
    r"(?:[\s\S]{0,200}?Category:\s*([\w-]+))?"
    r"(?:[\s\S]{0,400}?URL:\s*(.+?)$)?"
    r"(?:[\s\S]{0,400}?Evidence:\s*(.+?)$)?"
    # Primitive is OPTIONAL and instructed to come LAST in the block, so a
    # generous gap after Evidence lets it tolerate a CWE / Payload line in
    # between. Group 6. Absent → "" → ordinary (non-primitive) finding.
    r"(?:[\s\S]{0,400}?Primitive:\s*([\w-]+))?",
    re.MULTILINE,
)

# Match a JSON object (non-greedy) that contains a "findings" key. Used as a
# fallback when the model emits {"findings": [...]} instead of the markdown.
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

# Closing-verdict block (VERDICT_SCHEMA in system_prompt.py). The worker's
# self-assessment of whether its assigned class is the real issue on the
# tested surface — parsed into a signed Signal that updates hypothesis
# belief (confirm raises it over the COMMIT gate; refute drives it down).
VERDICT_PATTERN = re.compile(
    r"(?:\*\*VERDICT:?\*\*|##\s+VERDICT|##\s+Verdict)"
    r"(?:[\s\S]{0,160}?Class:\s*([\w-]+))?"
    r"(?:[\s\S]{0,200}?Surface:\s*(.+?)$)?"
    r"(?:[\s\S]{0,200}?Probe run:\s*(yes|no))?"
    r"[\s\S]{0,200}?Outcome:\s*(confirmed|refuted|inconclusive)"
    r"(?:[\s\S]{0,160}?Confidence:\s*([0-9.]+))?"
    r"(?:[\s\S]{0,200}?Redirect:\s*(.+?)$)?"
    r"(?:[\s\S]{0,200}?Note:\s*(.+?)$)?",
    re.MULTILINE | re.IGNORECASE,
)


def _findings_from_markdown(content: str, agent_id: str) -> list[Finding]:
    """Parse the structured **FINDING:** / ## Finding format."""
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
    """Fallback parser for JSON {"findings": [...]} blocks."""
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
    """Parse structured findings from agent messages.

    Tries the markdown FINDING format first; falls back to JSON
    {"findings": [...]} blocks. Both parsers run on every AIMessage and
    results are concatenated.
    """
    findings = []
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        findings.extend(_findings_from_markdown(content, agent_id))
        findings.extend(_findings_from_json(content, agent_id))
    return findings


# Verdict outcome → (base log-odds magnitude, Signal.kind). The executor's
# closing verdict is the deciding-probe feedback that closes the belief
# loop: a ``confirmed`` is the only signal kind that lets a hypothesis
# cross the COMMIT threshold; a ``refuted`` is the owning skill's "it is
# not me" and drives belief down hard.
_VERDICT_OUTCOME = {
    "confirmed": (3.0, "confirm"),
    "refuted": (3.0, "refute"),
    "inconclusive": (0.0, "observation"),
}


def _extract_verdicts(
    messages: list, agent_id: str, config_name: str,
) -> list[Signal]:
    """Parse the worker's closing VERDICT block into signed Signal atoms.

    Returns at most one verdict signal (plus an optional ``redirect``
    routing signal) — the LAST verdict in the trace wins, since a worker
    refines its assessment as it goes. ``Class`` / ``Surface`` default to
    the dispatched skill identity when the worker omits them. The signed
    weight feeds the hypothesis synthesis pass directly:

    - confirmed   → kind="confirm", weight +3·conf  (crosses COMMIT gate)
    - refuted     → kind="refute",  weight −3·(1−conf) (drives toward refuted)
    - inconclusive→ kind="observation", weight = (conf−0.5)·1.2 (mild, signed)
    """
    last: tuple = ()
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        for m in VERDICT_PATTERN.finditer(content):
            last = m.groups()
    if not last:
        return []

    cls_raw, surface_raw, probe_raw, outcome_raw, conf_raw, redirect_raw, note_raw = last
    outcome = (outcome_raw or "").strip().lower()
    if outcome not in _VERDICT_OUTCOME:
        return []
    # The deciding-probe gate: a confirm/refute is only trustworthy if the
    # worker actually ran the canonical test on the real surface. If it
    # says "Probe run: no" (or omits it while claiming a strong outcome),
    # downgrade to inconclusive — a worker that tested the wrong surface
    # must not suppress (refute) or over-commit (confirm) a class. This is
    # what stops a wrong-surface refute from burying the real answer.
    probe_run = (probe_raw or "").strip().lower() == "yes"
    if outcome in ("confirmed", "refuted") and not probe_run:
        outcome = "inconclusive"
    vuln_class = (cls_raw or config_name or "").strip().lower()
    surface = " ".join((surface_raw or "").split()).strip()
    note = " ".join((note_raw or "").split()).strip()[:200]
    try:
        conf = max(0.0, min(1.0, float(conf_raw))) if conf_raw else 0.5
    except (TypeError, ValueError):
        conf = 0.5

    base, kind = _VERDICT_OUTCOME[outcome]
    if outcome == "confirmed":
        weight = base * max(conf, 0.5)
    elif outcome == "refuted":
        weight = -base * max(1.0 - conf, 0.5)
    else:  # inconclusive — mild signed nudge around 0.5
        weight = (conf - 0.5) * 1.2

    out: list[Signal] = [Signal(
        observation=f"{agent_id} verdict on {vuln_class}: {outcome}"
                    + (f" — {note}" if note else ""),
        surface=surface,
        vuln_class=vuln_class,
        suggested_skill=config_name,
        weight=weight,
        kind=kind,
        source="executor_verdict",
        source_agent=agent_id,
    )]

    # A redirect ("looks like X, not Y") lifts the alternative class so it
    # can rise in the ranking — exactly what was missing when the real
    # class never surfaced in the top hypotheses.
    redirect = " ".join((redirect_raw or "").split()).strip()
    if redirect:
        redirect_class = _redirect_class(redirect)
        if redirect_class and redirect_class != vuln_class:
            out.append(Signal(
                observation=f"{agent_id} redirect: {redirect}"[:200],
                surface=surface,
                vuln_class=redirect_class,
                suggested_skill=redirect_class,
                technique=redirect[:120],
                weight=1.0,
                kind="routing",
                source="executor_verdict",
                source_agent=agent_id,
            ))
    return out


# Known dispatchable class tokens a redirect line might name. Kept loose —
# the synthesis pass tolerates an unknown class (it just becomes a new
# hypothesis bucket), so this only needs to catch the common spellings.
_REDIRECT_CLASSES = (
    "deserialization", "ssti", "sqli", "ssrf", "idor", "lfi", "rce", "xss",
    "xxe", "csrf", "auth", "open-redirect", "file-upload", "mass-assignment",
    "prototype-pollution", "request-smuggling", "crlf", "graphql",
)


def _redirect_class(text: str) -> str:
    """Pull a known class token out of a free-text redirect line."""
    low = text.lower()
    for c in _REDIRECT_CLASSES:
        if c in low:
            return c
    return ""


# ── Refusal-path primitive salvage ──────────────────────────────────
#
# The Codex safety classifier fires most often PRECISELY when a worker
# has just received its most valuable output — a dumped table, a shell
# ``id`` line, ``/etc/passwd`` contents — because that output is the
# most offensive-LOOKING thing in context. The flag salvage in the
# refusal branch only rescues a literal ``flag{...}``; without this, a
# worker that PROVED a non-flag primitive (a SQL extraction, command
# output, a file read) and was then refused on its next call loses that
# proof entirely — it reaches the planner only through the lossy,
# refusal-prone summariser digest. This deterministic scan mints a HIGH
# ``Finding`` carrying the primitive tag so the planner's
# ``_unconverted_primitive_directive`` can drive it to the objective on
# a later turn.
#
# Two guards (the same the planner uses) keep it from false-firing:
#   * received-not-sent: only ``ToolMessage`` content (server responses)
#     is scanned — never the worker's own command — so a payload the
#     worker merely TYPED (e.g. it wrote ``UNION SELECT``) cannot
#     self-trigger; only output that came BACK counts.
#   * negation guard: a marker preceded (within 32 chars) by a negation
#     cue is skipped, so "no group_concat output" does not fire.
#
# Markers are ordered strongest-first; the loop returns on the first
# real hit. Each maps to a canonical primitive tag + finding category.
_REFUSAL_PRIMITIVE_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("root:x:0:0", "file_read", "lfi"),        # /etc/passwd contents
    ("uid=", "rce", "rce"),                     # `id` command output
    ("gid=", "rce", "rce"),
    ("information_schema", "sqli_read", "sqli"),
    ("group_concat", "sqli_read", "sqli"),
    ("@@version", "sqli_read", "sqli"),
    ("database()", "sqli_read", "sqli"),
    ("union select", "sqli_read", "sqli"),
    ("www-data", "rce", "rce"),
)
_REFUSAL_NEGATION_CUES: tuple[str, ...] = (
    "no ", "not ", "n't ", "without ", "none", "zero ", "never ",
)


def _refusal_marker_is_real(text_lower: str, marker: str) -> bool:
    """True if ``marker`` occurs in ``text_lower`` at least once without a
    negation cue in the ~32 characters before it."""
    start = 0
    while True:
        idx = text_lower.find(marker, start)
        if idx < 0:
            return False
        window = text_lower[max(0, idx - 32):idx]
        if not any(cue in window for cue in _REFUSAL_NEGATION_CUES):
            return True
        start = idx + len(marker)


def _salvage_primitive_from_trace(
    partial_messages: list, agent_id: str,
) -> Finding | None:
    """Scan a refused worker's RECEIVED tool output for a proven primitive.

    Returns a HIGH ``Finding`` tagged with the matching primitive when a
    marker appears in ``ToolMessage`` content (received-not-sent guard),
    or ``None`` when nothing matches. The worker's own request text is
    never scanned, so a payload it merely typed cannot self-trigger.
    """
    tool_parts: list[str] = []
    for m in partial_messages:
        if not isinstance(m, ToolMessage):
            continue
        c = getattr(m, "content", None)
        if isinstance(c, str):
            tool_parts.append(c)
        elif isinstance(c, list):
            for block in c:
                if isinstance(block, dict):
                    tool_parts.append(str(block.get("text") or ""))
    haystack = "\n".join(tool_parts)
    if not haystack:
        return None
    low = haystack.lower()
    for marker, primitive_tag, category in _REFUSAL_PRIMITIVE_MARKERS:
        if marker in low and _refusal_marker_is_real(low, marker):
            idx = low.find(marker)
            excerpt = haystack[max(0, idx - 240):idx + len(marker) + 240]
            return Finding(
                title=(
                    "[salvaged from refused worker] proven "
                    f"{primitive_tag} primitive in tool output before "
                    f"refusal ({marker})"
                )[:240],
                severity=Severity.HIGH,
                category=category,
                description=(
                    "The worker hit a Codex policy refusal mid-run, but "
                    "its partial tool trace already contained received "
                    "output proving a working primitive. Refusals land "
                    "on exactly this high-value output; this finding "
                    "preserves the proven capability so it can be driven "
                    "to the objective on a later turn instead of lost."
                ),
                evidence=excerpt[:2400],
                agent_id=agent_id,
                url="",
                primitive=primitive_tag,
            )
    return None


# ── Worker memory: prior-attempts + web-search context injection ────────
#
# By default, every dispatch of ``run_skill_agent`` calls
# ``agent.ainvoke({"messages": []})`` — the worker starts cold with zero
# memory of:
#   1. its own previous run, when the planner re-dispatches the same
#      skill (``vulntype-sqli`` first run → web_search → second SQLi
#      dispatch starts from scratch and re-tries the same payloads), and
#   2. the supervisor's most recent ``web_search`` result, even though
#      the planner explicitly chose to research before dispatching.
#
# These two helpers fix both holes by seeding the create_agent loop with
# a single ``HumanMessage`` that includes:
#   - the latest ``[Web Search]`` synthesis (capped via
#     ``_WEB_SEARCH_INJECT_CHARS``), and
#   - a one-line summary of every prior tool call this agent_id made on
#     this run, paired with its tool-output exit code + trimmed body
#     (capped via ``_PRIOR_HISTORY_MAX_TURNS`` and
#     ``_PRIOR_PROBE_SUMMARY_CHARS``).
#
# Pairing is by ``tool_call_id`` (LangChain's stable round-trip ID), not
# by message order — so out-of-order ToolMessage delivery from parallel
# fan-out doesn't corrupt the summary. ``additional_kwargs.agent_id`` on
# both AIMessage and ToolMessage (set by ``run_skill_agent`` before
# trace propagation) is the per-skill filter.
#
# Returned by:
#   - ``_extract_latest_web_search(state)`` → str | None
#   - ``_collect_prior_skill_history(state, agent_id)`` → str | None
#
# Combined into the seed message inside ``run_skill_agent``.

# ── Curated-state seed blocks ──────────────────────────────────────────
#
# These four helpers render structured fields from ``state`` into
# markdown blocks the worker's seed HumanMessage will contain. Each
# returns ``None`` when its source field is empty so cold-boot workers
# (turn 1, no prior planner output) don't see empty ``##`` headers.
#
# Reading map:
#   - dispatch_reason   ← state["dispatch_reason"]      (planner per turn)
#   - findings          ← state["findings"]              (cumulative)
#   - recon_summary     ← state["recon_summary"]         (written once)
#   - relevant_summary  ← state["relevant_summary"]      (planner per turn)
#
# All four are pure renderers — no LLM calls, no side effects. They are
# invoked from ``run_skill_agent`` after the system prompt is built and
# before the agent loop starts.

# Cap on findings rendered in the seed. The findings list grows
# unboundedly across turns; a runaway swarm could produce dozens.
# Workers care most about the freshest evidence, so we render the
# tail. 30 is empirically enough to cover any realistic engagement
# without bloating the prompt past ~5 KB for this block alone.
_SEED_FINDINGS_TAIL = 30

# Per-evidence cap inside a finding's seed line. The full evidence is
# preserved in state["findings"] for the planner; workers only need
# enough to recognise the finding and copy any literal payload string.
_SEED_FINDING_EVIDENCE_CHARS = 400

# Recon summary cap. The full digest can run 5-10 KB; we keep all of it
# unless it's pathologically large. The reason for any cap at all is
# defensive — a misbehaving summarizer could in principle emit
# unbounded text, and silently truncating to a generous cap is safer
# than poisoning every worker prompt downstream.
_SEED_RECON_SUMMARY_CHARS = 12_000


def _format_dispatch_reason(state: dict) -> str | None:
    """Render the planner's reason-for-this-dispatch as a seed block.

    Returns ``None`` on the cold-boot path (initialize → recon, before
    the planner has spoken). The routing edge always writes
    ``state["dispatch_reason"]`` for planner-staged workers — empty
    string sentinel means "no reason recorded", which we also treat as
    no block.
    """
    reason = (state.get("dispatch_reason") or "").strip()
    if not reason:
        return None
    return (
        "## Why you were dispatched\n\n"
        "The supervisor picked you for this turn based on the state "
        "below. Treat the hypothesis as your primary objective; if the "
        "evidence you gather contradicts it, surface that in your "
        "report — do not silently pivot.\n\n"
        f"{reason}"
    )


def _render_finding_attempts(finding, n: int = 3) -> list[str]:
    """Render the last ``n`` conversion attempts on a finding as compact
    seed lines (``tried: method → result (note)``). Empty when the finding
    has no attempts (an ordinary observation, or pre-consolidation).
    """
    attempts = getattr(finding, "attempts", None)
    if not isinstance(attempts, list) or not attempts:
        return []
    out: list[str] = []
    for a in attempts[-n:]:
        if not isinstance(a, dict):
            continue
        method = str(a.get("method") or "").strip()
        result = str(a.get("result") or "").strip()
        if not method or not result:
            continue
        note = str(a.get("note") or "").strip()
        suffix = f" ({note})" if note else ""
        out.append(f"   tried: {method} → {result}{suffix}")
    return out


def _format_findings(state: dict) -> str | None:
    """Render the cumulative findings list as a seed block.

    Includes every finding accumulated across the run so far — recon's
    info-disclosures, prior attack workers' confirmed vulnerabilities,
    everything. Tail-capped at ``_SEED_FINDINGS_TAIL`` items so a
    runaway swarm cannot blow worker context; in practice 30 covers
    multi-turn engagements with room to spare.

    Each rendered line carries severity, title, url, category, and
    trimmed evidence — enough for the worker to recognise the finding
    and copy any literal payload string the previous worker captured.

    Prefers the consolidated ``canonical_findings`` view (deduped, status-
    stamped, ranked by ``lead_priority``) when the consolidation pass has
    produced one — so the worker sees one entry per issue, the conversion
    ``status``, and the ``attempts`` already tried on a primitive (so it
    does not repeat a dead method). Falls back to the raw append-only
    ``findings`` log before the first consolidation.
    """
    canonical = state.get("canonical_findings")
    use_canonical = bool(canonical)
    findings = list(canonical) if use_canonical else list(state.get("findings") or [])
    if not findings:
        return None

    # Canonical findings are pre-sorted by lead_priority (highest first),
    # so take the TOP N; the raw log is append-ordered, so take the most
    # RECENT N.
    rendered = (findings[:_SEED_FINDINGS_TAIL] if use_canonical
                else findings[-_SEED_FINDINGS_TAIL:])
    elided = len(findings) - len(rendered)

    lines: list[str] = []
    if elided > 0:
        which = "highest-priority" if use_canonical else "most recent"
        lines.append(
            f"_(showing the {len(rendered)} {which} of "
            f"{len(findings)} total findings; {elided} more elided for "
            "context budget)_"
        )
    for i, f in enumerate(rendered, 1):
        sev = getattr(getattr(f, "severity", None), "value", None) or "info"
        title = getattr(f, "title", "") or "(untitled)"
        url = getattr(f, "url", "") or ""
        category = getattr(f, "category", "") or ""
        status = (getattr(f, "status", "") or "").strip()
        evidence = (getattr(f, "evidence", "") or "").strip()
        if len(evidence) > _SEED_FINDING_EVIDENCE_CHARS:
            evidence = (
                evidence[: _SEED_FINDING_EVIDENCE_CHARS - 1]
                + "…"
            )
        # A primitive carries a conversion status — surface it inline so
        # the worker knows whether this is a proven capability to finish.
        stat = f" ({status})" if status else ""
        head = f"{i}. [{sev.upper()}]{stat} {title}"
        meta_bits = []
        if category:
            meta_bits.append(f"category={category}")
        if url:
            meta_bits.append(f"url={url}")
        lines.append(head)
        if meta_bits:
            lines.append(f"   {'  '.join(meta_bits)}")
        if evidence:
            lines.append(f"   evidence: {evidence}")
        # Conversion attempts already tried on this primitive — so the
        # worker does NOT repeat a dead method.
        for line in _render_finding_attempts(f):
            lines.append(line)

    body = "\n".join(lines)
    return (
        "## Confirmed findings so far (all turns)\n\n"
        "These are atomic, verified facts produced by earlier workers. "
        "Build on them — do not re-discover them. Each finding lists the "
        "URL, category, and exact evidence the worker captured.\n\n"
        f"{body}"
    )


def _format_recon_summary(state: dict) -> str | None:
    """Render the one-time recon application map as a seed block.

    Written once by the summarizer on its first pass that processes a
    recon worker; never decays. Tells the worker the routes, params,
    auth flow, framework fingerprint, and inferred server-side
    behaviour without making it re-walk the application.
    """
    raw = (state.get("recon_summary") or "").strip()
    if not raw:
        return None
    if len(raw) > _SEED_RECON_SUMMARY_CHARS:
        raw = raw[: _SEED_RECON_SUMMARY_CHARS] + "\n…[truncated for context budget]"
    return (
        "## Application map (from initial recon — treat as ground truth)\n\n"
        "The reconnaissance worker mapped the target's surface before "
        "any attack dispatches ran. The structured digest below is the "
        "canonical application map for this engagement — routes, "
        "parameters, auth flow, server fingerprint. Use it instead of "
        "re-probing the application surface.\n\n"
        f"{raw}"
    )


def _format_relevant_summary(state: dict) -> str | None:
    """Render the planner's curated investigation state as a seed block.

    Source: ``state["relevant_summary"]`` — a dict with three optional
    keys (``current_hypothesis``, ``ruled_out``, ``open_questions``)
    rewritten by the planner each turn. Returns ``None`` when nothing
    is present (turn-1 cold start, or planner failed validation).

    Renders only the keys that have content — a partial relevant_summary
    is more useful to the worker than no block at all, and the planner
    validator's fallback behaviour leaves missing keys empty rather than
    rejecting the whole dict.
    """
    rs = state.get("relevant_summary") or {}
    if not isinstance(rs, dict):
        return None

    hypothesis = (rs.get("current_hypothesis") or "").strip()
    ruled_out = [
        s.strip() for s in (rs.get("ruled_out") or [])
        if isinstance(s, str) and s.strip()
    ]
    open_questions = [
        s.strip() for s in (rs.get("open_questions") or [])
        if isinstance(s, str) and s.strip()
    ]
    untried = [
        u for u in (rs.get("untried") or [])
        if isinstance(u, dict) and (u.get("technique") or u.get("where"))
    ]

    if not (hypothesis or ruled_out or open_questions or untried):
        return None

    sections: list[str] = []
    if hypothesis:
        sections.append("### Current hypothesis\n" + hypothesis)
    if ruled_out:
        body = "\n".join(f"- {item}" for item in ruled_out)
        sections.append("### Ruled out\n" + body)
    if open_questions:
        body = "\n".join(f"- {item}" for item in open_questions)
        sections.append("### Open questions\n" + body)
    if untried:
        rows = []
        for u in untried:
            where = (u.get("where") or "").strip()
            tech = (u.get("technique") or "").strip()
            loc = f" — {where}" if where else ""
            rows.append(f"- {tech or where}{loc if tech else ''}")
        sections.append("### Untried next moves\n" + "\n".join(rows))

    return (
        "## Investigation state (current as of this turn)\n\n"
        "The supervisor maintains this picture across turns. Use it to "
        "avoid re-testing what was already ruled out and to prioritise "
        "the open questions.\n\n"
        + "\n\n".join(sections)
    )


def _format_hypotheses(state: dict) -> str | None:
    """Render the ranked hypotheses as a seed block so a dispatched worker
    sees the focused theory the supervisor committed to.

    Source: ``state["hypotheses"]`` — the belief/utility-ranked list the
    synthesis pass (``src/llm/hypotheses.py``) rebuilds each cycle from the
    raw signal log. Surfaces committed / supported / confirmed hypotheses
    with their belief and deciding probe. Complements
    ``_format_relevant_summary`` (the planner's free-text notes) with the
    machine-fused, scored view. Returns ``None`` when none are actionable.
    """
    hyps = state.get("hypotheses") or []
    rankable = [
        h for h in hyps
        if getattr(h, "state", "") in ("committed", "supported", "confirmed")
    ]
    if not rankable:
        return None

    rows: list[str] = []
    for h in rankable[:5]:
        surf = f" on {h.surface}" if getattr(h, "surface", "") else ""
        conf = getattr(h, "confidence", 0.0)
        tech = (getattr(h, "required_technique", "") or "").strip()
        skill = (getattr(h, "required_skill", "") or "").strip()
        if tech:
            action = tech + (f" (skill={skill})" if skill else "")
        elif skill:
            action = f"dispatch {skill}"
        else:
            action = ""
        line = (
            f"- **{h.vuln_class}{surf}** — {getattr(h, 'state', '')}, "
            f"confidence {conf:.0%}"
        )
        if action:
            line += f"\n  → deciding probe: {action}"
        rows.append(line)

    return (
        "## Leading hypotheses (ranked by the supervisor)\n\n"
        "Observations from across the swarm have been fused into these "
        "theories, scored by how strongly the evidence supports them. The "
        "top one is the supervisor's committed line — run its deciding probe "
        "before broadening.\n\n"
        + "\n".join(rows)
    )


def _format_tool_attempts(state: dict) -> str | None:
    """Render recent important tool outcomes for worker context."""
    attempts = [
        a for a in (state.get("tool_attempts") or [])
        if isinstance(a, dict)
    ]
    if not attempts:
        return None

    rows: list[str] = []
    for attempt in attempts[-10:]:
        surface = str(attempt.get("surface") or "").strip()
        tool = str(attempt.get("tool") or "").strip()
        status = str(attempt.get("status") or "").strip()
        coverage = str(attempt.get("coverage") or "").strip()
        error = str(attempt.get("error_type") or "").strip()
        fallback = bool(attempt.get("fallback_needed"))
        command = str(attempt.get("command") or "").strip()
        if not (surface or tool or command):
            continue
        bits = [b for b in (
            f"surface={surface}" if surface else "",
            f"tool={tool}" if tool else "",
            f"status={status}" if status else "",
            f"coverage={coverage}" if coverage else "",
            f"error={error}" if error else "",
            "fallback-needed" if fallback else "",
        ) if b]
        rows.append("- " + "; ".join(bits))
        if command:
            rows.append(f"  command: {command}")
    if not rows:
        return None
    return (
        "## Tool and surface outcomes\n\n"
        "These are structured outcomes from earlier high-level tools. A "
        "failed or partial tool run does NOT mean the surface was tested; "
        "use a fallback or narrower command when `fallback-needed` appears. "
        "A fully covered success should not be repeated without new evidence.\n\n"
        + "\n".join(rows)
    )


def _format_skill_context_catalogue(config_name: str) -> str | None:
    """Render the compact cross-skill context catalogue for a worker."""
    try:
        from src.skills.usage import render_context_skill_index

        body = render_context_skill_index(current_skill=config_name)
    except Exception:
        return None
    body = body.strip()
    return body or None


# Maximum chars per summarized probe in the prior-attempts block.
# Big enough to show the bash command + first/last bytes of output;
# small enough that 12 of these stays under ~5KB of context.
_PRIOR_PROBE_SUMMARY_CHARS = 280

# Cap on tool-call/response pairs included from prior runs of the same
# skill. Older probes past the cap are summarized as a count so the
# worker still knows N earlier attempts existed, even if it can't see
# them all.
_PRIOR_HISTORY_MAX_TURNS = 12

# Maximum chars of the latest web_search synthesis to inject. The research
# node now returns payload-rich, deduped technique guidance drawn from curated
# authoritative sources (HackTricks / PayloadsAllTheThings) — the verbatim
# payloads are the whole point, so the old 5000 cap truncated exactly what the
# worker needs. Raised to keep them; the synthesis is one concentrated block,
# not a tool-call trace. Tunable via env.
_WEB_SEARCH_INJECT_CHARS = int(os.getenv("SWARM_WEB_SEARCH_INJECT_CHARS", "16000"))


def _summarize_tool_call_pair(tool_call: dict, tool_msg: ToolMessage | None) -> str:
    """Render one (tool_call, tool_response) pair as a single probe line.

    Picks the most informative argument field — bash uses ``command``,
    fetch tools use ``url``, etc. — and pairs it with the response's
    exit code (parsed from the bash tool's ``[exit=N | cwd=...]``
    suffix when present) plus a trimmed body so failed and successful
    probes are visually distinguishable.
    """
    name = tool_call.get("name") if isinstance(tool_call, dict) else getattr(tool_call, "name", "tool")
    args = tool_call.get("args") if isinstance(tool_call, dict) else getattr(tool_call, "args", {})

    payload = ""
    if isinstance(args, dict):
        for key in ("command", "url", "data", "query", "payload", "target"):
            v = args.get(key)
            if isinstance(v, str) and v:
                payload = v
                break
        if not payload:
            for k, v in args.items():
                if k == "reasoning":
                    continue
                if isinstance(v, str) and v:
                    payload = f"{k}={v}"
                    break
    payload_str = (payload or "<no args>").strip()
    if len(payload_str) > 140:
        payload_str = payload_str[:137] + "..."

    if tool_msg is None:
        response = "(no response captured)"
    else:
        body = tool_msg.content if isinstance(tool_msg.content, str) else str(tool_msg.content)
        body = body.strip()
        m = re.search(r"\[exit=(-?\d+)", body)
        exit_code = m.group(1) if m else "?"
        # Keep first 100 + last 60 chars for very long outputs so both
        # the start and the end (where flag matches / errors usually
        # appear) are visible.
        if len(body) > 200:
            body = body[:100].replace("\n", " ") + " …trimmed… " + body[-60:].replace("\n", " ")
        else:
            body = body.replace("\n", " ")
        response = f"exit={exit_code} {body}"

    line = f"- {name}({payload_str}) → {response}"
    if len(line) > _PRIOR_PROBE_SUMMARY_CHARS:
        line = line[: _PRIOR_PROBE_SUMMARY_CHARS - 1] + "…"
    return line


_TOOL_OUTCOME_IMPORTANT_TOKENS = (
    "wpscan", "ffuf", "gobuster", "sqlmap", "nikto", "nmap", "nuclei",
    "tplmap", "sstimap", "tinja", "hydra", "curl --parallel",
    "xargs -p", "xargs -P", "parallel ", "threadpoolexecutor",
    "concurrent.futures", "asyncio",
)
_TOOL_OUTCOME_MAX_COMMAND_CHARS = 260
_TOOL_OUTCOME_MAX_EXCERPT_CHARS = 500


def _tool_message_text(tool_msg: ToolMessage | None) -> str:
    if tool_msg is None:
        return ""
    content = getattr(tool_msg, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text") or block.get("content") or ""))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content or "")


def _tool_call_arg(tool_call: dict, *names: str) -> str:
    args = tool_call.get("args") if isinstance(tool_call, dict) else {}
    if not isinstance(args, dict):
        return ""
    for name in names:
        value = args.get(name)
        if isinstance(value, str) and value.strip():
            return " ".join(value.split())
    return ""


def _compact_tool_field(value: str, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _tool_exit_code(output: str) -> int | None:
    match = re.search(r"\[.*?\bexit=(-?\d+).*?\]", output, re.DOTALL)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _tool_base_status(output: str, exit_code: int | None) -> tuple[str, str]:
    low = output.lower()
    if "timeout after" in low or "timed out" in low:
        return "timeout", "timeout"
    if "command not found" in low or "no such file or directory" in low:
        return "failed", "command-not-found"
    if exit_code is not None and exit_code != 0:
        return "failed", "nonzero-exit"
    return "success", ""


def _important_tool_surface(tool_name: str, command: str) -> bool:
    blob = f"{tool_name} {command}".lower()
    return any(token.lower() in blob for token in _TOOL_OUTCOME_IMPORTANT_TOKENS)


def _classify_tool_attempt(
    *,
    tool_name: str,
    command: str,
    output: str,
    exit_code: int | None,
    agent_id: str,
    config_name: str,
) -> dict | None:
    """Return a coverage-style tool outcome, or None for routine probes."""
    if not _important_tool_surface(tool_name, command):
        return None

    low_cmd = command.lower()
    low_out = output.lower()
    low_blob = f"{low_cmd}\n{low_out}"
    status, error_type = _tool_base_status(output, exit_code)
    surface = tool_name or "tool"
    coverage = "full" if status == "success" else "none"
    covered = status == "success"
    fallback_needed = False

    if "wpscan" in low_blob:
        surface = "wordpress component enumeration"
        wp_abort_markers = (
            "scan aborted", "update required", "database file is missing",
            "you can not run a scan", "cannot run a scan",
            "please run wpscan --update",
        )
        if any(marker in low_out for marker in wp_abort_markers):
            status = "failed"
            covered = False
            coverage = "none"
            fallback_needed = True
            error_type = "wpscan-db-missing-or-aborted"
        else:
            # `--enumerate p` can still miss arbitrary installed plugins.
            # Full component coverage needs the all-plugins/all-themes forms.
            enum_full = bool(
                re.search(r"--enumerate\s+[^\s]*\bap\b", low_cmd)
                or re.search(r"--enumerate\s+[^\s]*\bat\b", low_cmd)
            )
            if status == "success" and not enum_full:
                covered = False
                coverage = "partial"
                fallback_needed = True
                error_type = "partial-wordpress-component-enumeration"
            elif status != "success":
                fallback_needed = True
        tool_name = "wpscan"
    elif "wp-content/plugins" in low_blob or "wp-content/themes" in low_blob:
        surface = "wordpress component fallback enumeration"
        coverage = "partial" if status == "success" else "none"
        covered = status == "success"
    elif "sqlmap" in low_blob:
        surface = "sql injection automated probe"
        tool_name = "sqlmap"
    elif "nmap" in low_blob:
        surface = "network/service enumeration"
        tool_name = "nmap"
    elif "nikto" in low_blob:
        surface = "web server known-issue scan"
        tool_name = "nikto"
    elif "ffuf" in low_blob or "gobuster" in low_blob:
        surface = "content/path enumeration"
        tool_name = "ffuf" if "ffuf" in low_blob else "gobuster"
        coverage = "partial" if status == "success" else "none"
    elif any(token in low_blob for token in (
        "curl --parallel", "xargs -p", "threadpoolexecutor",
        "concurrent.futures", "asyncio",
    )):
        surface = "concurrency/race probe"

    if status != "success" and not fallback_needed:
        fallback_needed = True

    return {
        "surface": surface,
        "tool": tool_name or "tool",
        "command": _compact_tool_field(command, _TOOL_OUTCOME_MAX_COMMAND_CHARS),
        "status": status,
        "covered": covered,
        "coverage": coverage,
        "error_type": error_type,
        "fallback_needed": fallback_needed,
        "source_agent": agent_id,
        "config_name": config_name,
        "exit_code": exit_code,
        "output_excerpt": _compact_tool_field(output, _TOOL_OUTCOME_MAX_EXCERPT_CHARS),
    }


def _extract_tool_attempts_from_trace(
    messages: list,
    *,
    agent_id: str,
    config_name: str,
) -> list[dict]:
    """Extract important tool outcomes from AI tool calls + ToolMessages."""
    responses: dict[str, ToolMessage] = {}
    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        call_id = str(getattr(msg, "tool_call_id", "") or "")
        if call_id:
            responses[call_id] = msg

    attempts: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        for tool_call in getattr(msg, "tool_calls", []) or []:
            if not isinstance(tool_call, dict):
                continue
            call_id = str(tool_call.get("id") or tool_call.get("tool_call_id") or "")
            tool_name = str(tool_call.get("name") or "").strip()
            command = _tool_call_arg(
                tool_call,
                "command", "cmd", "url", "query", "target", "data",
            )
            if not command:
                continue
            output = _tool_message_text(responses.get(call_id))
            exit_code = _tool_exit_code(output)
            attempt = _classify_tool_attempt(
                tool_name=tool_name,
                command=command,
                output=output,
                exit_code=exit_code,
                agent_id=agent_id,
                config_name=config_name,
            )
            if not attempt:
                continue
            key = (
                str(attempt.get("surface") or ""),
                str(attempt.get("tool") or ""),
                str(attempt.get("command") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            attempts.append(attempt)
    return attempts[-20:]


# ── Per-skill investigation thread (continuity + compaction) ──────────
#
# Measured: a single fresh worker context peaks around 45-87k tokens —
# under the ~120k point where the model degrades. Carrying prior work
# forward (continuity) is what risks crossing that line, so the thread is
# compacted to a bounded CHARACTER budget that leaves headroom for the
# fresh work on top. Commands are kept verbatim; tool OUTPUTS are shrunk
# to a one-line summary (the user's "keep what was executed, shrink the
# outputs"). ~120k chars ≈ 30k tokens for the carried thread.
_THREAD_CHAR_BUDGET = 120_000
_RECORD_CMD_CHARS = 240
_RECORD_OUTPUT_CHARS = 200
_MAX_STEPS_PER_RUN = 40

# Cheap artifact tells worth preserving in a shrunk output summary — the
# things that actually decide whether a probe progressed.
_OUTPUT_TELLS = (
    "root:x:0:0", "uid=", "gid=", "flag{", "information_schema",
    "union select", "@@version", "traceback", "stack trace", "exception",
    "denied", "forbidden", "not a number", "500 internal", "200 ok",
    "302 found", "401 ", "403 ", "404 ", "no such", "syntax error",
)


def _summarize_output(output: str) -> str:
    """Shrink a tool output to a one-line summary: size + first line +
    the decisive artifact tells that survive compaction."""
    o = (output or "").strip()
    if not o:
        return "(no output)"
    first_line = next((ln for ln in o.splitlines() if ln.strip()), "")[:120]
    low = o.lower()
    tells = sorted({t for t in _OUTPUT_TELLS if t in low})
    tail = f"  tells={','.join(tells[:5])}" if tells else ""
    return f"[{len(o)}b] {first_line}{tail}"[:_RECORD_OUTPUT_CHARS]


def _compact_run_record(messages: list, verdict_signals: list) -> str:
    """Build a compact record of ONE dispatch: each step's command kept
    verbatim, its tool output shrunk to a one-line summary, then the
    closing verdict. This is the unit the continuity thread accumulates."""
    responses: dict[str, ToolMessage] = {}
    for msg in messages:
        if isinstance(msg, ToolMessage):
            cid = str(getattr(msg, "tool_call_id", "") or "")
            if cid:
                responses[cid] = msg

    lines: list[str] = []
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        for tc in getattr(msg, "tool_calls", []) or []:
            if not isinstance(tc, dict):
                continue
            cmd = _tool_call_arg(tc, "command", "cmd", "url", "query", "target", "data")
            if not cmd:
                continue
            cid = str(tc.get("id") or tc.get("tool_call_id") or "")
            out = _tool_message_text(responses.get(cid))
            lines.append(
                f"- `{' '.join(cmd.split())[:_RECORD_CMD_CHARS]}` "
                f"→ {_summarize_output(out)}"
            )
            if len(lines) >= _MAX_STEPS_PER_RUN:
                break
        if len(lines) >= _MAX_STEPS_PER_RUN:
            break

    for s in (verdict_signals or []):
        if str(getattr(s, "source", "")) == "executor_verdict":
            lines.append(f"- VERDICT: {str(getattr(s, 'observation', ''))[:200]}")
            break

    return "\n".join(lines) if lines else "(no tool steps this run)"


def _build_investigation_thread(
    state: dict, config_name: str, messages: list, verdict_signals: list,
) -> dict:
    """Append this dispatch's compacted record to the skill's thread,
    increment its run count, and trim the OLDEST runs until the thread is
    back under the character budget. Returns the single-key update for
    ``state['investigation_threads']``."""
    prior = (state.get("investigation_threads") or {}).get(config_name) or {}
    run_count = int(prior.get("run_count", 0)) + 1
    runs = [str(r) for r in (prior.get("runs") or [])]
    runs.append(_compact_run_record(messages, verdict_signals))
    # Drop oldest runs (keeping at least the current one) until under budget.
    while len(runs) > 1 and sum(len(r) for r in runs) > _THREAD_CHAR_BUDGET:
        runs.pop(0)
    return {config_name: {"run_count": run_count, "runs": runs}}


def _collect_prior_skill_history(state: dict, agent_id: str) -> str | None:
    """Return the previous summarizer report for this ``agent_id``, or
    ``None`` if there is no prior dispatch.

    Background: in the pre-summarizer-node design this function walked
    ``state['messages']`` looking for raw ``AIMessage``s with matching
    ``agent_id`` and reconstructed a "previous attempts" block from
    their tool calls. After the worker → summarizer hand-off
    (``state.pending_summary_inputs`` + ``SummarizerNode``), those raw
    ``AIMessage``s no longer enter ``state['messages']`` — only the
    summarizer's structured ``worker_report`` does.

    So we just look up the most recent ``worker_report`` for the
    matching ``agent_id``. The report is already in the right format
    and tone (probe enumeration, what-was-NOT-tried, recommended next
    angle) — no per-probe re-formatting needed here.

    See :func:`src.llm.digest.find_prior_worker_report` for the lookup.
    """
    from src.llm.digest import find_prior_worker_report

    report = find_prior_worker_report(state.get("messages") or [], agent_id)
    if report is None:
        return None
    body = report.content if isinstance(report.content, str) else str(report.content)
    if not body.strip():
        return None
    return (
        "## Your prior dispatch's report to the supervisor\n\n"
        "The supervisor previously dispatched you on this target. The "
        "summarizer's report from that run is below — it lists what was "
        "tried, what was NOT tried, and the recommended next angle. Do "
        "NOT repeat probes already tried; pick up from where the "
        "previous run left off.\n\n"
        f"{body}"
    )


def _format_investigation_thread(state: dict, config_name: str) -> str | None:
    """Render this skill's own compacted cross-dispatch history as a seed
    block, with the run count, so a re-dispatched worker CONTINUES instead
    of starting fresh. Complements ``_collect_prior_skill_history`` (the
    supervisor's digest) with the worker's own raw command trail."""
    th = (state.get("investigation_threads") or {}).get(config_name)
    if not th:
        return None
    runs = [str(r) for r in (th.get("runs") or []) if str(r).strip()]
    if not runs:
        return None
    run_count = int(th.get("run_count", len(runs)))
    start = run_count - len(runs) + 1
    body = "\n\n".join(f"### Run {start + i}\n{r}" for i, r in enumerate(runs))
    trimmed = "" if len(runs) >= run_count else (
        "(your earliest runs were trimmed for context budget)\n\n"
    )
    return (
        f"## Your prior work on this skill — you have been dispatched "
        f"{run_count} time(s)\n\n"
        "This is YOUR OWN compacted history across dispatches: commands kept "
        "verbatim, tool outputs shrunk to a one-line summary. CONTINUE from "
        "here — do not repeat a probe already run below; deepen it or pivot "
        "based on what it showed. If you have now tried enough to judge this "
        "class on this surface, say so plainly in your closing VERDICT: a "
        "confident `refuted` (\"it is not me\") frees the swarm to move on "
        "and is as useful as a finding.\n\n"
        + trimmed + body
    )


def _extract_latest_web_search(state: dict) -> str | None:
    """Return the most recent ``[Web Search] ...`` AIMessage content,
    truncated to ``_WEB_SEARCH_INJECT_CHARS``, or ``None``.

    The web_search node prefixes its synthesis with a literal
    ``[Web Search]`` marker (see ``src/nodes/web_search.py``), which
    makes it cheap to find and disambiguate from worker output.
    """
    msgs = state.get("messages") or []
    for m in reversed(msgs):
        if not isinstance(m, AIMessage):
            continue
        content = m.content if isinstance(m.content, str) else str(m.content or "")
        if content.lstrip().startswith("[Web Search]"):
            if len(content) > _WEB_SEARCH_INJECT_CHARS:
                content = content[:_WEB_SEARCH_INJECT_CHARS] + "\n…[truncated for context budget]"
            return content
    return None


def _persist_worker_trace(
    *,
    trace: list[Any],
    run_id: str,
    agent_id: str,
):
    """No-op shim — worker traces are no longer mirrored to disk.

    The previous behaviour wrote one row per LangChain message into
    ``logs/run-<run_id>/worker_traces.jsonl``. The file was nearly
    redundant with ``full_logs.jsonl`` (every LLM round-trip is already
    captured there with full prompt + response) and was never read by
    a human in practice. Removed as part of the 2026-05 log
    consolidation.

    Kept as a function (instead of being deleted) so call sites in
    ``run_skill_agent`` can keep invoking it without conditional logic.
    Returns ``None`` so any caller that stored the path falls back to
    its empty-path branch.
    """
    del trace, run_id, agent_id  # explicitly unused
    return None


# ────────────────────────────────────────────────────────────────────────────
# The runner itself.
#
# ``run_skill_agent`` is the entire worker lifecycle: build the system
# prompt, seed cross-turn context, run the agent loop with refusal
# retries, parse findings, salvage on crash. ``BaseNode.run_skill_agent``
# is a thin async wrapper that just forwards ``self`` and delegates here.
# ────────────────────────────────────────────────────────────────────────────


async def run_skill_agent(
    node: "BaseNode",
    config: AgentConfig,
    state: dict,
    llm: BaseChatModel | None = None,
) -> dict:
    """Run a ``create_agent`` loop with the given skill config.

    Public entry point. Thin wrapper that guarantees per-worker shell
    cleanup runs whether the implementation succeeded, raised, was
    salvaged, or refused. The actual worker lifecycle lives in
    :func:`_run_skill_agent_impl` immediately below.

    Why the wrapper exists: without it, every worker leaves its tmux
    session and bash subprocess alive in the
    :class:`~src.tools.shell.manager.ShellManager` registry until
    ``atexit`` fires at process death. For benchmark runs with many
    parallel/sequential workers that means dozens of live sessions
    accumulating in one Python process — fine in theory, sloppy in
    practice. The finally-block frees them as each worker finishes.
    """
    try:
        return await _run_skill_agent_impl(node, config, state, llm)
    finally:
        # Best-effort per-worker shell cleanup. Never raise from the
        # finally — a cleanup failure must not mask a successful return
        # or a real exception from the implementation.
        try:
            from src.tools.shell import get_shell_manager
            await get_shell_manager().cleanup_agent(config.agent_id)
        except Exception as e:  # noqa: BLE001
            node.log.warning(
                "[%s] shell cleanup_agent failed (non-fatal): %s",
                config.agent_id, e,
            )


async def _run_skill_agent_impl(
    node: "BaseNode",
    config: AgentConfig,
    state: dict,
    llm: BaseChatModel | None = None,
) -> dict:
    """Run a ``create_agent`` loop with the given skill config.

    Returns the standard worker-node update dict::

        {
            "messages":      [...],   # mirrored agent trace
            "agent_results": [AgentResult(...)],
            "findings":      [Finding, ...],
            "active_agents": [agent_id],
        }

    ``node`` is the BaseNode instance whose method delegated here. We
    use it for ``node.log`` (per-node logger), ``node.name`` (used by
    the LLM call config and for trace persistence), and the focused
    sub-LLM helper ``node.ask_focused`` (which the refusal-recovery
    path needs).

    Called only via :func:`run_skill_agent` (the public entry point
    that adds the per-worker shell cleanup ``finally``).
    """
    if llm is None:
        from src.llm.provider import get_llm  # lazy — see module docstring
        llm = get_llm()

    target_url = state.get("target_url", "")

    # Build system message with phase-appropriate rule bundle. The
    # benchmark-mode addendum used to be appended here when
    # ``state.expected_flag`` was set; it was removed on 2026-05-14
    # because the flag success-criterion language was the strongest
    # cyber_policy refusal trigger in worker prompts. The planner
    # owns flag submission (``action="submit_flag"`` verified by
    # ``src/edges/routing.py:route_after_planner``); workers only
    # need to surface flag-shaped strings in their findings.
    #
    # Findings injection used to happen here via the never-populated
    # ``phase1_findings`` state field. That was dead code; cumulative
    # findings now reach the worker through the seed HumanMessage's
    # "## Confirmed findings" block (see ``_format_findings`` below).
    #
    # ``is_benchmark`` gates the playful BENCHMARK_GUIDANCE addendum
    # (executor-only) — re-introduced 2026-05-31. Detected from the same
    # state fields the FlagWatcher reads below.
    is_benchmark = bool(
        (state or {}).get("expected_flag")
        or (state or {}).get("expected_flag_candidates")
    )
    system_msg = _build_system_message(
        config, target_url, is_benchmark=is_benchmark,
    )

    # NB: agent construction is now deferred to ``_agent_factory``
    # below so the tier-2 refusal-retry can rebuild the agent with
    # a vocab-filtered system prompt without losing any of this
    # call site's wiring.

    # Seed the create_agent loop with whatever cross-turn context we can
    # recover from state. The seed is a single HumanMessage prepended to
    # the agent's input so a fresh worker doesn't start cold.
    #
    # Order matters for both model focus and prompt caching. Stable, heavy
    # content goes first so it stays in the shared prefix; volatile run state
    # follows; the concrete assignment remains at the end where it is most
    # salient for the worker.
    #
    #   1. skill_catalogue   — stable all-skill routing/context descriptions
    #   2. findings          — "what is already confirmed true"
    #   3. recon_summary     — "what does the application look like"
    #   4. relevant_summary  — "what's the live investigation state"
    #   5. tool_attempts     — "which high-level tools covered or failed"
    #   6. web_search        — "what external knowledge was just pulled"
    #   7. prior_history     — "what did I myself try on a previous run"
    #   8. dispatch_reason   — "why am I here, what's the hypothesis"
    #
    # Each helper returns ``None`` when its source field is empty, so
    # cold first dispatches (turn 1, before the planner has spoken)
    # produce an empty seed and the worker starts cold — backward-
    # compatible with the original ``{"messages": []}`` behavior.
    seed_parts: list[str] = []

    skill_catalogue_block = _format_skill_context_catalogue(config.config_name)
    if skill_catalogue_block:
        seed_parts.append(skill_catalogue_block)

    findings_block = _format_findings(state)
    if findings_block:
        seed_parts.append(findings_block)

    recon_block = _format_recon_summary(state)
    if recon_block:
        seed_parts.append(recon_block)

    relevant_block = _format_relevant_summary(state)
    if relevant_block:
        seed_parts.append(relevant_block)

    hypotheses_block = _format_hypotheses(state)
    if hypotheses_block:
        seed_parts.append(hypotheses_block)

    tool_attempts_block = _format_tool_attempts(state)
    if tool_attempts_block:
        seed_parts.append(tool_attempts_block)

    web_search_ctx = _extract_latest_web_search(state)
    if web_search_ctx:
        seed_parts.append(
            "## Supervisor's most recent web research\n\n"
            "The supervisor ran a web search before dispatching you. "
            "The synthesis below is drawn from cited public sources — "
            "use it for technique guidance instead of re-deriving "
            "everything from scratch.\n\n"
            f"{web_search_ctx}"
        )

    thread_block = _format_investigation_thread(state, config.config_name)
    if thread_block:
        seed_parts.append(thread_block)

    prior_history = _collect_prior_skill_history(state, config.agent_id)
    if prior_history:
        seed_parts.append(prior_history)

    dispatch_block = _format_dispatch_reason(state)
    if dispatch_block:
        seed_parts.append(dispatch_block)

    if seed_parts:
        seed_parts.append(
            "Begin testing now. Build on the context above; do not "
            "re-discover what's already mapped or re-probe what's "
            "already been confirmed."
        )

    # Benchmark status footer — appended LAST (after the "Begin testing"
    # tail) so it is the final thing the worker reads each dispatch. In
    # benchmark mode capture is fully static (the FlagWatcher scans tool
    # output and ends the run on the real token), so this keeps a worker
    # from concluding the exercise is finished on its own and returning
    # early. See ``BENCHMARK_PROGRESS_FOOTER``. Mirrors the supervisor
    # footer appended in ``src/nodes/planner.py``.
    if is_benchmark:
        seed_parts.append(BENCHMARK_PROGRESS_FOOTER)

    if seed_parts:
        seed_msgs: list = [HumanMessage(content="\n\n".join(seed_parts))]
        node.log.info(
            "[%s] seeding worker with %d context block(s) "
            "(dispatch_reason=%s, findings=%s, recon_summary=%s, "
            "relevant_summary=%s, tool_attempts=%s, skill_catalogue=%s, "
            "web_search=%s, prior_history=%s, benchmark_footer=%s)",
            config.agent_id,
            sum(bool(b) for b in (
                dispatch_block, findings_block, recon_block,
                relevant_block, tool_attempts_block, skill_catalogue_block,
                web_search_ctx, prior_history,
            )),
            bool(dispatch_block),
            bool(findings_block),
            bool(recon_block),
            bool(relevant_block),
            bool(tool_attempts_block),
            bool(skill_catalogue_block),
            bool(web_search_ctx),
            bool(prior_history),
            is_benchmark,
        )
    else:
        seed_msgs = []

    trace: list = []
    findings: list[Finding] = []
    verdict_signals: list[Signal] = []
    # Resolve the run_id once so every LLM call below logs into the
    # same ``logs/run-<id>/llm_calls.jsonl`` and so on a crash the
    # salvage path knows where to write its output.
    run_id = (state or {}).get("run_id") or make_run_id(
        target_url=target_url,
    )
    # ``call_config`` carries: callbacks (token logger + optional
    # flag watcher), metadata (agent_id / run_id / node — read by the
    # callback to attribute each LLM call), and the recursion_limit
    # budget. Using a helper keeps every LLM call site in the codebase
    # consistent — a missing callback here would silently drop
    # token-cost rows from llm_calls.jsonl.
    #
    # In benchmark mode the FlagWatcherCallback hooks ``on_tool_end``
    # and raises ``FlagCapturedSignal`` the instant a tool returns the
    # expected flag literal. This short-circuits the worker BEFORE the
    # next LLM call is queued — saves 60-90 s of gpt-5.5 reasoning per
    # capture and unblocks the LangGraph fan-in much faster (other
    # parallel workers then also stop on the same capture via the
    # ``state.captured_flag`` reducer). See the module docstring of
    # ``src.nodes.base.flag_watcher`` for the full incident retro.
    from src.nodes.base.flag_watcher import FlagWatcherCallback
    # Pass the full candidate set to the watcher — see
    # :func:`src.edges.flag_match.flags_match` for why benchmarks can
    # legitimately have multiple expected flag values. Falls back to
    # the (back-compat) single ``expected_flag`` field if the runner
    # didn't populate the candidates tuple.
    expected_flag_candidates_for_callback: tuple[str, ...] = tuple(
        (state or {}).get("expected_flag_candidates") or ()
    )
    if not expected_flag_candidates_for_callback:
        single = (state or {}).get("expected_flag") or ""
        if single:
            expected_flag_candidates_for_callback = (single,)
    worker_callbacks: list = []
    if expected_flag_candidates_for_callback:
        worker_callbacks.append(FlagWatcherCallback(
            expected_flag=expected_flag_candidates_for_callback,
            agent_id=config.agent_id,
        ))
    # ``config.max_iterations`` is the worker's budget in REAL tool-using
    # rounds (one round = the model decides + a tool runs). LangGraph's
    # ``recursion_limit`` instead counts super-steps, and the create_agent
    # loop spends ~3 super-steps per round (the no-progress middleware's
    # before_model node + the model node + the tools node) — empirically a
    # limit of 40 stops a worker at exactly 13 rounds (measured across
    # XBEN-030/088/095, see tests/FAILURES.md 2026-06-10). Convert rounds →
    # super-steps here (``3*rounds + 1``) so the config, this budget, and
    # ``_count_worker_iterations`` all speak in the same real-round units.
    recursion_limit = config.max_iterations * 3 + 1
    call_config = make_call_config(
        run_id=run_id,
        agent_id=config.agent_id,
        node=node.name,
        recursion_limit=recursion_limit,
        extra_callbacks=worker_callbacks or None,
    )

    # Stream rather than ainvoke so a partial state snapshot
    # survives crashes. ``stream_mode="values"`` yields successive
    # full-state snapshots; we keep the latest one. When LangGraph
    # raises ``GraphRecursionError`` mid-loop, ``last_snapshot``
    # holds the messages accumulated up to the last successful
    # step — which is exactly what salvage_finding() consumes.
    #
    # The agent is reconstructed inside the retry helper because
    # vocab-filter / tier-2 model-swap both rebuild it from scratch.
    #
    # The no-progress nudge middleware is shared across the primary and
    # fallback factories (one per-worker plateau state). It fires only
    # on byte-identical tool outputs and only re-surfaces the existing
    # DIVERSITY_RULES guidance — it never stops the worker, so it is
    # safe in both benchmark and real-pentest mode. See
    # ``src/nodes/base/no_progress.py``.
    from src.nodes.base.no_progress import NoProgressNudgeMiddleware
    _no_progress_mw = NoProgressNudgeMiddleware(
        agent_id=config.agent_id, log=node.log,
    )

    # Per-dispatch progressive-disclosure tool: when this skill ships
    # reference files (src/skills/<name>/references/*.md), bind a scoped
    # read_reference tool so the worker can page one in on demand. Skills
    # without references (generic executor, custom, recon) keep config.tools
    # unchanged. Wrapped defensively — reference wiring must never break a run.
    _run_tools = list(config.tools)
    try:
        from src.skills.loader import list_references
        from src.tools.references import (
            make_read_reference_tool,
            make_read_skill_context_tool,
            make_read_skill_reference_tool,
        )
        if list_references(config.config_name):
            _run_tools.append(make_read_reference_tool(config.config_name))
        _run_tools.append(make_read_skill_context_tool())
        _run_tools.append(make_read_skill_reference_tool())
    except Exception as _ref_exc:
        node.log.debug("reference/context tool wiring skipped: %s", _ref_exc)

    def _agent_factory(sys_prompt: str):
        return create_agent(
            model=llm,
            tools=_run_tools,
            system_prompt=sys_prompt,
            middleware=[_no_progress_mw],
        )

    # Tier-2 fallback factory — only wired when the primary provider
    # is Codex (model-swap to gpt-5.4 isn't meaningful for anthropic
    # / local / openrouter routes). See ``src/refusals/retry.py`` for
    # the tier ladder and ``config.budgets.fallback_*`` env knobs for
    # tuning the fallback model + reasoning_effort.
    from src.llm.provider import LLMConfig as _LLMConfig
    from src.llm.provider import Provider as _Provider
    fallback_factory: Any = None
    _fallback_model: str | None = None
    _fallback_effort: str | None = None
    _primary_cfg = _LLMConfig()
    if _primary_cfg.provider == _Provider.CODEX:
        # Lazy import — skill_runner is imported transitively from
        # src.graph during its own initialization, so a top-level
        # ``from src.graph import config`` would re-enter the module
        # while it's still binding ``config``. Reading via the module
        # object at call-time (after graph.py has finished) avoids
        # that.
        from src import graph as _graph_module
        _fallback_model = str(getattr(
            _graph_module.config.budgets, "fallback_model", "gpt-5.4",
        ))
        _fallback_effort = str(getattr(
            _graph_module.config.budgets, "fallback_reasoning_effort", "low",
        ))

        def _fallback_agent_factory(sys_prompt: str):
            from src.llm.provider import get_llm as _get_llm
            fb_llm = _get_llm(_LLMConfig(
                provider=_Provider.CODEX,
                model=_fallback_model,
                reasoning_effort=_fallback_effort,
            ))
            return create_agent(
                model=fb_llm,
                tools=_run_tools,
                system_prompt=sys_prompt,
                middleware=[_no_progress_mw],
            )

        fallback_factory = _fallback_agent_factory

    last_snapshot: dict | None = None
    worker_attempts = 0
    worker_last_tier = "primary"
    flag_watcher_capture: str | None = None
    sibling_captured_value: str = ""

    # Sticky fallback: if this config's prompt already tripped the primary
    # model's cyber_policy classifier earlier this run, start its dispatch
    # directly on the fallback model — the primary would refuse the same
    # prompt again, wasting 3 retries. (No-op when no fallback is wired.)
    start_on_fallback = (
        fallback_factory is not None
        and config.config_name in set((state or {}).get("fallback_configs") or [])
    )
    if start_on_fallback:
        node.log.info(
            "[%s] config %r refused on the primary model earlier this run — "
            "dispatching directly on the fallback model",
            config.agent_id, config.config_name,
        )
    try:
        # Inner try catches the FlagWatcher's short-circuit signals so
        # they never reach the outer ``except Exception`` (which would
        # mis-classify them as refusals). Two distinct signals:
        #
        #   * FlagCapturedSignal — THIS worker matched the flag in its
        #     own tool output. We synthesise a ToolMessage so the
        #     downstream auto-verify scan picks the flag up via its
        #     existing extract_flags + flags_match path, then build a
        #     normal worker-result dict. captured_flag lands in state
        #     via the reducer.
        #
        #   * SiblingCapturedSignal — ANOTHER worker captured while we
        #     were mid-LLM-call. We exit cleanly with an empty-findings
        #     update so the fan-in can complete fast and the routing
        #     edge ``route_after_summarizer`` can route to END. We do
        #     NOT set captured_flag (the winning worker already did).
        #
        # Single code path for the WINNING worker — capture via
        # FlagWatcher (early, milliseconds after tool returns) and the
        # end-of-worker fallback scan (late, after the agent loop ends
        # naturally) both feed the same downstream auto-verify block.
        try:
            (
                last_snapshot,
                worker_attempts,
                worker_last_tier,
            ) = await astream_with_refusal_retry(
                agent_factory=_agent_factory,
                fallback_agent_factory=fallback_factory,
                fallback_model_label=(
                    str(_fallback_model) if fallback_factory is not None else None
                ),
                system_msg=system_msg,
                seed_msgs=seed_msgs,
                call_config=call_config,
                config=config,
                log=node.log,
                start_on_fallback=start_on_fallback,
            )
        except FlagCapturedSignal as sig:
            flag_watcher_capture = sig.flag
            node.log.info(
                "[%s] FlagWatcher captured flag in %s output: %s — "
                "short-circuiting worker (saves Codex spend + unblocks "
                "fan-in)",
                config.agent_id, sig.tool_name or "tool", sig.flag,
            )
            # Append a synthetic ToolMessage with the captured value
            # to the last partial snapshot. The downstream auto-verify
            # scan iterates ``last_snapshot["messages"]`` and matches
            # ``extract_flags(content) → flags_match(...)``; this
            # synthetic entry is exactly what that scan expects.
            #
            # Why the snapshot is partial: the FlagWatcher raises
            # inside ``on_tool_end``, which fires AFTER the tool
            # returns but BEFORE LangGraph yields the next state
            # snapshot. So ``last_snapshot`` holds the state from
            # before the flag-producing tool call. The synthetic
            # message bridges that gap without us needing to
            # reconstruct the missing snapshot ourselves.
            snap = dict(last_snapshot or {})
            msgs = list(snap.get("messages") or [])
            msgs.append(ToolMessage(
                content=sig.flag,
                tool_call_id="_flag_watcher_synthetic",
                name=sig.tool_name or "_flag_watcher",
            ))
            snap["messages"] = msgs
            last_snapshot = snap
        except SiblingCapturedSignal as sig:
            # Sibling worker captured first; this worker exits with
            # an empty update so fan-in completes fast. Routing reads
            # state.captured_flag (set by the winning worker) to drive
            # termination — we don't touch it here.
            sibling_captured_value = sig.captured_flag
            node.log.info(
                "[%s] sibling worker captured the flag (%s) — "
                "exiting cleanly to unblock fan-in",
                config.agent_id, sig.captured_flag,
            )

        result = last_snapshot or {}
        messages = result.get("messages", [])
        findings = _extract_findings(messages, config.agent_id)
        verdict_signals = _extract_verdicts(
            messages, config.agent_id, config.config_name,
        )

        # If the FlagWatcher fired, also synthesise a CRITICAL Finding
        # so the worker reports ``1 finding`` instead of ``0`` and the
        # summarizer's per-worker digest has something concrete to
        # echo. Capture itself routes through ``captured_flag`` (set
        # by the downstream auto-verify block); this Finding is the
        # human-readable companion to that machine-readable signal.
        if flag_watcher_capture and not findings:
            findings = [
                Finding(
                    title=f"Flag captured: {flag_watcher_capture}",
                    severity=Severity.CRITICAL,
                    category="flag-capture",
                    description=(
                        "Worker tool output contained the expected "
                        "flag literal. The FlagWatcher callback "
                        "strict-equal matched it against "
                        "state.expected_flag and short-circuited the "
                        "worker loop to save downstream Codex spend."
                    ),
                    evidence=f"Captured flag: {flag_watcher_capture}",
                    agent_id=config.agent_id,
                    url=target_url or "",
                    cwe="",
                    reproduced=True,
                )
            ]

        # Mirror the inner agent trace up to the parent so Studio chat
        # shows every tool call (`run_command("curl ...")`) and the
        # corresponding ToolMessage response inline. Without this the
        # entire conversation is hidden inside the create_agent
        # sub-graph and the parent chat looks frozen.
        trace = [m for m in messages if isinstance(m, (AIMessage, ToolMessage))]
        for m in trace:
            # Tag each message with the agent_id so Studio (and
            # downstream consumers) can group / filter by agent.
            try:
                m.additional_kwargs.setdefault("agent_id", config.agent_id)
            except Exception:
                pass

        # Refusal detection — if 0 findings AND the last assistant
        # message reads like a safety refusal, surface it explicitly
        # instead of letting it get swallowed as "0 findings".
        #
        # Skip this entire block when ``sibling_captured_value`` is
        # set: the worker exited early because another worker captured
        # the flag, not because of any refusal or anomalous output.
        # Treating it as "0 findings — looks like a refusal" would
        # trigger an unnecessary recovery sub-call AND emit a
        # misleading warning to the operator.
        last_text = ""
        for m in reversed(messages):
            if isinstance(m, AIMessage):
                last_text = (
                    m.content if isinstance(m.content, str) else str(m.content)
                )
                break

        refused = (not findings) and looks_like_refusal(last_text)
        if not findings and not sibling_captured_value:
            node.log.warning(
                f"[{config.agent_id}] produced 0 findings — "
                f"last output: {last_text[:500]!r}"
            )
        if refused and not sibling_captured_value:
            node.log.warning(
                f"[{config.agent_id}] looks like a model refusal — "
                "attempting focused-sub-call recovery"
            )
            recovered = await recover_from_refusal(
                config=config,
                messages=messages,
                last_text=last_text,
                ask_focused=node.ask_focused,
                log=node.log,
                run_id=run_id,
            )
            if recovered:
                node.log.info(
                    f"[{config.agent_id}] refusal recovery returned a "
                    "focused suggestion"
                )
                trace.append(AIMessage(
                    content=(
                        f"[focused-followup for {config.agent_id}] "
                        "The agent's primary response read as a "
                        "refusal. A narrow-framing sub-call returned "
                        f"this suggestion instead:\n\n{recovered}"
                    ),
                    additional_kwargs={
                        "agent_id": config.agent_id,
                        "recovered": True,
                    },
                ))
                # Treat as not-refused so AgentResult.completed=True
                # and the planner sees the suggestion in the trace
                # as actionable evidence for its next turn.
                refused = False
            else:
                node.log.warning(
                    f"[{config.agent_id}] refusal recovery also "
                    "failed (no probes to summarize, or sub-LLM "
                    "also refused)"
                )
                trace.append(AIMessage(
                    content=(
                        f"⚠️ [{config.agent_id}] model refused the task. "
                        f"Last output: {last_text[:300]}"
                    ),
                    additional_kwargs={
                        "agent_id": config.agent_id,
                        "refusal": True,
                    },
                ))

        # Sibling-cancelled workers are not refusals and not crashes —
        # they're a clean cooperative exit. Surface them on a distinct
        # ``error`` channel so the planner / triage tooling can tell
        # the difference between "this worker tried and failed" and
        # "this worker stood down because another worker won".
        if sibling_captured_value:
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                completed=False,
                error="sibling captured first",
            )
        else:
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                completed=not refused,
                error="model refused" if refused else None,
            )
    except Exception as e:
        # Rate-limit (429) / quota-exhausted errors are NOT salvageable —
        # this run never got a fair attempt, so it's a crash. Re-raise so the
        # error propagates out of the worker and aborts the run; xbow_runner
        # then marks the benchmark ~ crashed and the usage guard pauses the
        # sweep until the 5-hour window resets. Everything else (refusals,
        # step-budget stops, ordinary tool crashes) keeps the salvage path
        # below. Lazy import respects the planner/executor import-order dance.
        try:
            from src.llm.codex import (
                CodexQuotaExceededError as _CodexQuota,
                CodexRateLimitError as _CodexRateLimit,
            )
            _rate_limit_types: tuple = (_CodexQuota, _CodexRateLimit)
        except ImportError:
            _rate_limit_types = ()
        if _rate_limit_types and isinstance(e, _rate_limit_types):
            raise

        # The refusal-retry ladder tags the exception with the tier it
        # reached. On a terminal refusal the tuple-unpack above never ran,
        # so ``worker_last_tier`` is still its "primary" default — recover
        # the real tier here so the sticky-fallback record below fires when
        # this config exhausted the fallback model too.
        worker_last_tier = getattr(e, "_swarm_last_tier", worker_last_tier)

        # Cyber-policy / invalid-prompt failures from the Codex API
        # are *refusals*, not crashes. Surface them on the
        # ``error="model refused"`` channel so the planner's
        # repetition + refusal logic can pick a different skill
        # rather than treating this as a hard exception. We also
        # try a focused-recovery sub-call: if the agent had already
        # made any probes via ``create_agent`` before the API
        # rejected the next request, we may have a partial trace
        # with usable observations.
        #
        # Lazy-imported to keep the planner / executor import dance
        # working — see ``src/graph.py``'s ordering note.
        try:
            from src.llm.codex import (
                CodexCyberPolicyError,
                CodexInvalidPromptError,
            )
            refusal_exc_types = (
                CodexCyberPolicyError,
                CodexInvalidPromptError,
            )
        except ImportError:
            refusal_exc_types = ()

        # Pull whatever messages survived the crash into the trace
        # so the parent chat / nodes.jsonl still show what the
        # worker did before dying. Without this, recursion-limit
        # crashes look like the worker did literally nothing.
        #
        # On a terminal refusal / step-budget stop / crash the tuple-unpack
        # at the ``astream_with_refusal_retry`` call site never ran, so
        # ``last_snapshot`` is still its ``None`` init. ``_run_agent_once``
        # and the retry helper attach the worker's richest partial trace to
        # the exception — recover it here so the salvage / wrap-up / summary
        # below (and the success-path flag auto-verify scan further down)
        # operate on the REAL work. Without this, an exception exit produced
        # ``tool_msgs_scanned: 0`` and 0 findings even when the worker had
        # already extracted data (XBEN-095 auth-testing, 2026-06-09 — ~24
        # loops of SQL work lost across a refusal and a step-budget stop).
        if last_snapshot is None:
            _recovered = getattr(e, "_swarm_partial_snapshot", None)
            if isinstance(_recovered, dict):
                last_snapshot = _recovered
        partial_messages = (last_snapshot or {}).get("messages", []) or []

        if refusal_exc_types and isinstance(e, refusal_exc_types):
            node.log.warning(
                "[%s] API-level refusal (%s) after %d retry attempts "
                "(last tier: %s): %s — surfacing as model refusal so "
                "the planner can pivot.",
                config.agent_id, type(e).__name__,
                worker_attempts, worker_last_tier, str(e)[:200],
            )

            trace = [
                m for m in partial_messages
                if isinstance(m, (AIMessage, ToolMessage))
            ]
            # Refusal-time flag salvage. The Codex API can refuse
            # mid-run after the worker has already executed a few
            # tool calls — and one of those ToolMessage responses
            # may contain a captured ``flag{...}`` string. Without
            # this scan, the refusal branch wipes ``findings = []``
            # and the planner never learns the worker actually
            # won. Concrete example: XBEN-006-24 run on
            # 2026-05-09, where ``owasp-input-validation`` extracted
            # ``flag{582d82bb-...}`` at iteration 5 and got refused
            # at iteration 6, dropping the win.
            #
            # Lazy import so the ``src.edges.flag_match`` module is only
            # loaded on the refusal path (it is also imported at routing
            # time, but defensive imports here keep startup costs
            # tied to actual usage).
            findings = []
            try:
                from src.edges.flag_match import extract_flags

                # Stringify partial messages inline. The old code used a
                # private ``_stringify_messages`` helper from ``src.flag``;
                # that helper was deleted in the 2026-05 refactor that
                # replaced state scanning with explicit ``submit_flag``.
                # Salvage still legitimately scans the partial trace of a
                # refused worker, so the stringifier lives here now —
                # narrower scope, no public API surface for state scans.
                parts: list[str] = []
                for m in partial_messages:
                    c = getattr(m, "content", None)
                    if isinstance(c, str):
                        parts.append(c)
                    elif isinstance(c, list):
                        for block in c:
                            if isinstance(block, dict):
                                parts.append(str(block.get("text") or ""))
                haystack = "\n".join(parts)
                flag_hits = extract_flags(haystack)
                if flag_hits:
                    flag_value = flag_hits[0]
                    # Pull a short evidence excerpt around the
                    # match so a human reading the report can
                    # eyeball the request that produced it.
                    idx = haystack.find(flag_value)
                    excerpt_start = max(0, idx - 240)
                    excerpt_end = min(
                        len(haystack), idx + len(flag_value) + 240,
                    )
                    excerpt = haystack[excerpt_start:excerpt_end]
                    findings = [
                        Finding(
                            title=(
                                "[salvaged from refused worker] "
                                f"flag captured before refusal: "
                                f"{flag_value}"
                            )[:240],
                            severity=Severity.CRITICAL,
                            category="flag-capture",
                            description=(
                                "The worker hit a Codex policy "
                                "refusal mid-run, but its partial "
                                "tool trace already contained a "
                                "flag-pattern match. The matched "
                                "string is the actual flag string "
                                "captured during testing."
                            ),
                            evidence=excerpt[:2400],
                            agent_id=config.agent_id,
                            url="",
                            cwe="",
                            reproduced=False,
                        )
                    ]
                    node.log.warning(
                        "[%s] refusal-path flag salvage: captured "
                        "%r from partial trace before discard.",
                        config.agent_id, flag_value[:80],
                    )
            except Exception as salv_err:  # noqa: BLE001
                # Salvage must never make the refusal path worse;
                # log and fall through with empty findings.
                node.log.warning(
                    "[%s] refusal-path flag salvage failed: %s: %s",
                    config.agent_id,
                    type(salv_err).__name__,
                    str(salv_err)[:160],
                )

            # Refusal-path PRIMITIVE salvage. If no flag was recovered,
            # the worker may still have PROVEN a non-flag capability (a
            # SQL extraction, command output, an /etc/passwd read) in the
            # tool output the API refused on — refusals land on exactly
            # that high-value output more often than not. Mint a HIGH
            # primitive finding so the planner's
            # ``_unconverted_primitive_directive`` can drive it to the
            # flag on a later turn, instead of the proof evaporating with
            # the refusal. Scans received tool output only (never the
            # worker's own payload) with a negation guard; never raises.
            salvaged_primitive = False
            if not findings:
                try:
                    prim = _salvage_primitive_from_trace(
                        partial_messages, config.agent_id,
                    )
                    if prim is not None:
                        findings = [prim]
                        salvaged_primitive = True
                        node.log.warning(
                            "[%s] refusal-path primitive salvage: "
                            "recovered a %r primitive from the partial "
                            "trace before discard.",
                            config.agent_id, prim.primitive,
                        )
                except Exception as prim_err:  # noqa: BLE001
                    node.log.warning(
                        "[%s] refusal-path primitive salvage failed: "
                        "%s: %s",
                        config.agent_id,
                        type(prim_err).__name__,
                        str(prim_err)[:160],
                    )

            trace.append(AIMessage(
                content=(
                    f"⚠️ [{config.agent_id}] model refused the task at "
                    f"the API safety layer ({type(e).__name__}). "
                    "Recommend the planner pick a different skill or "
                    "rephrase the goal more narrowly."
                    + (
                        f"\n\n[salvage] Recovered a "
                        f"{findings[0].severity.value} finding from the "
                        f"partial trace before refusal: {findings[0].title}"
                        if findings
                        else ""
                    )
                ),
                additional_kwargs={
                    "agent_id": config.agent_id,
                    "refusal": True,
                    "refusal_kind": "api_cyber_policy",
                    "salvaged_flag": bool(findings) and not salvaged_primitive,
                    "salvaged_primitive": salvaged_primitive,
                },
            ))
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                # If we salvaged a flag, treat the worker as
                # completed for planner-loop accounting — its
                # contribution was real, even though the API
                # rejected the next iteration.
                completed=bool(findings),
                error="model refused" if not findings else None,
            )
        elif (
            "recursion limit" in str(e).lower()
            or type(e).__name__ == "GraphRecursionError"
        ):
            # ── Step-budget stop (NOT a crash) ──────────────────────
            # The worker exhausted its LangGraph ``recursion_limit``
            # (``config.max_iterations`` real rounds, converted to super-steps
            # where ``call_config`` is built). The model is still perfectly
            # reachable — it just ran out of turns. So we do NOT use the
            # post-crash salvage guesser here (that exists for the case
            # the LLM channel is dead — a refusal). Instead:
            #   1. recover the ``**FINDING:**`` blocks the worker already
            #      wrote before the wall (the success path would have
            #      parsed these; the old crash path threw them away), and
            #   2. make ONE forced wrap-up call asking the worker to stop
            #      and summarize its own work + emit any not-yet-written
            #      findings.
            # See src/nodes/base/graceful_wrapup.py for the rationale.
            node.log.warning(
                "[%s] reached its step budget (%s) — forcing a graceful "
                "wrap-up instead of discarding the run.",
                config.agent_id, str(e)[:160],
            )
            from src.nodes.base.graceful_wrapup import force_wrapup_summary

            own_findings = _extract_findings(partial_messages, config.agent_id)
            wrapup_msg = await force_wrapup_summary(
                config=config,
                partial_messages=partial_messages,
                target_url=target_url,
                log=node.log,
                run_id=run_id,
            )
            wrapup_findings = (
                _extract_findings([wrapup_msg], config.agent_id)
                if wrapup_msg else []
            )
            # Dedup by (title, url) — the worker often re-emits in the
            # wrap-up a finding it had already written in the trace.
            findings = []
            _seen_keys: set = set()
            for f in own_findings + wrapup_findings:
                key = (getattr(f, "title", ""), getattr(f, "url", ""))
                if key in _seen_keys:
                    continue
                _seen_keys.add(key)
                findings.append(f)

            trace = [
                m for m in partial_messages
                if isinstance(m, (AIMessage, ToolMessage))
            ]
            if wrapup_msg:
                trace.append(wrapup_msg)
            trace.append(AIMessage(
                content=(
                    f"⏱ [{config.agent_id}] reached its step budget and "
                    f"was asked to wrap up ({e}). This is a completed pass "
                    f"that ran out of room, not a crash — "
                    f"{len(findings)} finding(s) recovered from its work. "
                    "If its lead looked promising, re-dispatch it "
                    "(optionally with a larger budget) rather than "
                    "treating it as a dead end."
                ),
                additional_kwargs={
                    "agent_id": config.agent_id,
                    "budget_stop": True,
                    "findings_recovered": len(findings),
                },
            ))
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                # Informative, but NOT "model refused" — so the planner's
                # refusal/repetition logic does not mis-handle it.
                error="stopped at step budget",
                # A budget stop is a real, completed pass: count it as a
                # turn so a worker that ran out of room is not mistaken
                # for a no-op.
                completed=True,
            )
        else:
            node.log.error(f"Agent {config.agent_id} failed: {e}")
            # Genuine crash — not a refusal, not a step-budget stop (e.g.
            # a tool blew up, a transport error, an unexpected exception).
            # Here the trace may hold impact the worker never formalized,
            # so we fall back to the post-crash salvage guesser as a last
            # resort. See src/refusals/salvage.py for the rationale and
            # the XBEN-006-24 incident that motivated it. The salvage call
            # is bounded (one sub-LLM call, ~9 KB prompt) and silently
            # returns None on failure, so this never makes the crash path
            # worse.
            salvaged = await try_salvage(
                config=config,
                partial_messages=partial_messages,
                target_url=target_url,
                log=node.log,
                run_id=run_id,
            )
            trace = [
                m for m in partial_messages
                if isinstance(m, (AIMessage, ToolMessage))
            ]
            trace.append(AIMessage(
                content=(
                    f"❌ [{config.agent_id}] crashed: {e}"
                    + (
                        f"\n\n[salvage] Recovered a "
                        f"{salvaged.severity.value} finding from the "
                        f"partial trace: {salvaged.title}"
                        if salvaged
                        else ""
                    )
                ),
                additional_kwargs={
                    "agent_id": config.agent_id,
                    "error": True,
                    "salvaged_finding": bool(salvaged),
                },
            ))
            findings = [salvaged] if salvaged else []
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                error=str(e),
                # A salvaged finding lets the planner act, so we
                # report completed=True for that case so the
                # repetition-loop detector counts it as a real turn.
                completed=bool(salvaged),
            )

    # Persist the full trace to disk for forensics. The planner will
    # never see this file directly — it's the per-worker forensic
    # artefact (and a fallback the salvage path can re-read). The
    # summarizer node consumes the in-memory ``trace`` we hand back
    # via ``pending_summary_inputs`` below, so the disk path is
    # primarily for human debugging after the run.
    trace_path = _persist_worker_trace(
        trace=trace,
        run_id=run_id,
        agent_id=config.agent_id,
    )

    # Resolve the dispatch reason from state — set by the planner
    # via ``pending_dispatch[i]["dispatch_reason"]`` and forwarded
    # through the routing edge. Empty for cold runs (initialize →
    # recon, before the planner has spoken) and that's fine — the
    # summarizer prompt handles missing reason gracefully.
    dispatch_reason = (
        state.get("dispatch_reason")
        or state.get("dispatch_focus")
        or ""
    )

    tool_attempts = _extract_tool_attempts_from_trace(
        trace,
        agent_id=config.agent_id,
        config_name=config.config_name,
    )
    if tool_attempts:
        node.log.info(
            "[%s] extracted %d structured tool outcome(s)",
            config.agent_id, len(tool_attempts),
        )
        try:
            from src.observability.writers import append_event
            append_event(
                run_id,
                "tool_attempts_extracted",
                agent_id=config.agent_id,
                config_name=config.config_name,
                attempts=tool_attempts,
            )
        except Exception:  # noqa: BLE001
            pass

    # The worker's effective system prompt (after the preventive vocab
    # filter that ``astream_with_refusal_retry`` always applies). We
    # propagate it into ``summary_input`` so the summariser node can
    # replay it byte-identically as Pattern B's prefix and get a
    # prompt-cache hit. ``filter_text`` is a deterministic regex
    # substitution — re-running it here yields the same bytes the
    # retry helper sent on the wire. Lazy import to avoid a hard
    # dependency cycle through ``src.refusals`` at module load.
    from src.refusals.vocabulary import (
        filter_messages as _filter_messages,
        filter_text as _filter_text,
    )
    worker_system_prompt_used, _ = _filter_text(system_msg)
    worker_seed_msgs_used, _ = _filter_messages(seed_msgs)

    # Reconstruct the exact worker conversation prefix for the summarizer:
    # filtered seed HumanMessage(s) + the worker's AI/Tool trace. Prefer the
    # full LangGraph snapshot because it also includes middleware-injected
    # HumanMessage notes. Append any synthetic wrap-up/salvage messages we
    # added after the snapshot so the report still sees them.
    snapshot_messages = []
    if isinstance(last_snapshot, dict):
        snapshot_messages = [
            m for m in (last_snapshot.get("messages") or [])
            if isinstance(m, BaseMessage)
        ]
    if snapshot_messages:
        worker_messages_for_summary = list(snapshot_messages)
        seen_msg_ids = {id(m) for m in worker_messages_for_summary}
        for msg in trace:
            if isinstance(msg, BaseMessage) and id(msg) not in seen_msg_ids:
                worker_messages_for_summary.append(msg)
                seen_msg_ids.add(id(msg))
    else:
        worker_messages_for_summary = [
            m for m in list(worker_seed_msgs_used) + list(trace)
            if isinstance(m, BaseMessage)
        ]

    # The summary input that the SummarizerNode will consume. Each
    # parallel worker writes a singleton list; the
    # ``_summary_inputs_reducer`` accumulates them so the
    # SummarizerNode (the synchronization point after fan-out) sees
    # one entry per worker. See ``src/state.py`` for the reducer
    # and ``src/nodes/summarizer.py`` for the consumer.
    summary_input: dict = {
        "agent_id": config.agent_id,
        "config_name": config.config_name,
        "methodology": config.methodology,
        "dispatch_reason": dispatch_reason,
        "trace": trace,                    # in-memory, not mirrored to messages
        "worker_messages": worker_messages_for_summary,
        "trace_path": str(trace_path) if trace_path else "",
        "completed": getattr(agent_result, "completed", False),
        "error": getattr(agent_result, "error", None),
        "refused": (getattr(agent_result, "error", None) == "model refused"),
        "findings_count": len(findings),
        "iteration_count": _count_worker_iterations(trace),
        "target_url": target_url,
        "tool_attempts": tool_attempts,
        # Keep the summarizer request shape cache-compatible with the worker.
        # Codex's prompt cache includes tool schemas, so replaying the same
        # textual prefix with tools removed misses the cache.
        "summary_tools": list(_run_tools),
        # The exact system prompt the worker's LLM saw — fed to the
        # summariser so its call shares the worker's cached prefix.
        "worker_system_prompt": worker_system_prompt_used,
    }
    if worker_last_tier == "fallback" and _fallback_model:
        summary_input["summary_model"] = _fallback_model
        summary_input["summary_reasoning_effort"] = _fallback_effort or "low"

    # ── Success-path flag auto-verification ─────────────────────
    # In benchmark mode (``expected_flag`` set), scan the worker's
    # tool messages for ``flag{...}`` substrings and strict-equal
    # them against ``expected_flag``. On a match, surface the
    # captured value via ``state.captured_flag`` (consumed by
    # ``route_after_summarizer`` to terminate the graph) AND push
    # it onto ``submission_attempts`` (consumed by ``xbow_runner``
    # as the verdict source of truth).
    #
    # Why this exists: prior to 2026-05-25 the only termination
    # path was the planner explicitly emitting ``submit_flag`` with
    # a flag-shaped string. The summarizer's digest LLM was
    # observed (XBEN-006-24 on 2026-05-25, see tests/FAILURES.md)
    # to rewrite the "Server responses" prose and DROP literal
    # ``flag{...}`` strings — so the planner never saw the
    # capture, never submitted, run timed out.
    #
    # Why this is SAFE despite the 2026-05-24 removal of the old
    # regex-only auto-terminate: the strict-equality gate
    # against ``expected_flag`` is itself the false-positive
    # filter. Swagger ``flag{example}`` examples, README
    # placeholders, and the agent's own ``python3 -c "flag=…"``
    # script literals all FAIL strict equality with the
    # deterministic ``FLAG{sha256(BENCHMARK_UPPER)}`` value, so
    # they never set this field. Only the actual served flag does.
    #
    # In real-pentest mode (``expected_flag`` empty), this block
    # is a no-op — capture remains planner-driven.
    captured_flag_value: str | None = None
    expected_flag = (state or {}).get("expected_flag") or ""
    # Full candidate set the matcher accepts — see
    # :func:`src.edges.flag_match.flags_match` for why benchmarks can
    # have multiple legitimate expected values. Falls back to the
    # single ``expected_flag`` when the runner didn't populate the
    # candidates tuple (back-compat).
    expected_flag_candidates: tuple[str, ...] = tuple(
        (state or {}).get("expected_flag_candidates") or ()
    )
    if not expected_flag_candidates and expected_flag:
        expected_flag_candidates = (expected_flag,)
    # Counters that always end up in the auto-verify summary event,
    # so post-mortem can see "we scanned N tool messages, looked at
    # K candidate flag-shaped strings, matched 0" without re-reading
    # the entire worker trace.
    tool_msgs_scanned = 0
    candidates_seen = 0
    if expected_flag_candidates and last_snapshot:
        from src.edges.flag_match import extract_flags, flags_match
        scanned_msgs = last_snapshot.get("messages", []) or []
        for m in scanned_msgs:
            if not isinstance(m, ToolMessage):
                continue
            tool_msgs_scanned += 1
            c = getattr(m, "content", None)
            if isinstance(c, str):
                content_str = c
            elif isinstance(c, list):
                # ToolMessage content can be a list of content blocks
                # under certain provider shapes — flatten to text.
                content_str = "\n".join(
                    str((block or {}).get("text") or block)
                    if isinstance(block, dict) else str(block)
                    for block in c
                )
            else:
                continue
            for candidate in extract_flags(content_str):
                candidates_seen += 1
                if flags_match(
                    submitted=candidate,
                    expected=expected_flag_candidates,
                ):
                    captured_flag_value = candidate
                    node.log.info(
                        "[%s] auto-verified flag in tool output: %s "
                        "(matches any of %d expected candidates)",
                        config.agent_id, candidate,
                        len(expected_flag_candidates),
                    )
                    break
            if captured_flag_value:
                break

    # Structured record of the scan — fires whether or not we matched,
    # so the post-mortem can answer "did the scan even run?" with a
    # single ``jq`` query rather than reconstructing it from logger
    # output that may have been dropped by compact mode. The 2026-05-25
    # XBEN-006-24 incident is the canonical case: three workers had the
    # flag in tool output but no on-disk artefact recorded whether the
    # scan matched, so it was unclear whether the bug was detection
    # (scan didn't fire / didn't match) or routing (matched but graph
    # didn't terminate from inside a fan-out).
    if expected_flag:
        try:
            from src.observability.writers import append_event
            run_id = (state or {}).get("run_id")
            append_event(
                run_id,
                "flag_auto_verified",
                agent_id=config.agent_id,
                node=node.name,
                expected_flag=expected_flag,
                expected_flag_candidates=list(expected_flag_candidates),
                captured_flag=captured_flag_value or "",
                matched=captured_flag_value is not None,
                tool_msgs_scanned=tool_msgs_scanned,
                candidates_seen=candidates_seen,
                last_snapshot_present=last_snapshot is not None,
            )
        except Exception:  # noqa: BLE001
            pass

    # Build the expensive worker digest while the worker's prompt prefix is
    # still hot in the provider cache. The SummarizerNode remains the fan-in
    # merger, but it can now reuse this precomputed report instead of waiting
    # until the slowest sibling reaches the barrier and then issuing all
    # digest calls. Skip LLM digesting on capture/cancel paths so a solved
    # benchmark is not delayed by a report the planner will never need.
    if captured_flag_value is not None:
        summary_input["skip_digest_reason"] = "flag captured"
        summary_input["precomputed_report"] = AIMessage(
            content=(
                "## Status\nsuccess — flag captured\n\n"
                f"## Target\n{target_url}\n\n"
                "## Inputs tried\nThe worker captured the expected flag "
                "during tool execution; see the raw worker trace for the "
                "exact request/response.\n\n"
                f"## Server responses\nCaptured flag: {captured_flag_value}\n\n"
                "## Inferred server-side behaviour\nThe exercised path "
                "returned the benchmark token.\n\n"
                "## NOT tried\nNot applicable after verified capture.\n\n"
                "## Recommended next dispatch\nNone — verified capture.\n\n"
                "## Cross-skill handoffs\n[]\n\n"
                "## Next skill suggestions\n[]"
            ),
            additional_kwargs={
                "agent_id": config.agent_id,
                "kind": "worker_report",
                "config_name": config.config_name,
                "methodology": config.methodology,
                "status": "success",
                "iteration_count": int(summary_input.get("iteration_count") or 0),
                "findings_count": len(findings),
                "precomputed_at_worker_exit": True,
                "skip_digest_reason": "flag captured",
            },
        )
    elif sibling_captured_value:
        summary_input["skip_digest_reason"] = "sibling captured"
        summary_input["precomputed_report"] = AIMessage(
            content=(
                "## Status\nstopped — sibling worker captured the flag\n\n"
                f"## Target\n{target_url}\n\n"
                "## Inputs tried\nThis worker exited early after another "
                "worker captured the expected flag.\n\n"
                "## Server responses\nNo additional response summary was "
                "generated after sibling capture.\n\n"
                "## Inferred server-side behaviour\nNot applicable.\n\n"
                "## NOT tried\nNot applicable after verified capture.\n\n"
                "## Recommended next dispatch\nNone — another worker already "
                "captured the flag.\n\n"
                "## Cross-skill handoffs\n[]\n\n"
                "## Next skill suggestions\n[]"
            ),
            additional_kwargs={
                "agent_id": config.agent_id,
                "kind": "worker_report",
                "config_name": config.config_name,
                "methodology": config.methodology,
                "status": "sibling_captured",
                "iteration_count": int(summary_input.get("iteration_count") or 0),
                "findings_count": len(findings),
                "precomputed_at_worker_exit": True,
                "skip_digest_reason": "sibling captured",
            },
        )
    else:
        try:
            from src.llm.digest import (
                bind_tools_for_summary_cache,
                summarize_worker_trace,
            )

            summary_llm: Any = llm
            if worker_last_tier == "fallback" and _fallback_model:
                try:
                    from src.llm.provider import get_llm as _get_llm
                    summary_llm = _get_llm(_LLMConfig(
                        provider=_Provider.CODEX,
                        model=_fallback_model,
                        reasoning_effort=_fallback_effort or "low",
                    ))
                except Exception as e:  # noqa: BLE001
                    node.log.debug(
                        "[%s] fallback summary model rebuild failed; "
                        "using primary model for digest: %s",
                        config.agent_id,
                        e,
                    )
            summary_llm = bind_tools_for_summary_cache(summary_llm, _run_tools)

            summary_input["precomputed_report"] = await summarize_worker_trace(
                trace=list(summary_input.get("trace") or []),
                worker_messages=list(summary_input.get("worker_messages") or []),
                worker_system_prompt=str(
                    summary_input.get("worker_system_prompt") or ""
                ),
                agent_id=config.agent_id,
                config_name=config.config_name,
                methodology=config.methodology,
                dispatch_reason=str(summary_input.get("dispatch_reason") or ""),
                target_url=str(summary_input.get("target_url") or target_url or ""),
                findings_count=len(findings),
                iteration_count=int(summary_input.get("iteration_count") or 0),
                completed=bool(getattr(agent_result, "completed", False)),
                error=getattr(agent_result, "error", None),
                refused=bool(getattr(agent_result, "error", None) == "model refused"),
                model=summary_llm,
                run_id=(state or {}).get("run_id"),
                node_name="summarizer",
            )
            akw = dict(
                getattr(summary_input["precomputed_report"], "additional_kwargs", {})
                or {}
            )
            akw["precomputed_at_worker_exit"] = True
            summary_input["precomputed_report"].additional_kwargs = akw
        except Exception as e:  # noqa: BLE001
            node.log.warning(
                "[%s] worker-exit digest failed (%s: %s); "
                "SummarizerNode will retry at fan-in",
                config.agent_id,
                type(e).__name__,
                str(e)[:200],
            )

    update: dict[str, Any] = {
        # NOTE: no ``"messages": trace`` — that was the cause of the
        # global-prompt explosion. The full trace stays on disk and
        # in ``pending_summary_inputs[*].trace`` until the
        # SummarizerNode replaces it with one ``AIMessage`` digest.
        "pending_summary_inputs": [summary_input],
        "agent_results": [agent_result],
        "findings": findings,
        "active_agents": [config.agent_id],
    }
    if verdict_signals:
        # The worker's closing self-assessment — the deciding-probe
        # feedback that lets the synthesis pass recalibrate belief (confirm
        # crosses COMMIT, refute drives toward refuted). See _extract_verdicts.
        update["signals"] = verdict_signals
        node.log.info(
            "[%s] verdict: %s",
            config.agent_id,
            "; ".join(
                f"{s.vuln_class}={'+' if s.weight >= 0 else ''}{s.weight:.1f}({s.kind})"
                for s in verdict_signals
            ),
        )
    if tool_attempts:
        update["tool_attempts"] = tool_attempts
    # Continuity: append this dispatch's compacted record to the skill's
    # investigation thread so the NEXT dispatch continues instead of
    # re-deriving (commands kept, outputs shrunk, oldest runs trimmed to a
    # bounded budget). See _build_investigation_thread.
    try:
        update["investigation_threads"] = _build_investigation_thread(
            state, config.config_name, messages, verdict_signals,
        )
    except Exception as e:  # noqa: BLE001 — continuity must never break a run
        node.log.warning(
            "[%s] investigation-thread build failed (%s) — skipping",
            config.agent_id, e,
        )
    # Sticky-fallback bookkeeping: if this dispatch used the fallback model
    # (rescued by it, exhausted it, or was sent straight to it), record the
    # config so its NEXT dispatch this run skips the doomed primary tier.
    if start_on_fallback or worker_last_tier == "fallback":
        update["fallback_configs"] = [config.config_name]
    if captured_flag_value is not None:
        update["captured_flag"] = captured_flag_value
        # Mirror onto submission_attempts so xbow_runner.run_one's
        # existing verdict path (which reads submission_attempts[-1])
        # sees the capture without any change to that consumer. The
        # graph terminates via the normal route_after_summarizer →
        # END path: this update's captured_flag lands in state via
        # the reducer; sibling workers exit fast via the FlagWatcher
        # callback's sibling-cancel path (see flag_watcher module
        # docstring); fan-in completes; summarizer fires;
        # route_after_summarizer reads captured_flag → END.
        update["submission_attempts"] = [captured_flag_value]
    return update
