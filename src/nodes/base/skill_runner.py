# Skill runner — turn a loaded skill config into an executing LangChain agent.
# Each worker dispatch builds the prompt, seeds cross-turn context, runs the
# create_agent loop with the refusal-retry ladder, parses findings, salvages on
# crash. AgentConfig (the input contract) lives here; loading is in skills/loader.

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
from src.nodes.base.prompt_builder import _build_system_message
from src.nodes.base.system_prompt import BENCHMARK_PROGRESS_FOOTER
from src.observability import make_run_id
from src.observability.state import _count_worker_iterations
from src.refusals.detect import looks_like_refusal
from src.refusals.recover import recover_from_refusal
from src.refusals.retry import astream_with_refusal_retry
from src.refusals.salvage import try_salvage
from src.state import AgentResult, Finding, Severity, Signal

if TYPE_CHECKING:
    from src.nodes.base import BaseNode


# ── AgentConfig — in-memory carrier produced by src.skills.loader ──


@dataclass
class AgentConfig:
    # What makes one swarm agent different from another. Skill content
    # (system_prompt + tools + caps) is parsed from SKILL.md by skills/loader.py;
    # this is the in-memory carrier the loader produces.

    agent_id: str  # unique name, e.g. "owasp-auth-testing"
    methodology: str  # "owasp" | "vulntype" | "custom" | "skill"
    config_name: str  # primary key for planner dispatch — matches skill folder
    system_prompt: str = ""  # the SKILL.md body, minus frontmatter
    tools: list[BaseTool] = field(default_factory=list)  # LangChain instances resolved from SKILL.md tool names
    max_iterations: int = 20  # worker budget in REAL tool rounds; → recursion_limit (~3 super-steps/round); fallback default only
    skip_base_prompt: bool = False  # True → skip preamble/rules/role/RAG, SKILL.md body is the whole prompt
    phase: str = "executor"  # rule bundle: "executor" (full methodology) | "recon" (universal + recon hint, no exploit blocks)


# ── Finding extraction ──
# Two parsers run per assistant message: structured **FINDING:** / ## Finding,
# then JSON {"findings": [...]} as fallback. Moved verbatim into worker/findings.py;
# re-imported here so the public API (FINDING_PATTERN / SEVERITY_MAP / _extract_findings
# / …) stays importable from src.nodes.base.skill_runner.
from src.nodes.base.worker.findings import (  # noqa: E402
    FINDING_PATTERN,
    JSON_FINDINGS_PATTERN,
    SEVERITY_MAP,
    _extract_findings,
    _findings_from_json,
    _findings_from_markdown,
)

# ── Closing-verdict parsing + specialist-refutation gate ──
# Moved verbatim into worker/verdicts.py. _extract_verdicts (used by the runner)
# and the names it builds on are re-imported here for back-compat.
from src.nodes.base.worker.verdicts import (  # noqa: E402
    VERDICT_PATTERN,
    _CLASS_ALIASES,
    _extract_verdicts,
    _norm_class,
    _redirect_class,
    _REDIRECT_CLASSES,
    _SKILL_OWNED_CLASSES,
    _VERDICT_OUTCOME,
    _worker_owns_class,
)


# ── Refusal-path primitive salvage ──
# The Codex classifier fires most often right when a worker received its most
# valuable output (dumped table, `id` line, /etc/passwd) — so a refused worker
# can lose a PROVEN primitive. This scan mints a HIGH Finding from received
# ToolMessage output only (negation-guarded), markers strongest-first.
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
    # True if marker occurs at least once without a negation cue in the ~32 chars
    # before it.
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
    # Scan a refused worker's RECEIVED tool output for a proven primitive. Returns
    # a HIGH Finding tagged with the matching primitive, or None. The worker's own
    # request text is never scanned, so a typed payload can't self-trigger.
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


# ── Worker memory: prior-attempts + web-search context injection ──
# By default a worker starts cold. These helpers seed the create_agent loop with
# a HumanMessage carrying the latest [Web Search] synthesis and a one-line summary
# of every prior tool call this agent_id made (paired by tool_call_id, not order).

# ── Curated-state seed blocks ──
# These helpers render structured state fields into markdown blocks for the
# worker's seed HumanMessage (dispatch_reason, findings, recon_summary,
# relevant_summary). Each returns None when its source is empty. Pure renderers.

_SEED_FINDINGS_TAIL = 30  # cap on findings rendered in the seed (tail); 30 covers any realistic engagement

_SEED_FINDING_EVIDENCE_CHARS = 400  # per-evidence cap in a seed line; full evidence stays in state for the planner

_SEED_RECON_SUMMARY_CHARS = 12_000  # recon summary cap — defensive only, against an unbounded summarizer


def _format_dispatch_reason(state: dict) -> str | None:
    # Render the planner's reason-for-this-dispatch as a seed block. None on the
    # cold-boot path (initialize → recon) or when no reason was recorded.
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
    # Render the last n conversion attempts on a finding as compact seed lines.
    # Empty when the finding has no attempts.
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
    # Render the cumulative findings as a seed block: every finding across the run,
    # tail-capped at _SEED_FINDINGS_TAIL. Each line carries severity, title, url,
    # category, trimmed evidence. Prefers the consolidated canonical_findings view
    # (deduped, ranked, with attempts) when available; else the raw findings log.
    canonical = state.get("canonical_findings")
    use_canonical = bool(canonical)
    findings = list(canonical) if use_canonical else list(state.get("findings") or [])
    if not findings:
        return None

    # Canonical is pre-sorted by lead_priority → take TOP N; raw log is
    # append-ordered → take most RECENT N.
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
        # A primitive carries a conversion status — surface it inline.
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
        # Conversion attempts already tried — so the worker doesn't repeat a dead method.
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
    # Render the one-time recon application map as a seed block: routes, params,
    # auth flow, framework, inferred behaviour — so the worker need not re-walk it.
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
    # Render the planner's curated investigation state (current_hypothesis,
    # ruled_out, open_questions) as a seed block. None when nothing is present.
    # Renders only keys that have content.
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
    # Render the ranked hypotheses so a worker sees the supervisor's committed
    # theory. Source: state["hypotheses"] (belief/utility-ranked by the synthesis
    # pass). Surfaces committed/supported/confirmed with belief + deciding probe.
    # None when none are actionable.
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
    # Render recent important tool outcomes for worker context.
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
    # Render the compact cross-skill context catalogue for a worker.
    try:
        from src.skills.usage import render_context_skill_index

        body = render_context_skill_index(current_skill=config_name)
    except Exception:
        return None
    body = body.strip()
    return body or None


_PRIOR_PROBE_SUMMARY_CHARS = 280  # max chars per summarized probe in the prior-attempts block

# Cap on tool-call/response pairs from prior runs of the same skill; older ones
# are summarized as a count.
_PRIOR_HISTORY_MAX_TURNS = 12

# Max chars of the latest web_search synthesis to inject. The research node returns
# payload-rich curated guidance (HackTricks / PayloadsAllTheThings); the verbatim
# payloads are the point, so the cap is generous. Tunable via env.
_WEB_SEARCH_INJECT_CHARS = int(os.getenv("SWARM_WEB_SEARCH_INJECT_CHARS", "16000"))


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
    # Return a coverage-style tool outcome, or None for routine probes.
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
            # --enumerate p can miss arbitrary plugins; full coverage needs ap/at.
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
    # Extract important tool outcomes from AI tool calls + ToolMessages.
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


# ── Per-skill investigation thread (continuity + compaction) ──
# A fresh worker context peaks ~45-87k tokens; carrying prior work forward risks
# crossing the ~120k degradation point, so the thread is compacted to a bounded
# char budget — commands kept verbatim, tool OUTPUTS shrunk to one line.
_THREAD_CHAR_BUDGET = 120_000
_RECORD_CMD_CHARS = 240
_RECORD_OUTPUT_CHARS = 200
_MAX_STEPS_PER_RUN = 40

# Cheap artifact tells worth preserving in a shrunk output summary — what actually
# decides whether a probe progressed.
_OUTPUT_TELLS = (
    "root:x:0:0", "uid=", "gid=", "flag{", "information_schema",
    "union select", "@@version", "traceback", "stack trace", "exception",
    "denied", "forbidden", "not a number", "500 internal", "200 ok",
    "302 found", "401 ", "403 ", "404 ", "no such", "syntax error",
)


def _summarize_output(output: str) -> str:
    # Shrink a tool output to one line: size + first line + decisive artifact tells.
    o = (output or "").strip()
    if not o:
        return "(no output)"
    first_line = next((ln for ln in o.splitlines() if ln.strip()), "")[:120]
    low = o.lower()
    tells = sorted({t for t in _OUTPUT_TELLS if t in low})
    tail = f"  tells={','.join(tells[:5])}" if tells else ""
    return f"[{len(o)}b] {first_line}{tail}"[:_RECORD_OUTPUT_CHARS]


def _compact_run_record(messages: list, verdict_signals: list) -> str:
    # Compact record of ONE dispatch: each command verbatim, its output shrunk to
    # one line, then the closing verdict. The unit the continuity thread accumulates.
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
    # Append this dispatch's compacted record to the skill's thread, bump its run
    # count, trim oldest runs until under the char budget. Returns the single-key
    # update for state['investigation_threads'].
    prior = (state.get("investigation_threads") or {}).get(config_name) or {}
    run_count = int(prior.get("run_count", 0)) + 1
    runs = [str(r) for r in (prior.get("runs") or [])]
    runs.append(_compact_run_record(messages, verdict_signals))
    # Drop oldest runs (keep ≥ current) until under budget.
    while len(runs) > 1 and sum(len(r) for r in runs) > _THREAD_CHAR_BUDGET:
        runs.pop(0)
    return {config_name: {"run_count": run_count, "runs": runs}}


def _collect_prior_skill_history(state: dict, agent_id: str) -> str | None:
    # Return the previous summarizer report for this agent_id, or None. Since the
    # worker → summarizer hand-off, raw AIMessages no longer enter state['messages']
    # — only the structured worker_report does, so we look up the most recent one.
    # See src.llm.digest.find_prior_worker_report.
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
    # Render this skill's own compacted cross-dispatch history as a seed block (with
    # run count) so a re-dispatched worker CONTINUES instead of starting fresh.
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
    # Return the most recent [Web Search] AIMessage content, truncated to
    # _WEB_SEARCH_INJECT_CHARS, or None. The web_search node prefixes its synthesis
    # with a literal [Web Search] marker.
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
    # No-op shim — worker traces are no longer mirrored to disk (the old
    # worker_traces.jsonl was redundant with full_logs.jsonl). Kept as a function
    # so call sites need no conditional; returns None.
    del trace, run_id, agent_id  # explicitly unused
    return None


# ── The runner ──
# run_skill_agent is the entire worker lifecycle: build the prompt, seed context,
# run the agent loop with refusal retries, parse findings, salvage on crash.
# BaseNode.run_skill_agent is a thin async wrapper that forwards here.


async def run_skill_agent(
    node: "BaseNode",
    config: AgentConfig,
    state: dict,
    llm: BaseChatModel | None = None,
) -> dict:
    # Public entry point. Thin wrapper around _run_skill_agent_impl that guarantees
    # per-worker shell cleanup runs in a finally — otherwise each worker leaks its
    # tmux session + bash subprocess in the ShellManager until atexit.
    try:
        return await _run_skill_agent_impl(node, config, state, llm)
    finally:
        # Best-effort per-worker shell cleanup. Never raise from the finally — a
        # cleanup failure must not mask a successful return or a real exception.
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
    # Run a create_agent loop with the given skill config. Returns the standard
    # worker-node update dict (messages / agent_results / findings / active_agents).
    # node supplies node.log, node.name, node.ask_focused. Called only via
    # run_skill_agent (which adds the shell-cleanup finally).
    if llm is None:
        from src.llm.provider import get_llm  # lazy — see module docstring
        llm = get_llm()

    target_url = state.get("target_url", "")

    # Build the system message with the phase-appropriate rule bundle. The old
    # benchmark flag-criterion addendum was removed (2026-05-14) as the strongest
    # cyber_policy trigger; the planner owns flag submission. is_benchmark gates
    # the BENCHMARK_GUIDANCE addendum (executor-only).
    is_benchmark = bool(
        (state or {}).get("expected_flag")
        or (state or {}).get("expected_flag_candidates")
    )
    system_msg = _build_system_message(
        config, target_url, is_benchmark=is_benchmark,
    )

    # Agent construction is deferred to _agent_factory below so tier-2 refusal-retry
    # can rebuild it with a vocab-filtered prompt without losing this call's wiring.

    # Seed the loop with cross-turn context as a single HumanMessage. Order matters
    # for focus + prompt caching: stable/heavy first (skill_catalogue, findings,
    # recon), volatile state next, the concrete assignment last. Each helper returns
    # None when empty, so cold first dispatches start cold (back-compat).
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

    # Benchmark status footer — appended LAST so it's the final thing the worker
    # reads. Capture is static (FlagWatcher ends the run on the real token), so this
    # keeps a worker from concluding early. Mirrors the planner footer.
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
    # Resolve run_id once so every LLM call logs into the same llm_calls.jsonl and
    # the salvage path knows where to write.
    run_id = (state or {}).get("run_id") or make_run_id(
        target_url=target_url,
    )
    # call_config carries callbacks (token logger + optional flag watcher), metadata
    # (agent_id/run_id/node), and the recursion_limit budget. In benchmark mode the
    # FlagWatcherCallback hooks on_tool_end and raises FlagCapturedSignal the instant
    # a tool returns the expected flag — short-circuiting before the next LLM call.
    from src.nodes.base.flag_watcher import FlagWatcherCallback
    # Pass the full candidate set to the watcher — benchmarks can legitimately have
    # multiple expected values. Falls back to the single expected_flag field.
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
    # max_iterations is the budget in REAL tool rounds; LangGraph's recursion_limit
    # counts super-steps (~3/round: nudge before_model + model + tools). Convert
    # rounds → super-steps (3*rounds + 1) so config, budget, and
    # _count_worker_iterations all speak in real-round units.
    recursion_limit = config.max_iterations * 3 + 1
    call_config = make_call_config(
        run_id=run_id,
        agent_id=config.agent_id,
        node=node.name,
        recursion_limit=recursion_limit,
        extra_callbacks=worker_callbacks or None,
    )

    # Stream (not ainvoke) so a partial snapshot survives crashes: stream_mode=
    # "values" yields full-state snapshots, we keep the latest. On GraphRecursionError
    # last_snapshot holds messages up to the last step — what salvage consumes. The
    # agent is rebuilt inside the retry helper (vocab-filter / tier-2 swap).
    #
    # The no-progress nudge middleware (shared across primary + fallback factories)
    # fires only on byte-identical tool outputs and only re-surfaces existing
    # DIVERSITY_RULES guidance — it never stops the worker.
    from src.nodes.base.prompt_builder import NoProgressNudgeMiddleware
    _no_progress_mw = NoProgressNudgeMiddleware(
        agent_id=config.agent_id, log=node.log,
    )
    # Ablation: the nudge re-injects DIVERSITY_RULES / TRANSFORMATION_HYPOTHESIS in
    # loop, so it IS a dynamically-delivered prompting technique. When prompting
    # techniques are ablated, drop it too, else a stuck worker is still rescued by
    # the exact guidance the ablation removes. Read via module object (import cycle).
    from src import graph as _graph_module
    _prompting_off = bool(getattr(
        getattr(_graph_module.config, "capability", None),
        "disable_prompting_techniques", False,
    ))
    _middleware = [] if _prompting_off else [_no_progress_mw]

    # Per-dispatch progressive-disclosure tool: when this skill ships reference files,
    # bind a scoped read_reference tool. Wrapped defensively — reference wiring must
    # never break a run.
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
            middleware=_middleware,
        )

    # Tier-2 fallback factory — only wired when the primary provider is Codex
    # (model-swap to gpt-5.4 isn't meaningful for other routes). See
    # src/refusals/retry.py for the tier ladder and config.budgets.fallback_* knobs.
    from src.llm.provider import LLMConfig as _LLMConfig
    from src.llm.provider import Provider as _Provider
    fallback_factory: Any = None
    _fallback_model: str | None = None
    _fallback_effort: str | None = None
    _primary_cfg = _LLMConfig()
    if _primary_cfg.provider == _Provider.CODEX:
        # Lazy import — skill_runner is imported transitively from src.graph
        # during init, so a top-level import would re-enter while config is still
        # binding. Read via the module object at call-time.
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
                middleware=_middleware,
            )

        fallback_factory = _fallback_agent_factory

    last_snapshot: dict | None = None
    worker_attempts = 0
    worker_last_tier = "primary"
    flag_watcher_capture: str | None = None
    sibling_captured_value: str = ""

    # Sticky fallback: if this config's prompt already tripped the primary's
    # cyber_policy classifier this run, start on the fallback model — the primary
    # would refuse again, wasting 3 retries. (No-op when no fallback is wired.)
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
        # Inner try catches the FlagWatcher's short-circuit signals so they don't
        # reach the outer except (mis-classified as refusals). FlagCapturedSignal:
        # THIS worker matched → synthesise a ToolMessage for the auto-verify scan.
        # SiblingCapturedSignal: another worker won → exit clean, don't set captured_flag.
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
            # Append a synthetic ToolMessage with the captured value to the partial
            # snapshot — the downstream auto-verify scan expects exactly this. The
            # snapshot is partial because FlagWatcher raises in on_tool_end, before
            # LangGraph yields the next snapshot; this bridges the gap.
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
            # Sibling captured first; exit with an empty update so fan-in completes.
            # Routing reads state.captured_flag (set by the winner) — not touched here.
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

        # If the FlagWatcher fired, synthesise a CRITICAL Finding so the worker
        # reports 1 finding, not 0. Capture itself routes via captured_flag; this is
        # the human-readable companion.
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

        # Mirror the inner agent trace to the parent so Studio chat shows every tool
        # call + response inline; otherwise the conversation is hidden in the
        # create_agent sub-graph and the parent looks frozen.
        trace = [m for m in messages if isinstance(m, (AIMessage, ToolMessage))]
        for m in trace:
            # Tag each message with agent_id so consumers can group/filter by agent.
            try:
                m.additional_kwargs.setdefault("agent_id", config.agent_id)
            except Exception:
                pass

        # Refusal detection — if 0 findings AND the last assistant message reads like
        # a safety refusal, surface it explicitly instead of swallowing it as "0
        # findings". Skipped when sibling_captured_value is set (clean early exit, not
        # a refusal — treating it as one would trigger a needless recovery sub-call).
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
                # Treat as not-refused so completed=True and the planner sees the
                # suggestion as actionable evidence.
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

        # Sibling-cancelled workers are a clean cooperative exit, not a refusal or
        # crash — surface on a distinct error channel so triage can tell "tried and
        # failed" from "stood down because another worker won".
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
        # Rate-limit (429) / quota errors are NOT salvageable — this run never got a
        # fair attempt, so re-raise to abort; xbow_runner marks it crashed and the
        # usage guard pauses the sweep. Everything else keeps the salvage path below.
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

        # The refusal-retry ladder tags the exception with the tier it reached. On a
        # terminal refusal the tuple-unpack never ran, so recover the real tier here
        # so the sticky-fallback record fires when the fallback was exhausted too.
        worker_last_tier = getattr(e, "_swarm_last_tier", worker_last_tier)

        # Cyber-policy / invalid-prompt failures from Codex are refusals, not crashes.
        # Surface on error="model refused" so the planner can pivot, and try a focused
        # recovery sub-call in case the agent made usable probes before the API
        # rejected the next request. Lazy import for the planner/executor import dance.
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

        # Pull whatever messages survived the crash into the trace so the chat /
        # nodes.jsonl still show what the worker did. On a terminal refusal / budget
        # stop / crash the tuple-unpack never ran, so last_snapshot is None — recover
        # the richest partial trace the retry helper attached to the exception.
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
            # Refusal-time flag salvage: Codex can refuse mid-run after the worker
            # already executed tool calls, one of whose responses may hold a captured
            # flag{...}. Without this the refusal branch wipes findings and the planner
            # never learns the worker won (XBEN-006-24, 2026-05-09). Lazy import.
            findings = []
            try:
                from src.edges.flag_match import extract_flags

                # Stringify partial messages inline. The old src.flag helper was
                # deleted in the 2026-05 refactor; salvage still scans a refused
                # worker's partial trace, so the stringifier lives here now.
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
                    # Short evidence excerpt around the match so a human can eyeball
                    # the request that produced it.
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
                # Salvage must never make the refusal path worse; log and fall through.
                node.log.warning(
                    "[%s] refusal-path flag salvage failed: %s: %s",
                    config.agent_id,
                    type(salv_err).__name__,
                    str(salv_err)[:160],
                )

            # Refusal-path PRIMITIVE salvage: if no flag, the worker may still have
            # PROVEN a non-flag capability in the refused output. Mint a HIGH primitive
            # finding so the planner can drive it to the flag later. Scans received
            # tool output only, negation-guarded; never raises.
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
                # If we salvaged a flag, treat the worker as completed for planner
                # accounting — its contribution was real despite the API rejection.
                completed=bool(findings),
                error="model refused" if not findings else None,
            )
        elif (
            "recursion limit" in str(e).lower()
            or type(e).__name__ == "GraphRecursionError"
        ):
            # ── Step-budget stop (NOT a crash) ──
            # The worker exhausted its recursion_limit; the model is still reachable,
            # it just ran out of turns. So no post-crash salvage guesser. Instead:
            # recover the FINDING blocks already written, then make ONE forced wrap-up
            # call. See src/nodes/base/prompt_builder.py.
            node.log.warning(
                "[%s] reached its step budget (%s) — forcing a graceful "
                "wrap-up instead of discarding the run.",
                config.agent_id, str(e)[:160],
            )
            from src.nodes.base.prompt_builder import force_wrapup_summary

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
            # Dedup by (title, url) — the worker often re-emits in the wrap-up a
            # finding it already wrote in the trace.
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
                # Informative but NOT "model refused", so the planner's refusal/
                # repetition logic doesn't mis-handle it. A budget stop is a real
                # completed pass — count it as a turn.
                error="stopped at step budget",
                completed=True,
            )
        else:
            node.log.error(f"Agent {config.agent_id} failed: {e}")
            # Genuine crash — not a refusal or budget stop (tool blew up, transport
            # error, unexpected exception). The trace may hold impact the worker never
            # formalized, so fall back to the post-crash salvage guesser (one bounded
            # sub-LLM call, returns None on failure). See src/refusals/salvage.py.
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
                # A salvaged finding lets the planner act, so completed=True so the
                # repetition detector counts it as a real turn.
                completed=bool(salvaged),
            )

    # Persist the full trace to disk for forensics — the planner never reads it
    # directly; the summarizer consumes the in-memory trace via pending_summary_inputs.
    # Primarily for human debugging after the run.
    trace_path = _persist_worker_trace(
        trace=trace,
        run_id=run_id,
        agent_id=config.agent_id,
    )

    # Resolve the dispatch reason from state (set by the planner, forwarded through
    # the routing edge). Empty for cold runs — the summarizer handles that gracefully.
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

    # The worker's effective system prompt (after the preventive vocab filter the
    # retry helper always applies). Propagated into summary_input so the summariser
    # replays it byte-identically for a prompt-cache hit. filter_text is deterministic.
    # Lazy import to avoid a cycle through src.refusals at load.
    from src.refusals.vocabulary import (
        filter_messages as _filter_messages,
        filter_text as _filter_text,
    )
    worker_system_prompt_used, _ = _filter_text(system_msg)
    worker_seed_msgs_used, _ = _filter_messages(seed_msgs)

    # Reconstruct the exact worker conversation prefix for the summarizer: filtered
    # seed message(s) + the AI/Tool trace. Prefer the full snapshot (it includes
    # middleware-injected notes); append synthetic wrap-up/salvage messages added after.
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

    # The summary input the SummarizerNode consumes. Each parallel worker writes a
    # singleton list; _summary_inputs_reducer accumulates them so the summarizer (the
    # fan-out sync point) sees one entry per worker.
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
        # Keep the summarizer request cache-compatible with the worker: Codex's
        # prompt cache includes tool schemas, so replaying with tools removed misses it.
        "summary_tools": list(_run_tools),
        # The exact system prompt the worker's LLM saw — so the summariser shares
        # the worker's cached prefix.
        "worker_system_prompt": worker_system_prompt_used,
    }
    if worker_last_tier == "fallback" and _fallback_model:
        summary_input["summary_model"] = _fallback_model
        summary_input["summary_reasoning_effort"] = _fallback_effort or "low"

    # ── Success-path flag auto-verification ──
    # In benchmark mode, scan the worker's tool messages for flag{...} and strict-
    # equal them against expected_flag. On a match, surface via state.captured_flag
    # (terminates the graph) and push onto submission_attempts (xbow_runner's verdict).
    # Strict equality is the false-positive filter; in real-pentest mode this is a no-op.
    captured_flag_value: str | None = None
    expected_flag = (state or {}).get("expected_flag") or ""
    # Full candidate set the matcher accepts — benchmarks can have multiple legitimate
    # values. Falls back to the single expected_flag (back-compat).
    expected_flag_candidates: tuple[str, ...] = tuple(
        (state or {}).get("expected_flag_candidates") or ()
    )
    if not expected_flag_candidates and expected_flag:
        expected_flag_candidates = (expected_flag,)
    # Counters that always end up in the auto-verify event, so post-mortem can see
    # "scanned N messages, K candidates, matched 0" without re-reading the trace.
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
                # ToolMessage content can be a list of content blocks — flatten to text.
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

    # Structured record of the scan — fires whether or not we matched, so post-mortem
    # can answer "did the scan run?" with one jq query. The 2026-05-25 XBEN-006-24
    # incident: workers had the flag in output but no artefact recorded whether the
    # scan matched, so detection vs routing was ambiguous.
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

    # Build the worker digest now, while the prompt prefix is still hot in the provider
    # cache, instead of waiting for the slowest sibling at the fan-in barrier. Skip
    # LLM digesting on capture/cancel paths so a solved benchmark isn't delayed.
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
        # NOTE: no "messages": trace — that caused the global-prompt explosion. The
        # trace stays on disk and in pending_summary_inputs[*].trace until the
        # SummarizerNode replaces it with one AIMessage digest.
        "pending_summary_inputs": [summary_input],
        "agent_results": [agent_result],
        "findings": findings,
        "active_agents": [config.agent_id],
    }
    if verdict_signals:
        # The worker's closing self-assessment — deciding-probe feedback that lets the
        # synthesis pass recalibrate belief (confirm crosses COMMIT, refute drives down).
        # See _extract_verdicts.
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
    # Continuity: append this dispatch's compacted record to the skill's investigation
    # thread so the NEXT dispatch continues instead of re-deriving. See _build_investigation_thread.
    try:
        update["investigation_threads"] = _build_investigation_thread(
            state, config.config_name, messages, verdict_signals,
        )
    except Exception as e:  # noqa: BLE001 — continuity must never break a run
        node.log.warning(
            "[%s] investigation-thread build failed (%s) — skipping",
            config.agent_id, e,
        )
    # Sticky-fallback bookkeeping: if this dispatch used the fallback model, record the
    # config so its NEXT dispatch this run skips the doomed primary tier.
    if start_on_fallback or worker_last_tier == "fallback":
        update["fallback_configs"] = [config.config_name]
    if captured_flag_value is not None:
        update["captured_flag"] = captured_flag_value
        # Mirror onto submission_attempts so xbow_runner's verdict path (reads [-1])
        # sees the capture unchanged. The graph terminates via the normal route_after_
        # summarizer → END path: captured_flag lands via the reducer, siblings exit fast,
        # fan-in completes, summarizer fires, routing reads captured_flag → END.
        update["submission_attempts"] = [captured_flag_value]
    return update
