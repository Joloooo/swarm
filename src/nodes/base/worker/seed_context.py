# Worker memory: prior-attempts + web-search context injection.
# By default a worker starts cold. These helpers seed the create_agent loop with
# a HumanMessage carrying the latest [Web Search] synthesis and a one-line summary
# of every prior tool call this agent_id made (paired by tool_call_id, not order).
#
# ── Curated-state seed blocks ──
# These helpers render structured state fields into markdown blocks for the
# worker's seed HumanMessage (dispatch_reason, findings, recon_summary,
# relevant_summary). Each returns None when its source is empty. Pure renderers.

from __future__ import annotations

import os

from langchain_core.messages import AIMessage


_SEED_FINDINGS_TAIL = 30  # cap on findings rendered in the seed (tail); 30 covers any realistic engagement

_SEED_FINDING_EVIDENCE_CHARS = 400  # per-evidence cap in a seed line; full evidence stays in state for the planner

_SEED_RECON_SUMMARY_CHARS = 12_000  # recon summary cap — defensive only, against an unbounded summarizer


def _format_dispatch_reason(state: dict, steer_off: bool = False) -> str | None:
    # Render the planner's reason-for-this-dispatch as a seed block. None on the
    # cold-boot path (initialize → recon) or when no reason was recorded.
    #
    # The reason itself is plumbing — the hypothesis / lead the planner is handing
    # off — and always stays. The "treat it as your primary objective / do not
    # pivot" wrapper is run-state STEERING (it tells the worker what to prioritise
    # this turn), so it drops under disable_steering_directives — mirroring how the
    # planner drops its own steering SYSTEM NOTEs while keeping the evidence digest.
    reason = (state.get("dispatch_reason") or "").strip()
    if not reason:
        return None
    intro = "The supervisor picked you for this turn based on the state below."
    if not steer_off:
        intro += (
            " Treat the hypothesis as your primary objective; if the "
            "evidence you gather contradicts it, surface that in your "
            "report — do not silently pivot."
        )
    return f"## Why you were dispatched\n\n{intro}\n\n{reason}"


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


def _format_hypotheses(state: dict, steer_off: bool = False) -> str | None:
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

    intro = (
        "Observations from across the swarm have been fused into these "
        "theories, scored by how strongly the evidence supports them."
    )
    # "run its deciding probe before broadening" is the worker-side echo of the
    # planner's committed-hypothesis steering directive (gated there by
    # disable_steering_directives); drop it under the same flag. The ranked
    # hypothesis rows themselves are plumbing and always stay.
    if not steer_off:
        intro += (
            " The top one is the supervisor's committed line — run its "
            "deciding probe before broadening."
        )
    return (
        "## Leading hypotheses (ranked by the supervisor)\n\n"
        + intro + "\n\n"
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
