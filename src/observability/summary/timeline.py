"""Per-node detail-section renderers for ``summary.md``.

Every node row in ``nodes.jsonl`` becomes a collapsible ``<details>``
block in the summary. Different node types render slightly differently:

  * ``planner``        → :func:`_render_planner_node` — decision JSON,
                         reasoning, no tool-call grouping (planner has
                         no shell tools).
  * ``executor`` /
    ``recon`` /
    ``web_search``     → :func:`_render_worker_node` — full layered view:
                         dispatch info → summarizer's compressed report
                         → grouped tool calls → reasoning chain →
                         findings emitted.
  * ``summarizer``     → :func:`_render_summarizer_node` — minimal
                         acknowledgement; the actual reports live
                         inside each worker's section.
  * ``report``         → :func:`_render_report_node` — final report
                         text inline (it IS the user-facing artefact).
  * everything else    → :func:`_render_simple_node` — title + summary
                         line for ``initialize`` and any future node
                         type.

The dispatcher :func:`_render_node_section` picks the right renderer
based on ``node_row['node']``.

Tool-call grouping (``_classify_tool_call`` /
``_extract_tool_call_summary`` / ``_group_tool_calls`` /
``_render_tool_call_groups``), reasoning-chain extraction
(``_extract_reasoning_chain`` / ``_render_reasoning_chain``), and the
summarizer-report index (``_index_summarizer_reports`` /
``_consume_summarizer_report``) all live here too because they are
used only by the per-node renderers.

The full per-node transcript (every AIMessage + ToolMessage) is NOT
rendered here. It lives on disk in ``nodes.jsonl`` row N →
``.delta.messages_added_full`` and the renderers point at it instead.
Two reasons: (1) raw-mode readers (``cat summary.md``) get overwhelmed
by 36 KB collapsibles they can't actually collapse; (2) the JSONL is
the source-of-truth safety layer — duplication adds bytes without
adding information.
"""

from __future__ import annotations

import json
import re
from typing import Any

from src.observability.summary._helpers import (
    _details,
    _fmt_bytes_short,
    _fmt_dur_ms,
    _fmt_tokens_short,
    _llm_calls_for_node,
    _md_code_block,
    _md_escape_pipe,
    _pair_llm_calls,
)
from src.observability.summary.findings import _render_finding_md


# ── LLM call rendering (per-node "Calls" sub-section) ───────────────────


def _render_request_block(request: dict) -> str:
    """Render the LLM request body (system + messages + tools) collapsed."""
    if not request:
        return ""
    lines: list[str] = []
    sysp = request.get("system_prompt") or ""
    if sysp:
        lines.append("**System prompt**")
        lines.append("")
        lines.append(_md_code_block(str(sysp)[:8000]
                                    + ("\n…[truncated]" if len(str(sysp)) > 8000 else "")))
        lines.append("")
    msgs = request.get("messages") or []
    if msgs:
        lines.append(f"**Conversation messages ({len(msgs)})**")
        lines.append("")
        for i, m in enumerate(msgs[-12:], 1):  # last 12 keeps it readable
            role = m.get("role") or "?"
            content = m.get("content") or ""
            if isinstance(content, list):
                content = json.dumps(content, default=str, ensure_ascii=False)
            content = str(content)
            preview = content[:1200] + ("\n…[truncated]" if len(content) > 1200 else "")
            lines.append(f"_{i}. {role}_")
            lines.append("")
            lines.append(_md_code_block(preview))
            lines.append("")
    return "\n".join(lines).rstrip()


def _render_llm_call(call: dict, idx: int) -> str:
    """Render one LLM call (start+end paired) as a markdown bullet with
    a nested ``<details>`` containing the request prompt."""
    model    = call.get("model") or "?"
    duration = _fmt_dur_ms(call.get("duration_ms"))
    in_t     = _fmt_tokens_short(call.get("input_tokens"))
    out_t    = _fmt_tokens_short(call.get("output_tokens"))
    think_t  = _fmt_tokens_short(call.get("reasoning_tokens"))
    err      = call.get("error")

    head_bits = [
        f"**Call {idx}** — `{model}`",
        f"in={in_t} out={out_t} think={think_t}",
        f"({duration})",
    ]
    if err:
        head_bits.append(f"❌ {err}")

    parts = [f"- {' · '.join(head_bits)}"]

    request_md = _render_request_block(call.get("request") or {})
    if request_md:
        # Indent the <details> block by 2 spaces so it nests under the
        # bullet in markdown rendering.
        details = _details("Request prompt", request_md)
        indented = "\n".join("  " + ln for ln in details.splitlines())
        parts.append(indented)

    return "\n".join(parts)


def _render_tool_call_from_msg(msg: dict, idx: int) -> str:
    """Render a ToolMessage entry from delta.messages_added_full."""
    name = msg.get("name") or "tool"
    content = str(msg.get("content") or "")
    chars = len(content)
    first = ""
    for ln in content.splitlines():
        if ln.strip():
            first = ln.strip()[:140]
            break
    parts = [f"- **#{idx}** `{name}` — {_fmt_bytes_short(chars)}"]
    if first:
        parts.append(f"  - first line: `{_md_escape_pipe(first)}`")
    if content:
        parts.append("  " + _details(
            "Full output",
            _md_code_block(content[:20_000]
                           + ("\n…[truncated]" if len(content) > 20_000 else "")),
        ).replace("\n", "\n  "))
    return "\n".join(parts)


def _render_assistant_block_from_msg(msg: dict, idx: int) -> str:
    """Render an AIMessage entry — content + reasoning_summary + tool_calls."""
    content = str(msg.get("content") or "")
    addl = msg.get("additional_kwargs") or {}
    reasoning = str(addl.get("reasoning_summary") or "")
    tool_calls = msg.get("tool_calls") or []

    parts = [f"- **#{idx}** assistant"]
    if content.strip():
        # Strip the boundary checkmarks the BaseNode wrapper adds.
        if content.startswith(("✅ [", "❌ [")):
            parts[0] += f" — _{content.splitlines()[0]}_"
        else:
            preview = content.strip().splitlines()[0][:120]
            parts[0] += f" — {_md_escape_pipe(preview)}"
            parts.append("  " + _details(
                "Full content", _md_code_block(content),
            ).replace("\n", "\n  "))
    if tool_calls:
        names = ", ".join(
            f"`{tc.get('name', '?')}`" for tc in tool_calls[:4]
        )
        parts.append(f"  - tool calls: {names}"
                     + (f" (+{len(tool_calls) - 4} more)"
                        if len(tool_calls) > 4 else ""))
    if reasoning:
        parts.append("  " + _details(
            "Reasoning summary",
            f"> {reasoning[:8000]}"
            + ("\n\n…[truncated]" if len(reasoning) > 8000 else ""),
        ).replace("\n", "\n  "))
    return "\n".join(parts)


# ── Tool-call grouping ────────────────────────────────────────────────────
#
# Patterns are evaluated TOP-FIRST; first regex match wins. Tune by
# adding entries when a real run mis-groups. The fallback bucket is
# "Other" and renders one line per command so nothing disappears
# silently.

_TOOL_CALL_PATTERN_TABLE: tuple[tuple[str, str], ...] = (
    ("SQLi probes",        r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*--|''\s*or|sqlmap|or\s+'1'\s*=\s*'1)"),
    ("SQLi-shaped JSON",   r"(?i)(job_type|payload|variants?\s*=\s*\[)"),
    ("Surface mapping",    r"(?i)(curl[^|]*?\s(/|/index|/robots\.txt|/sitemap\.xml|/favicon\.ico|/openapi\.json|/docs|/redoc|/health|/healthz|/ping))"),
    ("Directory enum",     r"(?i)(gobuster|dirb|wfuzz|ffuf|dirsearch)"),
    ("Tech fingerprint",   r"(?i)(whatweb|wappalyzer|nikto|httpx|nmap)"),
    ("HTTP method probes", r"(?i)(curl[^|]*-X\s+(GET|PUT|DELETE|PATCH|OPTIONS|HEAD)\b)"),
    ("Source recovery",    r"(?i)(ps\s+-ef|pgrep|lsof|os\.walk|find\s+\S+\s+-name|grep\s+-r|rg\s+-)"),
    ("Workspace mining",   r"(swarm-workspace|sed\s+-n.*\.(py|txt|json|sh|md))"),
    ("Docker introspect",  r"(?i)(docker\s+(ps|inspect|exec|logs|compose))"),
    ("Generic curl",       r"(?i)\bcurl\b"),
    ("Python one-liner",   r"python3?\s+-\s*<<'?PY'?"),
    ("Shell pipeline",     r"\|\s*(grep|awk|sed|jq|head|tail|sort|uniq)"),
)


def _classify_tool_call(tool_name: str, command: str) -> str:
    """Return the group label for a tool call.

    Bash-style tools (``bash``, ``shell``, ``run_command``) get
    classified by regex over their ``args.command``. Other tools
    (``fetch_page``, ``whatweb``, ``nikto``, ``crawler``, ...) are
    classified by the tool name itself — the recon node in particular
    uses dedicated tools rather than raw bash, and grouping by tool
    name gives a cleaner read than trying to regex over their
    ``args``.
    """
    bash_like = tool_name.lower() in (
        "bash", "shell", "run_command", "tmux", "exec",
    )
    if bash_like and command:
        for label, pattern in _TOOL_CALL_PATTERN_TABLE:
            try:
                if re.search(pattern, command):
                    return label
            except re.error:
                continue
        return "Other"
    # Non-bash tools: prettify the tool name into a group label.
    # ``fetch_page`` → ``fetch_page``; ``whatweb`` → ``whatweb``;
    # falling back to "Other" for unnamed tools.
    if tool_name:
        return f"`{tool_name}`"
    return "Other"


def _extract_tool_call_summary(tc: dict) -> str:
    """Best-effort one-line representation of a tool call's intent.

    For bash: the command string itself. For HTTP fetchers: the
    ``url`` argument. For search tools: the ``query``. Falls back to
    a JSON dump of args trimmed to ~150 chars so something always
    surfaces.
    """
    args = tc.get("args") or {}
    if not isinstance(args, dict):
        return str(args)[:300]
    for key in ("command", "cmd", "url", "query", "input", "target"):
        v = args.get(key)
        if isinstance(v, str) and v.strip():
            return v[:300]
    # Last resort — JSON dump minus the noisy reasoning/agent_id keys.
    trimmed = {
        k: v for k, v in args.items()
        if k not in ("reasoning", "agent_id") and isinstance(v, (str, int, float, bool))
    }
    if trimmed:
        return json.dumps(trimmed, default=str, ensure_ascii=False)[:300]
    return "(no args)"


def _group_tool_calls(msgs_added: list[dict]) -> list[dict]:
    """Walk a node's added messages, classify each tool call, and return
    a list of consecutive-same-label *groups*.

    Output: list of ``{label, count, samples}`` dicts where ``samples``
    holds up to 3 representative ``{cmd, exit_marker, bytes, agent_id}``
    entries. The grouping is intentionally cheap — it's a heuristic on
    bash command patterns — and is preserved across the message stream
    in original order. Adjacent groups with the same label merge.

    Tool calls are paired with their preceding AIMessage's
    ``tool_calls[*]`` entry by ``tool_call_id`` so we can read the
    command string the model actually issued (the ToolMessage only
    carries the *output*).
    """
    intent_by_id: dict[str, tuple[str, str, str]] = {}
    for m in msgs_added:
        if m.get("role") != "assistant":
            continue
        for tc in (m.get("tool_calls") or []):
            tcid = tc.get("id") or ""
            tool_name = str(tc.get("name") or "")
            summary = _extract_tool_call_summary(tc)
            args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
            reasoning = args.get("reasoning") if isinstance(args, dict) else ""
            if tcid:
                intent_by_id[tcid] = (tool_name, summary, str(reasoning or ""))

    groups: list[dict] = []
    cur: dict | None = None
    for m in msgs_added:
        if m.get("role") != "tool":
            continue
        tcid = m.get("tool_call_id") or ""
        tool_name, cmd, reasoning = intent_by_id.get(
            tcid, (str(m.get("name") or ""), "", ""),
        )
        label = _classify_tool_call(tool_name, cmd)

        # Extract exit marker (e.g. "exit=0", "exit=127", "[TIMEOUT...]")
        # from the tool output for the per-group sample line. The shell
        # wrapper appends a "[exit=N | cwd=...]" tag at the end of every
        # output; we just grep for it.
        content = str(m.get("content") or "")
        exit_marker = ""
        em = re.search(r"\[(?:exit=\-?\d+|TIMEOUT[^\]]*)[^\]]*\]", content)
        if em:
            exit_marker = em.group(0)[:48]

        sample = {
            "cmd": cmd[:300] if cmd else "(no command captured)",
            "reasoning": reasoning[:200] if reasoning else "",
            "exit_marker": exit_marker,
            "bytes": len(content),
        }
        if cur is None or cur["label"] != label:
            if cur is not None:
                groups.append(cur)
            cur = {"label": label, "count": 0, "samples": []}
        cur["count"] += 1
        if len(cur["samples"]) < 3:
            cur["samples"].append(sample)
    if cur is not None:
        groups.append(cur)
    return groups


def _render_tool_call_groups(groups: list[dict]) -> str:
    """Render the grouped-tool-calls list as a markdown bullet list.

    One bullet per group, with the group label in bold, the count, and
    a sample line. ``Other`` groups are rendered as one bullet *per*
    sample (since they're singleton-ish by definition) so nothing
    disappears.
    """
    if not groups:
        return ""
    lines: list[str] = []
    for g in groups:
        label = g["label"]
        count = g["count"]
        samples = g["samples"]
        if label == "Other":
            for s in samples:
                cmd_preview = s["cmd"].replace("\n", " ⏎ ")[:120]
                tail = f" — {s['exit_marker']}" if s["exit_marker"] else ""
                lines.append(f"- `{cmd_preview}`{tail}")
            continue
        head = f"- **{label}** × {count}"
        if samples:
            first = samples[0]
            cmd_preview = first["cmd"].replace("\n", " ⏎ ")[:100]
            tail = f" → {first['exit_marker']}" if first["exit_marker"] else ""
            lines.append(f"{head}  \n  e.g. `{cmd_preview}`{tail}")
        else:
            lines.append(head)
    return "\n".join(lines)


# ── Reasoning-chain extraction ──────────────────────────────────────────


def _extract_reasoning_chain(msgs_added: list[dict]) -> list[str]:
    """Pull each AIMessage's reasoning_summary in order.

    Empty list when no message carried reasoning — that's normal for
    providers without chain-of-thought (or when ``SWARM_REASONING_SUMMARY``
    is set to ``none``). The summaries themselves can run multiple
    paragraphs each; we don't truncate here — the renderer wraps them
    in a collapsed ``<details>`` so length is tolerable.
    """
    out: list[str] = []
    for m in msgs_added:
        if m.get("role") != "assistant":
            continue
        akw = m.get("additional_kwargs") or {}
        summary = akw.get("reasoning_summary")
        if isinstance(summary, str) and summary.strip():
            out.append(summary.strip())
    return out


def _render_reasoning_chain(chain: list[str]) -> str:
    """Render the reasoning chain as a numbered list inside a ``<details>``."""
    if not chain:
        return ""
    items = []
    for i, thought in enumerate(chain, 1):
        # Indent multi-paragraph thoughts so they nest under the bullet.
        indented = thought.replace("\n", "\n   ")
        items.append(f"{i}. {indented}")
    body = "\n".join(items)
    return _details(f"{len(chain)} thoughts · click to expand", body)


# ── Summarizer-output index ─────────────────────────────────────────────


def _index_summarizer_reports(nodes: list[dict]) -> dict[str, list[dict]]:
    """Scan ALL nodes for summarizer ``worker_report`` AIMessages and
    index them by ``agent_id``.

    The summarizer node fires after each worker batch and emits one
    AIMessage per worker with ``additional_kwargs.kind ==
    "worker_report"`` and ``additional_kwargs.agent_id ==
    <worker_agent_id>``. Per-worker rendering looks up the matching
    report and includes its content as the "Summary" section.

    Returns a dict mapping agent_id → list of report dicts (in
    chronological order, since one worker can run multiple times in a
    run).
    """
    by_agent: dict[str, list[dict]] = {}
    for n in nodes:
        if (n.get("node") or "") != "summarizer":
            continue
        for m in (n.get("delta") or {}).get("messages_added_full") or []:
            if m.get("role") != "assistant":
                continue
            akw = m.get("additional_kwargs") or {}
            if akw.get("kind") != "worker_report":
                continue
            agent_id = str(akw.get("agent_id") or "")
            if not agent_id:
                continue
            by_agent.setdefault(agent_id, []).append(m)
    return by_agent


def _consume_summarizer_report(
    by_agent: dict[str, list[dict]],
    agent_id: str,
) -> str | None:
    """Pop the *next* (oldest unused) summarizer report for ``agent_id``.

    A worker can be dispatched multiple times in a run (planner→executor
    → planner→executor again with the same skill). Each dispatch gets
    its own summarizer report. Consuming oldest-first keeps the per-
    invocation alignment correct without a more complex join.
    """
    reports = by_agent.get(agent_id) or []
    if not reports:
        return None
    report = reports.pop(0)
    content = report.get("content")
    if isinstance(content, str) and content.strip():
        return content.strip()
    return None


# ── Per-node header bits + planner decision parser ──────────────────────


def _render_header_bits(
    n_idx: int,
    node_row: dict,
    paired: list[dict],
) -> list[str]:
    """Build the bits that go on every node's collapsible header line:
    duration, findings count, LLM-call totals, error tag.
    """
    name = node_row.get("node") or "?"
    duration = _fmt_dur_ms(node_row.get("duration_ms"))
    err = node_row.get("error")
    delta = node_row.get("delta") or {}

    bits = [f"**{n_idx}. {name}** — {duration}"]
    if delta.get("findings_added"):
        bits.append(f"⚑ {delta['findings_added']} finding(s)")
    if paired:
        in_total = sum(c.get("input_tokens", 0) or 0 for c in paired)
        out_total = sum(c.get("output_tokens", 0) or 0 for c in paired)
        think_total = sum(c.get("reasoning_tokens", 0) or 0 for c in paired)
        bits.append(
            f"{len(paired)} LLM calls · in={_fmt_tokens_short(in_total)}"
            f" out={_fmt_tokens_short(out_total)}"
            f" think={_fmt_tokens_short(think_total)}"
        )
    if err:
        bits.append(f"❌ {err}")
    return bits


def _planner_decision_text(node_row: dict) -> tuple[str, str]:
    """Pull the planner's JSON decision out of its delta messages.

    Returns ``(action, reasoning_one_liner)``. Both strings empty when
    the planner produced no parseable JSON (which happens on retry /
    refusal paths). The decision text is then rendered inline at the
    top of the planner section.
    """
    msgs = (node_row.get("delta") or {}).get("messages_added_full") or []
    for m in msgs:
        if m.get("role") != "assistant":
            continue
        content = m.get("content")
        if not isinstance(content, str):
            continue
        match = re.search(r"\{[^{}]*\"action\"\s*:[^{}]+\}", content, re.S)
        if not match:
            # Fall back to fenced ```json```
            match = re.search(
                r"```json\s*(\{.*?\})\s*```", content, re.S,
            )
            if match:
                blob = match.group(1)
            else:
                continue
        else:
            blob = match.group(0)
        try:
            parsed = json.loads(blob)
        except json.JSONDecodeError:
            continue
        action = str(parsed.get("action") or "")
        reasoning = str(parsed.get("reasoning") or "")
        return action, reasoning
    return "", ""


# ── Per-node section renderers ──────────────────────────────────────────


def _render_planner_node(
    n_idx: int,
    node_row: dict,
    paired: list[dict],
) -> str:
    """Planner section: decision + reasoning + collapsed reasoning chain.

    No "what it tried" — planner has no shell tools. No "summary" —
    summarizer doesn't run for planner. Just the decision in plain
    sight + the chain-of-thought one click below.
    """
    msgs = (node_row.get("delta") or {}).get("messages_added_full") or []
    body: list[str] = []

    action, reasoning = _planner_decision_text(node_row)
    if action:
        target = ""
        # Best-effort target_url extraction from the same JSON.
        for m in msgs:
            content = m.get("content") or ""
            if not isinstance(content, str):
                continue
            tm = re.search(r'"target_url"\s*:\s*"([^"]+)"', content)
            if tm:
                target = tm.group(1)
                break
        body.append(f"### Decision")
        body.append("")
        target_part = f" (target: `{target}`)" if target else ""
        body.append(f"→ **{action}**{target_part}")
        body.append("")
        if reasoning:
            for line in reasoning.splitlines():
                body.append(f"> {line}")
            body.append("")
    elif node_row.get("error"):
        body.append(f"### Outcome")
        body.append("")
        body.append(f"❌ {node_row['error']}")
        body.append("")
    else:
        # No parseable JSON — show whatever final text the planner
        # produced so the run isn't opaque.
        for m in reversed(msgs):
            if m.get("role") != "assistant":
                continue
            content = m.get("content")
            if isinstance(content, str) and content.strip():
                body.append("### Output")
                body.append("")
                body.append(_md_code_block(content[:1500]))
                body.append("")
                break

    chain = _extract_reasoning_chain(msgs)
    if chain:
        body.append("### Reasoning chain")
        body.append("")
        body.append(_render_reasoning_chain(chain))
        body.append("")

    body.append(f"_See `nodes.jsonl` row {n_idx} for full conversation._")

    header = _render_header_bits(n_idx, node_row, paired)
    return _details(" · ".join(header), "\n".join(body).rstrip())


def _render_worker_node(
    n_idx: int,
    node_row: dict,
    paired: list[dict],
    summarizer_reports_by_agent: dict[str, list[dict]],
) -> str:
    """Worker section: dispatch info + summarizer summary + grouped tool
    calls + reasoning chain + findings.

    The summarizer's compressed text is the **first** thing the reader
    sees inside the expanded section. Tool calls are grouped by intent
    pattern (``SQLi probes × 35``); the raw conversation is *not*
    rendered — it lives in nodes.jsonl on disk.
    """
    name = node_row.get("node") or "?"
    delta = node_row.get("delta") or {}
    msgs_added = delta.get("messages_added_full") or []
    findings_added = delta.get("findings_added_full") or []
    active_agents = (
        (node_row.get("after") or {}).get("active_agents")
        or (node_row.get("before") or {}).get("active_agents")
        or []
    )
    body: list[str] = []

    # ── Dispatch info ──────────────────────────────────────
    if active_agents:
        body.append("### Dispatched as")
        body.append("")
        for a in active_agents:
            body.append(f"- `{a}`")
        body.append("")

    # ── Summarizer output ─────────────────────────────────
    summary_blocks: list[tuple[str, str]] = []
    for a in (active_agents or [name]):
        report = _consume_summarizer_report(summarizer_reports_by_agent, a)
        if report:
            summary_blocks.append((a, report))
    if summary_blocks:
        body.append("### Summary")
        body.append("")
        body.append("_Compressed by the summarizer node — same text the "
                    "next planner turn reads._")
        body.append("")
        for agent_id, text in summary_blocks:
            if len(summary_blocks) > 1:
                body.append(f"**`{agent_id}`**")
                body.append("")
            body.append(text)
            body.append("")

    # ── What it tried (grouped tool calls) ─────────────────
    groups = _group_tool_calls(msgs_added)
    if groups:
        body.append("### What it tried")
        body.append("")
        body.append(_render_tool_call_groups(groups))
        body.append("")

    # ── Reasoning chain (collapsed) ────────────────────────
    chain = _extract_reasoning_chain(msgs_added)
    if chain:
        body.append("### Reasoning chain")
        body.append("")
        body.append(_render_reasoning_chain(chain))
        body.append("")

    # ── Findings emitted ───────────────────────────────────
    if findings_added:
        body.append(f"### Findings emitted ({len(findings_added)})")
        body.append("")
        for f in findings_added:
            body.append(_render_finding_md(f, depth=4))
        body.append("")

    body.append(f"_See `nodes.jsonl` row {n_idx} for full conversation._")

    header = _render_header_bits(n_idx, node_row, paired)
    return _details(" · ".join(header), "\n".join(body).rstrip())


def _render_summarizer_node(
    n_idx: int,
    node_row: dict,
    paired: list[dict],
) -> str:
    """Summarizer section: minimal acknowledgement.

    The summarizer's actual reports are surfaced inside each worker's
    section above. Here we just confirm it ran and how many reports
    it emitted, plus an LLM-call total. No body — the value is in the
    worker sections.
    """
    delta = node_row.get("delta") or {}
    msgs_added = delta.get("messages_added_full") or []
    n_reports = sum(
        1 for m in msgs_added
        if m.get("role") == "assistant"
        and (m.get("additional_kwargs") or {}).get("kind") == "worker_report"
    )
    body = [
        f"_Compressed {n_reports} worker trace(s) into report messages._",
        "",
        "Reports are surfaced under each worker's **Summary** section "
        "above; that is also the text the next planner turn reads.",
    ]
    if node_row.get("error"):
        body.append("")
        body.append(f"❌ {node_row['error']}")
    body.append("")
    body.append(f"_See `nodes.jsonl` row {n_idx} for full conversation._")
    header = _render_header_bits(n_idx, node_row, paired)
    return _details(" · ".join(header), "\n".join(body).rstrip())


def _render_report_node(
    n_idx: int,
    node_row: dict,
    paired: list[dict],
) -> str:
    """Report section: render the final report inline.

    The report node is the last step; its output IS the user-facing
    artefact. So we drop the report's full text directly into the
    section (collapsible like all others, but typically open by
    default in the writer).
    """
    msgs_added = (node_row.get("delta") or {}).get("messages_added_full") or []
    body: list[str] = []
    # Pull the longest assistant message — the report itself is verbose
    # and the boundary ✅/❌ messages are short, so longest-wins is
    # robust without parsing additional_kwargs.
    candidates = [
        m for m in msgs_added if m.get("role") == "assistant"
    ]
    if candidates:
        report_msg = max(
            candidates, key=lambda m: len(str(m.get("content") or "")),
        )
        content = str(report_msg.get("content") or "")
        body.append("### Final report")
        body.append("")
        body.append(content)
        body.append("")
    body.append(f"_See `nodes.jsonl` row {n_idx} for full conversation._")
    header = _render_header_bits(n_idx, node_row, paired)
    return _details(" · ".join(header), "\n".join(body).rstrip())


def _render_simple_node(
    n_idx: int,
    node_row: dict,
    paired: list[dict],
) -> str:
    """Initialize / fallback rendering: title + summary line."""
    summary = str(node_row.get("summary") or "")
    body = []
    if summary:
        body.append(f"_{summary}_")
    elif node_row.get("error"):
        body.append(f"❌ {node_row['error']}")
    else:
        body.append("_(no summary)_")
    body.append("")
    body.append(f"_See `nodes.jsonl` row {n_idx} for full conversation._")
    header = _render_header_bits(n_idx, node_row, paired)
    return _details(" · ".join(header), "\n".join(body).rstrip())


# ── Dispatcher ──────────────────────────────────────────────────────────


def _render_node_section(
    n_idx: int,
    node_row: dict,
    node_invocations_so_far: dict[str, int],
    llm_rows: list[dict],
    summarizer_reports_by_agent: dict[str, list[dict]],
) -> str:
    """Dispatch to the right per-node renderer based on node name.

    ``summarizer_reports_by_agent`` is a shared, mutable dict — each
    rendered worker section consumes one report from it via
    ``_consume_summarizer_report``, so a second invocation of the same
    skill correctly picks up the second report rather than re-using
    the first.
    """
    name = node_row.get("node") or "?"
    node_invocations_so_far[name] = node_invocations_so_far.get(name, 0) + 1
    nth = node_invocations_so_far[name]
    paired = _pair_llm_calls(_llm_calls_for_node(llm_rows, name, nth))

    if name == "planner":
        return _render_planner_node(n_idx, node_row, paired)
    if name in ("executor", "recon", "web_search"):
        return _render_worker_node(
            n_idx, node_row, paired, summarizer_reports_by_agent,
        )
    if name == "summarizer":
        return _render_summarizer_node(n_idx, node_row, paired)
    if name == "report":
        return _render_report_node(n_idx, node_row, paired)
    return _render_simple_node(n_idx, node_row, paired)
