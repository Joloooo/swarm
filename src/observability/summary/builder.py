"""Top-level orchestrator that writes ``logs/run-<id>/summary.md``.

This is the entry point everyone calls. It reads ``nodes.jsonl`` +
``llm_calls.jsonl`` (plus the live ``final_state.json`` passed in by
the runner) and assembles them into a navigable markdown document.

The actual rendering is delegated to the sibling modules:

  * ``_helpers.py``  — formatters, JSONL readers, LLM-call pairing
  * ``findings.py``  — :func:`_render_finding_md` for one finding
  * ``timeline.py``  — per-node detail sections + tool-call grouping
  * ``header.py``    — debug-hints rules engine

This file owns only the orchestration: header bullets, timeline
table, the per-section calls into the renderers above, and the file
legend at the bottom.

Layout of the output:

    # Run <id> — outcome banner
    ## Quick facts          (target, model, totals, run dir)
    ## 🔍 If you're debugging  (debug hints rules engine)
    ## Timeline             (one row per node, sortable table)
    ## Findings             (full evidence, severity-sorted)
    ## Per-node detail      (one <details> per node call)
    ## Per-agent results    (one bullet per AgentResult)
    ## Files in this run dir (legend pointing back to JSONL files)
"""

from __future__ import annotations

from pathlib import Path

from src.observability.summary._helpers import (
    _fmt_dur_ms,
    _fmt_tokens_short,
    _llm_calls_for_node,
    _md_escape_pipe,
    _read_jsonl,
    _read_node_events,
    _severity_str,
    _ev_field,
)
from src.observability.summary.findings import _render_finding_md
from src.observability.summary.header import _render_debug_hints
from src.observability.summary.timeline import (
    _index_summarizer_reports,
    _render_node_section,
)
from src.observability.writers import run_dir


def write_summary(
    run_id: str,
    *,
    benchmark_id: str | None,
    target_url: str | None,
    expected_flag: str | None,
    flag_found: bool | None,
    duration_s: float,
    error: str | None,
    final_state: dict,
) -> Path:
    """Generate ``summary.md`` — the human entry point for a run.

    This is the **first file you open** after a run. Every other
    artefact in the run dir (``nodes.jsonl``, ``llm_calls.jsonl``,
    ``terminal_events.jsonl``, ``final_state.json``) is the
    machine-readable layer; this file collates the same data into a
    navigable markdown document with HTML ``<details>`` collapsing
    so you can drill from the top-level outcome down to a specific
    LLM prompt or bash output without leaving the file.

    The function is defensive: missing files or malformed rows
    produce a partial summary rather than raising. Disk failures
    are NOT swallowed (the summary writer is end-of-run, not
    in-the-hot-path).
    """
    rdir = run_dir(run_id)
    nodes = _read_node_events(run_id)  # auto-merges legacy state_diffs.jsonl
    llm_rows = _read_jsonl(rdir / "llm_calls.jsonl")
    # Backwards-compat: legacy runs wrote LLM start rows to a sister
    # ``llm_requests.jsonl``. Interleave them with the end rows by
    # timestamp so the per-invocation partitioning logic in
    # ``_llm_calls_for_node`` sees the same chronological order it'd
    # see in a post-consolidation run.
    legacy_requests = _read_jsonl(rdir / "llm_requests.jsonl")
    if legacy_requests and not any(r.get("phase") == "start" for r in llm_rows):
        llm_rows = sorted(
            llm_rows + legacy_requests,
            key=lambda r: str(r.get("ts") or ""),
        )

    findings = final_state.get("findings") or []
    agent_results = final_state.get("agent_results") or []

    # Outcome verdict.
    if flag_found is True:
        verdict = "✅ Flag captured"
    elif error:
        verdict = f"⚠️ Error: {error}"
    elif flag_found is False:
        verdict = "❌ Flag not found"
    else:
        verdict = "—"

    # Aggregate token totals across all LLM calls.
    total_in = sum(int(r.get("input_tokens") or 0)
                   for r in llm_rows if r.get("phase") == "end")
    total_out = sum(int(r.get("output_tokens") or 0)
                    for r in llm_rows if r.get("phase") == "end")
    total_think = sum(int(r.get("reasoning_tokens") or 0)
                      for r in llm_rows if r.get("phase") == "end")
    n_llm_calls = sum(1 for r in llm_rows if r.get("phase") == "end")

    # Bash/tool-call total — count the tool-role messages across all
    # nodes' deltas (terminal_events.jsonl gives the same count but
    # this avoids reading another file).
    n_tool_calls = 0
    for n in nodes:
        msgs = ((n.get("delta") or {}).get("messages_added_full") or [])
        n_tool_calls += sum(1 for m in msgs if m.get("role") == "tool")

    # Findings counts by severity.
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = _severity_str(f).lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines: list[str] = []
    out = lines.append

    # ── Header ───────────────────────────────────────────────────
    out(f"# Run `{run_id}`")
    out("")
    out(f"**{verdict}** · {duration_s:.1f}s · "
        f"{len(findings)} finding{'s' if len(findings) != 1 else ''} · "
        f"{n_llm_calls} LLM call{'s' if n_llm_calls != 1 else ''} · "
        f"{n_tool_calls} bash command{'s' if n_tool_calls != 1 else ''}")
    out("")

    # ── Quick facts ──────────────────────────────────────────────
    out("## Quick facts")
    out("")
    out(f"- **Benchmark**: `{benchmark_id or '—'}`")
    out(f"- **Target**: `{target_url or '—'}`")
    out(f"- **Expected flag**: `{expected_flag or '—'}`")
    # Pick the first model we saw — they should all match within a run.
    model = "?"
    for r in llm_rows:
        if r.get("model") and r.get("model") != "?":
            model = r["model"]
            break
    out(f"- **Model**: `{model}`")
    out(f"- **LLM tokens**: in={_fmt_tokens_short(total_in)} · "
        f"out={_fmt_tokens_short(total_out)} · "
        f"think={_fmt_tokens_short(total_think)}")
    if sev_counts:
        sev_text = " · ".join(f"{k}={v}" for k, v in sorted(sev_counts.items()))
        out(f"- **Findings by severity**: {sev_text}")
    out(f"- **Run dir**: `{rdir}`")
    out("")

    # ── Debugging hints ──────────────────────────────────────────
    # Auto-flagged anomalies — top-of-file because if the run failed,
    # this is the section the user wants first. ``_render_debug_hints``
    # runs a small rules engine over (nodes, llm_rows, final_state)
    # and prints a bulleted list. Renders "_No anomalies detected._"
    # on a clean run; disabled with SWARM_LIVE_DEBUG_HINTS=0.
    out("## 🔍 If you're debugging")
    out("")
    out(_render_debug_hints(
        nodes=nodes,
        llm_rows=llm_rows,
        final_state=final_state,
        error=error,
        flag_found=flag_found,
    ))
    out("")

    # ── Timeline ─────────────────────────────────────────────────
    out("## Timeline")
    out("")
    out("| # | Node | Duration | LLM calls | Tokens (in/out/think) | Outcome |")
    out("|---|------|----------|-----------|------------------------|---------|")
    seen_invocations: dict[str, int] = {}
    for i, n in enumerate(nodes, 1):
        name = n.get("node") or "?"
        seen_invocations[name] = seen_invocations.get(name, 0) + 1
        nth = seen_invocations[name]
        node_calls = _llm_calls_for_node(llm_rows, name, nth)
        end_calls = [r for r in node_calls if r.get("phase") == "end"]
        in_t  = sum(int(r.get("input_tokens") or 0)     for r in end_calls)
        out_t = sum(int(r.get("output_tokens") or 0)    for r in end_calls)
        thk_t = sum(int(r.get("reasoning_tokens") or 0) for r in end_calls)
        token_cell = (
            f"{_fmt_tokens_short(in_t)} / {_fmt_tokens_short(out_t)} "
            f"/ {_fmt_tokens_short(thk_t)}"
            if end_calls else "—"
        )
        outcome = ""
        if n.get("error"):
            outcome = f"❌ {n['error']}"
        else:
            delta = n.get("delta") or {}
            findings_added = delta.get("findings_added") or 0
            if findings_added:
                outcome = f"⚑ {findings_added} finding(s)"
            else:
                outcome = _md_escape_pipe(n.get("summary", "") or "")
        out(f"| {i} | `{name}` | {_fmt_dur_ms(n.get('duration_ms'))} | "
            f"{len(end_calls)} | {token_cell} | {outcome} |")
    out("")

    # ── Findings ─────────────────────────────────────────────────
    out("## Findings")
    out("")
    if not findings:
        out("_None._")
        out("")
    else:
        # Severity ordering: critical → high → medium → low → info.
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings, key=lambda f: sev_rank.get(_severity_str(f).lower(), 9),
        )
        for f in sorted_findings:
            out(_render_finding_md(f, depth=3))

    # ── Per-node detail ──────────────────────────────────────────
    #
    # Each node renders as a layered ``<details>`` block: dispatch info
    # at the top, the summarizer's compressed text next (for workers),
    # then grouped tool calls, then a collapsed reasoning chain. The
    # **full transcript is intentionally not rendered here** — it lives
    # on disk in ``nodes.jsonl`` row N → ``.delta.messages_added_full``
    # so a 200 KB collapsible doesn't overwhelm raw-mode readers
    # (``cat summary.md``).
    out("## Per-node detail")
    out("")
    out("_Click a node to expand its summary, grouped tool calls, and "
        "reasoning chain. The full per-node transcript lives in "
        "`nodes.jsonl` (one row per node, full text under "
        "`.delta.messages_added_full`)._")
    out("")
    # Pre-index summarizer reports so each worker section can pick up
    # the right report (oldest-first when a skill ran multiple times).
    summarizer_reports = _index_summarizer_reports(nodes)
    invocations: dict[str, int] = {}
    for i, n in enumerate(nodes, 1):
        out(_render_node_section(i, n, invocations, llm_rows,
                                 summarizer_reports))
        out("")

    # ── Per-agent results ────────────────────────────────────────
    if agent_results:
        out("## Per-agent results")
        out("")
        for ar in agent_results:
            agent_id = _ev_field(ar, "agent_id", "?")
            cfg = _ev_field(ar, "config_name", "?")
            phase = _ev_field(ar, "phase", "?")
            completed = _ev_field(ar, "completed", False)
            err = _ev_field(ar, "error", "")
            ar_findings = _ev_field(ar, "findings", []) or []
            check = "✓" if completed else "✗"
            err_part = f" · error=`{err}`" if err else ""
            out(f"- {check} **`{agent_id}`** ({cfg} / {phase}) — "
                f"{len(ar_findings)} finding(s){err_part}")
        out("")

    # ── File legend ──────────────────────────────────────────────
    out("## Files in this run dir")
    out("")
    out("- **`summary.md`** — this file (the human entry point).")
    out("- **`nodes.jsonl`** — one row per node finish; each row carries "
        "`before`, `after`, and `delta` (with full text of every newly "
        "added message / finding).")
    out("- **`llm_calls.jsonl`** — two rows per LLM call: `phase=start` "
        "with the full prompt, `phase=end` (or `phase=error`) with token "
        "usage and duration. Live-cadence.")
    out("- **`terminal_events.jsonl`** — one row per shell command. "
        "Live-cadence.")
    out("- **`final_state.json`** — full LangGraph state at exit.")
    out("")

    path = rdir / "summary.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
