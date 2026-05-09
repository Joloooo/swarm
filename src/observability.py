"""Per-run observability: one folder per graph invocation.

For each run we write everything under ``logs/run-<run_id>/``:

    nodes.jsonl           one line per BaseNode.__call__ — duration, summary,
                          full state shape before/after, full text of every
                          newly added message/finding/agent_result. This is
                          the file you read when answering "what did node X
                          do?" — both the timeline and the per-node forensic
                          replay live here.
    llm_calls.jsonl       two lines per LLM call: one ``phase=start`` row
                          with the full prompt sent, and one ``phase=end``
                          row (or ``phase=error``) with usage tokens,
                          duration, and response. Same file so live tail
                          shows both sides of every round-trip.
    terminal_events.jsonl tool-call log (redirected from src/tools/terminal.py)
    final_state.json      graph.ainvoke() return value, in full
    summary.md            human-readable digest of the whole run

The run_id embeds the benchmark id (or target host) so that ``ls logs/``
tells you immediately which run hit which target.

Nothing is truncated. Disk is cheap; thesis analysis needs the full record.

History note: prior to this consolidation we wrote separate
``state_diffs.jsonl`` (per-node shape diff) and ``llm_requests.jsonl``
(per-call prompts). Both were folded into the files above so the run
dir has 5 artefacts instead of 7. The shape-diff data is still there
under each ``nodes.jsonl`` row's ``before`` / ``after`` / ``delta``
keys; the request bodies are still there under ``llm_calls.jsonl``
``phase=start`` rows.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# logs/ at project root (this file lives at SwarmAttacker/src/observability.py).
LOGS_ROOT = Path(__file__).resolve().parents[1] / "logs"

_NODES_LOCK = threading.Lock()  # parallel executor workers append concurrently


def _slug(s: str, *, max_len: int = 60) -> str:
    """Filesystem-safe slug. Keeps letters, digits, dot, dash, underscore."""
    s = re.sub(r"[^\w.-]+", "-", s).strip("-_.")
    return s[:max_len] or "x"


def make_run_id(
    *,
    benchmark_id: str | None = None,
    target_url: str | None = None,
) -> str:
    """Build a run_id that ties target identity to a readable timestamp.

    Format:  ``<slug>__<YYYY-MM-DD>_<HHhMMmSSs>``

    Example: ``XBEN-006-24__2026-05-03_21h18m10s``

    The slug embeds whichever of these is most identifying, in order:
        1. benchmark_id (XBEN-019-24)
        2. target host (target-localhost-32768)
        3. ``studio`` fallback for langgraph dev runs

    The pid suffix (used in earlier versions to disambiguate concurrent
    runs of the same benchmark) is dropped — colliding runs of the same
    bench id are pathological enough that letting them share a directory
    is acceptable, and the readable timestamp is the user-visible win.
    """
    now = dt.datetime.now()
    ts = now.strftime("%Y-%m-%d_%Hh%Mm%Ss")
    if benchmark_id:
        slug = _slug(benchmark_id)
    elif target_url:
        parsed = urlparse(target_url)
        host = parsed.hostname or "unknown"
        port = f"-{parsed.port}" if parsed.port else ""
        slug = _slug(f"target-{host}{port}")
    else:
        slug = "studio"
    return f"{slug}__{ts}"


def run_dir(run_id: str) -> Path:
    """Return (and create) the log directory for a run."""
    d = LOGS_ROOT / f"run-{run_id}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def append_node_event(run_id: str, event: dict) -> None:
    """Append one JSON line to ``nodes.jsonl``.

    Failures are swallowed — observability must never break a graph run.
    Lock-guarded so parallel executor workers don't interleave half-lines.
    """
    try:
        path = run_dir(run_id) / "nodes.jsonl"
        line = json.dumps(event, default=str, ensure_ascii=False) + "\n"
        with _NODES_LOCK, path.open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:  # noqa: BLE001
        pass


def write_final_state(run_id: str, state: dict) -> Path:
    """Dump the full agent_state to ``final_state.json``."""
    path = run_dir(run_id) / "final_state.json"
    path.write_text(
        json.dumps(state, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


# -- summary.md -----------------------------------------------------------

def _msg_text(msg: Any) -> str:
    """Best-effort extraction of message content for human reading."""
    content = getattr(msg, "content", None)
    if content is None and isinstance(msg, dict):
        content = msg.get("content")
    if content is None:
        return repr(msg)
    if isinstance(content, list):
        # Multi-part content (e.g. tool calls) — flatten to readable text
        parts = []
        for part in content:
            if isinstance(part, dict):
                parts.append(part.get("text") or json.dumps(part, default=str))
            else:
                parts.append(str(part))
        return "\n".join(parts)
    return str(content)


def _msg_role(msg: Any) -> str:
    cls = type(msg).__name__
    return {
        "HumanMessage": "user",
        "AIMessage": "assistant",
        "SystemMessage": "system",
        "ToolMessage": "tool",
    }.get(cls, cls)


def _read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file into a list of dicts.

    Used for ``nodes.jsonl``, ``llm_calls.jsonl``, ``terminal_events.jsonl``.
    Tolerates the file not existing (returns ``[]``) and silently
    skips malformed lines (better to emit a partial summary than to
    raise on a half-flushed log).
    """
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _read_node_events(run_id: str) -> list[dict]:
    """Read nodes.jsonl, transparently merging the legacy state_diffs.jsonl
    if the current rows lack ``delta``.

    Prior to the consolidation in this commit, ``nodes.jsonl`` carried
    only ``{ts, node, duration_ms, summary, result}`` and the per-node
    state-shape diff lived in a sister ``state_diffs.jsonl``. Old run
    dirs sit on disk with that split. So summaries can still render
    against them, we read both files and zip-merge by index — both
    were appended in lockstep at end-of-call so position is a sound
    join key.

    Forward case (post-consolidation): every nodes.jsonl row already
    has ``delta``, the state_diffs.jsonl file doesn't exist, the merge
    is a no-op.
    """
    rdir = run_dir(run_id)
    rows = _read_jsonl(rdir / "nodes.jsonl")
    needs_backfill = any("delta" not in r for r in rows)
    if not needs_backfill:
        return rows
    state_rows = _read_jsonl(rdir / "state_diffs.jsonl")
    if not state_rows:
        return rows
    # Zip by index. Tolerate length mismatch (a partial run could leave
    # one file ahead of the other) by only filling rows we have data for.
    merged = []
    for i, row in enumerate(rows):
        if "delta" in row:
            merged.append(row)
            continue
        if i < len(state_rows):
            sr = state_rows[i]
            row = {**row,
                   "before": sr.get("before"),
                   "after":  sr.get("after"),
                   "delta":  sr.get("delta")}
        merged.append(row)
    return merged


# ── summary.md helpers ──────────────────────────────────────────────────


def _fmt_dur_ms(ms: int | float | str | None) -> str:
    """Human-readable duration. ``413`` → ``413ms``, ``25400`` → ``25.4s``."""
    try:
        n = int(ms or 0)
    except (TypeError, ValueError):
        return "?"
    if n < 1_000:
        return f"{n}ms"
    if n < 60_000:
        return f"{n / 1000:.1f}s"
    return f"{n // 60_000}m{(n % 60_000) // 1000}s"


def _fmt_tokens_short(n: int | None) -> str:
    """``1234`` → ``1.2k``; ``150`` → ``150``; ``None`` → ``—``."""
    if n is None:
        return "—"
    try:
        v = int(n)
    except (TypeError, ValueError):
        return str(n)
    if v < 1_000:
        return str(v)
    if v < 10_000:
        return f"{v / 1_000:.1f}k"
    return f"{v // 1_000}k"


def _fmt_bytes_short(n: int | None) -> str:
    if n is None:
        return "—"
    try:
        v = int(n)
    except (TypeError, ValueError):
        return str(n)
    if v < 1024:
        return f"{v}B"
    if v < 1024 * 1024:
        return f"{v / 1024:.1f}KB"
    return f"{v / (1024 * 1024):.1f}MB"


def _md_escape_pipe(s: str) -> str:
    """Escape pipe chars so a string is safe inside a markdown table cell."""
    return (s or "").replace("|", "\\|").replace("\n", " ")


def _md_code_block(content: str, lang: str = "") -> str:
    """Render ``content`` as a fenced code block.

    Bumps the fence to backticks-of-N when the content contains a
    triple-backtick run, so we don't break out of the block. Common
    case (no nested fences) stays at 3 backticks.
    """
    n = 3
    while "`" * n in (content or ""):
        n += 1
    fence = "`" * n
    return f"{fence}{lang}\n{content}\n{fence}"


def _details(summary_text: str, body: str) -> str:
    """Wrap ``body`` in an HTML ``<details>`` block.

    GitHub / Cursor / Obsidian all render this natively as a click-to-
    expand. The blank line after the ``<summary>`` is required for
    Markdown inside the body to render correctly.
    """
    return f"<details>\n<summary>{summary_text}</summary>\n\n{body}\n\n</details>"


def _ev_field(obj: Any, key: str, default: Any = "") -> Any:
    """Read ``key`` from a Finding/AgentResult-like object.

    Works on both dataclass instances (live `Finding`) and plain dicts
    (rehydrated from JSONL). The summary writer is fed both shapes
    depending on whether the caller passed the live state or read
    from disk.
    """
    if obj is None:
        return default
    val = getattr(obj, key, None)
    if val is None and isinstance(obj, dict):
        val = obj.get(key, default)
    if val is None:
        return default
    return val


def _severity_str(obj: Any) -> str:
    sev = _ev_field(obj, "severity", "info")
    return getattr(sev, "value", None) or str(sev or "info")


def _llm_calls_for_node(
    llm_rows: list[dict],
    node_name: str,
    nth_invocation: int,
) -> list[dict]:
    """Slice the LLM-calls log to the rows belonging to ``node_name``'s
    ``nth_invocation`` (1-based).

    LLM rows carry a ``node`` field but not a "which invocation". We
    distinguish by walking the rows in order and partitioning each
    contiguous run of same-node rows. Adjacent rows for the same node
    that aren't separated by a different node belong to the same
    invocation. This isn't perfect — if planner→recon→planner→recon
    ran in quick succession with both planners zero LLM calls it
    could mislabel — but in practice every node makes LLM calls so
    the partitioning matches the timeline.
    """
    runs: list[list[dict]] = []
    current: list[dict] = []
    last_node = None
    for row in llm_rows:
        n = row.get("node") or ""
        if n != last_node:
            if current:
                runs.append(current)
            current = [row]
            last_node = n
        else:
            current.append(row)
    if current:
        runs.append(current)

    matching = [r for r in runs if r and (r[0].get("node") or "") == node_name]
    if 1 <= nth_invocation <= len(matching):
        return matching[nth_invocation - 1]
    return []


def _pair_llm_calls(rows: list[dict]) -> list[dict]:
    """Pair ``phase=start`` and ``phase=end`` / ``phase=error`` rows
    into per-call dicts.

    Pairing strategy:
        1. Prefer matching by ``lc_run_id`` when both rows carry it
           (the post-consolidation default).
        2. If end rows lack ``lc_run_id`` (legacy ``llm_calls.jsonl``
           shape — present in older runs and back-compat-merged from
           the now-defunct ``llm_requests.jsonl``), fall back to
           positional pairing within the rows: the Nth start matches
           the Nth end / error.
        3. Unmatched rows still contribute a per-call entry with
           whatever fields they had — better than dropping the call
           silently.

    Output (one entry per LLM round-trip)::

        {
            "agent_id":          "owasp-recon",
            "model":             "gpt-5.4-mini",
            "duration_ms":       48000,
            "input_tokens":      8100,
            "output_tokens":     3800,
            "reasoning_tokens":  2800,
            "request":           {...},
            "error":             None,
        }
    """
    starts = [r for r in rows if r.get("phase") == "start"]
    ends   = [r for r in rows if r.get("phase") in ("end", "error")]

    # Index ends by lc_run_id when available, by ordinal index when not.
    ends_by_lc: dict[str, dict] = {}
    ends_no_lc: list[dict] = []
    for end_row in ends:
        lc = str(end_row.get("lc_run_id") or "")
        if lc:
            ends_by_lc[lc] = end_row
        else:
            ends_no_lc.append(end_row)

    out: list[dict] = []
    for s in starts:
        lc = str(s.get("lc_run_id") or "")
        end_row = None
        if lc and lc in ends_by_lc:
            end_row = ends_by_lc.pop(lc)
        elif ends_no_lc:
            end_row = ends_no_lc.pop(0)
        out.append(_merge_call_pair(s, end_row))

    # Unmatched ends (e.g. start row was lost or filtered out): keep
    # them too so the rendered list reflects every round-trip we
    # observed.
    for end_row in list(ends_by_lc.values()) + ends_no_lc:
        out.append(_merge_call_pair(None, end_row))

    return out


def _merge_call_pair(start: dict | None, end: dict | None) -> dict:
    """Combine a paired start + end row into the unified per-call shape."""
    s = start or {}
    e = end or {}
    err_type = e.get("error_type") if e.get("phase") == "error" else None
    return {
        "agent_id":         s.get("agent_id") or e.get("agent_id"),
        "model":            s.get("model") or e.get("model") or "?",
        "duration_ms":      e.get("duration_ms", 0),
        "input_tokens":     e.get("input_tokens", 0),
        "output_tokens":    e.get("output_tokens", 0),
        "reasoning_tokens": e.get("reasoning_tokens", 0),
        "request":          s.get("request") or {},
        "start_ts":         s.get("ts"),
        "end_ts":           e.get("ts"),
        "error":            err_type,
    }


def _render_finding_md(f: Any, depth: int = 3) -> str:
    """Render one finding as a markdown block with collapsed evidence."""
    sev = _severity_str(f).upper()
    title = str(_ev_field(f, "title", "(no title)"))
    cat = str(_ev_field(f, "category", "?"))
    agent = str(_ev_field(f, "agent_id", "?"))
    url = str(_ev_field(f, "url", ""))
    evidence = str(_ev_field(f, "evidence", ""))
    description = str(_ev_field(f, "description", ""))
    cwe = str(_ev_field(f, "cwe", ""))
    reproduced = bool(_ev_field(f, "reproduced", False))

    h = "#" * max(1, min(depth, 6))
    parts = [f"{h} [{sev}] {title}"]
    parts.append("")
    bullets = [
        f"- **Agent**: `{agent}`",
        f"- **Category**: `{cat}`",
    ]
    if url:
        bullets.append(f"- **URL**: `{url}`")
    if cwe:
        bullets.append(f"- **CWE**: `{cwe}`")
    bullets.append(f"- **Reproduced**: {'yes' if reproduced else 'no'}")
    parts.extend(bullets)
    if description:
        parts.append("")
        parts.append(f"> {description}")
    if evidence:
        parts.append("")
        parts.append(_details("Evidence", _md_code_block(evidence)))
    parts.append("")
    return "\n".join(parts)


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


def _render_node_section(
    n_idx: int,
    node_row: dict,
    node_invocations_so_far: dict[str, int],
    llm_rows: list[dict],
) -> str:
    """Render one node's collapsible section.

    Pulls structured data from the (now consolidated) ``nodes.jsonl``
    row's ``delta.messages_added_full`` for the actual conversation,
    and joins to ``llm_calls.jsonl`` rows by node name + invocation
    index for the per-LLM-call detail.
    """
    name = node_row.get("node") or "?"
    duration = _fmt_dur_ms(node_row.get("duration_ms"))
    summary = str(node_row.get("summary") or "")
    err = node_row.get("error")
    delta = node_row.get("delta") or {}
    msgs_added = delta.get("messages_added_full") or []
    findings_added = delta.get("findings_added_full") or []

    node_invocations_so_far[name] = node_invocations_so_far.get(name, 0) + 1
    nth = node_invocations_so_far[name]

    paired = _pair_llm_calls(_llm_calls_for_node(llm_rows, name, nth))

    # Header line that the reader sees BEFORE expanding.
    header_bits = [f"**{n_idx}. {name}** — {duration}"]
    if delta.get("findings_added"):
        header_bits.append(f"⚑ {delta['findings_added']} finding(s)")
    if paired:
        in_total = sum(c.get("input_tokens", 0) or 0 for c in paired)
        out_total = sum(c.get("output_tokens", 0) or 0 for c in paired)
        think_total = sum(c.get("reasoning_tokens", 0) or 0 for c in paired)
        header_bits.append(
            f"{len(paired)} LLM calls · in={_fmt_tokens_short(in_total)}"
            f" out={_fmt_tokens_short(out_total)}"
            f" think={_fmt_tokens_short(think_total)}"
        )
    if err:
        header_bits.append(f"❌ {err}")

    body: list[str] = []
    if summary:
        body.append(f"_{summary}_")
        body.append("")

    # LLM calls
    if paired:
        body.append(f"**LLM calls ({len(paired)})**")
        body.append("")
        for j, call in enumerate(paired, 1):
            body.append(_render_llm_call(call, j))
        body.append("")

    # Conversation: separate AI messages and tool messages so the
    # reader can scan the dialogue at a glance.
    ai_msgs = [m for m in msgs_added if (m.get("role") == "assistant")]
    tool_msgs = [m for m in msgs_added if (m.get("role") == "tool")]

    if ai_msgs:
        body.append(f"**Assistant messages ({len(ai_msgs)})**")
        body.append("")
        for j, m in enumerate(ai_msgs, 1):
            body.append(_render_assistant_block_from_msg(m, j))
        body.append("")

    if tool_msgs:
        body.append(f"**Tool calls ({len(tool_msgs)})**")
        body.append("")
        for j, m in enumerate(tool_msgs, 1):
            body.append(_render_tool_call_from_msg(m, j))
        body.append("")

    if findings_added:
        body.append(f"**Findings emitted ({len(findings_added)})**")
        body.append("")
        for f in findings_added:
            body.append(_render_finding_md(f, depth=4))

    return _details(" · ".join(header_bits), "\n".join(body).rstrip())


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

    Layout:

        # Run <id> — outcome banner
        ## Quick facts          (target, model, totals, run dir)
        ## Timeline             (one row per node, sortable table)
        ## Findings             (full evidence, severity-sorted)
        ## Per-node detail      (one <details> per node call, with
                                 nested <details> for prompts and
                                 tool outputs)
        ## Files in this dir    (legend pointing back to JSONL files)

    Reading inputs:
        - ``nodes.jsonl``         — timeline + per-node delta with
                                    full text of new messages
        - ``llm_calls.jsonl``     — paired phase=start / phase=end
                                    rows for token + prompt detail
        - ``final_state.json``    — passed in via ``final_state`` arg

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
    out("## Per-node detail")
    out("")
    out("_Click any node to expand its LLM calls, assistant messages, "
        "and tool outputs._")
    out("")
    invocations: dict[str, int] = {}
    for i, n in enumerate(nodes, 1):
        out(_render_node_section(i, n, invocations, llm_rows))
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


# Re-export the live renderer so callers can keep doing
# ``from src.observability import LIVE`` even though the renderer itself
# lives at ``src/live.py``. Imported at the bottom because the renderer
# does a lazy ``from src.graph import config``; either order works
# (live.py defers config access to call time), but bottom keeps the
# disk-logging surface above the renderer surface for readers.
from src.live import LIVE, HttpxQuietFilter, LiveLogHandler  # noqa: E402
