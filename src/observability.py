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


# ── Layered per-node rendering ──────────────────────────────────────────
#
# Every node in the timeline gets a collapsible ``<details>`` block, but
# the body is laid out in **layers** ordered by how much detail the
# reader probably wants:
#
#   1. **Decision / dispatch info** — what this node was for
#   2. **Summary** — for worker nodes only, the summarizer.py output (the
#      same compressed text that flows into the next planner turn)
#   3. **What it tried** — grouped tool calls (e.g. "SQLi sweep × 35")
#   4. **Reasoning chain** — the model's chain-of-thought summaries, in
#      order, collapsed by default
#   5. **Findings emitted** — anything the worker structured-output'd
#
# The full per-node transcript (every AIMessage + ToolMessage) is NOT
# rendered into ``summary.md`` any more. It lives on disk in
# ``nodes.jsonl`` row N → ``.delta.messages_added_full`` and we point at
# it instead. Two reasons: (1) raw-mode readers (``cat summary.md``) get
# overwhelmed by 36 KB collapsibles they can't actually collapse;
# (2) the JSONL is the source-of-truth safety layer — duplication adds
# bytes without adding information.
#
# Node types render slightly differently:
#   - **planner**: decision JSON + reasoning. No "what it tried" / "summary"
#     because the planner doesn't run shell tool calls or invoke the
#     summarizer.
#   - **executor / recon**: full layered view above.
#   - **summarizer**: minimal — its output is already surfaced inside the
#     worker section it summarised, so we just acknowledge it ran.
#   - **report**: render the report text inline (it IS the user-facing
#     artefact).
#   - **initialize / web_search**: simple — title + summary line.


# --- Tool-call grouping ------------------------------------------------
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
    # Build a tool_call_id → (tool_name, summary, reasoning) map from
    # assistant tool_calls entries that appeared in the same message
    # stream. We need the tool_name (e.g. "bash", "fetch_page",
    # "whatweb") to know whether to regex the command or group by tool
    # name — the recon node uses dedicated tools rather than raw bash,
    # so name-based grouping reads cleaner there.
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


# --- Reasoning-chain extraction ----------------------------------------


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


# --- Summarizer-output extraction --------------------------------------


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


# --- The main per-node dispatcher --------------------------------------


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
    # Workers usually run one agent at a time; for fan-out (custom-attack
    # 4-way) we'll consume all matching reports so each shows up.
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


# ── Debugging-hints rules engine ────────────────────────────────────────
#
# Rules are pure functions over (nodes, llm_rows, final_state, error,
# flag_found). Each returns a string (the hint to print) or None. The
# aggregator collects non-None returns into a single section. None of
# the rules ever raise — defensive logging only, observability must
# not break the writer.


def _rule_recursion_limit(
    *, nodes: list[dict], **_: Any,
) -> str | None:
    """Worker hit LangGraph's recursion_limit before the graph could
    complete. Common cause: skill cap too tight, or worker stuck in a
    no-progress probing loop."""
    for i, n in enumerate(nodes, 1):
        err = str(n.get("error") or "")
        if "Recursion limit" in err or "GRAPH_RECURSION_LIMIT" in err:
            name = n.get("node") or "?"
            active = (n.get("after") or {}).get("active_agents") or []
            agent = active[0] if active else "?"
            return (
                f"⚠️ Node {i} `{name}` (agent `{agent}`) hit the LangGraph "
                f"recursion limit. The skill's iteration cap was "
                f"exhausted before the worker could reach a stop "
                f"condition; bump `max_iterations` in its SKILL.md or "
                f"strengthen the skill's stop-on-impact rule."
            )
    return None


def _rule_repeated_empty_dispatches(
    *, nodes: list[dict], **_: Any,
) -> str | None:
    """3+ consecutive worker turns with the same agent_id and zero
    findings — the planner is hammering one skill that isn't
    progressing."""
    worker_runs = []
    for n in nodes:
        if (n.get("node") or "") not in ("executor", "recon"):
            continue
        active = (n.get("after") or {}).get("active_agents") or []
        if not active:
            continue
        findings_added = (n.get("delta") or {}).get("findings_added") or 0
        worker_runs.append((active[0], findings_added))
    # Sliding window of 3.
    for i in range(len(worker_runs) - 2):
        a0, _ = worker_runs[i]
        a1, _ = worker_runs[i + 1]
        a2, _ = worker_runs[i + 2]
        if a0 == a1 == a2:
            total = sum(f for _, f in worker_runs[i:i + 3])
            if total == 0:
                return (
                    f"⚠️ Skill `{a0}` was dispatched 3 times in a row "
                    f"with 0 findings each time. Planner may be stuck "
                    f"on this skill instead of pivoting; check the "
                    f"loop-detection logic in `src/nodes/base.py:detect_repetition`."
                )
    return None


def _rule_context_rot_crossed(
    *, llm_rows: list[dict], **_: Any,
) -> str | None:
    """Any single LLM call's input_tokens crossed 100k. Codex / o-series
    quality degrades visibly past ~128k."""
    peaks: list[tuple[str, int]] = []
    for r in llm_rows:
        if r.get("phase") != "end":
            continue
        try:
            n = int(r.get("input_tokens") or 0)
        except (TypeError, ValueError):
            continue
        if n >= 100_000:
            peaks.append((str(r.get("agent_id") or "?"), n))
    if not peaks:
        return None
    peaks.sort(key=lambda t: -t[1])
    a, n = peaks[0]
    extra = f" (and {len(peaks) - 1} more call(s) above 100k)" if len(peaks) > 1 else ""
    return (
        f"⚠️ Agent `{a}` sent {_fmt_tokens_short(n)} input tokens in a "
        f"single LLM call{extra}. Quality degrades visibly past ~128k; "
        f"consider stopping and re-dispatching a fresh worker."
    )


def _rule_api_refusal(
    *, llm_rows: list[dict], **_: Any,
) -> str | None:
    """Any LLM phase=error with a cyber-policy / invalid-prompt error
    type. Means the prompt classifier blocked the call, not that the
    target was hardened."""
    refusals: dict[str, int] = {}
    for r in llm_rows:
        if r.get("phase") != "error":
            continue
        et = str(r.get("error_type") or "")
        if any(k in et for k in ("CyberPolicy", "InvalidPrompt", "ContentFilter")):
            agent = str(r.get("agent_id") or "?")
            refusals[agent] = refusals.get(agent, 0) + 1
    if not refusals:
        return None
    top = max(refusals.items(), key=lambda kv: kv[1])
    extra = f" across {len(refusals)} agent(s)" if len(refusals) > 1 else ""
    return (
        f"⚠️ Detected {sum(refusals.values())} API-level refusal(s) "
        f"(top: `{top[0]}` × {top[1]}){extra}. The model rejected "
        f"these calls at the safety layer — the worker prompt may "
        f"need rewording, or switch to a more permissive model "
        f"(`SWARM_MODEL=gpt-5.4-mini`)."
    )


def _rule_salvage_without_finding(
    *, llm_rows: list[dict], final_state: dict, **_: Any,
) -> str | None:
    """A salvage call fired but no salvaged finding made it into the
    final state. Means the crashed worker's scratchpad didn't show
    demonstrated impact."""
    salvage_called = any(
        "__salvage" in str(r.get("agent_id") or "")
        for r in llm_rows if r.get("phase") in ("end", "error")
    )
    if not salvage_called:
        return None
    findings = final_state.get("findings") or []
    salvaged = sum(
        1 for f in findings
        if "[salvaged" in str(_ev_field(f, "title", ""))
    )
    if salvaged == 0:
        return (
            f"ℹ️ A salvage call fired (a worker crashed mid-loop) but "
            f"no salvaged finding was extracted. The crashed worker's "
            f"scratchpad showed no *demonstrated* impact (only "
            f"signals). Check the crash node's tool-call groups — "
            f"if a working exploit was within reach, raise the "
            f"skill's `max_iterations` cap."
        )
    return None


def _rule_bench_timeout(
    *, error: str | None, flag_found: bool | None, **_: Any,
) -> str | None:
    """The bench-level wall-clock timeout fired before the planner
    could close the loop with action=report."""
    if not error:
        return None
    if "timeout" in str(error).lower():
        return (
            f"⚠️ Wall-clock timeout fired before the planner reached "
            f"action=report. Check whether the executor was making "
            f"progress (per-node tokens / findings in the timeline) "
            f"or stuck in low-yield probing; consider raising "
            f"`RUN_TIMEOUT_S` in `benchmarks/xbow_runner.py`."
        )
    return None


def _rule_finding_without_flag(
    *, final_state: dict, flag_found: bool | None, **_: Any,
) -> str | None:
    """High-severity finding identified but the flag wasn't captured."""
    if flag_found:
        return None
    findings = final_state.get("findings") or []
    if not findings:
        return None
    high_sev = [
        f for f in findings
        if _severity_str(f).lower() in ("critical", "high")
    ]
    if not high_sev:
        return None
    titles = [str(_ev_field(f, "title", ""))[:80] for f in high_sev[:2]]
    suffix = f" (+ {len(high_sev) - 2} more)" if len(high_sev) > 2 else ""
    title_str = "; ".join(t for t in titles if t)
    return (
        f"ℹ️ {len(high_sev)} high/critical finding(s) identified but "
        f"the flag was not captured: _{title_str}_{suffix}. The "
        f"vulnerability was diagnosed but not weaponised — check if "
        f"the executor specialised on extraction after the recon "
        f"finding fired."
    )


_DEBUG_HINT_RULES = (
    _rule_recursion_limit,
    _rule_repeated_empty_dispatches,
    _rule_context_rot_crossed,
    _rule_api_refusal,
    _rule_salvage_without_finding,
    _rule_bench_timeout,
    _rule_finding_without_flag,
)


def _render_debug_hints(
    *,
    nodes: list[dict],
    llm_rows: list[dict],
    final_state: dict,
    error: str | None,
    flag_found: bool | None,
) -> str:
    """Run every rule, collect non-None hints, render as a markdown block.

    Defensive: any rule that raises is silently skipped — the writer
    must never break on a buggy rule. ``SWARM_LIVE_DEBUG_HINTS=0``
    disables the section entirely (renders just a one-line "_disabled_"
    note so the user knows it's intentional).
    """
    import os as _os
    if _os.environ.get("SWARM_LIVE_DEBUG_HINTS") == "0":
        return "_(debug hints disabled via SWARM_LIVE_DEBUG_HINTS=0)_"
    hints: list[str] = []
    for rule in _DEBUG_HINT_RULES:
        try:
            r = rule(
                nodes=nodes,
                llm_rows=llm_rows,
                final_state=final_state,
                error=error,
                flag_found=flag_found,
            )
        except Exception:  # noqa: BLE001
            continue
        if r:
            hints.append(f"- {r}")
    if not hints:
        return "_No anomalies detected._"
    return "\n".join(hints)


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


# Re-export the live renderer so callers can keep doing
# ``from src.observability import LIVE`` even though the renderer itself
# lives at ``src/live.py``. Imported at the bottom because the renderer
# does a lazy ``from src.graph import config``; either order works
# (live.py defers config access to call time), but bottom keeps the
# disk-logging surface above the renderer surface for readers.
from src.live import LIVE, HttpxQuietFilter, LiveLogHandler  # noqa: E402
