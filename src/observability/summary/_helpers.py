"""Shared helpers used by the summary builder modules.

Tiny pure functions that don't fit any one renderer's concern but
get used by several of them. Kept private (underscore prefix) and
internal to ``observability/summary/`` — no external module should
import from here.

The categories:

  * ``_msg_text`` / ``_msg_role`` — best-effort message inspection
    used when rendering raw delta entries from ``nodes.jsonl``.
  * ``_read_jsonl`` / ``_read_node_events`` — JSONL file readers,
    tolerant of missing files and malformed lines.
  * ``_fmt_dur_ms`` / ``_fmt_tokens_short`` / ``_fmt_bytes_short`` —
    human-readable formatters for the per-node table cells.
  * ``_md_escape_pipe`` / ``_md_code_block`` / ``_details`` — markdown
    quoting helpers; used to keep table rows valid and to wrap
    expandable sections in HTML ``<details>``.
  * ``_ev_field`` / ``_severity_str`` — ``Finding`` / ``AgentResult``
    accessors that work on both live dataclass instances and rehydrated
    JSON dicts (the writer is fed both shapes depending on the path).
  * ``_llm_calls_for_node`` / ``_pair_llm_calls`` / ``_merge_call_pair``
    — ``llm_calls.jsonl`` partitioning and start/end pairing logic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


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
    from src.observability.writers import run_dir
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


# ── LLM call partitioning + pairing ─────────────────────────────────────


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
