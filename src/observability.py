"""Per-run observability: one folder per graph invocation.

For each run we write everything under ``logs/run-<run_id>/``:

    nodes.jsonl           one line per BaseNode.__call__ (full result)
    final_state.json      graph.ainvoke() return value, in full
    summary.md            human-readable digest of the whole run
    terminal_events.jsonl tool-call log (redirected from src/tools/terminal.py)

The run_id embeds the benchmark id (or target host) so that ``ls logs/``
tells you immediately which run hit which target.

Nothing is truncated. Disk is cheap; thesis analysis needs the full record.
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


def _read_node_events(run_id: str) -> list[dict]:
    path = run_dir(run_id) / "nodes.jsonl"
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
    """Generate ``summary.md`` — a human-readable digest of the run.

    Reads ``nodes.jsonl`` (already written by BaseNode.__call__) and
    the final_state to produce a single document the user can scan.
    """
    nodes = _read_node_events(run_id)
    findings = final_state.get("findings") or []
    messages = final_state.get("messages") or []
    agent_results = final_state.get("agent_results") or []

    lines: list[str] = []
    out = lines.append

    # -- Header --
    if flag_found is True:
        verdict = "✅ Flag found"
    elif error:
        verdict = f"⚠️ Error: {error}"
    elif flag_found is False:
        verdict = "❌ Flag not found"
    else:
        verdict = "—"

    out(f"# Run `{run_id}`")
    out("")
    out(f"- **Benchmark:** `{benchmark_id or '—'}`")
    out(f"- **Target:** {target_url or '—'}")
    out(f"- **Expected flag:** `{expected_flag or '—'}`")
    out(f"- **Outcome:** {verdict}")
    out(f"- **Duration:** {duration_s:.1f}s")
    out(f"- **Findings:** {len(findings)}")
    out(f"- **Node calls:** {len(nodes)}")
    out(f"- **Agents that returned:** {len(agent_results)}")
    out("")

    # -- Node timeline --
    out("## Node timeline")
    out("")
    out("| # | Node | Duration | Status | Summary |")
    out("|---|------|----------|--------|---------|")
    for i, ev in enumerate(nodes, 1):
        dur = ev.get("duration_ms", "—")
        status = "❌" if ev.get("error") else "✓"
        summ = ev.get("summary", "").replace("|", "\\|")
        out(f"| {i} | `{ev.get('node', '?')}` | {dur} ms | {status} | {summ} |")
    out("")

    # -- Findings --
    out("## Findings")
    out("")
    if not findings:
        out("_None._")
    else:
        for f in findings:
            sev = getattr(f, "severity", None) or (
                f.get("severity") if isinstance(f, dict) else "?"
            )
            sev = getattr(sev, "value", str(sev))
            title = getattr(f, "title", None) or (
                f.get("title") if isinstance(f, dict) else str(f)
            )
            cat = getattr(f, "category", None) or (
                f.get("category") if isinstance(f, dict) else "?"
            )
            agent = getattr(f, "agent_id", None) or (
                f.get("agent_id") if isinstance(f, dict) else "?"
            )
            url = getattr(f, "url", None) or (
                f.get("url", "") if isinstance(f, dict) else ""
            )
            evidence = getattr(f, "evidence", None) or (
                f.get("evidence", "") if isinstance(f, dict) else ""
            )
            out(f"### [{sev}] {title}  _({cat}, {agent})_")
            if url:
                out(f"- **URL:** {url}")
            if evidence:
                out("- **Evidence:**")
                out("  ```")
                for ln in str(evidence).splitlines():
                    out(f"  {ln}")
                out("  ```")
            out("")

    # -- Per-agent results --
    out("## Per-agent results")
    out("")
    if not agent_results:
        out("_No agent_results recorded._")
    else:
        for ar in agent_results:
            agent_id = getattr(ar, "agent_id", None) or (
                ar.get("agent_id") if isinstance(ar, dict) else "?"
            )
            cfg = getattr(ar, "config_name", None) or (
                ar.get("config_name") if isinstance(ar, dict) else "?"
            )
            phase = getattr(ar, "phase", None) or (
                ar.get("phase", "?") if isinstance(ar, dict) else "?"
            )
            completed = getattr(ar, "completed", None)
            if completed is None and isinstance(ar, dict):
                completed = ar.get("completed")
            err = getattr(ar, "error", None) or (
                ar.get("error") if isinstance(ar, dict) else None
            )
            ar_findings = getattr(ar, "findings", None) or (
                ar.get("findings", []) if isinstance(ar, dict) else []
            )
            out(f"### `{agent_id}`  _({cfg} / {phase})_")
            out(f"- completed: {completed}")
            if err:
                out(f"- error: `{err}`")
            out(f"- findings: {len(ar_findings)}")
            out("")

    # -- Full message stream --
    out("## Full message stream")
    out("")
    if not messages:
        out("_No messages._")
    else:
        for i, m in enumerate(messages):
            node = (getattr(m, "additional_kwargs", None) or {}).get("node") or "—"
            role = _msg_role(m)
            text = _msg_text(m)
            out(f"### {i+1}. `{role}` _(node: {node})_")
            out("")
            out("```")
            for ln in text.splitlines() or [""]:
                out(ln)
            out("```")
            out("")

    # -- Per-node full results (collapsible-ish) --
    out("## Per-node full result dumps")
    out("")
    for i, ev in enumerate(nodes, 1):
        out(f"### {i}. `{ev.get('node', '?')}` ({ev.get('duration_ms', '?')} ms)")
        out("")
        out("```json")
        out(json.dumps(ev.get("result"), indent=2, default=str, ensure_ascii=False))
        out("```")
        out("")

    path = run_dir(run_id) / "summary.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# Re-export the live renderer so callers can keep doing
# ``from src.observability import LIVE`` even though the renderer itself
# lives at ``src/live.py``. Imported at the bottom because the renderer
# does a lazy ``from src.graph import config``; either order works
# (live.py defers config access to call time), but bottom keeps the
# disk-logging surface above the renderer surface for readers.
from src.live import LIVE, HttpxQuietFilter, LiveLogHandler  # noqa: E402
