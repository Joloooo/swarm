"""All JSONL appenders + the final-state writer for one run.

Each artefact written under ``logs/run-<run_id>/`` has its own writer
function in this file. The shape is uniform — open the file in append
mode under a per-artefact lock, JSON-serialise one row, write one
line — so they share the ``_JsonlWriter`` helper.

Artefacts:

  - ``nodes.jsonl``           — :func:`append_node_event` (called from
                                 ``BaseNode.__call__`` per node finish)
  - ``worker_traces.jsonl``   — :func:`append_worker_trace` (called from
                                 ``run_skill_agent`` per worker finish)
  - ``llm_calls.jsonl``       — :func:`append_llm_event` (called from
                                 ``TokenLoggingCallback`` per LLM call)
  - ``terminal_events.jsonl`` — :func:`append_terminal_event` (called from
                                 ``src/tools/shell/_common.py`` per
                                 shell command)
  - ``refusals.jsonl``        — :func:`append_refusal` (called from
                                 ``src/nodes/base/skill_runner.py`` per
                                 cyber_policy refusal). FOLLOW-UP: this
                                 artefact is nearly redundant with
                                 ``llm_calls.jsonl`` error rows; flagged
                                 as a deletion candidate in a future
                                 session.
  - ``final_state.json``      — :func:`write_final_state` (called from
                                 the runner at end-of-run)

Run-id resolution helpers (``make_run_id``, ``run_dir``, ``LOGS_ROOT``)
also live here because they are file-system concerns.

Why one file: every writer is the same shape. They belong together so
``grep -rn "<artefact>.jsonl"`` finds the writer in one searchable
file. If any individual writer grows past ~80 lines (e.g. complex
serialization), split THAT one out then; default to the simpler shape.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import threading
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from src.refusals.errors import RefusalError

logger = logging.getLogger(__name__)


# logs/ at project root. ``__file__`` is observability/writers.py so we
# go up three (writers.py → observability/ → src/ → project root).
LOGS_ROOT = Path(__file__).resolve().parents[2] / "logs"


# ────────────────────────────────────────────────────────────────────────────
# Per-artefact thread locks. Parallel executor workers append concurrently;
# the lock keeps lines atomic so a half-flushed JSONL row never appears.
# One lock per file is enough — different artefacts can be written in
# parallel without coordination.
# ────────────────────────────────────────────────────────────────────────────


_NODES_LOCK = threading.Lock()
_WORKER_TRACES_LOCK = threading.Lock()
_LLM_CALLS_LOCK = threading.Lock()
_TERMINAL_EVENTS_LOCK = threading.Lock()
_REFUSALS_LOCK = threading.Lock()


# ────────────────────────────────────────────────────────────────────────────
# Run-id resolution + directory paths
# ────────────────────────────────────────────────────────────────────────────


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


# ────────────────────────────────────────────────────────────────────────────
# JSONL writers — one function per artefact, sharing the same shape.
# ────────────────────────────────────────────────────────────────────────────


def _append_jsonl(path: Path, payload: dict | list[dict], lock: threading.Lock) -> None:
    """Shared body for every JSONL appender.

    Serialises one row (or N rows when ``payload`` is a list) and
    writes them under the per-artefact lock. Best-effort — failures
    log a warning but never raise; observability must not break the
    graph run.
    """
    try:
        rows = payload if isinstance(payload, list) else [payload]
        if not rows:
            return
        lines = [
            json.dumps(r, default=str, ensure_ascii=False) + "\n"
            for r in rows
        ]
        with lock, path.open("a", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:  # noqa: BLE001
        logger.warning("Could not append to %s: %s", path, e)


def append_node_event(run_id: str, event: dict) -> None:
    """Append one JSON line to ``nodes.jsonl``.

    Called from ``BaseNode.__call__`` after every node finish. Each
    row carries timestamp, node name, run id, duration, summary, the
    state shape before/after, and the per-call ``delta`` block (full
    text of every newly added message / finding).
    """
    _append_jsonl(run_dir(run_id) / "nodes.jsonl", event, _NODES_LOCK)


def append_worker_trace(run_id: str, rows: list[dict]) -> Path:
    """Append worker trace messages to ``worker_traces.jsonl``.

    Replaces the older per-worker subdirectory layout
    (``worker-<agent_id>-<ts>/trace.jsonl``) which produced one folder
    per worker invocation — that didn't scale to 15+ workers per bench
    and made the run directory hard to navigate. Each row in the
    consolidated file carries ``agent_id`` and ``dispatch_ts`` fields
    so multiple invocations of the same worker stay distinguishable;
    ``i`` is the message index within a single dispatch.

    Returns the file path (constant per run) for the caller's benefit.
    """
    path = run_dir(run_id) / "worker_traces.jsonl"
    if rows:
        _append_jsonl(path, rows, _WORKER_TRACES_LOCK)
    return path


def append_llm_event(run_id: str | None, event: dict) -> None:
    """Append one JSON line to ``llm_calls.jsonl``.

    Called from ``TokenLoggingCallback`` for every LLM call: one
    ``phase=start`` row when the call begins, one ``phase=end`` (or
    ``phase=error``) row when it ends. The summary builder pairs them
    by ``lc_run_id`` to render per-call cost.

    Tolerates ``run_id=None`` (e.g. callbacks that fire before the
    run id is propagated) by no-op'ing — better silent drop than crash.
    """
    if not run_id:
        return
    _append_jsonl(run_dir(run_id) / "llm_calls.jsonl", event, _LLM_CALLS_LOCK)


def append_terminal_event(run_id: str | None, event: dict) -> None:
    """Append one JSON line to ``terminal_events.jsonl``.

    Called from the bash + tmux tool wrappers per shell command. Each
    row carries timestamp, agent, command, exit_code, duration_ms,
    bytes, tail, and reasoning — mirroring what ``LIVE.shell_command``
    and ``LIVE.shell_output`` render to stderr.
    """
    if not run_id:
        return
    _append_jsonl(
        run_dir(run_id) / "terminal_events.jsonl", event, _TERMINAL_EVENTS_LOCK,
    )


def append_refusal(err: "RefusalError", *, run_id: str | None) -> None:
    """Append one JSON line to ``refusals.jsonl``.

    Takes a :class:`src.refusals.errors.RefusalError` and serialises
    its structured fields (agent_id, skill_name, iteration, request
    sizes, attempts made, last tier attempted, raw refusal message).
    Called from ``run_skill_agent`` once the tier ladder has exhausted.

    FOLLOW-UP: this artefact is nearly redundant with
    ``llm_calls.jsonl`` error rows, undercounts (only writes once per
    tier-exhausted worker, not once per retry), and the
    ``refusal_message`` field is identical generic Codex boilerplate
    for every row. A future session should evaluate deleting it
    entirely and computing the count from ``llm_calls.jsonl`` rows
    where ``error_type`` matches the refusal pattern. NOT done in
    this refactor (the rule was "no behaviour change").
    """
    if not run_id:
        return
    payload = {
        "ts": _now_iso(),
        "run_id": run_id,
        **asdict(err),
    }
    _append_jsonl(
        run_dir(run_id) / "refusals.jsonl", payload, _REFUSALS_LOCK,
    )


def write_final_state(run_id: str, state: dict) -> Path:
    """Dump the full agent_state to ``final_state.json``.

    Called once at end-of-run by the runner. Unlike the JSONL appenders
    this is a one-shot write of the entire state dict; failure here is
    not swallowed — the summary builder consumes the file.
    """
    path = run_dir(run_id) / "final_state.json"
    path.write_text(
        json.dumps(state, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def _now_iso() -> str:
    """Return the current local time as ``YYYY-MM-DDTHH:MM:SS``.

    Matches the timestamp shape used by the legacy
    ``src/llm/refusal.py:log_refusal`` so existing tests + log
    parsers keep working unchanged.
    """
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%S")
