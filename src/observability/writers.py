"""Disk writers for the per-run debug logs.

Each run writes two artefacts under ``logs/run-<run_id>/``:

  - ``full_logs.jsonl``              — every LLM call (start + end / error
                                        rows) and every shell command,
                                        chronologically interleaved.
                                        One row per event. Each row has a
                                        ``type`` field so consumers can
                                        filter (``llm_start``, ``llm_end``,
                                        ``llm_error``, ``shell_*``, …).
                                        Written by :func:`append_event`.
  - ``displayed_terminal_logs.log``   — plain-text mirror of the live
                                        ticker output, ANSI-stripped so
                                        any editor / ``grep`` works.
                                        Written by the LIVE renderer
                                        through the sink configured in
                                        :func:`set_terminal_log_file`.

History — the pre-refactor run dir had seven files (``nodes.jsonl``,
``worker_traces.jsonl``, ``llm_calls.jsonl``, ``terminal_events.jsonl``,
``refusals.jsonl``, ``final_state.json``, ``summary.md``). Five never
got read in practice; three were redundant with each other. The two
files above are the survivors that actually answer debugging
questions: ``full_logs.jsonl`` for "what did the model see / what did
the tools do", ``displayed_terminal_logs.log`` for "what was the
human-readable story of the run".
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import threading
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# logs/ at project root. ``__file__`` is observability/writers.py so we
# go up three (writers.py → observability/ → src/ → project root).
LOGS_ROOT = Path(__file__).resolve().parents[2] / "logs"


# Per-artefact locks. Parallel executors emit concurrently; the lock keeps
# JSONL rows atomic so a half-flushed line never appears.
_FULL_LOGS_LOCK = threading.Lock()
_TERMINAL_LOG_LOCK = threading.Lock()


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


def full_logs_path(run_id: str) -> Path:
    """Return the path to ``full_logs.jsonl`` for a run."""
    return run_dir(run_id) / "full_logs.jsonl"


def terminal_log_path(run_id: str) -> Path:
    """Return the path to ``displayed_terminal_logs.log`` for a run."""
    return run_dir(run_id) / "displayed_terminal_logs.log"


# ────────────────────────────────────────────────────────────────────────────
# Unified event writer — every structured event in one chronological file.
# ────────────────────────────────────────────────────────────────────────────


def append_event(run_id: str | None, type: str, **fields: object) -> None:
    """Append one event row to ``full_logs.jsonl``.

    ``type`` is required and identifies the event kind so consumers can
    filter with ``jq 'select(.type == "shell_output")'`` and similar.
    Conventional types:

      * ``llm_start``   — LLM call begins (with full prompt).
      * ``llm_end``     — LLM call completes (with response + tokens).
      * ``llm_error``   — LLM call raised (refusal, network, etc.).
      * ``shell_command``, ``shell_output``, ``shell_spawn``,
        ``shell_blocked``, … — one row per shell event.

    Best-effort: failures log a warning but never raise. Observability
    must not break a graph run. Tolerates ``run_id=None`` (e.g. callbacks
    fired before the run id is propagated) by no-op'ing.
    """
    if not run_id:
        return
    try:
        row = {
            "ts": dt.datetime.now().isoformat(timespec="milliseconds"),
            "type": type,
            **fields,
        }
        line = json.dumps(row, default=str, ensure_ascii=False) + "\n"
        path = full_logs_path(run_id)
        with _FULL_LOGS_LOCK, path.open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:  # noqa: BLE001 — observability must not break the graph
        logger.warning("append_event(%s) failed: %s", type, e)


# ────────────────────────────────────────────────────────────────────────────
# Plain-text terminal-log sink — set once at run start by the runner.
#
# The LIVE renderer (src/observability/live.py) calls
# ``write_terminal_line(text)`` for every line it emits to stderr. This
# function tees that text (ANSI-stripped) to ``displayed_terminal_logs.log``
# so the file is a verbatim, color-stripped mirror of what showed on
# screen.
# ────────────────────────────────────────────────────────────────────────────


# Single sink path for the whole process. ``None`` means "do not write a
# file" — the LIVE renderer continues to print to stderr regardless.
_TERMINAL_LOG_FILE: Path | None = None


# ANSI CSI escape sequences (colours, cursor moves). Stripped so the
# saved file opens cleanly in plain editors / behaves under ``grep``.
_ANSI_RE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")


def set_terminal_log_file(path: Path | None) -> None:
    """Set (or clear) the path the LIVE renderer tees output to.

    Called once from the benchmark runner / CLI entry after the run_id
    is known. Passing ``None`` disables file output (useful for Studio
    / langgraph dev sessions where there is no run dir yet).
    """
    global _TERMINAL_LOG_FILE
    if path is None:
        _TERMINAL_LOG_FILE = None
        return
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _TERMINAL_LOG_FILE = path


def get_terminal_log_file() -> Path | None:
    return _TERMINAL_LOG_FILE


def write_terminal_line(line: str) -> None:
    """Append one line to ``displayed_terminal_logs.log`` if a sink is set.

    Strips ANSI escape codes so the file is readable in any editor.
    The trailing newline is added if not already present. Best-effort —
    failures swallow silently (LIVE must always print to stderr).
    """
    path = _TERMINAL_LOG_FILE
    if path is None:
        return
    try:
        stripped = _ANSI_RE.sub("", line)
        if not stripped.endswith("\n"):
            stripped += "\n"
        with _TERMINAL_LOG_LOCK, path.open("a", encoding="utf-8") as f:
            f.write(stripped)
    except Exception:
        # Never let log writes break a run. The screen has the data either way.
        pass


def write_terminal_chunk(text: str) -> None:
    """Append a raw chunk (no newline added) to ``displayed_terminal_logs.log``.

    Used by the streaming reasoning path in ``src/observability/live.py``
    where chunks are sub-line fragments that get concatenated into
    paragraphs as the model emits them. The companion
    :func:`write_terminal_line` would corrupt the stream by injecting a
    newline after every word.

    Strips ANSI escape codes so the saved file stays editor-friendly.
    Best-effort: failures swallow silently.
    """
    path = _TERMINAL_LOG_FILE
    if path is None or not text:
        return
    try:
        stripped = _ANSI_RE.sub("", text)
        with _TERMINAL_LOG_LOCK, path.open("a", encoding="utf-8") as f:
            f.write(stripped)
    except Exception:
        pass
