"""Disk writers for the per-run debug logs.

Each run writes three artefacts under ``logs/run-<run_id>/``:

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
  - ``displayed_terminal_logs.ansi.log`` — colour-preserving sibling of
                                        the terminal log for exact replay
                                        of what was printed.

History — the pre-refactor run dir had seven files (``nodes.jsonl``,
``worker_traces.jsonl``, ``llm_calls.jsonl``, ``terminal_events.jsonl``,
``refusals.jsonl``, ``final_state.json``, ``summary.md``). Five never
got read in practice; three were redundant with each other. The two
files above are the survivors that actually answer debugging
questions: ``full_logs.jsonl`` for "what did the model see / what did
the tools do", and ``displayed_terminal_logs.log`` for "what was the
human-readable story of the run". The optional ``.ansi.log`` sibling
keeps the exact colour/cursor stream for terminal replay.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import threading
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# logs/ at project root. ``__file__`` is observability/writers.py so we
# go up three (writers.py → observability/ → src/ → project root).
#
# ``SWARM_LOGS_ROOT`` overrides the default so a parallel "campaign" sweep
# can redirect every per-run log dir under one folder
# (e.g. ``logs/full_run_<ts>/``) instead of the flat ``logs/`` root — see
# benchmarks/launch_split.py. Read once at import, exactly like the
# historical hardcoded path: each benchmark runs in a fresh subprocess
# that inherits the env, so the override is in place before this module
# is imported. Unset ⇒ byte-identical to the previous behaviour.
_DEFAULT_LOGS_ROOT = Path(__file__).resolve().parents[2] / "logs"
LOGS_ROOT = (
    Path(os.environ["SWARM_LOGS_ROOT"]).expanduser()
    if os.environ.get("SWARM_LOGS_ROOT")
    else _DEFAULT_LOGS_ROOT
)


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

    Format:  ``<MM-DD>_<HHhMMmSSs>_<slug>``
    Example: ``05-25_16h40m26s_XBEN-006``

    Date-first so ``ls logs/`` sorts chronologically. Year is omitted —
    operators distinguish years by archive folder, not by filename. The
    XBEN benchmark-year suffix (``-24``) is stripped from the slug for
    the same reason: it's the same value for every benchmark in the
    current set and adds noise.
    """
    now = dt.datetime.now()
    ts = now.strftime("%m-%d_%Hh%Mm%Ss")
    if benchmark_id:
        # Drop the trailing two-digit bench year (``-24`` today, ``-25``
        # when the next batch lands). Conservative regex — only strips
        # ``-NN`` at the very end, leaves IDs without that shape alone.
        bid = re.sub(r"-\d{2}$", "", benchmark_id)
        slug = _slug(bid)
    elif target_url:
        parsed = urlparse(target_url)
        host = parsed.hostname or "unknown"
        port = f"-{parsed.port}" if parsed.port else ""
        slug = _slug(f"target-{host}{port}")
    else:
        slug = "studio"
    return f"{ts}_{slug}"


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
      * ``log``         — mirrored stdlib ``logger.*`` call (installed
                          by :class:`JsonlLogHandler`).
      * ``flag_auto_verified``  — skill_runner detected a worker tool
                          message strict-equal to ``state.expected_flag``.
      * ``routing_decision``    — a conditional edge chose its next node
                          (e.g. ``route_after_summarizer`` → END).

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
# Stdlib-logging mirror — capture every ``logger.*`` call into full_logs.jsonl
# so the structured log is the single source of truth.
#
# History — 2026-05-25 XBEN-006-24 timed out with three workers having
# captured the flag literal in tool output. The skill-runner's auto-verify
# block called ``node.log.info("auto-verified flag …")`` which IS the
# load-bearing signal that "we matched". But in compact mode (the default
# runtime mode) the root logger is set to WARNING — that INFO line was
# silently dropped. There was no record anywhere on disk that the scan
# had even fired. The diagnosis took 30 minutes of reading code to rule
# out other branches. With this handler the same scan emits a row to
# ``full_logs.jsonl`` regardless of console verbosity.
# ────────────────────────────────────────────────────────────────────────────


# Logger-name prefixes that produce too much noise (and no insight) to
# mirror — third-party HTTP / async machinery. Anything not on this list
# is captured. Keep the list short; better to err on the side of
# capturing than silently filtering something a future debugger needs.
_LOGGER_NOISE_PREFIXES = (
    "httpx",
    "httpcore",
    "openai",
    "anthropic",
    "urllib3",
    "asyncio",
    "websockets",
    "h11",
    "h2",
)


# Loggers we explicitly want to capture — the root-of-tree names. We
# attach our handler to each of these (not the global root) so that
# pure third-party records that propagate up to root are skipped without
# needing the noise filter to enumerate them all.
_LOGGER_TARGETS = ("src", "node", "benchmarks")


class JsonlLogHandler(logging.Handler):
    """Mirror every stdlib ``logger.*`` call into ``full_logs.jsonl``.

    Resolves the active run_id per-emit from the terminal-log sink path
    (the same mechanism :func:`src.tools.shell._common.log_event` uses)
    so the handler can be installed once at process start and route to
    the correct per-bench log file automatically — no per-run wiring.

    Captures at ``DEBUG`` level. The handler is attached to a curated
    set of parent loggers (``src``, ``node``, ``benchmarks``) rather
    than the global root, so third-party libraries that happen to log
    at WARNING/ERROR (httpx, openai, …) don't pollute the JSONL even
    if their records would otherwise propagate to root.
    """

    def emit(self, record: logging.LogRecord) -> None:
        # Belt-and-braces noise filter — even though we attach to
        # ``src`` / ``node`` / ``benchmarks`` rather than root, callers
        # sometimes write under unexpected names; this catches them.
        if any(record.name.startswith(p) for p in _LOGGER_NOISE_PREFIXES):
            return
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return
        rid = _resolve_active_run_id()
        if not rid:
            return
        fields: dict[str, object] = {
            "level": record.levelname,
            "logger": record.name,
            "msg": msg,
        }
        # Surface the path:line so a future reader can jump straight
        # to the call site. Cheap and almost always wanted.
        if record.pathname:
            fields["where"] = f"{record.pathname}:{record.lineno}"
        if record.exc_info:
            try:
                fields["exc"] = self.format(record)
            except Exception:  # noqa: BLE001
                pass
        try:
            append_event(rid, "log", **fields)
        except Exception:  # noqa: BLE001
            # Observability must not break the graph — and our own
            # append_event already logs its own failures.
            pass


def _resolve_active_run_id() -> str | None:
    """Best-effort: derive run_id from the terminal-log sink path.

    Mirrors :func:`src.tools.shell._common._RUN_ID_for_logging` so this
    module stays self-contained. Returns ``None`` between benches (when
    :func:`set_terminal_log_file` has been called with ``None``), which
    correctly causes the handler to no-op for any stray logs that fire
    after a run ends.
    """
    sink = _TERMINAL_LOG_FILE
    if sink is None:
        return None
    parent = sink.parent.name  # "run-<run_id>"
    if parent.startswith("run-"):
        return parent[len("run-"):]
    return None


# Single global handler — installed once at process start by the
# runner. Stored at module level so re-installation is idempotent
# (e.g. ``xbow_runner`` invoked twice in the same process).
_JSONL_LOG_HANDLER: JsonlLogHandler | None = None


def install_jsonl_log_handler() -> None:
    """Attach :class:`JsonlLogHandler` to ``src`` / ``node`` / ``benchmarks``.

    Idempotent. Called once from the runner's main(). The handler then
    routes per-bench via the terminal-log sink path; no per-run wiring
    is required.

    Why we attach to specific parent loggers instead of root: the root
    logger also processes third-party records (httpx warnings, openai
    rate-limit notices). Attaching here scopes the mirror to our code.
    Child loggers like ``node.executor`` and ``src.nodes.summarizer``
    propagate to these parents by default, so coverage is total for
    anything we own.

    Also lowers each target logger's effective level to ``DEBUG`` so
    INFO records actually reach the handler — they would otherwise be
    filtered at the logger level (the root WARNING in compact mode
    blocks INFO from propagating in the first place). The new lower
    level affects ONLY records flowing through these loggers — root
    and its existing handlers (LiveLogHandler, basicConfig
    StreamHandler) keep their own levels and behaviour.
    """
    global _JSONL_LOG_HANDLER
    if _JSONL_LOG_HANDLER is not None:
        return  # already installed
    handler = JsonlLogHandler(level=logging.DEBUG)
    for name in _LOGGER_TARGETS:
        log = logging.getLogger(name)
        # NOTSET (0) means inherit from parent; bump to DEBUG so INFO
        # records pass the logger-level filter and reach our handler.
        if log.level == logging.NOTSET or log.level > logging.DEBUG:
            log.setLevel(logging.DEBUG)
        log.addHandler(handler)
    _JSONL_LOG_HANDLER = handler


def uninstall_jsonl_log_handler() -> None:
    """Detach the JSONL log handler. Idempotent. Used by tests."""
    global _JSONL_LOG_HANDLER
    if _JSONL_LOG_HANDLER is None:
        return
    for name in _LOGGER_TARGETS:
        try:
            logging.getLogger(name).removeHandler(_JSONL_LOG_HANDLER)
        except Exception:  # noqa: BLE001
            pass
    _JSONL_LOG_HANDLER = None


# ────────────────────────────────────────────────────────────────────────────
# Terminal-log sinks — set once at run start by the runner.
#
# The LIVE renderer (src/observability/live.py) calls
# ``write_terminal_line(text)`` for every line it emits to stderr. This
# function tees that text (ANSI-stripped) to the plain ``*.log`` sink.
# ────────────────────────────────────────────────────────────────────────────


# Single sink path for the whole process. ``None`` means "do not write a
# file" — the LIVE renderer continues to print to stderr regardless.
_TERMINAL_LOG_FILE: Path | None = None
_TERMINAL_ANSI_LOG_FILE: Path | None = None


# A SECOND, sweep-level sink. Unlike ``_TERMINAL_LOG_FILE`` (which the
# benchmark runner points at each run's ``displayed_terminal_logs.log``
# and then CLEARS to ``None`` between benches), this one stays attached
# for the whole runner invocation. It exists so the cross-bench lines the
# per-run sink misses — the ``bench_end`` verdict block ("◆ XBEN-… ✓ FLAG
# FOUND …") and the final ``Summary: N pass …`` tally, both emitted while
# the per-run sink is ``None`` — still land in a file. ``write_terminal_
# line`` / ``write_terminal_chunk`` tee to BOTH sinks. ``None`` disables it.
_SWEEP_LOG_FILE: Path | None = None
_SWEEP_ANSI_LOG_FILE: Path | None = None


# ANSI CSI escape sequences (colours, cursor moves). Stripped so the
# saved file opens cleanly in plain editors / behaves under ``grep``.
_ANSI_RE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")


def set_terminal_log_file(path: Path | None) -> None:
    """Set (or clear) the path the LIVE renderer tees output to.

    Called once from the benchmark runner / CLI entry after the run_id
    is known. Passing ``None`` disables per-run file output.
    """
    global _TERMINAL_LOG_FILE, _TERMINAL_ANSI_LOG_FILE
    if path is None:
        _TERMINAL_LOG_FILE = None
        _TERMINAL_ANSI_LOG_FILE = None
        return
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _TERMINAL_LOG_FILE = path
    # ANSI sink intentionally disabled: the raw-colour ``*.ansi.log`` was a
    # byte-for-byte duplicate of the plain ``*.log`` (minus the escape codes)
    # that nothing consumed and only cluttered every run dir. Keep the plain
    # log only. (Left as ``None`` so the tee loops in write_terminal_* skip it.)
    _TERMINAL_ANSI_LOG_FILE = None


def get_terminal_log_file() -> Path | None:
    return _TERMINAL_LOG_FILE


def get_terminal_ansi_log_file() -> Path | None:
    return _TERMINAL_ANSI_LOG_FILE


def set_sweep_log_file(path: Path | None) -> None:
    """Set (or clear) the sweep-level sink.

    Unlike :func:`set_terminal_log_file` (per-bench, cleared between
    benches), this sink stays attached for the whole runner invocation so
    the per-bench verdict blocks and the final ``Summary`` line — emitted
    while the per-run sink is ``None`` — are persisted. ``None`` disables it.
    """
    global _SWEEP_LOG_FILE, _SWEEP_ANSI_LOG_FILE
    if path is None:
        _SWEEP_LOG_FILE = None
        _SWEEP_ANSI_LOG_FILE = None
        return
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _SWEEP_LOG_FILE = path
    # ANSI sink disabled — see set_terminal_log_file. Plain sweep log only.
    _SWEEP_ANSI_LOG_FILE = None


def get_sweep_log_file() -> Path | None:
    return _SWEEP_LOG_FILE


def get_sweep_ansi_log_file() -> Path | None:
    return _SWEEP_ANSI_LOG_FILE


def write_terminal_line(line: str) -> None:
    """Append one line to the active terminal-log sink(s).

    Tees to the per-run sink (``displayed_terminal_logs.log``) AND, when
    set, the sweep-level sink (:func:`set_sweep_log_file`) so cross-bench
    verdict/summary lines are persisted too. The files are ANSI-stripped so
    any editor / ``grep`` works. The trailing newline is added if not already
    present. Best-effort — failures swallow silently (LIVE must always print
    to stderr).
    """
    if (
        _TERMINAL_LOG_FILE is None
        and _SWEEP_LOG_FILE is None
        and _TERMINAL_ANSI_LOG_FILE is None
        and _SWEEP_ANSI_LOG_FILE is None
    ):
        return
    stripped = _ANSI_RE.sub("", line)
    if not stripped.endswith("\n"):
        stripped += "\n"
    raw = line if line.endswith("\n") else line + "\n"
    with _TERMINAL_LOG_LOCK:
        for path in (_TERMINAL_LOG_FILE, _SWEEP_LOG_FILE):
            if path is None:
                continue
            try:
                with path.open("a", encoding="utf-8") as f:
                    f.write(stripped)
            except Exception:
                # Never let log writes break a run. The screen has the data either way.
                pass
        for path in (_TERMINAL_ANSI_LOG_FILE, _SWEEP_ANSI_LOG_FILE):
            if path is None:
                continue
            try:
                with path.open("a", encoding="utf-8") as f:
                    f.write(raw)
            except Exception:
                pass


def write_terminal_chunk(text: str) -> None:
    """Append a raw chunk (no newline added) to the active sink(s).

    Used by the streaming reasoning path in ``src/observability/live.py``
    where chunks are sub-line fragments that get concatenated into
    paragraphs as the model emits them. The companion
    :func:`write_terminal_line` would corrupt the stream by injecting a
    newline after every word. Tees to both the per-run and sweep sinks.

    The ``*.log`` files stay ANSI-stripped and editor-friendly. Best-effort:
    failures swallow silently.
    """
    if (
        _TERMINAL_LOG_FILE is None
        and _SWEEP_LOG_FILE is None
        and _TERMINAL_ANSI_LOG_FILE is None
        and _SWEEP_ANSI_LOG_FILE is None
    ) or not text:
        return
    stripped = _ANSI_RE.sub("", text)
    with _TERMINAL_LOG_LOCK:
        for path in (_TERMINAL_LOG_FILE, _SWEEP_LOG_FILE):
            if path is None:
                continue
            try:
                with path.open("a", encoding="utf-8") as f:
                    f.write(stripped)
            except Exception:
                pass
        for path in (_TERMINAL_ANSI_LOG_FILE, _SWEEP_ANSI_LOG_FILE):
            if path is None:
                continue
            try:
                with path.open("a", encoding="utf-8") as f:
                    f.write(text)
            except Exception:
                pass
