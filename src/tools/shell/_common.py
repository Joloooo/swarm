"""Shared utilities for the shell tools (bash + tmux).

Both ``bash.py`` and ``tmux.py`` need the same plumbing:

- One row per shell event in the shared ``full_logs.jsonl`` (via
  :func:`src.observability.writers.append_event` — same file the LLM
  events land in, interleaved chronologically).
- A live-stream "watch the agent think" stderr printer.
- Head-and-tail truncation that keeps output the LLM sees bounded.
- A per-run, per-agent workspace directory under
  ``~/swarm-workspace/<run_id>/<agent_id>/`` where files produced by
  the agent (``nmap -oX scan.xml``, sqlmap session dirs, ...) land
  with predictable relative paths.

Keeping these here means both shell tools log via the same writer with
the same shape, so ``jq 'select(.type == "bash_output")'`` works
uniformly. It also lets you swap backends per tool without touching
the observability layer.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# -- Run identity & workspace ------------------------------------------------
#
# A "run" is one end-to-end invocation of the graph. The runner (CLI or
# benchmark harness) calls ``set_run_id()`` early to lock in a stable id;
# if it never does, we synthesize one from the wall clock + pid so a
# bare ``langgraph dev`` session still gets a sane workspace.

_RUN_ID: str = f"run-{datetime.now():%Y%m%d-%H%M%S}-{os.getpid()}"

_DEFAULT_WORKSPACE_ROOT = Path(
    os.getenv("SWARM_WORKSPACE_ROOT", str(Path.home() / "swarm-workspace"))
)
_WORKSPACE_ROOT: Path = _DEFAULT_WORKSPACE_ROOT


def set_run_id(run_id: str) -> str:
    """Override the run id used for workspace paths.

    Call this once from the benchmark runner / CLI before any agent has
    started so all bash/tmux workspaces share the same root.
    Returns the value actually used (so callers can log it).
    """
    global _RUN_ID
    _RUN_ID = run_id
    return _RUN_ID


def get_run_id() -> str:
    return _RUN_ID


def set_workspace_root(path: Path) -> Path:
    """Override the workspace root directory. Mostly for tests."""
    global _WORKSPACE_ROOT
    _WORKSPACE_ROOT = Path(path)
    return _WORKSPACE_ROOT


def workspace_for(agent_id: str) -> Path:
    """Return ``<root>/<run_id>/<agent_id>/``, creating it if missing.

    Used by both ``bash.py`` and ``tmux.py`` so the agent's commands
    have a predictable cwd and a place to drop output files.
    """
    p = _WORKSPACE_ROOT / _RUN_ID / agent_id
    p.mkdir(parents=True, exist_ok=True)
    # The hidden ``.swarm/`` subdirectory holds per-command bookkeeping
    # files (.out, .err, .exit, .cwd) written by the bash wrapper. Kept
    # hidden so an ``ls`` in the workspace shows just the user-visible
    # tool output.
    (p / ".swarm").mkdir(exist_ok=True)
    return p


# -- JSONL event log ---------------------------------------------------------
#
# Pre-refactor we wrote shell events to a standalone ``terminal_events.jsonl``
# with its own log-file plumbing (set_log_file / get_log_file). The unified
# log layout collapses that into ``logs/run-<run_id>/full_logs.jsonl`` via
# :func:`src.observability.writers.append_event` — same file the LLM events
# land in, interleaved chronologically.
#
# ``set_log_file`` / ``get_log_file`` are kept as no-op shims for any
# remaining call sites in third-party / older harnesses. The runner does
# not call them any more.


def set_log_file(path: Path) -> Path:
    """No-op shim. Shell events now go to ``full_logs.jsonl`` via the
    central writer; the path argument is ignored. Retained so existing
    benchmark harnesses can call it without breaking.
    """
    return Path(path)


def get_log_file() -> Path:
    """Compatibility shim — there is no longer a single shell log file.

    Returns a placeholder path inside the most recent run dir so a
    caller printing the value still sees something sensible. For the
    real artefacts, look under ``logs/run-<run_id>/``.
    """
    try:
        from src.observability.writers import LOGS_ROOT, get_terminal_log_file
        sink = get_terminal_log_file()
        if sink is not None:
            return sink
        return LOGS_ROOT
    except Exception:
        return Path("logs")


def _verbose_print(event: str, *, agent: str | None, payload: dict) -> None:
    """Stream a human-readable view of a tool event to stderr.

    Routes through :data:`src.observability.LIVE` so the active
    verbosity mode (``silent`` / ``compact`` / ``verbose``) decides what
    actually shows up. The live config lives at ``config.verbosity.mode``
    in ``src/graph.py``.

    The renderer is imported lazily to keep this module dependency-light
    and to avoid the
    ``graph → nodes → base → observability → graph`` import cycle.
    """
    if event not in ("command", "output", "bash_command", "bash_output"):
        return
    try:
        from src.observability import LIVE  # lazy — avoid import cycle
    except Exception:
        return
    if event in ("command", "bash_command"):
        backend = "bash" if event == "bash_command" else "tmux"
        LIVE.shell_command(
            agent=agent,
            backend=backend,
            cmd=str(payload.get("cmd", "")),
            reasoning=str(payload.get("reasoning", "") or ""),
        )
    else:
        LIVE.shell_output(
            agent=agent,
            exit_code=payload.get("exit_code"),
            duration_ms=payload.get("duration_ms", "?"),
            n_bytes=payload.get("bytes", "?"),
            tail=str(payload.get("tail", "") or ""),
        )


def log_event(event: str, *, agent: str | None = None, **payload: Any) -> None:
    """Append one shell event to ``full_logs.jsonl`` via the unified writer.

    Never raises — logging is observability, not a hard dependency. If
    the writer can't open its file, the graph still finishes.

    Also streams a human-readable rendering of ``command`` / ``output``
    events to stderr via the LIVE renderer so the user can watch the
    agent live (mode-gated by ``config.verbosity.mode``).
    """
    _verbose_print(event, agent=agent, payload=payload)
    try:
        # Lazy import — keeps this module dependency-light and avoids
        # any chance of an import-time cycle with ``src.observability``.
        from src.observability.writers import append_event

        fields: dict[str, Any] = dict(payload)
        if agent is not None:
            fields["agent"] = agent
        # The shell backends use bare event names like ``bash_command``,
        # ``bash_output``, ``session_kill_noop``. Prefix with ``shell_``
        # is unnecessary — bash/tmux events are already distinctive.
        # Consumers filter with e.g. ``jq 'select(.type == "bash_output")'``.
        append_event(_RUN_ID_for_logging(), event, **fields)
    except Exception:
        # Intentionally swallow. Do NOT let a log failure interrupt a run.
        pass


def _RUN_ID_for_logging() -> str | None:
    """Best-effort lookup of the active run_id for the unified writer.

    The shell tools have always derived their workspace path from the
    in-process ``_RUN_ID`` (see ``set_run_id`` at the top of this file).
    The unified writer expects a different shape — the same id the
    observability layer was initialised with. Pull it from the
    terminal-log sink path if the runner set one; fall back to the
    shell ``_RUN_ID``.
    """
    try:
        from src.observability.writers import get_terminal_log_file
        sink = get_terminal_log_file()
        if sink is not None:
            # Path shape: logs/run-<run_id>/displayed_terminal_logs.log
            parent = sink.parent.name  # "run-<run_id>"
            if parent.startswith("run-"):
                return parent[len("run-"):]
    except Exception:
        pass
    return _RUN_ID


# Legacy alias — terminal.py used a leading underscore. We expose both so
# old call sites importing the private name through the shim still work,
# and new code uses the un-prefixed public name.
_log_event = log_event


# -- Output formatting -------------------------------------------------------


def truncate_output(output: str, *, head: int = 100, tail: int = 50) -> str:
    """Keep the first ``head`` and last ``tail`` lines, drop the middle.

    Both bash and tmux apply this before returning to the LLM so the
    agent's context window doesn't blow up on a verbose nmap run. The
    full untruncated output is still in the JSONL log (capped at 4 KB
    tail) and on disk for ``bash`` (workspace temp files).
    """
    lines = output.split("\n")
    if len(lines) <= head + tail:
        return output
    h = lines[:head]
    t = lines[-tail:]
    skipped = len(lines) - head - tail
    return "\n".join(h + [f"\n... [{skipped} lines truncated] ...\n"] + t)


def format_bash_result(
    *,
    stdout: str,
    stderr: str,
    exit_code: int,
    cwd: str | None,
    timed_out: bool,
    timeout_s: int | None,
) -> str:
    """Combine the four bash-result streams into one LLM-facing string.

    The format keeps stdout first (what the LLM cares about most),
    stderr second only if non-empty, and a trailing tag line with the
    exit code. Working-directory changes are surfaced inline so the
    LLM notices when ``cd`` happened.
    """
    parts: list[str] = []
    if stdout:
        parts.append(stdout.rstrip("\n"))
    if stderr.strip():
        parts.append(f"\n[stderr]\n{stderr.rstrip()}")
    tag_bits: list[str] = []
    if timed_out:
        tag_bits.append(f"TIMEOUT after {timeout_s}s — process killed")
    tag_bits.append(f"exit={exit_code}")
    if cwd:
        tag_bits.append(f"cwd={cwd}")
    parts.append(f"\n[{' | '.join(tag_bits)}]")
    return "\n".join(p for p in parts if p)


# Re-exports so ``from src.tools.shell._common import ...`` is one
# import for everything most callers need.
__all__ = [
    "set_run_id",
    "get_run_id",
    "set_workspace_root",
    "workspace_for",
    "set_log_file",
    "get_log_file",
    "log_event",
    "_log_event",  # back-compat with the underscore name in terminal.py
    "truncate_output",
    "format_bash_result",
]
