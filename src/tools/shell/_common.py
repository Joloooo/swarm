"""Shared utilities for the shell tools (bash + tmux).

Both ``bash.py`` and ``tmux.py`` need the same plumbing:

- A JSONL run-event log (``terminal_events.jsonl``) with locking so
  parallel agents don't interleave half-lines.
- A live-stream "watch the agent think" stderr printer gated on
  ``SWARM_VERBOSE=1``.
- Head-and-tail truncation that keeps output the LLM sees bounded.
- A per-run, per-agent workspace directory under
  ``~/swarm-workspace/<run_id>/<agent_id>/`` where files produced by
  the agent (``nmap -oX scan.xml``, sqlmap session dirs, ...) land
  with predictable relative paths.

Keeping these here means both shell tools log into the same file with
the same shape, so jq queries work uniformly. It also lets you swap
backends per tool without touching the observability layer.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
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


def _init_log_file() -> Path:
    """Pick a log file path, falling back to /tmp if the preferred dir is unwritable."""
    preferred = Path(os.getenv("SWARM_LOG_DIR", "logs"))
    for base in (preferred, Path("/tmp/swarmattacker-logs")):
        try:
            base.mkdir(parents=True, exist_ok=True)
            return base / f"run-{datetime.now():%Y%m%d-%H%M%S}-{os.getpid()}.jsonl"
        except Exception:
            continue
    # Last resort: a flat file in /tmp with a unique name.
    return Path(f"/tmp/swarmattacker-run-{os.getpid()}.jsonl")


_LOG_FILE: Path = _init_log_file()
_LOG_LOCK = threading.Lock()

# Tell the user where the log lives — printed to stderr so it always shows,
# even if stdout is being captured by another process (langgraph dev, pytest).
print(
    f"[swarmattacker] terminal event log → {_LOG_FILE.resolve()}\n"
    f"[swarmattacker] live-tail with:  tail -f {_LOG_FILE} | jq",
    file=sys.stderr,
    flush=True,
)


def set_log_file(path: Path) -> Path:
    """Redirect terminal event logging to *path* for the rest of the process.

    Used by the benchmark runner to land all artifacts of a run under a
    shared ``logs/run-<run_id>/`` directory. The parent directory is
    created if missing. Returns the new path so callers can confirm.

    Safe to call multiple times across a multi-benchmark sweep — each
    benchmark sets its own log file before invoking the graph.
    """
    global _LOG_FILE
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _LOG_FILE = path
    print(
        f"[swarmattacker] terminal event log → {_LOG_FILE.resolve()}",
        file=sys.stderr,
        flush=True,
    )
    return _LOG_FILE


def get_log_file() -> Path:
    return _LOG_FILE


def _verbose_print(event: str, *, agent: str | None, payload: dict) -> None:
    """Live-stream a human-readable view of a tool event to stderr.

    Active only when ``SWARM_VERBOSE=1`` is in the environment (set by
    the benchmark runner's ``--verbose`` flag). Designed for
    "I want to watch the agent think" debug sessions: one tool call per
    stanza, full output not truncated.
    """
    if not os.getenv("SWARM_VERBOSE"):
        return
    if event not in ("command", "output", "bash_command", "bash_output"):
        return
    ts = datetime.now().strftime("%H:%M:%S")
    tag = f"[{agent or '?'} @ {ts}]"
    if event in ("command", "bash_command"):
        cmd = payload.get("cmd", "")
        reason = payload.get("reasoning", "")
        backend = "bash" if event == "bash_command" else "tmux"
        print(f"\n{tag} ({backend}) $ {cmd}", file=sys.stderr, flush=True)
        if reason:
            print(f"{tag}   reasoning: {reason}", file=sys.stderr, flush=True)
    elif event in ("output", "bash_output"):
        dur_ms = payload.get("duration_ms", "?")
        nbytes = payload.get("bytes", "?")
        exit_code = payload.get("exit_code")
        tail = payload.get("tail", "") or ""
        suffix = f", exit={exit_code}" if exit_code is not None else ""
        print(
            f"{tag} ↳ output ({dur_ms} ms, {nbytes} bytes{suffix}):",
            file=sys.stderr, flush=True,
        )
        for line in str(tail).splitlines() or [""]:
            print(f"{tag}   {line}", file=sys.stderr, flush=True)


def log_event(event: str, *, agent: str | None = None, **payload: Any) -> None:
    """Append one JSON event to the run log. Failures are swallowed.

    Never raises — logging is observability, not a hard dependency. If
    the disk is full or the file gets unlinked mid-run, the graph should
    still finish. Writes are serialised through a lock so parallel
    agents don't produce interleaved half-lines.

    When ``SWARM_VERBOSE=1`` is set we also stream a human-readable
    rendering of ``command`` / ``output`` events to stderr so the user
    can watch the agent live without a second ``tail -f`` window.
    """
    _verbose_print(event, agent=agent, payload=payload)
    try:
        record: dict = {
            "ts": datetime.now().isoformat(timespec="milliseconds"),
            "event": event,
        }
        if agent is not None:
            record["agent"] = agent
        record.update(payload)
        line = json.dumps(record, default=str, ensure_ascii=False) + "\n"
        with _LOG_LOCK, _LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        # Intentionally swallow. Do NOT let a log failure interrupt a run.
        pass


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
