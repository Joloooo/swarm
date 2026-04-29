"""tmux-based terminal tool for agent command execution.

Each agent gets its own tmux pane for session isolation.
Inspired by Strix's proven tmux approach — persistent, debuggable,
survives crashes, and gives each agent its own isolated shell.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from langchain_core.tools import tool

logger = logging.getLogger(__name__)


# -- Structured event log (JSONL, tail -f friendly) --
#
# Every tmux operation — session/pane setup, command send, output capture,
# timeout, error — is appended to a JSONL file as one event per line.
# Pair with ``tail -f <file> | jq`` in a separate terminal while the graph
# runs. Every agent's commands are logged with an ``agent`` field so you
# can filter per-agent, e.g. ``jq 'select(.agent=="owasp-recon")'``.
#
# Override the directory with the ``SWARM_LOG_DIR`` env var. Default is
# ``./logs/`` relative to the working directory so both ``langgraph dev``
# and the ``swarmattacker`` CLI drop logs in the project root.

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


_LOG_FILE = _init_log_file()
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


def _verbose_print(event: str, *, agent: str | None, payload: dict) -> None:
    """Live-stream a human-readable view of a tool event to stderr.

    Active only when ``SWARM_VERBOSE=1`` is in the environment (set by the
    benchmark runner's ``--verbose`` flag). Designed for "I want to watch
    the agent think" debug sessions: one tool call per stanza, full output
    not truncated.
    """
    if not os.getenv("SWARM_VERBOSE"):
        return
    if event not in ("command", "output"):
        return
    ts = datetime.now().strftime("%H:%M:%S")
    tag = f"[{agent or '?'} @ {ts}]"
    if event == "command":
        cmd = payload.get("cmd", "")
        reason = payload.get("reasoning", "")
        print(f"\n{tag} $ {cmd}", file=sys.stderr, flush=True)
        if reason:
            print(f"{tag}   reasoning: {reason}", file=sys.stderr, flush=True)
    elif event == "output":
        dur_ms = payload.get("duration_ms", "?")
        nbytes = payload.get("bytes", "?")
        tail = payload.get("tail", "") or ""
        print(
            f"{tag} ↳ output ({dur_ms} ms, {nbytes} bytes):",
            file=sys.stderr, flush=True,
        )
        for line in str(tail).splitlines() or [""]:
            print(f"{tag}   {line}", file=sys.stderr, flush=True)


def _log_event(event: str, *, agent: str | None = None, **payload) -> None:
    """Append one JSON event to the run log. Failures are swallowed.

    Never raises — logging is observability, not a hard dependency. If
    the disk is full or the file gets unlinked mid-run, the graph should
    still finish. We also serialize writes through a lock so parallel
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


# -- tmux session manager (used internally by tools) --

SESSION_NAME = "swarmattacker"
_PANE_REGISTRY: dict[str, str] = {}  # agent_id -> pane_id

# Locks: parallel agents (Send() fan-out) call _ensure_session and
# _get_or_create_pane concurrently. Without locking, two simultaneous
# `tmux new-session -d -s NAME` calls race and one fails with
# "duplicate session: swarmattacker" — the bug from the user's logs.
# We also use `tmux new-session -A` (attach if exists) as a belt-and-suspenders
# idempotency guarantee at the shell level.
_SESSION_LOCK = threading.Lock()
_PANE_LOCK = threading.Lock()


def _ensure_session() -> None:
    """Create the tmux session if it doesn't exist (idempotent under concurrency).

    Uses ``tmux new-session -A`` so the call is a no-op when the session
    already exists. Wrapped in a lock so two concurrent callers can't both
    pass the existence check and then both try to create.
    """
    import subprocess

    with _SESSION_LOCK:
        # -A: attach if exists, otherwise create. -d: detached. -s: name.
        result = subprocess.run(
            ["tmux", "new-session", "-A", "-d", "-s", SESSION_NAME],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            _log_event(
                "session_ensure_failed",
                session=SESSION_NAME,
                rc=result.returncode,
                stderr=stderr,
            )
            # `-A` should make this idempotent; if it still fails something
            # is genuinely wrong (e.g. tmux not installed). Surface it.
            raise RuntimeError(
                f"tmux session creation failed (rc={result.returncode}): {stderr}"
            )
        _log_event("session_ensure", session=SESSION_NAME)


def _get_or_create_pane(agent_id: str) -> str:
    """Get (or create) a tmux pane for the given agent (concurrency-safe)."""
    import subprocess

    with _PANE_LOCK:
        if agent_id in _PANE_REGISTRY:
            pane_id = _PANE_REGISTRY[agent_id]
            # Validate the cached pane still exists (session may have been killed).
            check = subprocess.run(
                ["tmux", "list-panes", "-t", pane_id],
                capture_output=True,
            )
            if check.returncode == 0:
                _log_event("pane_reuse", agent=agent_id, pane=pane_id)
                return pane_id
            _log_event("pane_stale", agent=agent_id, pane=pane_id)
            del _PANE_REGISTRY[agent_id]

        _ensure_session()

        # Create a new window for this agent
        result = subprocess.run(
            ["tmux", "new-window", "-t", SESSION_NAME, "-n", agent_id,
             "-P", "-F", "#{pane_id}"],
            capture_output=True,
            text=True,
            check=True,
        )
        pane_id = result.stdout.strip()
        _PANE_REGISTRY[agent_id] = pane_id
        _log_event("pane_create", agent=agent_id, pane=pane_id)
        return pane_id


def _run_in_pane(pane_id: str, command: str, timeout: int = 120) -> str:
    """Send a command to a tmux pane and capture the output.

    Uses a marker-based approach: sends the command, then a unique
    echo marker, and reads pane output until the marker appears.
    The 120s default is an infra timeout (how long tmux waits for the
    command to print its marker), not an agent budget.
    """
    import subprocess

    marker = f"__SWARM_DONE_{int(time.time() * 1000)}__"

    # Send command and marker as two separate send-keys so the marker
    # always runs, even if the command has weird escape/quoting issues.
    subprocess.run(
        ["tmux", "send-keys", "-t", pane_id, command, "Enter"],
        check=True,
    )
    subprocess.run(
        ["tmux", "send-keys", "-t", pane_id, f"echo {marker}", "Enter"],
        check=True,
    )

    # Poll pane output until marker appears or timeout
    start = time.time()
    while time.time() - start < timeout:
        result = subprocess.run(
            ["tmux", "capture-pane", "-t", pane_id, "-p", "-S", "-500"],
            capture_output=True,
            text=True,
        )
        output = result.stdout
        if marker in output:
            # Extract everything between the command and the marker
            lines = output.split("\n")
            capture = []
            found_cmd = False
            for line in lines:
                if marker in line:
                    break
                if found_cmd:
                    capture.append(line)
                if command[:40] in line:  # match on first 40 chars of command
                    found_cmd = True
            return "\n".join(capture).strip()
        time.sleep(0.5)

    return f"[TIMEOUT after {timeout}s] Last output:\n{output[-2000:]}"


async def _async_run_in_pane(pane_id: str, command: str, timeout: int = 120) -> str:
    """Async wrapper around _run_in_pane."""
    return await asyncio.to_thread(_run_in_pane, pane_id, command, timeout)


# -- LangChain tools exposed to agents --

@tool
async def run_command(
    reasoning: str,
    command: str,
    agent_id: str = "default",
) -> str:
    """Execute a shell command in the agent's isolated tmux session.

    Use this for any command-line tool: nmap, curl, sqlmap, gobuster, etc.
    Each agent has its own tmux pane, so commands don't interfere.

    Args:
        reasoning: Required. One to two sentences stating the hypothesis
            you are testing with this command and what a positive or
            negative result would mean for the next step. Shown to the
            operator live in Studio and recorded in the run log.
            Don't narrate mechanics ("I will run curl"); narrate the
            decision ("Gobuster listed /admin — confirming whether it
            is a login page or an open panel").
        command: The shell command to execute.
        agent_id: The agent's ID (used to route to the correct tmux pane).

    Returns:
        The command's stdout output (truncated if very large).
    """
    pane_id = await asyncio.to_thread(_get_or_create_pane, agent_id)

    t0 = time.perf_counter()
    _log_event(
        "command",
        agent=agent_id,
        pane=pane_id,
        cmd=command,
        reasoning=reasoning,
    )

    output = await _async_run_in_pane(pane_id, command)

    dt_ms = int((time.perf_counter() - t0) * 1000)
    raw_bytes = len(output)
    # Log the tail of raw output BEFORE context-window truncation so the
    # debug log reflects what tmux actually produced, not what the agent
    # sees after we shrink it. Capped at 4 KB to keep jq-view readable.
    _log_event(
        "output",
        agent=agent_id,
        pane=pane_id,
        cmd=command,
        reasoning=reasoning,
        duration_ms=dt_ms,
        bytes=raw_bytes,
        tail=output[-4000:],
        truncated_in_log=raw_bytes > 4000,
        timed_out=output.startswith("[TIMEOUT"),
    )

    # Context management layer 2: output truncation
    # Keep first 100 + last 50 lines, discard middle
    lines = output.split("\n")
    if len(lines) > 200:
        head = lines[:100]
        tail = lines[-50:]
        truncated = len(lines) - 150
        output = "\n".join(head + [f"\n... [{truncated} lines truncated] ...\n"] + tail)

    return output


@tool
async def read_file(reasoning: str, file_path: str) -> str:
    """Read the contents of a file on the target system.

    Use this to read files discovered during testing (config files,
    source code, etc.). For very large files, only the first 500 lines
    are returned.

    Args:
        reasoning: Required. Why does reading this specific file matter
            for the investigation — what configuration, credential, or
            code pattern do you expect to find and how will it advance
            the attack plan?
        file_path: Absolute path to the file.

    Returns:
        File contents (truncated if large).
    """
    import aiofiles

    try:
        async with aiofiles.open(file_path, "r") as f:
            content = await f.read()
    except Exception as e:
        _log_event(
            "read_file_error", path=file_path, reasoning=reasoning, error=str(e)
        )
        return f"Error reading {file_path}: {e}"

    lines = content.split("\n")
    _log_event(
        "read_file",
        path=file_path,
        reasoning=reasoning,
        bytes=len(content),
        lines=len(lines),
    )
    if len(lines) > 500:
        content = "\n".join(lines[:500]) + f"\n\n... [{len(lines) - 500} more lines]"

    return content


def cleanup_session() -> None:
    """Kill the tmux session and clear the pane registry.

    Called on shutdown AND at the start of every run (from initialize_node)
    so a stale session left over from a previous run can't cause "duplicate
    session" failures or hand out invalid pane IDs from the registry.
    """
    import subprocess

    with _SESSION_LOCK, _PANE_LOCK:
        prior_panes = dict(_PANE_REGISTRY)
        result = subprocess.run(
            ["tmux", "kill-session", "-t", SESSION_NAME],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            logger.info(f"Killed stale tmux session: {SESSION_NAME}")
            _log_event(
                "session_killed", session=SESSION_NAME, panes=prior_panes
            )
        else:
            # Most common benign case: no session existed to kill. Logged
            # so the absence of a kill event isn't mysterious when reading
            # the run log back.
            _log_event(
                "session_kill_noop",
                session=SESSION_NAME,
                rc=result.returncode,
                stderr=result.stderr.strip(),
            )
        _PANE_REGISTRY.clear()
