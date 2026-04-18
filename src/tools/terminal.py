"""tmux-based terminal tool for agent command execution.

Each agent gets its own tmux pane for session isolation.
Inspired by Strix's proven tmux approach — persistent, debuggable,
survives crashes, and gives each agent its own isolated shell.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass

from langchain_core.tools import tool

logger = logging.getLogger(__name__)


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
            # `-A` should make this idempotent; if it still fails something
            # is genuinely wrong (e.g. tmux not installed). Surface it.
            raise RuntimeError(
                f"tmux session creation failed (rc={result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )


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
                return pane_id
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
        return pane_id


def _run_in_pane(pane_id: str, command: str, timeout: int = 120) -> str:
    """Send a command to a tmux pane and capture the output.

    Uses a marker-based approach: sends the command, then a unique
    echo marker, and reads pane output until the marker appears.
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
async def run_command(command: str, agent_id: str = "default") -> str:
    """Execute a shell command in the agent's isolated tmux session.

    Use this for any command-line tool: nmap, curl, sqlmap, gobuster, etc.
    Each agent has its own tmux pane, so commands don't interfere.

    Args:
        command: The shell command to execute.
        agent_id: The agent's ID (used to route to the correct tmux pane).

    Returns:
        The command's stdout output (truncated if very large).
    """
    pane_id = await asyncio.to_thread(_get_or_create_pane, agent_id)
    output = await _async_run_in_pane(pane_id, command)

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
async def read_file(file_path: str) -> str:
    """Read the contents of a file on the target system.

    Use this to read files discovered during testing (config files,
    source code, etc.). For very large files, only the first 500 lines
    are returned.

    Args:
        file_path: Absolute path to the file.

    Returns:
        File contents (truncated if large).
    """
    import aiofiles

    try:
        async with aiofiles.open(file_path, "r") as f:
            content = await f.read()
    except Exception as e:
        return f"Error reading {file_path}: {e}"

    lines = content.split("\n")
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
        result = subprocess.run(
            ["tmux", "kill-session", "-t", SESSION_NAME],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            logger.info(f"Killed stale tmux session: {SESSION_NAME}")
        _PANE_REGISTRY.clear()
