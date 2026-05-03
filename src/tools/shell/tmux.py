"""tmux-based interactive shell tool for agent command execution.

Each agent gets its own tmux pane for session isolation.
Inspired by Strix's proven tmux approach — persistent, debuggable,
survives crashes, and gives each agent its own isolated shell with a
real TTY (so interactive programs like ``msfconsole``, popped SSH
shells, and ``nc -lvnp`` listeners actually work).

Use this tool only for genuinely interactive things. For one-shot
commands (nmap, curl, sqlmap, gobuster, ...) prefer the ``bash`` tool
in ``src.tools.shell.bash`` — it returns a clean stdout/stderr/exit
code triple instead of having to scrape pane scrollback.

This file was refactored out of ``src/tools/terminal.py`` in May 2026.
The shared logging / truncation / workspace helpers now live in
``_common.py`` and the pre-flight safety checks (scope, attacker-host
write protection) in ``safety.py``. ``terminal.py`` itself is kept as
a 1-line back-compat shim until all callers are migrated.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from langchain_core.tools import tool

from src.tools.shell._common import (
    log_event as _log_event,
    set_log_file,  # re-exported for the back-compat shim
    truncate_output,
    workspace_for,
)
from src.tools.shell.safety import (
    check_attacker_host_safety,
    check_scope,
    classify_command,
)

logger = logging.getLogger(__name__)


# Read scope from env so the existing CLI / benchmark plumbing can
# pre-seed it without us having to thread state through the @tool
# wrapper. Empty string → no enforcement (the default for now).
def _current_scope() -> list[str]:
    raw = os.getenv("SWARM_SCOPE", "").strip()
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


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

        # Drop the pane into the agent's workspace so relative paths in
        # output flags (e.g. ``nmap -oX scan.xml``) land somewhere
        # predictable and the bash tool's workspace_for() agrees.
        try:
            ws = workspace_for(agent_id)
            subprocess.run(
                ["tmux", "send-keys", "-t", pane_id, f"cd {ws}", "Enter"],
                check=True,
            )
        except Exception as e:  # noqa: BLE001
            _log_event("pane_workspace_cd_failed", agent=agent_id,
                       pane=pane_id, error=str(e))

        _log_event("pane_create", agent=agent_id, pane=pane_id)
        return pane_id


def _run_in_pane(pane_id: str, command: str, timeout: int = 120) -> str:
    """Send a command to a tmux pane and capture the output.

    Uses a **dual-sentinel** marker approach: prints a unique start
    marker BEFORE the command, the command itself, then a unique end
    marker AFTER. Each marker is sent as its own ``send-keys`` call so
    the shell receives them as three sequential commands.

    Why two markers, and why bare-line matching?
    -------------------------------------------
    The previous single-marker version returned as soon as the marker
    *substring* appeared in the pane scrollback. But ``tmux send-keys``
    types the ``echo MARKER`` line straight into the pane TTY, which
    the terminal locally echoes into the visible buffer the instant we
    type it — i.e. before the command has even started running. The
    substring check therefore matched the typed text and returned
    blank output for any command that didn't finish printing its
    output before the next ``capture-pane`` poll. SSH (banner takes
    seconds), gobuster (slow startup), sqlmap (network) all hit this.
    See ``tests/FAILURES.md`` 2026-05-02 for the full bug.

    The fix:
    - Both markers must appear on a line by *themselves* to count
      (``re.MULTILINE`` ``^MARKER$``). That only happens when the
      shell actually runs ``echo MARKER`` — typed text always has a
      shell prompt prefix or appears mid-line.
    - A ``start`` sentinel before the command + an ``end`` sentinel
      after gives us two robust delimiters. Output between the
      bare-line start and bare-line end is what the command actually
      produced, regardless of how long the typed command line was or
      whether it line-wrapped in the pane.
    - For interactive commands (``ssh``, ``msfconsole``) that take
      over the TTY, the start marker is printed by the local shell
      before the cmd runs and the end marker is printed by whatever
      shell is in foreground when the queued ``echo END`` finally
      reaches it (typically the remote bash, after the ssh banner).

    The 120s default is an infra timeout (how long tmux waits for the
    end marker to print), not an agent budget.
    """
    ts = int(time.time() * 1000)
    start_marker = f"__SWARM_START_{ts}__"
    end_marker = f"__SWARM_DONE_{ts}__"
    start_re = re.compile(rf"^{re.escape(start_marker)}\s*$", re.MULTILINE)
    end_re = re.compile(rf"^{re.escape(end_marker)}\s*$", re.MULTILINE)

    # Send three keystroke streams: start sentinel, command, end
    # sentinel. Each ``send-keys`` queues a complete ``...\n`` into
    # the pane TTY; the shell processes them one command at a time.
    for keystroke in (f"echo {start_marker}", command, f"echo {end_marker}"):
        subprocess.run(
            ["tmux", "send-keys", "-t", pane_id, keystroke, "Enter"],
            check=True,
        )

    # Poll pane output until the bare-line end marker appears or we
    # time out.
    poll_start = time.time()
    output = ""
    while time.time() - poll_start < timeout:
        result = subprocess.run(
            ["tmux", "capture-pane", "-t", pane_id, "-p", "-S", "-500"],
            capture_output=True,
            text=True,
        )
        output = result.stdout
        end_match = end_re.search(output)
        if end_match:
            # Slice off everything from the bare-line end marker
            # onwards, then locate the bare-line start marker (use
            # the LAST one — re-runs in the same pane could leave
            # stale start lines from prior calls).
            before = output[: end_match.start()]
            start_matches = list(start_re.finditer(before))
            if start_matches:
                last_start = start_matches[-1]
                # Skip past the start marker's whole line.
                nl = before.find("\n", last_start.end())
                captured = before[nl + 1:] if nl >= 0 else ""
            else:
                # No bare-line start marker found (e.g. it scrolled
                # off the buffer). Fall back to the entire pre-end
                # window — better some output than none.
                captured = before

            # Drop any line that mentions either marker. This catches
            # the typed ``echo START`` / ``echo END`` lines that the
            # shell echoes back as ``prompt$ echo MARKER``, plus any
            # locally-echoed typed text from the moment between
            # send-keys and the foreground process actually reading.
            lines = [
                ln for ln in captured.split("\n")
                if start_marker not in ln and end_marker not in ln
            ]
            return "\n".join(lines).strip()
        time.sleep(0.5)

    return f"[TIMEOUT after {timeout}s] Last output:\n{output[-2000:]}"


async def _async_run_in_pane(pane_id: str, command: str, timeout: int = 120) -> str:
    """Async wrapper around _run_in_pane."""
    return await asyncio.to_thread(_run_in_pane, pane_id, command, timeout)


def _check_safety(command: str, *, agent_id: str) -> str | None:
    """Run pre-flight safety checks. Returns a block reason or None.

    Both the attacker-host write check and the scope-of-engagement
    check are applied. On block, we log the rejection so it shows up
    in the JSONL audit trail.
    """
    host_err = check_attacker_host_safety(command)
    if host_err:
        _log_event("blocked_host_safety", agent=agent_id, cmd=command,
                   reason=host_err)
        return host_err

    scope = _current_scope()
    scope_err = check_scope(command, scope)
    if scope_err:
        _log_event("blocked_scope", agent=agent_id, cmd=command,
                   scope=scope, reason=scope_err)
        return scope_err

    # Diagnostic: log when we couldn't classify the binary, so the
    # operator notices the scope check silently passed it through.
    if scope:
        info = classify_command(command)
        if info["binary"] is not None and info["host"] is None:
            _log_event(
                "scope_unknown",
                agent=agent_id, cmd=command,
                binary=info["binary"], target=info["target"],
            )

    return None


# -- LangChain tools exposed to agents --

@tool
async def run_command(
    reasoning: str,
    command: str,
    agent_id: str = "default",
) -> str:
    """Execute a shell command in the agent's isolated tmux session.

    Prefer the ``bash`` tool for one-shot non-interactive commands
    (nmap, curl, sqlmap, gobuster, ...) — it returns clean
    stdout/stderr/exit code. Use ``run_command`` when you specifically
    need an interactive TTY: ``msfconsole``, an SSH shell on a popped
    box, ``nc -lvnp`` listeners, or any program that prompts you mid-
    run for input you can't pre-supply.

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
    block = _check_safety(command, agent_id=agent_id)
    if block:
        return block

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

    return truncate_output(output)


async def shell(
    command: str,
    *,
    agent_id: str = "default",
    reasoning: str = "",
    timeout: int = 120,
) -> str:
    """Run a shell command in the agent's tmux pane and return captured output.

    Internal helper used by the typed tool wrappers (sqlmap_basic,
    sslscan_full, gobuster_dir, etc.) so they don't have to drive the
    LangChain `@tool` machinery to get at the same plumbing as
    ``run_command``. Logs every call to the JSONL run log just like
    ``run_command`` does, so verbose mode and the audit trail stay
    consistent regardless of which entry point fired.
    """
    block = _check_safety(command, agent_id=agent_id)
    if block:
        return block

    pane_id = await asyncio.to_thread(_get_or_create_pane, agent_id)

    t0 = time.perf_counter()
    _log_event(
        "command",
        agent=agent_id,
        pane=pane_id,
        cmd=command,
        reasoning=reasoning,
    )

    output = await _async_run_in_pane(pane_id, command, timeout)

    dt_ms = int((time.perf_counter() - t0) * 1000)
    raw_bytes = len(output)
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

    return truncate_output(output)


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


__all__ = [
    "run_command",
    "shell",
    "read_file",
    "cleanup_session",
    "set_log_file",  # re-export for shim back-compat
    "SESSION_NAME",
]
