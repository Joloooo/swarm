"""Persistent-bash tool for one-shot non-interactive commands.

This is the OpenCode-style command tool: each agent owns a long-lived
``bash`` subprocess for the whole run, and every command the LLM
issues is wrapped as a 5-line script that redirects stdout/stderr to
temp files, captures the exit code, snapshots the working directory,
and prints a unique sentinel marker.

Why this exists separately from ``tmux.py``
-------------------------------------------
- Clean structured output (stdout, stderr, exit code, cwd) instead of
  parsing pane scrollback.
- No 500-line scrollback truncation — output goes to files, capped
  much higher.
- Real exit codes the agent can branch on.
- ``cd``, ``export``, ``source venv/bin/activate`` persist naturally
  across calls within an agent's run.
- No TTY though — for things that *need* a terminal (msfconsole, ssh
  shells, nc listeners), the LLM uses ``run_command`` (tmux) instead.

How a single call works
-----------------------
1. Acquire the per-agent lock so two simultaneous tool calls for the
   same agent serialise (bash can only run one command at a time).
2. Run pre-flight safety checks (attacker-host writes, scope).
3. Pick a 12-char id. Build the wrapper script:
       eval <quoted-cmd> < /dev/null > <id>.out 2> <id>.err
       EXEC_EXIT_CODE=$?
       pwd > <id>.cwd
       echo $EXEC_EXIT_CODE > <id>.exit
       echo __SWARM_BASH_DONE_<id>__
   The four files land under <workspace>/.swarm/.
4. Write the script as bytes into bash's stdin.
5. Read bash's stdout pipe line-by-line until the sentinel arrives.
   The pipe only ever sees small bookkeeping output, so the 64 KB
   pipe buffer never fills — no deadlock risk.
6. Read the four temp files. Update tracked cwd if it changed.
   Delete the temp files.
7. Format the result and return.

Per-agent isolation: same pattern as the tmux tool — one persistent
bash per ``agent_id``, looked up from a registry. Different agents
run in parallel; commands within the same agent serialise.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import signal
import time
import uuid
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from src.tools.shell._common import (
    format_bash_result,
    log_event as _log_event,
    truncate_output,
)
from src.tools.shell.manager import BashSession, get_shell_manager
from src.tools.shell.safety import (
    check_attacker_host_safety,
    check_scope,
    classify_command,
)

logger = logging.getLogger(__name__)


# Per-agent bash subprocess lifecycle (creation, registry, cleanup) lives
# in :mod:`src.tools.shell.manager`. This module owns only command
# execution against an existing :class:`BashSession`: the wrapper-script
# build, the sentinel-driven readback, and the LangChain-facing tool
# wrappers below. All session lookups go through
# ``get_shell_manager().get_or_create_bash(agent_id)``.

# Default timeout was previously ``_DEFAULT_TIMEOUT_S`` here. It now lives
# on the manager (``ShellManager.DEFAULT_TIMEOUT_S``) so all shell-tool
# defaults sit in one place.
_MAX_TIMEOUT_S = 60 * 30  # 30 minutes hard ceiling

# How often to check the bash stdout pipe for the sentinel. 100 ms is
# small enough to feel snappy, large enough not to pin a CPU core.
_POLL_INTERVAL_S = 0.1

# Cap on how many bytes we read from each result file. The full file
# stays on disk inside the workspace until cleanup, so the agent can
# still grep / read / re-process a giant scan output via other tools.
_MAX_BYTES_PER_STREAM = 256_000


def _current_scope() -> list[str]:
    raw = os.getenv("SWARM_SCOPE", "").strip()
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


# -- The wrapper script -----------------------------------------------------

_SENTINEL_RE = re.compile(r"^__SWARM_BASH_DONE_([0-9a-f]{12})__\s*$")


def _build_script(command: str, cmd_id: str, workspace: Path) -> str:
    """Build the 5-line bash wrapper that redirects output and prints a sentinel."""
    out = workspace / ".swarm" / f"{cmd_id}.out"
    err = workspace / ".swarm" / f"{cmd_id}.err"
    cwd = workspace / ".swarm" / f"{cmd_id}.cwd"
    exit_f = workspace / ".swarm" / f"{cmd_id}.exit"
    sentinel = f"__SWARM_BASH_DONE_{cmd_id}__"

    quoted_cmd = shlex.quote(command)
    out_q = shlex.quote(str(out))
    err_q = shlex.quote(str(err))
    cwd_q = shlex.quote(str(cwd))
    exit_q = shlex.quote(str(exit_f))

    # All on one logical line so bash reads it as a single command and
    # the sentinel only echoes after everything else completes.
    return (
        f"eval {quoted_cmd} < /dev/null > {out_q} 2> {err_q}; "
        f"EXEC_EXIT_CODE=$?; "
        f"pwd > {cwd_q}; "
        f"echo $EXEC_EXIT_CODE > {exit_q}; "
        f"echo {sentinel}\n"
    )


def _read_safe(p: Path, max_bytes: int = _MAX_BYTES_PER_STREAM) -> str:
    """Read up to *max_bytes* from a file. Returns "" if the file is missing.

    Files are deleted after read so the workspace doesn't accumulate
    cruft. If unlinking fails (file already gone, permissions), we
    swallow — the temp dir gets cleaned up at run end either way.
    """
    try:
        with p.open("r", errors="replace") as f:
            data = f.read(max_bytes)
    except FileNotFoundError:
        return ""
    except OSError:
        return ""
    finally:
        try:
            p.unlink()
        except OSError:
            pass
    return data


# -- The actual runner ------------------------------------------------------

async def _wait_for_sentinel(
    sess: BashSession,
    sentinel: str,
    deadline: float,
) -> bool:
    """Read sess.proc.stdout line-by-line until the sentinel appears or deadline hits.

    Returns True if the sentinel was seen, False on timeout.
    Lines that aren't the sentinel are dropped — the only thing the
    pipe is supposed to carry is bookkeeping. (If the agent's command
    accidentally echoes something here, it'll be ignored; the real
    output is in the .out file.)
    """
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return False

        # readline() blocks; wrap in wait_for so we honour the deadline.
        try:
            line = await asyncio.wait_for(
                sess.proc.stdout.readline(),
                timeout=min(remaining, _POLL_INTERVAL_S * 5),
            )
        except asyncio.TimeoutError:
            continue

        if not line:
            # EOF — the bash process died.
            return False

        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
        if text == sentinel:
            return True
        # Otherwise: incidental output on the pipe. Ignore.


async def _kill_running_command(sess: BashSession) -> None:
    """SIGINT the foreground command in bash without killing bash itself.

    ``start_new_session=True`` put bash in its own process group when
    we spawned it. The *running command* gets reparented into a
    foreground process group of its own under bash. SIGINT on the
    process group reaches the command, mimicking Ctrl-C.
    """
    try:
        os.killpg(sess.proc.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    except OSError as e:
        _log_event(
            "bash_sigint_failed",
            agent=sess.agent_id,
            error=str(e),
        )


async def _run_one(
    sess: BashSession,
    command: str,
    timeout: int,
) -> dict[str, Any]:
    """Run a single wrapped command in the session. Returns the structured result dict."""
    cmd_id = uuid.uuid4().hex[:12]
    sentinel = f"__SWARM_BASH_DONE_{cmd_id}__"
    script = _build_script(command, cmd_id, sess.workspace)

    t0 = time.perf_counter()
    deadline = t0 + timeout

    # Send the script into bash's stdin.
    try:
        sess.proc.stdin.write(script.encode())
        await sess.proc.stdin.drain()
    except (BrokenPipeError, ConnectionResetError) as e:
        # bash died; mark session bad so the next call spawns a fresh one.
        _log_event(
            "bash_stdin_broken",
            agent=sess.agent_id,
            error=str(e),
        )
        return {
            "stdout": "",
            "stderr": f"bash session for agent {sess.agent_id!r} died: {e}",
            "exit_code": -1,
            "cwd": sess.cwd,
            "duration_ms": int((time.perf_counter() - t0) * 1000),
            "timed_out": False,
        }

    # Wait for the sentinel.
    seen = await _wait_for_sentinel(sess, sentinel, deadline)
    timed_out = not seen

    if timed_out:
        await _kill_running_command(sess)
        # Give the command a brief grace window to actually die so its
        # bookkeeping files exist when we read them.
        try:
            await asyncio.wait_for(
                _wait_for_sentinel(sess, sentinel, time.perf_counter() + 2.0),
                timeout=2.5,
            )
        except asyncio.TimeoutError:
            pass

    swarm_dir = sess.workspace / ".swarm"
    stdout = _read_safe(swarm_dir / f"{cmd_id}.out")
    stderr = _read_safe(swarm_dir / f"{cmd_id}.err")
    exit_raw = _read_safe(swarm_dir / f"{cmd_id}.exit").strip()
    new_cwd = _read_safe(swarm_dir / f"{cmd_id}.cwd").strip() or None

    try:
        exit_code = int(exit_raw) if exit_raw else (-1 if timed_out else 0)
    except ValueError:
        exit_code = -1

    if new_cwd:
        sess.cwd = new_cwd

    return {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "cwd": new_cwd or sess.cwd,
        "duration_ms": int((time.perf_counter() - t0) * 1000),
        "timed_out": timed_out,
    }


# -- Public tool entrypoints ------------------------------------------------

def _check_safety(command: str, *, agent_id: str) -> str | None:
    """Same pre-flight as tmux.py — refactored here so both go through one path."""
    host_err = check_attacker_host_safety(command)
    if host_err:
        _log_event("blocked_host_safety", agent=agent_id, cmd=command,
                   reason=host_err, backend="bash")
        return host_err

    scope = _current_scope()
    scope_err = check_scope(command, scope)
    if scope_err:
        _log_event("blocked_scope", agent=agent_id, cmd=command,
                   scope=scope, reason=scope_err, backend="bash")
        return scope_err

    if scope:
        info = classify_command(command)
        if info["binary"] is not None and info["host"] is None:
            _log_event(
                "scope_unknown",
                agent=agent_id, cmd=command, backend="bash",
                binary=info["binary"], target=info["target"],
            )

    return None


@tool
async def bash(
    reasoning: str,
    command: str,
    # Default kept as a literal so @tool can introspect it statically;
    # MUST match ShellManager.DEFAULT_TIMEOUT_S in src/tools/shell/manager.py.
    timeout: int = 120,
    agent_id: str = "default",
) -> str:
    """Run a one-shot non-interactive shell command.

    Use this for nmap, curl, sqlmap, gobuster, dig, ffuf, nikto, and
    any command that runs to completion and prints output. Returns
    the command's stdout (with stderr appended if non-empty), an exit
    code marker, and the working directory. State persists across
    calls within your agent's session — ``cd``, ``export``,
    ``source venv/bin/activate`` all stick.

    For interactive programs (msfconsole, ssh shells, ``nc -lvnp``
    listeners, anything that prompts you mid-run), use ``run_command``
    instead — it gives you a tmux pane with a real TTY.

    Output files (e.g. ``nmap -oX scan.xml``, sqlmap session dirs)
    land in your agent's workspace at
    ``~/swarm-workspace/<run_id>/<agent_id>/``. Use relative paths.

    Args:
        reasoning: Required. One to two sentences stating the
            hypothesis you are testing with this command and what a
            positive or negative result would mean for the next step.
            Don't narrate mechanics; narrate the decision.
        command: The shell command to execute.
        timeout: Maximum seconds to wait. Defaults to 120 s. Capped
            at 30 minutes. On timeout the running command is sent
            SIGINT and partial output is returned.
        agent_id: The agent's ID — routes to the correct bash session.

    Returns:
        Combined stdout/stderr/exit-code string suitable for the LLM.
    """
    timeout = max(1, min(int(timeout), _MAX_TIMEOUT_S))

    block = _check_safety(command, agent_id=agent_id)
    if block:
        return block

    sess = await get_shell_manager().get_or_create_bash(agent_id)

    _log_event(
        "bash_command",
        agent=agent_id,
        cmd=command,
        reasoning=reasoning,
        timeout_s=timeout,
    )

    async with sess.lock:
        result = await _run_one(sess, command, timeout)

    formatted = format_bash_result(
        stdout=result["stdout"],
        stderr=result["stderr"],
        exit_code=result["exit_code"],
        cwd=result["cwd"],
        timed_out=result["timed_out"],
        timeout_s=timeout if result["timed_out"] else None,
    )

    raw_total = len(result["stdout"]) + len(result["stderr"])
    _log_event(
        "bash_output",
        agent=agent_id,
        cmd=command,
        reasoning=reasoning,
        duration_ms=result["duration_ms"],
        bytes=raw_total,
        exit_code=result["exit_code"],
        cwd=result["cwd"],
        timed_out=result["timed_out"],
        tail=formatted[-4000:],
        truncated_in_log=raw_total > 4000,
    )

    return truncate_output(formatted)


async def bash_exec(
    command: str,
    *,
    agent_id: str = "default",
    reasoning: str = "",
    # Mirror the @tool default so internal callers and LLM-facing
    # callers behave identically; canonical home is
    # ShellManager.DEFAULT_TIMEOUT_S.
    timeout: int = 120,
) -> str:
    """Run a one-shot command and return its raw stdout.

    Internal helper for the typed tool wrappers (sqlmap_basic,
    gobuster_dir, nikto_scan, …) — same plumbing as the @tool
    :func:`bash` but without the LLM-facing exit-code/cwd headers,
    since those wrappers want to forward output verbatim. On a
    non-zero exit the stderr is appended after a ``[stderr]`` marker
    so the wrapper still sees error messages; on timeout the partial
    output is prefixed with a ``[TIMEOUT]`` marker.

    Logs the same ``bash_command`` / ``bash_output`` JSONL events as
    :func:`bash` so verbose mode and the audit trail stay consistent
    regardless of which entry point fired.
    """
    timeout = max(1, min(int(timeout), _MAX_TIMEOUT_S))

    block = _check_safety(command, agent_id=agent_id)
    if block:
        return block

    sess = await get_shell_manager().get_or_create_bash(agent_id)

    _log_event(
        "bash_command",
        agent=agent_id,
        cmd=command,
        reasoning=reasoning,
        timeout_s=timeout,
        entrypoint="bash_exec",
    )

    async with sess.lock:
        result = await _run_one(sess, command, timeout)

    raw_total = len(result["stdout"]) + len(result["stderr"])
    _log_event(
        "bash_output",
        agent=agent_id,
        cmd=command,
        reasoning=reasoning,
        duration_ms=result["duration_ms"],
        bytes=raw_total,
        exit_code=result["exit_code"],
        cwd=result["cwd"],
        timed_out=result["timed_out"],
        tail=(result["stdout"] + result["stderr"])[-4000:],
        truncated_in_log=raw_total > 4000,
        entrypoint="bash_exec",
    )

    out = result["stdout"]
    if result["stderr"] and result["exit_code"] != 0:
        out = (out + "\n[stderr]\n" + result["stderr"]).strip()
    if result["timed_out"]:
        out = f"[TIMEOUT after {timeout}s]\n{out}"
    return truncate_output(out)


__all__ = [
    "bash",
    "bash_exec",
    "BashSession",  # re-exported (defined in manager.py) for back-compat
]
