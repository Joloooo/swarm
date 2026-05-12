"""Shell-tool package.

Two LLM-facing tools live here:

- ``bash`` — one-shot non-interactive commands via a persistent bash
  subprocess. Clean stdout/stderr/exit-code structure. Use this for
  nmap, curl, sqlmap, gobuster, dig, ffuf, nikto, and anything that
  runs to completion.
- ``run_command`` — interactive tmux pane. Use only for things that
  need a real TTY (msfconsole, ssh shells, ``nc -lvnp`` listeners).

Session lifecycle (creating sessions, killing them on process exit or
Ctrl+C) is owned by :mod:`src.tools.shell.manager` — a module-level
singleton that registers ``atexit`` + signal handlers at import time.
Callers that need explicit per-agent cleanup call
``get_shell_manager().cleanup_agent(agent_id)``.
"""

from __future__ import annotations

from src.tools.shell._common import (
    get_log_file,
    get_run_id,
    log_event,
    set_log_file,
    set_run_id,
    set_workspace_root,
    workspace_for,
)
from src.tools.shell.bash import bash, bash_exec
from src.tools.shell.manager import (
    BashSession,
    ShellManager,
    get_shell_manager,
)
from src.tools.shell.safety import (
    check_attacker_host_safety,
    check_scope,
    classify_command,
    strip_wrappers,
)
from src.tools.shell.tmux import (
    read_file,
    run_command,
    shell,
)


async def cleanup_shell() -> None:
    """Tear down every bash subprocess and tmux session this process owns.

    Thin wrapper around :meth:`ShellManager.cleanup_all` kept under the
    historical name so callers (CLI, benchmark teardown, pytest
    fixtures) don't need to update. The singleton's ``atexit`` hook
    also runs this on interpreter shutdown — calling it explicitly
    from the runner is belt-and-suspenders, never required.
    """
    await get_shell_manager().cleanup_all()


__all__ = [
    # tools
    "bash",
    "bash_exec",
    "run_command",
    "read_file",
    "shell",
    # lifecycle
    "cleanup_shell",
    "get_shell_manager",
    "ShellManager",
    "BashSession",
    "set_log_file",
    "set_run_id",
    "set_workspace_root",
    "get_log_file",
    "get_run_id",
    "log_event",
    "workspace_for",
    # safety (re-exported so callers can run pre-flight checks themselves)
    "strip_wrappers",
    "check_scope",
    "check_attacker_host_safety",
    "classify_command",
]
