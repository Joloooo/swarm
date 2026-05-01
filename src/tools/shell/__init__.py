"""Shell-tool package.

Two LLM-facing tools live here:

- ``bash`` — one-shot non-interactive commands via a persistent bash
  subprocess. Clean stdout/stderr/exit-code structure. Use this for
  nmap, curl, sqlmap, gobuster, dig, ffuf, nikto, and anything that
  runs to completion.
- ``run_command`` — interactive tmux pane. Use only for things that
  need a real TTY (msfconsole, ssh shells, ``nc -lvnp`` listeners).

Plus shared helpers (``read_file``, ``shell``) and lifecycle hooks
(``cleanup_shell``, ``set_log_file``, ``set_run_id``).
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
from src.tools.shell.bash import bash, cleanup_bash_sessions
from src.tools.shell.safety import (
    check_attacker_host_safety,
    check_scope,
    classify_command,
    strip_wrappers,
)
from src.tools.shell.tmux import (
    cleanup_session,
    read_file,
    run_command,
    shell,
)


async def cleanup_shell() -> None:
    """Tear down both bash subprocesses and the tmux session.

    Call from ``cli.py`` / graph teardown / pytest fixtures so an
    interrupted run doesn't leave background bash processes or stale
    tmux state behind.
    """
    await cleanup_bash_sessions()
    cleanup_session()


__all__ = [
    # tools
    "bash",
    "run_command",
    "read_file",
    "shell",
    # lifecycle
    "cleanup_shell",
    "cleanup_bash_sessions",
    "cleanup_session",
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
