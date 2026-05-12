"""Back-compat shim. The real implementation moved to ``src.tools.shell``.

Historically all shell-execution lived in this single 486-line file.
It has been split into the ``src.tools.shell`` package:

- ``shell/_common.py``  — JSONL logging, output truncation, workspace mgmt
- ``shell/safety.py``   — pre-flight scope / attacker-host safety checks
- ``shell/tmux.py``     — tmux pane tool (``run_command``, ``shell``,
                          ``read_file``)
- ``shell/bash.py``     — persistent-bash tool (``bash``, ``bash_exec``)
- ``shell/manager.py``  — singleton ``ShellManager`` that owns session
                          lifecycle (atexit + signals + per-agent cleanup)
- ``shell/__init__.py`` — public exports + ``cleanup_shell()``

This file re-exports the symbols the rest of the codebase already
imports (``run_command``, ``shell``, ``read_file``, ``set_log_file``)
so existing call sites keep working through the migration. Once every
importer is on ``src.tools.shell`` directly, delete this shim.

History note: this shim used to also re-export ``cleanup_session`` from
the old per-process tmux teardown. That function was removed when
session lifecycle moved to ``ShellManager`` (May 2026 refactor); callers
that need explicit cleanup now use ``cleanup_shell()`` (process-wide) or
``get_shell_manager().cleanup_agent(agent_id)`` (per-worker).

To find direct importers of this module:

    rg "from src\\.tools\\.terminal|src\\.tools\\.terminal" --include='*.py'
"""

from __future__ import annotations

from src.tools.shell import (
    read_file,
    run_command,
    set_log_file,
    shell,
)

__all__ = [
    "run_command",
    "read_file",
    "shell",
    "set_log_file",
]
