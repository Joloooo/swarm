"""Back-compat shim. The real implementation moved to ``src.tools.shell``.

Historically all shell-execution lived in this single 486-line file.
It has been split into the ``src.tools.shell`` package:

- ``shell/_common.py``  — JSONL logging, output truncation, workspace mgmt
- ``shell/safety.py``   — pre-flight scope / attacker-host safety checks
- ``shell/tmux.py``     — tmux pane tool (``run_command``, ``shell``,
                          ``read_file``, ``cleanup_session``)
- ``shell/bash.py``     — new persistent-bash tool (``bash``,
                          ``cleanup_bash_sessions``)
- ``shell/__init__.py`` — public exports + ``cleanup_shell()``

This file re-exports the symbols the rest of the codebase already
imports (``run_command``, ``shell``, ``read_file``, ``cleanup_session``,
``set_log_file``) so existing call sites keep working through the
migration. Once every importer is on ``src.tools.shell`` directly,
delete this shim.

To find direct importers of this module:

    rg "from src\\.tools\\.terminal|src\\.tools\\.terminal" --include='*.py'
"""

from __future__ import annotations

from src.tools.shell import (
    cleanup_session,
    read_file,
    run_command,
    set_log_file,
    shell,
)

__all__ = [
    "run_command",
    "read_file",
    "shell",
    "cleanup_session",
    "set_log_file",
]
