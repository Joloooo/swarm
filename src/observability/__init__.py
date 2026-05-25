"""Per-run observability — two artefacts per graph invocation.

Layout under ``logs/run-<run_id>/``:

  ``full_logs.jsonl``
      Every LLM call (start + end / error) and every shell event,
      chronologically interleaved. One row per event with a ``type``
      field so consumers can filter:
        * ``llm_start``  — full prompt sent to the model
        * ``llm_end``    — response + token usage + duration
        * ``llm_error``  — refusal / network error / timeout
        * ``shell_*``    — bash + tmux events (command, output, blocked,
                           spawn, …) emitted by ``src/tools/shell/``.
      ``jq 'select(.type == "llm_error")' full_logs.jsonl`` is the fast
      path to "why did the model refuse".

  ``displayed_terminal_logs.log``
      Plain-text verbatim mirror of the LIVE ticker output, ANSI-stripped
      so it opens cleanly in any editor and ``grep`` works without
      regex tricks. Whatever you saw on the terminal during a run is
      what's in this file.

The run_id embeds the benchmark id (or target host) so ``ls logs/``
tells you immediately which run hit which target.

Package layout:

  * ``writers.py``         — ``append_event`` (full_logs.jsonl) +
                             ``write_terminal_line`` / ``set_terminal_log_file``
                             (displayed_terminal_logs.log).
  * ``live.py``            — the ``LIVE`` singleton: silent / compact /
                             verbose stderr rendering, tees through to
                             the terminal-log sink in ``writers.py``.
  * ``decision_parser.py`` — shared planner-JSON extractor used by both
                             ``live.py`` and ``src/nodes/planner.py``.

History — the pre-refactor dir had seven artefacts plus a
``summary/`` markdown builder. Five never got read in practice
(``nodes.jsonl``, ``worker_traces.jsonl``, ``refusals.jsonl``,
``final_state.json``, ``summary.md``). The two artefacts above are
the survivors that actually answer debugging questions.
"""

from __future__ import annotations

# Disk writers — unified event log + terminal log sink.
from src.observability.writers import (
    LOGS_ROOT,
    JsonlLogHandler,
    append_event,
    full_logs_path,
    get_terminal_log_file,
    install_jsonl_log_handler,
    make_run_id,
    run_dir,
    set_terminal_log_file,
    terminal_log_path,
    uninstall_jsonl_log_handler,
    write_terminal_chunk,
    write_terminal_line,
)

# Live stderr renderer + stdlib logging adapters.
from src.observability.live import (
    HttpxQuietFilter,
    LIVE,
    LiveLogHandler,
)

__all__ = [
    "HttpxQuietFilter",
    "JsonlLogHandler",
    "LIVE",
    "LOGS_ROOT",
    "LiveLogHandler",
    "append_event",
    "full_logs_path",
    "get_terminal_log_file",
    "install_jsonl_log_handler",
    "make_run_id",
    "run_dir",
    "set_terminal_log_file",
    "terminal_log_path",
    "uninstall_jsonl_log_handler",
    "write_terminal_chunk",
    "write_terminal_line",
]
