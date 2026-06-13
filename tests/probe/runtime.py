"""Process-state isolation between replays + per-replay run-id binding.

A repeated in-process replay (N-sampling, or several fixtures in one process)
shares module-level singletons that ``run_one`` resets between every benchmark
(``benchmarks/xbow_runner.py`` — ``reset_captured`` / ``reset_totals`` /
``reset_rate_limited`` + the per-agent shell cleanup). Without the same resets,
replay K poisons replay K+1:

  - a captured flag from K stays set, so FlagWatcher cancels K+1's FIRST LLM call;
  - K's per-agent token totals accumulate into K+1's context-rot numbers;
  - a 429 in K marks every later replay rate-limited;
  - K's bash/tmux session (keyed by ``agent_id``) leaks its cwd/env into K+1.

This module mirrors those resets so every replay starts clean. Best-effort: a
missing or refactored reset must never break a replay, so each is suppressed
individually.
"""

from __future__ import annotations

import contextlib

_RUN_ID_COUNTER = 0


def reset_process_state(*, agent_id: str | None = None) -> None:
    """Clear the synchronous process-globals that leak between in-process replays.

    (The worker shell session is async — see :func:`cleanup_agent_shell`, which
    the Level-2 executor driver awaits separately.)
    """
    with contextlib.suppress(Exception):
        from src.nodes.base.flag_watcher import reset_captured

        reset_captured()
    with contextlib.suppress(Exception):
        from src.llm.callbacks import reset_totals

        reset_totals()
    with contextlib.suppress(Exception):
        from src.llm.rate_limit_signal import reset_rate_limited

        reset_rate_limited()


async def cleanup_agent_shell(agent_id: str) -> None:
    """Tear down a worker's bash/tmux session so the next replay of the same
    ``agent_id`` does not inherit its cwd/env/background processes. Idempotent."""
    if not agent_id:
        return
    with contextlib.suppress(Exception):
        from src.tools.shell.manager import get_shell_manager

        await get_shell_manager().cleanup_agent(agent_id)


def fresh_run_id(label: str) -> str:
    """A unique-per-process run_id so replay K and K+1 write to separate
    ``logs/run-*/`` dirs (clean per-replay captures to score). A counter is
    appended because the timestamp is only second-granular and Level-1 replays
    are sub-second."""
    global _RUN_ID_COUNTER
    _RUN_ID_COUNTER += 1
    from src.observability import make_run_id

    return f"{make_run_id(benchmark_id=f'probe-{label}')}-{_RUN_ID_COUNTER}"


@contextlib.contextmanager
def bind_run_logs(run_id: str):
    """Route this replay's terminal/JSONL events into its own run dir, then
    unbind — mirrors ``run_one``'s ``set_terminal_log_file(...)`` + teardown so a
    Level-2 node replay's logs land under ``logs/run-<run_id>/``."""
    from src.observability import set_terminal_log_file, terminal_log_path

    set_terminal_log_file(terminal_log_path(run_id))
    try:
        yield run_id
    finally:
        with contextlib.suppress(Exception):
            set_terminal_log_file(None)
