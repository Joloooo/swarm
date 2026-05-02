"""Initialize node — seeds defaults before the supervisor takes over.

Runs once at graph start. The target URL is **not** set here — the
supervisor planner populates ``target_url`` / ``target_scope`` on its
first turn, after reading the user's message and calling the
``normalize_url`` tool. This node only:

- Establishes the stealth baseline (``waf_detected=False``,
  ``stealth_level=0``).
- Resets the supervisor iteration counter (``planner_iters``) and
  related flags.
- Tears down any leftover tmux session from a previous run so the
  first agent's ``tmux new-session`` can't collide with a stale
  session (the source of ``duplicate session: swarmattacker`` errors
  when re-running the graph inside the same ``langgraph dev``
  process).
"""

import asyncio

from langchain_core.messages import AIMessage

from src.nodes.base import BaseNode
from src.tools.shell import cleanup_bash_sessions, cleanup_session


class InitializeNode(BaseNode):
    """Seed stealth defaults, reset planner counters, clean shell state."""

    async def execute(self, state: dict) -> dict:
        # Wipe any leftover shell state from a prior run before any agent
        # call. The bash backend (per-agent persistent subprocess) and the
        # tmux backend (one shared session, one window per agent) both
        # leave state that survives the graph but breaks the next run.
        #
        # ``cleanup_session`` does ``subprocess.run(["tmux", "kill-session"])``
        # which is synchronous and would otherwise trigger langgraph-api's
        # blockbuster guard by running sync I/O on the event-loop thread.
        # Offload to a worker thread so the event loop stays responsive.
        try:
            await cleanup_bash_sessions()
        except Exception as e:  # noqa: BLE001 — never block the graph on cleanup
            self.log.warning(f"bash cleanup failed (non-fatal): {e}")
        try:
            await asyncio.to_thread(cleanup_session)
        except Exception as e:  # noqa: BLE001 — never block the graph on cleanup
            self.log.warning(f"tmux cleanup failed (non-fatal): {e}")

        return {
            "waf_detected": False,
            "stealth_level": 0,
            "planner_iters": 0,
            "recon_done": False,
            "pending_dispatch": [],
            "messages": [
                AIMessage(
                    content=(
                        "Starting SwarmAttacker planning session. Supervisor "
                        "will read the user's request and decide the next step."
                    )
                )
            ],
        }


initialize_node = InitializeNode()
