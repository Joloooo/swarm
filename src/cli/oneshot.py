"""One-shot natural-language CLI flow.

Invoked when the user passes a positional argument to ``swarm`` /
``swarmattacker``. The argument is free-form user input, not a URL —
the supervisor planner reads it from ``state["messages"]`` on turn 1,
calls ``normalize_url`` / ``validate_website`` as needed, and decides
the first action.

    swarmattacker "test example.com for sqli"
    swarmattacker example.com
    swarmattacker "scan 192.168.1.10 — docker-compose lab"

The previous standalone ``src/cli.py`` ran its own argparse; this
module is now called by ``src.cli.__init__:main``, which parses the
shared argparse for BOTH this one-shot mode AND the new TUI mode.
``run(...)`` itself is unchanged — same graph invocation, same final
print — and is still re-exported from ``src.cli`` so any old import
``from src.cli import run`` keeps working.
"""

from __future__ import annotations

import argparse
import asyncio
import logging


def main(args: argparse.Namespace) -> None:
    """Run the one-shot natural-language flow with pre-parsed args."""
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    asyncio.run(run(
        user_input=args.user_input,
        target_scope=args.scope,
    ))


async def run(user_input: str, target_scope: str = "") -> None:
    from langchain_core.messages import HumanMessage

    from src.graph import GRAPH_RECURSION_LIMIT, graph

    initial_messages = [HumanMessage(content=user_input)]
    if target_scope:
        initial_messages.append(
            HumanMessage(
                content=(
                    f"Scope constraint from the user: {target_scope}. "
                    "Honor this when setting target_scope."
                )
            )
        )

    initial_state: dict = {
        "messages": initial_messages,
        "findings": [],
        "agent_results": [],
        "active_agents": [],
    }
    # If the user passed --scope, pre-seed it so the planner can carry
    # it forward even on a turn where the LLM forgets to include it.
    if target_scope:
        initial_state["target_scope"] = target_scope

    result = await graph.ainvoke(
        initial_state, config={"recursion_limit": GRAPH_RECURSION_LIMIT}
    )

    # Print the final report (last message).
    messages = result.get("messages", [])
    if messages:
        print(messages[-1].content)
    else:
        print("No output produced.")
