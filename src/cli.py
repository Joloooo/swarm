"""CLI entry point for SwarmAttacker.

The positional argument is free-form user input, not a URL. The
supervisor planner reads it from ``state["messages"]`` on turn 1,
calls ``normalize_url`` / ``validate_website`` as needed, and decides
the first action. Both invocation styles work:

    swarmattacker "test example.com for sqli"
    swarmattacker example.com
    swarmattacker "scan 192.168.1.10 — docker-compose lab"
"""

from __future__ import annotations

import argparse
import asyncio
import logging


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SwarmAttacker — multi-methodology swarm penetration testing agent",
    )
    parser.add_argument(
        "user_input",
        nargs="?",
        default=None,
        help=(
            "Free-form request (may include the target URL, IP, or a "
            "natural-language description). Optional; if omitted, start "
            "LangGraph Studio and chat with the graph there."
        ),
    )
    parser.add_argument(
        "--scope",
        default="",
        help="Scope restriction (e.g. '*.example.com'). Optional override; "
             "normally the planner derives scope from the target.",
    )
    parser.add_argument(
        "--experiment",
        default=None,
        help="Ablation experiment config (e.g. 'no_rag', 'single_agent')",
    )
    parser.add_argument(
        "--provider",
        default="anthropic",
        choices=["anthropic", "openai", "openrouter"],
        help="LLM provider (default: anthropic)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name override",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if not args.user_input:
        parser.error(
            "Nothing to do — pass a target or description as the first argument, "
            "e.g. `swarmattacker example.com` or `swarmattacker \"pentest "
            "192.168.1.10 for sqli\"`."
        )

    asyncio.run(run(
        user_input=args.user_input,
        target_scope=args.scope,
    ))


async def run(user_input: str, target_scope: str = "") -> None:
    from langchain_core.messages import HumanMessage

    from src.graph import graph

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

    result = await graph.ainvoke(initial_state)

    # Print the final report (last message).
    messages = result.get("messages", [])
    if messages:
        print(messages[-1].content)
    else:
        print("No output produced.")


if __name__ == "__main__":
    main()
