"""CLI entry point for SwarmAttacker."""

from __future__ import annotations

import argparse
import asyncio
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SwarmAttacker — Multi-methodology swarm penetration testing agent",
    )
    parser.add_argument(
        "target_url",
        help="Target URL to test (e.g. http://target.local)",
    )
    parser.add_argument(
        "--scope",
        default="",
        help="Scope restriction (e.g. '*.example.com'). Defaults to target URL only.",
    )
    parser.add_argument(
        "--provider",
        default="anthropic",
        choices=["anthropic", "openai", "openrouter"],
        help="LLM provider to use (default: anthropic)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name override (default depends on provider)",
    )
    args = parser.parse_args()

    asyncio.run(run(args.target_url, args.scope or args.target_url))


async def run(target_url: str, target_scope: str) -> None:
    from swarmattacker.graph import graph

    result = await graph.ainvoke({
        "target_url": target_url,
        "target_scope": target_scope,
        "messages": [],
        "findings": [],
        "agent_results": [],
        "active_agents": [],
    })

    # Print the final report (last message)
    messages = result.get("messages", [])
    if messages:
        print(messages[-1].content)
    else:
        print("No output produced.")


if __name__ == "__main__":
    main()
