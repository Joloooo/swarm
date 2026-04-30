"""Typed whatweb fingerprinting wrapper."""

from __future__ import annotations

import shlex

from langchain_core.tools import tool

from src.tools.terminal import shell


_DEFAULT_TIMEOUT = 90


@tool
async def whatweb(
    reasoning: str,
    url: str,
    aggression: int = 3,
    agent_id: str = "default",
) -> str:
    """Fingerprint the technologies running behind a URL with whatweb.

    Identifies the web server, language/framework, CMS, JS libraries,
    and analytics platforms by combining HTTP-header inspection with
    pattern matching against page bodies. Cheap and fast — usually run
    early in recon to scope which attack agents are worth dispatching.

    Args:
        reasoning: Required. What gap are you closing — initial recon,
            or following up on an unknown response header?
        url: Target URL.
        aggression: 1 (passive, headers only) to 4 (heavy probing).
            Default 3 is the standard "active scan" level.
        agent_id: tmux pane identifier (do not set manually).

    Returns:
        whatweb's one-line-per-host fingerprint output.
    """
    cmd = f"whatweb -a {int(aggression)} {shlex.quote(url)}"
    return await shell(
        cmd, agent_id=agent_id, reasoning=reasoning, timeout=_DEFAULT_TIMEOUT
    )
