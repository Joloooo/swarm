"""Typed nikto wrapper."""

from __future__ import annotations

import shlex

from langchain_core.tools import tool

from src.tools.shell import bash_exec


# nikto is loud and slow. 8 minute cap covers a single host + default
# plugins; bigger sweeps should be scoped down before raising this.
_DEFAULT_TIMEOUT = 480


@tool
async def nikto_scan(
    reasoning: str,
    url: str,
    tuning: str | None = None,
    agent_id: str = "default",
) -> str:
    """Run a nikto web-server vulnerability scan against a URL.

    nikto checks for thousands of known issues: outdated server software,
    default files / directories, dangerous HTTP methods, mis-set headers,
    and CGI vulns. Loud — every check shows up in target logs. Use after
    cheaper recon (whatweb, gobuster) has narrowed the surface.

    Args:
        reasoning: Required. Justify why nikto over a more targeted tool.
            Reference the surface you're sweeping over.
        url: Target URL (host:port or full URL).
        tuning: Optional ``-Tuning`` argument to scope checks (e.g. ``"x"``
            for XSS, ``"4"`` for SQLi, ``"123b"`` for several at once).
            See ``nikto -H`` for the full set. Omit to run all checks.
        agent_id: tmux pane identifier (do not set manually).

    Returns:
        nikto stdout. Use the ``+`` prefixed lines as the finding list.
    """
    parts = ["nikto", "-h", shlex.quote(url), "-ask", "no", "-nointeractive"]
    if tuning:
        parts.extend(["-Tuning", shlex.quote(tuning)])
    cmd = " ".join(parts)
    return await bash_exec(
        cmd, agent_id=agent_id, reasoning=reasoning, timeout=_DEFAULT_TIMEOUT
    )
