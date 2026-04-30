"""Typed testssl.sh wrapper.

testssl.sh is the heavyweight cousin of sslscan — slower but more
comprehensive (CVE checks, BEAST/POODLE/Heartbleed/ROBOT, HSTS, OCSP
stapling, etc). Use sslscan for the quick pass, this for the deep dive.
"""

from __future__ import annotations

import shlex

from langchain_core.tools import tool

from src.tools.terminal import shell


# testssl.sh can run 3–5 min on a single host with default test set.
_DEFAULT_TIMEOUT = 480


@tool
async def testssl_full(
    reasoning: str,
    host: str,
    port: int = 443,
    agent_id: str = "default",
) -> str:
    """Run testssl.sh against ``host:port`` for a deep TLS audit.

    Slower than ``sslscan_full`` but catches things sslscan misses:
    CVE-specific checks (Heartbleed, BEAST, POODLE, ROBOT, LOGJAM,
    DROWN), HSTS preload status, OCSP stapling, TLS-13 extensions,
    SCT presence, and common misconfigurations.

    Use after ``sslscan_full`` has surfaced something suspicious, or
    standalone when you specifically want CVE coverage.

    Args:
        reasoning: Required. Why testssl over sslscan here? Reference
            the sslscan finding you're following up on.
        host: Hostname or IP.
        port: TLS port, defaults to 443.
        agent_id: tmux pane identifier (do not set manually).

    Returns:
        testssl.sh stdout, head+tail truncated if very long.
    """
    cmd = f"testssl.sh --quiet --color 0 {shlex.quote(host)}:{int(port)}"
    return await shell(
        cmd, agent_id=agent_id, reasoning=reasoning, timeout=_DEFAULT_TIMEOUT
    )
