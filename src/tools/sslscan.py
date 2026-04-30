"""Typed sslscan wrapper.

Replaces the ``run_command("sslscan ...")`` pattern in the crypto skill
with a structured tool call. Default timeout covers full enumeration
on a slow handshake.
"""

from __future__ import annotations

import shlex

from langchain_core.tools import tool

from src.tools.terminal import shell


_DEFAULT_TIMEOUT = 240


@tool
async def sslscan_full(
    reasoning: str,
    host: str,
    port: int = 443,
    agent_id: str = "default",
) -> str:
    """Run sslscan against ``host:port`` to enumerate TLS configuration.

    Reports supported protocol versions, cipher suites, certificate chain,
    weak/insecure ciphers, signature algorithms, and renegotiation flags.
    Pair with ``nmap_ssl_enum`` when you want a second opinion or when
    sslscan misses an extension.

    Args:
        reasoning: Required. State which TLS weakness you suspect (e.g.
            "host header advertises legacy CDN, checking for TLS 1.0
            and weak cipher fallback").
        host: Hostname or IP. The tool quotes it for shell safety.
        port: TLS port, defaults to 443.
        agent_id: tmux pane identifier (do not set manually).

    Returns:
        sslscan stdout, head+tail truncated if very long.
    """
    cmd = f"sslscan {shlex.quote(host)}:{int(port)}"
    return await shell(
        cmd, agent_id=agent_id, reasoning=reasoning, timeout=_DEFAULT_TIMEOUT
    )
