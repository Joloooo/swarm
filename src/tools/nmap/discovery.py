"""Host-discovery nmap tools (phase 1: who's alive)."""

from __future__ import annotations

from typing import Literal

from langchain_core.tools import tool

from src.tools.nmap._engine import run
from src.tools.nmap._schema import ScanResult


@tool
async def nmap_ping_sweep(network: str, agent_id: str = "default") -> ScanResult:
    """Discover live hosts across a network range without port scanning.

    Runs `nmap -sn` (no port scan) against a CIDR block or host list,
    returning only hosts that respond to discovery probes. Use this
    as the first step when given an unknown network range.

    Args:
        network: Target CIDR (e.g. "10.0.0.0/24"), hyphenated range
                 (e.g. "10.0.0.1-20"), or space-separated host list.
        agent_id: Agent identifier (unused internally, kept for parity
                  with other tools).

    Returns:
        ScanResult — hosts list contains one entry per live host.
        Empty hosts list means nothing responded.
    """
    _ = agent_id
    return await run(
        tool="nmap_ping_sweep",
        target=network,
        user_args="-sn --max-retries 1 --host-timeout 30s",
        use_pn=False,  # whole purpose is host discovery
    )


@tool
async def nmap_host_discovery(
    target: str,
    method: Literal["icmp", "tcp-syn", "tcp-ack", "udp"] = "icmp",
    agent_id: str = "default",
) -> ScanResult:
    """Probe a single target with a specific discovery method.

    Use when ICMP is filtered and you want to try TCP/UDP discovery
    probes. TCP-SYN probes port 80/443 by default; UDP hits common
    ports.

    Args:
        target: Host or IP to probe.
        method: Discovery probe type.
            - "icmp": ICMP echo (-PE)
            - "tcp-syn": TCP SYN to common ports (-PS80,443)
            - "tcp-ack": TCP ACK to common ports (-PA80,443)
            - "udp": UDP probe (-PU) — needs root
        agent_id: Agent identifier.

    Returns:
        ScanResult — host entry present iff the probe got a reply.
    """
    _ = agent_id
    probe_flags = {
        "icmp": "-PE",
        "tcp-syn": "-PS80,443",
        "tcp-ack": "-PA80,443",
        "udp": "-PU",
    }
    probe = probe_flags[method]
    return await run(
        tool="nmap_host_discovery",
        target=target,
        user_args=f"-sn {probe} --max-retries 1 --host-timeout 30s",
        use_pn=False,
    )
