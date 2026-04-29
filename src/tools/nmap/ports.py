"""Port-scanning nmap tools (phase 2: what's listening)."""

from __future__ import annotations

from langchain_core.tools import tool

from src.tools.nmap._engine import run
from src.tools.nmap._schema import ScanResult


def _scan_type(tcp_connect: bool) -> str:
    return "-sT" if tcp_connect else ""


@tool
async def nmap_fast_scan(
    reasoning: str,
    target: str,
    top_ports: int = 100,
    tcp_connect: bool = False,
    agent_id: str = "default",
) -> ScanResult:
    """Fast first-pass port scan — top N most-common TCP ports.

    The agent-safe baseline for reconnaissance. Use this BEFORE any
    script or service-detection tool so you know which ports are
    actually open.

    Args:
        reasoning: Required. One to two sentences explaining what
            attack surface you expect to find and what you will do
            next based on what's open. Rendered inline in Studio.
        target: Host or IP.
        top_ports: How many top ports to probe (1–1000). Default 100.
        tcp_connect: If True, uses TCP connect scan (-sT) instead of
            SYN. SYN needs root; connect works as any user.
        agent_id: Agent identifier.

    Returns:
        ScanResult — hosts[].ports[] list open ports only.
    """
    _ = agent_id, reasoning
    top = max(1, min(1000, int(top_ports)))
    args = f"{_scan_type(tcp_connect)} --top-ports {top} --max-retries 1 --host-timeout 90s".strip()
    return await run(tool="nmap_fast_scan", target=target, user_args=args)


@tool
async def nmap_full_scan(
    reasoning: str,
    target: str,
    tcp_connect: bool = False,
    agent_id: str = "default",
) -> ScanResult:
    """Scan ALL 65535 TCP ports (slow, ~5-10 min per host).

    Use only when a fast_scan misses something you expect to be open.
    Never call this before a fast_scan has run.

    Args:
        reasoning: Required. Explain which service or port you expect
            the fast_scan may have missed and why a full sweep is
            justified — full scans take ~5-10 min so the cost matters.
        target: Host or IP.
        tcp_connect: If True, uses -sT instead of -sS.
        agent_id: Agent identifier.

    Returns:
        ScanResult — hosts[].ports[] list all open ports.
    """
    _ = agent_id, reasoning
    args = f"{_scan_type(tcp_connect)} -p- --max-retries 2 --host-timeout 10m".strip()
    return await run(tool="nmap_full_scan", target=target, user_args=args)


@tool
async def nmap_specific_ports(
    reasoning: str,
    target: str,
    ports: str,
    agent_id: str = "default",
) -> ScanResult:
    """Scan a specific port set.

    Use when you have a predefined target port list (e.g. after a
    ping_sweep identified live hosts and you want to check specific
    services across all of them).

    Args:
        reasoning: Required. Why this port set specifically? What
            service are you probing for and what would its presence
            or absence mean for the attack plan?
        target: Host, IP, or CIDR.
        ports: Comma-separated port list or range
            (e.g. "22,80,443,8080", "1-1024").
        agent_id: Agent identifier.

    Returns:
        ScanResult — open ports from the requested set.
    """
    _ = agent_id, reasoning
    args = f"-p {ports} --max-retries 1 --host-timeout 2m"
    return await run(tool="nmap_specific_ports", target=target, user_args=args)


@tool
async def nmap_udp_scan(
    reasoning: str,
    target: str,
    top_ports: int = 50,
    agent_id: str = "default",
) -> ScanResult:
    """Scan top UDP ports. Requires root (raw sockets).

    UDP scanning is slow and noisy — keep top_ports small. The tool
    will return a permission_denied error if not run as root.

    Args:
        reasoning: Required. UDP scans are slow and noisy — state
            what UDP-based service you suspect (DNS, SNMP, IKE, etc.)
            and why the TCP results make UDP investigation worthwhile.
        target: Host or IP.
        top_ports: Number of top UDP ports (1–200). Default 50.
        agent_id: Agent identifier.

    Returns:
        ScanResult — warnings list populated if run without root.
    """
    _ = agent_id, reasoning
    top = max(1, min(200, int(top_ports)))
    args = f"-sU --top-ports {top} --max-retries 1 --host-timeout 5m"
    return await run(tool="nmap_udp_scan", target=target, user_args=args)
