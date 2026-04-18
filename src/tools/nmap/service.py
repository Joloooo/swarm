"""Service / OS fingerprinting nmap tools (phase 3: what's running)."""

from __future__ import annotations

from langchain_core.tools import tool

from src.tools.nmap._engine import run
from src.tools.nmap._schema import ScanResult


def _ports_flag(ports: str | None) -> str:
    return f"-p {ports}" if ports else ""


@tool
async def nmap_service_detection(
    target: str,
    ports: str | None = None,
    intensity: int = 7,
    agent_id: str = "default",
) -> ScanResult:
    """Detect service name, product, and version for open ports.

    Runs `-sV` — prints things like `http nginx 1.21.6`. Use after a
    fast_scan when you need product/version info but not script output.

    Args:
        target: Host or IP.
        ports: Port list (e.g. "80,443"). If None, scans top 1000.
        intensity: Version detection intensity 0–9. Higher = more
            probes, slower, more accurate. Default 7.
        agent_id: Agent identifier.

    Returns:
        ScanResult — ports[] entries include service/product/version.
    """
    _ = agent_id
    intensity = max(0, min(9, int(intensity)))
    args = f"-sV --version-intensity {intensity} {_ports_flag(ports)} --host-timeout 5m"
    return await run(tool="nmap_service_detection", target=target, user_args=args)


@tool
async def nmap_os_detection(
    target: str,
    ports: str | None = None,
    agent_id: str = "default",
) -> ScanResult:
    """Detect the target operating system. Requires root.

    Uses TCP/IP stack fingerprinting (-O). The tool returns a
    permission_denied error if not run as root.

    Args:
        target: Host or IP.
        ports: Optional port hint — scanning with known-open ports
            improves OS detection accuracy.
        agent_id: Agent identifier.

    Returns:
        ScanResult — hosts[].os and hosts[].os_accuracy populated.
        Warnings list populated if run without root.
    """
    _ = agent_id
    args = f"-O --osscan-limit {_ports_flag(ports)} --host-timeout 3m"
    return await run(tool="nmap_os_detection", target=target, user_args=args)


@tool
async def nmap_aggressive(
    target: str,
    ports: str | None = None,
    agent_id: str = "default",
) -> ScanResult:
    """Aggressive scan — combines -sV -sC -O --traceroute. HEAVY.

    Use only on a scoped port set (pass `ports`) AFTER a fast_scan.
    Never call on an unscoped target — it runs every default NSE
    script on every port.

    Args:
        target: Host or IP.
        ports: REQUIRED in practice — without it, runs on all top 1000.
        agent_id: Agent identifier.

    Returns:
        ScanResult — ports with versions and default-script output;
        hosts with OS detection.
    """
    _ = agent_id
    args = f"-A {_ports_flag(ports)} --script-timeout 60s --host-timeout 10m"
    return await run(tool="nmap_aggressive", target=target, user_args=args)
