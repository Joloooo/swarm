"""NSE script nmap tools (phase 4: run scripts on known-open ports)."""

from __future__ import annotations

from langchain_core.tools import tool

from src.tools.nmap._engine import run
from src.tools.nmap._schema import ScanResult


@tool
async def nmap_default_scripts(
    target: str,
    ports: str,
    agent_id: str = "default",
) -> ScanResult:
    """Run the default NSE script category (-sC) plus -sV.

    Safe, non-intrusive scripts — banner grabbing, basic enumeration,
    cert inspection, etc. Use as the standard enrichment pass after
    a fast_scan identifies open ports.

    Args:
        target: Host or IP.
        ports: REQUIRED port list (e.g. "22,80,443").
        agent_id: Agent identifier.

    Returns:
        ScanResult — ports[] entries carry scripts[] with script
        id and output.
    """
    _ = agent_id
    args = f"-sC -sV -p {ports} --script-timeout 60s --host-timeout 5m"
    return await run(tool="nmap_default_scripts", target=target, user_args=args)


@tool
async def nmap_script(
    target: str,
    script: str,
    ports: str,
    script_args: str | None = None,
    agent_id: str = "default",
) -> ScanResult:
    """Run a specific NSE script or script category.

    For targeted script execution — use the purpose-built tools
    (ssl_enum, http_enum, smb_enum, vuln_scan) first; only reach
    for this when you need a script they don't cover.

    Args:
        target: Host or IP.
        script: NSE script name, comma-separated list, or category
            (e.g. "http-title", "ssl-cert,ssl-dh-params", "default,safe").
        ports: REQUIRED port list.
        script_args: Optional script args
            (e.g. "http-title.useget=true").
        agent_id: Agent identifier.

    Returns:
        ScanResult — scripts[] entries under each matching port.
    """
    _ = agent_id
    pieces = [f"--script={script}", f"-p {ports}", "--script-timeout 2m", "--host-timeout 10m"]
    if script_args:
        pieces.append(f"--script-args={script_args}")
    args = " ".join(pieces)
    return await run(tool="nmap_script", target=target, user_args=args)
