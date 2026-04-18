"""Vulnerability-oriented nmap tools (phase 5: find known issues)."""

from __future__ import annotations

from langchain_core.tools import tool

from src.tools.nmap._engine import run
from src.tools.nmap._schema import ScanResult


@tool
async def nmap_vuln_scan(
    target: str,
    ports: str,
    agent_id: str = "default",
) -> ScanResult:
    """Run NSE `vuln` category scripts against known-open ports.

    Intrusive — runs CVE-checking scripts that may trigger logs or
    IPS alerts. Call only after a fast_scan has confirmed the ports
    are open. Never on unscoped port ranges.

    Args:
        target: Host or IP.
        ports: REQUIRED port list (use output of a prior fast_scan).
        agent_id: Agent identifier.

    Returns:
        ScanResult — scripts[] under each port include CVE matches
        from `http-vuln-*`, `ssl-heartbleed`, etc.
    """
    _ = agent_id
    args = f"--script=vuln -sV -p {ports} --script-timeout 2m --host-timeout 15m"
    return await run(tool="nmap_vuln_scan", target=target, user_args=args)


@tool
async def nmap_ssl_enum(
    target: str,
    ports: str = "443",
    agent_id: str = "default",
) -> ScanResult:
    """TLS/SSL configuration audit.

    Runs ssl-enum-ciphers, ssl-cert, ssl-dh-params, and ssl-heartbleed.
    The canonical tool for checking a host's TLS posture — replaces
    `nmap --script ssl-enum-ciphers` invocations from run_command.

    Args:
        target: Host or IP.
        ports: Port list — default "443". Include 8443 or others
            if the target has multi-port TLS.
        agent_id: Agent identifier.

    Returns:
        ScanResult — each TLS port's scripts[] contains cipher list,
        cert details, DH parameters, and heartbleed test.
    """
    _ = agent_id
    scripts = "ssl-enum-ciphers,ssl-cert,ssl-dh-params,ssl-heartbleed"
    args = f"--script={scripts} -sV -p {ports} --script-timeout 2m --host-timeout 5m"
    return await run(tool="nmap_ssl_enum", target=target, user_args=args)


@tool
async def nmap_http_enum(
    target: str,
    ports: str = "80,443,8080,8443",
    agent_id: str = "default",
) -> ScanResult:
    """HTTP(S) surface enumeration.

    Runs http-headers, http-title, http-server-header, http-methods,
    and http-enum (path brute-forcing). Good second-pass for web
    targets after a fast_scan.

    Args:
        target: Host or IP.
        ports: HTTP-bearing ports (default covers 80/443/8080/8443).
        agent_id: Agent identifier.

    Returns:
        ScanResult — scripts[] include title, server header, allowed
        methods, and discovered paths.
    """
    _ = agent_id
    scripts = "http-enum,http-headers,http-methods,http-title,http-server-header"
    args = f"--script={scripts} -sV -p {ports} --script-timeout 2m --host-timeout 5m"
    return await run(tool="nmap_http_enum", target=target, user_args=args)


@tool
async def nmap_smb_enum(
    target: str,
    ports: str = "139,445",
    agent_id: str = "default",
) -> ScanResult:
    """SMB/NetBIOS enumeration (Windows/file-sharing targets).

    Runs smb-enum-shares, smb-enum-users, smb-os-discovery, and
    smb2-security-mode. Use when a fast_scan shows 139 or 445 open.

    Args:
        target: Host or IP.
        ports: Default "139,445".
        agent_id: Agent identifier.

    Returns:
        ScanResult — host_scripts[] and port scripts[] carry shares,
        users, OS info, and signing configuration.
    """
    _ = agent_id
    scripts = "smb-enum-shares,smb-enum-users,smb-os-discovery,smb2-security-mode"
    args = f"--script={scripts} -p {ports} --script-timeout 2m --host-timeout 5m"
    return await run(tool="nmap_smb_enum", target=target, user_args=args)
