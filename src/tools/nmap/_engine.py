"""python-nmap wrapper — runs nmap, parses XML, returns ScanResult.

python-nmap runs `nmap -oX - ...` internally and parses the XML into
dicts. This module adds:
  * async wrapping (asyncio.to_thread) since python-nmap is blocking
  * per-tool safe defaults (-n -T4 --open, timeouts, -Pn policy)
  * a normalizer from the raw python-nmap dict to our ScanResult schema
  * error classification via _errors.classify()
  * non-root detection and warnings for -sU / -O

Known tradeoff: python-nmap exposes NSE <script> output as a flat string
only, not the structured <elem>/<table> children. For v1 we accept this —
the output string is a pretty-printed form of the same data and is
sufficient for an LLM to reason over.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import nmap

from src.tools.nmap._errors import classify
from src.tools.nmap._schema import (
    ErrorInfo,
    HostResult,
    PortResult,
    ScanResult,
    ScriptResult,
)


_SCRIPT_OUTPUT_CAP = 2000
_BASE_ARGS = "-n -T4 --open"
_NEEDS_ROOT_TOOLS = {"nmap_udp_scan", "nmap_os_detection"}


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _is_ipv6(target: str) -> bool:
    # Crude but good enough: IPv6 literals have colons and no commas (not a port list).
    return ":" in target and "/" not in target.split(":")[0]


def _compose_args(user_args: str, target: str, use_pn: bool) -> str:
    """Build the final nmap arguments string."""
    parts = [_BASE_ARGS, user_args]
    if use_pn:
        parts.append("-Pn")
    if _is_ipv6(target):
        parts.append("-6")
    return " ".join(p for p in parts if p).strip()


def _cleanse_output(output: str) -> str:
    """Normalize NSE script output — replace XML newline entities, trim."""
    if not output:
        return ""
    cleaned = output.replace("&#xa;", "\n").replace("&#xA;", "\n").strip()
    if len(cleaned) > _SCRIPT_OUTPUT_CAP:
        cleaned = cleaned[:_SCRIPT_OUTPUT_CAP] + f"\n... [truncated, original {len(output)} chars]"
    return cleaned


def _extract_scripts(raw_scripts: dict[str, str] | None) -> list[ScriptResult]:
    """Convert python-nmap's {script_id: output} dict into ScriptResult list."""
    if not raw_scripts:
        return []
    results: list[ScriptResult] = []
    for script_id, output in raw_scripts.items():
        if not output or "ERROR: Script execution failed" in output:
            continue
        results.append({"id": script_id, "output": _cleanse_output(output)})
    return results


def _extract_ports(host_dict: dict[str, Any]) -> list[PortResult]:
    """Walk host[proto][port] dicts from python-nmap into PortResult list."""
    ports: list[PortResult] = []
    for proto in ("tcp", "udp"):
        port_map = host_dict.get(proto) or {}
        for port_num, info in port_map.items():
            state = info.get("state", "closed")
            port: PortResult = {
                "port": int(port_num),
                "protocol": proto,  # type: ignore[typeddict-item]
                "state": state,  # type: ignore[typeddict-item]
            }
            if info.get("name"):
                port["service"] = info["name"]
            if info.get("product"):
                port["product"] = info["product"]
            if info.get("version"):
                port["version"] = info["version"]
            if info.get("extrainfo"):
                port["extrainfo"] = info["extrainfo"]
            if info.get("cpe"):
                cpe = info["cpe"]
                port["cpe"] = cpe if isinstance(cpe, list) else [cpe]
            scripts = _extract_scripts(info.get("script"))
            if scripts:
                port["scripts"] = scripts
            ports.append(port)
    return ports


def _extract_host(host_ip: str, scanner: nmap.PortScanner) -> HostResult | None:
    """Build a HostResult from a single host entry. Skips hosts that are down."""
    host_dict = scanner[host_ip]
    state = host_dict.state()
    if state == "down":
        return None

    result: HostResult = {
        "host": host_ip,
        "state": state,  # type: ignore[typeddict-item]
        "ports": _extract_ports(host_dict),
    }

    hostnames = [h["name"] for h in host_dict.get("hostnames", []) if h.get("name")]
    if hostnames:
        result["hostnames"] = hostnames

    osmatch = host_dict.get("osmatch") or []
    if osmatch:
        best = osmatch[0]
        result["os"] = best.get("name", "")
        try:
            result["os_accuracy"] = int(best.get("accuracy", 0))
        except (TypeError, ValueError):
            pass

    host_scripts_raw = host_dict.get("hostscript") or []
    if host_scripts_raw:
        # hostscript is a list of {'id': ..., 'output': ...} dicts
        hs: list[ScriptResult] = []
        for entry in host_scripts_raw:
            if entry.get("output"):
                hs.append({"id": entry.get("id", "unknown"), "output": _cleanse_output(entry["output"])})
        if hs:
            result["host_scripts"] = hs

    return result


def _build_summary(tool: str, hosts: list[HostResult]) -> str:
    if not hosts:
        return f"{tool}: no live hosts"

    port_count = sum(len(h["ports"]) for h in hosts)
    if port_count == 0:
        return f"{tool}: {len(hosts)} host(s) up, no open ports"

    service_bits: list[str] = []
    for h in hosts:
        for p in h["ports"][:6]:  # cap to keep summary short
            svc = p.get("service", "?")
            prod = p.get("product")
            ver = p.get("version")
            bit = f"{p['port']}/{svc}"
            if prod:
                bit += f" {prod}"
                if ver:
                    bit += f" {ver}"
            service_bits.append(bit)
    services = ", ".join(service_bits[:8])
    return (
        f"{tool}: {len(hosts)} host(s) up, {port_count} open port(s) ({services})"
    )


def _normalize(tool: str, target: str, scanner: nmap.PortScanner, elapsed: float) -> ScanResult:
    hosts: list[HostResult] = []
    for ip in scanner.all_hosts():
        h = _extract_host(ip, scanner)
        if h is not None:
            hosts.append(h)

    return {
        "ok": True,
        "tool": tool,
        "target": target,
        "command": scanner.command_line(),
        "elapsed_seconds": round(elapsed, 2),
        "hosts": hosts,
        "summary": _build_summary(tool, hosts),
    }


def _error_result(tool: str, target: str, command: str, elapsed: float, err: ErrorInfo) -> ScanResult:
    return {
        "ok": False,
        "tool": tool,
        "target": target,
        "command": command,
        "elapsed_seconds": round(elapsed, 2),
        "hosts": [],
        "summary": f"{tool} failed: {err['code']} — {err['hint']}",
        "error": err,
    }


def _run_blocking(
    tool: str,
    target: str,
    user_args: str,
    use_pn: bool = True,
) -> ScanResult:
    """Synchronous core — runs on a background thread via asyncio.to_thread."""
    args = _compose_args(user_args, target, use_pn)
    scanner = nmap.PortScanner()
    start = time.monotonic()
    command_guess = f"nmap {args} {target}"

    try:
        scanner.scan(hosts=target, arguments=args, timeout=0)
    except nmap.PortScannerError as exc:
        elapsed = time.monotonic() - start
        stderr = str(exc)
        return _error_result(tool, target, command_guess, elapsed, classify(exc, stderr))
    except Exception as exc:  # noqa: BLE001
        elapsed = time.monotonic() - start
        return _error_result(tool, target, command_guess, elapsed, classify(exc, str(exc)))

    elapsed = time.monotonic() - start

    # python-nmap doesn't raise for DNS-resolve failures, timeouts, or
    # invalid-arg warnings — it records them in scaninfo. Check for
    # those before treating the scan as successful.
    scaninfo = scanner._scan_result.get("nmap", {}).get("scaninfo", {})
    scan_errors = scaninfo.get("error") or []
    if scan_errors and not scanner.all_hosts():
        stderr_blob = " ".join(str(e) for e in scan_errors)
        return _error_result(
            tool, target, scanner.command_line(), elapsed,
            classify(RuntimeError(stderr_blob), stderr_blob),
        )

    result = _normalize(tool, target, scanner, elapsed)

    warnings: list[str] = []
    if tool in _NEEDS_ROOT_TOOLS and not _is_root():
        warnings.append(
            f"{tool} ran without root — results may be degraded "
            "(UDP/OS detection needs raw sockets)."
        )
    # Surface non-fatal scaninfo warnings (e.g. partial timeouts)
    scan_warnings = scaninfo.get("warning") or []
    for w in scan_warnings:
        text = str(w).strip()
        if text and "No targets were specified" not in text:
            warnings.append(text[:500])
    if warnings:
        result["warnings"] = warnings

    return result


async def run(
    tool: str,
    target: str,
    user_args: str,
    use_pn: bool = True,
) -> ScanResult:
    """Async entry point used by every nmap_* tool."""
    return await asyncio.to_thread(_run_blocking, tool, target, user_args, use_pn)
