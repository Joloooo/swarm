"""Typed nmap tools for SwarmAttacker agents.

Every tool returns a ScanResult (TypedDict from _schema) built by
parsing nmap's native XML output (`-oX -`) via python-nmap.

Usage:
    from src.tools.nmap import nmap_fast_scan, nmap_default_scripts
    ...
    AgentConfig(..., tools=[nmap_fast_scan, nmap_default_scripts], ...)
"""

from src.tools.nmap.discovery import nmap_host_discovery, nmap_ping_sweep
from src.tools.nmap.ports import (
    nmap_fast_scan,
    nmap_full_scan,
    nmap_specific_ports,
    nmap_udp_scan,
)
from src.tools.nmap.scripts import nmap_default_scripts, nmap_script
from src.tools.nmap.service import (
    nmap_aggressive,
    nmap_os_detection,
    nmap_service_detection,
)
from src.tools.nmap.vuln import (
    nmap_http_enum,
    nmap_smb_enum,
    nmap_ssl_enum,
    nmap_vuln_scan,
)

__all__ = [
    "nmap_aggressive",
    "nmap_default_scripts",
    "nmap_fast_scan",
    "nmap_full_scan",
    "nmap_host_discovery",
    "nmap_http_enum",
    "nmap_os_detection",
    "nmap_ping_sweep",
    "nmap_script",
    "nmap_service_detection",
    "nmap_smb_enum",
    "nmap_specific_ports",
    "nmap_ssl_enum",
    "nmap_udp_scan",
    "nmap_vuln_scan",
]
