"""Tool registry — string name → callable lookup.

The skill loader (`src/skills/loader.py`) reads each SKILL.md's
``metadata.tools`` list, which is YAML strings (e.g. ``[run_command,
sqlmap_basic]``). To bind those names to actual LangChain tool callables
we need one canonical mapping. This module is that mapping.

Adding a new typed tool? Add an import below and a name → callable entry
in ``_REGISTRY``. The string MUST match the tool's ``@tool`` function
name so SKILL.md frontmatter and the registry agree.
"""

from __future__ import annotations

from langchain_core.tools import BaseTool

from src.tools.auth.hydra import hydra_http_form
from src.tools.nmap import (
    nmap_aggressive,
    nmap_default_scripts,
    nmap_fast_scan,
    nmap_full_scan,
    nmap_host_discovery,
    nmap_http_enum,
    nmap_os_detection,
    nmap_ping_sweep,
    nmap_script,
    nmap_service_detection,
    nmap_smb_enum,
    nmap_specific_ports,
    nmap_ssl_enum,
    nmap_udp_scan,
    nmap_vuln_scan,
)
from src.tools.shell import bash, read_file, run_command
from src.tools.sqlmap import sqlmap_basic, sqlmap_dump_table, sqlmap_enum_dbs
from src.tools.sslscan import sslscan_full
from src.tools.testssl import testssl_full
from src.tools.web_recon import fetch_page, gobuster_dir, nikto_scan, whatweb


_REGISTRY: dict[str, BaseTool] = {
    # Generic shell + file
    "bash":                   bash,         # one-shot non-interactive
    "run_command":            run_command,  # interactive tmux pane
    "read_file":              read_file,

    # nmap (typed)
    "nmap_aggressive":        nmap_aggressive,
    "nmap_default_scripts":   nmap_default_scripts,
    "nmap_fast_scan":         nmap_fast_scan,
    "nmap_full_scan":         nmap_full_scan,
    "nmap_host_discovery":    nmap_host_discovery,
    "nmap_http_enum":         nmap_http_enum,
    "nmap_os_detection":      nmap_os_detection,
    "nmap_ping_sweep":        nmap_ping_sweep,
    "nmap_script":            nmap_script,
    "nmap_service_detection": nmap_service_detection,
    "nmap_smb_enum":          nmap_smb_enum,
    "nmap_specific_ports":    nmap_specific_ports,
    "nmap_ssl_enum":          nmap_ssl_enum,
    "nmap_udp_scan":          nmap_udp_scan,
    "nmap_vuln_scan":         nmap_vuln_scan,

    # SQL injection (typed)
    "sqlmap_basic":           sqlmap_basic,
    "sqlmap_enum_dbs":        sqlmap_enum_dbs,
    "sqlmap_dump_table":      sqlmap_dump_table,

    # TLS / crypto (typed)
    "sslscan_full":           sslscan_full,
    "testssl_full":           testssl_full,

    # Web recon (typed)
    "fetch_page":             fetch_page,
    "gobuster_dir":           gobuster_dir,
    "whatweb":                whatweb,
    "nikto_scan":             nikto_scan,

    # Auth (typed)
    "hydra_http_form":        hydra_http_form,
}


def resolve_tool(name: str) -> BaseTool | None:
    """Look up a typed tool callable by its registered string name."""
    return _REGISTRY.get(name)


def resolve_tools(names: list[str]) -> list[BaseTool]:
    """Resolve a list of tool names; logs and skips unknown entries."""
    import logging
    logger = logging.getLogger(__name__)
    out: list[BaseTool] = []
    for n in names:
        t = _REGISTRY.get(n)
        if t is None:
            logger.warning("tool registry: unknown tool name %r — skipped", n)
            continue
        out.append(t)
    return out


def list_tools() -> list[str]:
    """Names of every registered tool (sorted, for diagnostics)."""
    return sorted(_REGISTRY.keys())
