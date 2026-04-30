"""Typed web-recon tool wrappers (gobuster, whatweb, nikto)."""

from src.tools.web_recon.gobuster import gobuster_dir
from src.tools.web_recon.nikto import nikto_scan
from src.tools.web_recon.whatweb import whatweb

__all__ = ["gobuster_dir", "nikto_scan", "whatweb"]
