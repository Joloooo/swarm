"""Typed web-recon tool wrappers (gobuster, whatweb, nikto, fetch_page)."""

from src.tools.web_recon.fetch_page import fetch_page
from src.tools.web_recon.gobuster import gobuster_dir
from src.tools.web_recon.nikto import nikto_scan
from src.tools.web_recon.whatweb import whatweb

__all__ = ["fetch_page", "gobuster_dir", "nikto_scan", "whatweb"]
