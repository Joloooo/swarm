"""URL normalization and reachability tools for the planner node.

These are *planner* tools — they don't take an ``agent_id`` and they
don't execute shell. They exist so the supervisor LLM can turn messy
user input ("example.com", "scan 192.168.1.10", "  HTTPS://Foo.com/ ")
into a canonical target URL and make an informed decision about
whether the target is reachable before dispatching attack workflows.

Ported from the TypeScript ``normalizeUrl`` / ``validateWebsite``
helpers the user referenced, adapted for a pentest context:

- Default scheme is ``http`` (pentest targets skew internal — CTF
  boxes, docker-compose, RFC1918 IPs rarely have TLS). The planner can
  override per-call with ``default_scheme="https"``.
- ``validate_website`` never raises; it always returns a structured
  dict and lets the planner decide whether a failure is blocking.
  An unreachable result is informational, not authoritative: RFC1918
  IPs behind a firewall, WAF-protected sites, and targets that block
  HEAD/GET from this IP can all fail this check legitimately.
- TLS verification is disabled (``verify=False``) because pentest
  targets routinely have self-signed or expired certs — the existing
  ``run_command`` tool already treats the target similarly.
"""

from __future__ import annotations

import ipaddress
import time
from urllib.parse import urlsplit, urlunsplit

from langchain_core.tools import tool


def _classify_host(host: str) -> tuple[bool, bool]:
    """Return (is_ip, is_private). Non-IP hosts always return (False, False)."""
    if not host:
        return False, False
    # IPv6 addresses arrive bracketed from urlsplit's hostname; strip them.
    bare = host.strip("[]")
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return False, False
    return True, bool(addr.is_private or addr.is_loopback or addr.is_link_local)


@tool
async def normalize_url(input: str, default_scheme: str = "http") -> dict:
    """Normalize a user-provided target string into a canonical URL.

    Accepts hostnames ("example.com"), IPv4/IPv6 addresses with or
    without ports ("192.168.1.10", "10.0.0.5:8080", "[::1]:8080"),
    URLs missing a scheme, URLs with a ``www.`` prefix, and strings
    with stray whitespace or mixed case. Returns a dict with:

    - ``href``: canonical URL, safe to hand to curl/nmap/httpx
    - ``host``: the hostname (no scheme, no port, no path)
    - ``display_host``: host with ``www.`` stripped, for log lines
    - ``scheme``: "http" or "https"
    - ``port``: the explicit port if given, else null
    - ``is_ip``: true if ``host`` is an IP literal
    - ``is_private``: true if ``host`` is RFC1918, loopback, or
      link-local — useful for the planner to decide whether public
      reachability checks make sense
    - ``original``: the raw input, for audit trails
    - ``valid``: false if parsing failed (planner should ask the user)

    Args:
        input: The raw target string from the user.
        default_scheme: Scheme to prepend when the input has none.
            Defaults to ``"http"`` because pentest targets skew
            internal; pass ``"https"`` for public web targets.
    """
    original = input or ""
    trimmed = original.strip()
    if not trimmed:
        return {
            "href": "",
            "host": "",
            "display_host": "",
            "scheme": "",
            "port": None,
            "is_ip": False,
            "is_private": False,
            "original": original,
            "valid": False,
            "reason": "empty input",
        }

    has_scheme = trimmed.lower().startswith(("http://", "https://"))
    with_scheme = trimmed if has_scheme else f"{default_scheme}://{trimmed}"

    try:
        parts = urlsplit(with_scheme)
        host = (parts.hostname or "").lower()
        if not host:
            raise ValueError("no host parsed")
        scheme = (parts.scheme or default_scheme).lower()
        if scheme not in ("http", "https"):
            scheme = default_scheme
        # Rebuild the href from the parsed parts so the scheme is lowercased
        # and any stray whitespace/case issues are normalized out.
        port = parts.port
        netloc = host if port is None else f"{host}:{port}"
        # IPv6 must remain bracketed in the netloc
        if ":" in host and not host.startswith("["):
            netloc = f"[{host}]" if port is None else f"[{host}]:{port}"
        href = urlunsplit((scheme, netloc, parts.path or "", parts.query, parts.fragment))
    except Exception as e:  # pragma: no cover — defensive
        return {
            "href": "",
            "host": "",
            "display_host": "",
            "scheme": "",
            "port": None,
            "is_ip": False,
            "is_private": False,
            "original": original,
            "valid": False,
            "reason": f"parse error: {e}",
        }

    is_ip, is_private = _classify_host(host)
    display_host = host[4:] if (not is_ip and host.startswith("www.")) else host

    return {
        "href": href,
        "host": host,
        "display_host": display_host,
        "scheme": scheme,
        "port": port,
        "is_ip": is_ip,
        "is_private": is_private,
        "original": original,
        "valid": True,
    }


@tool
async def validate_website(url: str, timeout_seconds: float = 5.0) -> dict:
    """Best-effort HTTP reachability check. Never raises.

    Sends a HEAD first, falls back to GET on 405/400 (some servers
    reject HEAD). Follows redirects. TLS verification is disabled so
    self-signed and expired certs don't produce false negatives.

    Returns:
        A dict with:

        - ``reachable``: true if any HTTP response came back
        - ``status_code``: the final HTTP status, or null
        - ``final_url``: the URL after redirects, or the input
        - ``reason``: null on success, else a short failure string
          ("timeout", "dns", "connection refused", etc.) — the planner
          uses this to judge whether the failure is blocking
        - ``elapsed_ms``: wall-clock time spent
        - ``method_used``: "HEAD" or "GET"

    Remember: a failure here is *informational*, not authoritative.
    RFC1918 IPs, docker-compose hosts, and WAF-protected sites can
    legitimately fail this check. The planner should read ``reason``
    and weigh it against the user's intent.
    """
    start = time.monotonic()

    try:
        import httpx  # Imported lazily so the rest of the codebase doesn't need it at import time.
    except ImportError:
        return {
            "reachable": False,
            "status_code": None,
            "final_url": url,
            "reason": "httpx not installed",
            "elapsed_ms": 0,
            "method_used": None,
        }

    async def _try(method: str, client: "httpx.AsyncClient") -> "httpx.Response":
        return await client.request(method, url)

    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=timeout_seconds,
        ) as client:
            method_used = "HEAD"
            try:
                resp = await _try("HEAD", client)
            except httpx.HTTPError:
                # Some servers break on HEAD; let GET fall through below.
                resp = None  # type: ignore[assignment]

            if resp is None or resp.status_code in (400, 405, 501):
                method_used = "GET"
                resp = await _try("GET", client)

            elapsed = int((time.monotonic() - start) * 1000)
            return {
                "reachable": True,
                "status_code": resp.status_code,
                "final_url": str(resp.url),
                "reason": None,
                "elapsed_ms": elapsed,
                "method_used": method_used,
            }
    except Exception as e:
        elapsed = int((time.monotonic() - start) * 1000)
        reason = _short_reason(e)
        return {
            "reachable": False,
            "status_code": None,
            "final_url": url,
            "reason": reason,
            "elapsed_ms": elapsed,
            "method_used": None,
        }


def _short_reason(exc: Exception) -> str:
    """Turn an httpx exception into a short, planner-friendly string."""
    name = type(exc).__name__
    msg = str(exc) or name
    # Common httpx exception classes — keep the message short so the
    # planner's prompt stays compact.
    if "Timeout" in name:
        return "timeout"
    if "ConnectError" in name or "ConnectionRefused" in msg:
        return "connection refused"
    if "NameResolution" in name or "dns" in msg.lower():
        return "dns resolution failed"
    if "SSL" in name or "Certificate" in name:
        return f"tls error: {msg[:80]}"
    return f"{name}: {msg[:80]}"
