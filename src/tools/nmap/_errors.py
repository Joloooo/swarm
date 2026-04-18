"""Classify nmap / python-nmap exceptions into an LLM-friendly error dict.

Every nmap tool catches exceptions at the engine boundary and passes
them through classify(). The LLM reads error.code and error.hint to
decide what to try next.
"""

from __future__ import annotations

import re

from src.tools.nmap._schema import ErrorInfo


_BINARY_MISSING = re.compile(r"not\s+found|no\s+such\s+file", re.IGNORECASE)
_PERMISSION_DENIED = re.compile(
    r"requires?\s+root|privileged|operation\s+not\s+permitted|raw\s+sockets?",
    re.IGNORECASE,
)
_RESOLVE_FAIL = re.compile(r"failed\s+to\s+resolve|unable\s+to\s+resolve", re.IGNORECASE)
_TIMEOUT = re.compile(r"timed\s*out|host-timeout|script-timeout", re.IGNORECASE)
_INVALID_ARGS = re.compile(r"invalid\s+argument|WARNING|ERROR:", re.IGNORECASE)


_HINTS: dict[str, str] = {
    "binary_missing": (
        "nmap is not installed in the tool sandbox. Fall back to run_command "
        "with an HTTP-based probe (curl) or ask the user to install nmap."
    ),
    "permission_denied": (
        "This scan type needs root (raw sockets). Retry with tcp_connect=True "
        "for port scans, or skip OS/UDP detection."
    ),
    "invalid_target": (
        "The target hostname did not resolve. Try an IP directly, or verify DNS."
    ),
    "timeout": (
        "Scan exceeded its host-timeout. Narrow the port range (smaller top_ports "
        "or specific ports) or run a fast_scan first to shrink the target set."
    ),
    "invalid_args": (
        "Nmap rejected the arguments. Check ports / script names; see stderr "
        "for the exact complaint and retry."
    ),
    "unknown": (
        "Unexpected nmap error. Read stderr, retry once, or fall back to run_command."
    ),
}


def classify(exc: BaseException, stderr: str = "") -> ErrorInfo:
    """Map any exception + optional stderr into an ErrorInfo dict."""
    msg = f"{exc} {stderr}"

    if _BINARY_MISSING.search(msg):
        code = "binary_missing"
    elif _PERMISSION_DENIED.search(msg):
        code = "permission_denied"
    elif _RESOLVE_FAIL.search(msg):
        code = "invalid_target"
    elif _TIMEOUT.search(msg):
        code = "timeout"
    elif _INVALID_ARGS.search(msg):
        code = "invalid_args"
    else:
        code = "unknown"

    err: ErrorInfo = {"code": code, "hint": _HINTS[code]}  # type: ignore[typeddict-item]
    if stderr:
        err["stderr"] = stderr[:1000]
    return err
