"""Configured artifact paths for real-target engagements.

Benchmarks intentionally do not import or use this module.  Their existing
``logs/`` and campaign directory layout remains unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
from urllib.parse import urlsplit

from src.config_schema import resolve


PROJECT_ROOT = Path(__file__).resolve().parents[1]

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_HOST_RE = re.compile(
    r"(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,63}|"
    r"(?:\d{1,3}\.){3}\d{1,3}|localhost)(?::\d+)?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LiveOutputLayout:
    """Human-readable paths for one real-target engagement."""

    target_name: str
    date_label: str
    artifact_prefix: str
    directory: Path


def configured_live_output_root() -> Path:
    """Return the configured live-output root as an absolute path.

    Relative paths are resolved from the SwarmAttacker repository root so the
    result does not depend on the shell's current working directory. ``~`` and
    absolute paths are supported for storage outside the repository.
    """
    raw = str(resolve().get("output", {}).get("directory") or "output").strip()
    path = Path(raw or "output").expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def _hostname_from_text(text: str) -> str:
    """Extract a hostname/IP from a scope or natural-language instruction."""
    value = str(text or "").strip()
    if not value:
        return ""

    url_match = _URL_RE.search(value)
    if url_match:
        hostname = urlsplit(url_match.group(0).rstrip(".,;:!?)]}")).hostname
        if hostname:
            return hostname.lower()

    # A scope is often just ``*.example.com`` or ``example.com:8443``.
    direct = value.strip("`'\"[](){}<>,; ").lstrip("*.")
    parsed = urlsplit(f"//{direct}")
    if parsed.hostname and (
        "." in parsed.hostname or parsed.hostname.lower() == "localhost"
    ):
        return parsed.hostname.lower()

    host_match = _HOST_RE.search(value)
    if host_match:
        parsed = urlsplit(f"//{host_match.group(0)}")
        if parsed.hostname:
            return parsed.hostname.lower()
    return ""


def target_name_from_instruction(user_input: str, target_scope: str = "") -> str:
    """Return a filesystem-safe target name, preferring explicit scope."""
    hostname = _hostname_from_text(target_scope) or _hostname_from_text(user_input)
    candidate = hostname or "target"
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "-", candidate).strip("-_.")
    return (safe or "target")[:100]


def create_live_output_layout(
    user_input: str,
    target_scope: str = "",
    *,
    now: datetime | None = None,
) -> LiveOutputLayout:
    """Create a target-first, date-labelled directory for one engagement.

    Example: ``nkd-test.medienbutler.online 15 jul pentest report``. If that
    target is tested more than once on the same day, `` (2)``, `` (3)``, ...
    is appended to the folder only so no prior run is overwritten.
    """
    generated = now or datetime.now().astimezone()
    target_name = target_name_from_instruction(user_input, target_scope)
    date_label = f"{generated.day} {generated.strftime('%b').lower()}"
    artifact_prefix = f"{target_name} {date_label}"
    folder_name = f"{artifact_prefix} pentest report"

    root = configured_live_output_root()
    root.mkdir(parents=True, exist_ok=True)
    counter = 1
    while True:
        suffix = "" if counter == 1 else f" ({counter})"
        directory = root / f"{folder_name}{suffix}"
        try:
            directory.mkdir()
            break
        except FileExistsError:
            counter += 1

    return LiveOutputLayout(
        target_name=target_name,
        date_label=date_label,
        artifact_prefix=artifact_prefix,
        directory=directory.resolve(),
    )


__all__ = [
    "LiveOutputLayout",
    "configured_live_output_root",
    "create_live_output_layout",
    "target_name_from_instruction",
]
