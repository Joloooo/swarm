"""Live-target traffic policy and per-target pacing.

Benchmark runs deliberately keep the historical fast behaviour.  The real-
target entry point enables ``remote_safe`` for the lifetime of one engagement;
all supported network tools then share one host-level lane, a minimum delay,
and timeout/block backoff.  A :class:`ContextVar` keeps concurrent benchmark
processes and ordinary imports on the fast path unless they explicitly opt in.
"""

from __future__ import annotations

import asyncio
import re
import time
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import AsyncIterator, Iterator
from urllib.parse import urlparse


FAST_PROFILE = "benchmark_fast"
REMOTE_SAFE_PROFILE = "remote_safe"
DEFAULT_LIVE_ENGAGEMENT_SECONDS = 4 * 60 * 60
# Backward-compatible name for callers that still want the historical default.
LIVE_ENGAGEMENT_SECONDS = DEFAULT_LIVE_ENGAGEMENT_SECONDS

_profile: ContextVar[str] = ContextVar("swarm_traffic_profile", default=FAST_PROFILE)


@dataclass
class _HostState:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_finished: float = 0.0
    consecutive_blocks: int = 0
    retry_after: float = 0.0


_loop_id: int | None = None
_hosts: dict[str, _HostState] = {}

_BLOCK_SIGNALS = re.compile(
    r"(?:timed?\s*out|timeout(?:error)?|failed to connect|connecttimeout|"
    r"429\b|too many requests|retry-after|request blocked|access denied)",
    re.IGNORECASE,
)


def current_profile() -> str:
    return _profile.get()


def is_remote_safe() -> bool:
    return current_profile() == REMOTE_SAFE_PROFILE


@contextmanager
def remote_safe_engagement() -> Iterator[None]:
    """Enable polite live-target traffic handling in the current async context."""
    token = _profile.set(REMOTE_SAFE_PROFILE)
    try:
        yield
    finally:
        _profile.reset(token)


def _host_key(target: str | None) -> str:
    # One real-target engagement has one authorised target. Use a single lane
    # even when workers spell it as a hostname, IP, redirect URL, or a raw
    # shell command whose classifier cannot recover the host. This prevents
    # recon, crawler, and shell workers from independently stampeding it.
    if is_remote_safe():
        return "__live_engagement__"
    raw = (target or "").strip()
    if not raw:
        return "__live_target__"
    try:
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        return (parsed.hostname or raw).lower()
    except Exception:
        return raw.lower()


def _state_for(target: str | None) -> _HostState:
    global _loop_id, _hosts
    loop = asyncio.get_running_loop()
    this_loop = id(loop)
    if _loop_id != this_loop:
        # The TUI can run multiple engagements through separate asyncio.run()
        # loops. Locks from a closed loop must never leak into the next run.
        _loop_id = this_loop
        _hosts = {}
    return _hosts.setdefault(_host_key(target), _HostState())


@asynccontextmanager
async def traffic_slot(
    target: str | None,
    *,
    minimum_delay_s: float = 2.0,
) -> AsyncIterator[None]:
    """Serialize live traffic to one host and enforce spacing/backoff."""
    if not is_remote_safe():
        yield
        return

    state = _state_for(target)
    async with state.lock:
        now = time.monotonic()
        wait_until = max(state.last_finished + minimum_delay_s, state.retry_after)
        if wait_until > now:
            await asyncio.sleep(wait_until - now)
        try:
            yield
        finally:
            state.last_finished = time.monotonic()


def observe_traffic(target: str | None, output: object) -> None:
    """Update live-target backoff from a tool result; no-op for benchmarks."""
    if not is_remote_safe():
        return
    state = _state_for(target)
    text = str(output or "")
    if _BLOCK_SIGNALS.search(text):
        state.consecutive_blocks = min(state.consecutive_blocks + 1, 6)
        # 5, 15, 30, 60, 120, 120 seconds. This pauses the shared lane, so
        # sibling workers do not stampede a host that has started dropping us.
        delays = (5, 15, 30, 60, 120, 120)
        delay = delays[state.consecutive_blocks - 1]
        state.retry_after = max(state.retry_after, time.monotonic() + delay)
    else:
        state.consecutive_blocks = 0
        state.retry_after = 0.0


def live_shell_block(command: str, binary: str | None) -> str | None:
    """Reject unmistakably loud raw scanners during a live engagement."""
    if not is_remote_safe():
        return None
    low = command.lower()
    name = (binary or "").lower()
    if name in {"masscan", "naabu", "rustscan"}:
        return (
            "BLOCKED by remote-safe live profile: high-rate port scanner. "
            "Use a narrow nmap_specific_ports check against evidence-backed ports."
        )
    if name == "nmap" and (
        " -p-" in f" {low}" or "-a " in f" {low} " or "--script=vuln" in low
        or " -su" in f" {low}"
    ):
        return (
            "BLOCKED by remote-safe live profile: broad/aggressive nmap command. "
            "Check the supplied web port or a small explicit port list at low rate."
        )
    if name == "gobuster" and not (
        re.search(r"(?:^|\s)-t\s+1(?:\s|$)", command)
        and "--delay" in low
        and "--timeout" in low
    ):
        return (
            "BLOCKED by remote-safe live profile: raw gobuster must use "
            "'-t 1 --delay 2s --timeout 60s'. Prefer the gobuster_dir tool, "
            "which applies these limits automatically."
        )
    return None


REMOTE_SAFE_PROMPT = """\
## Remote-safe live-target profile (enforced)

This is a real remote system, not a local benchmark. Treat it as slow and
fragile. The tool layer serializes traffic per host, spaces requests, backs off
after timeouts/block signals, and rejects broad scanners.

- Start with the supplied URL/port and evidence-backed paths.
- Never run an all-port, aggressive, UDP, or vulnerability-script nmap scan.
- Use one request at a time. Do not create parallel request loops in Python or shell.
- Prefer a few targeted paths before wordlist enumeration.
- A timeout is not a negative application result. Stop that probe family and let
  the shared backoff expire before one lightweight reachability check.
- Do not bypass the remote-safe guard by substituting another high-rate scanner.
"""
