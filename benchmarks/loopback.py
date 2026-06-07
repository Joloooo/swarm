"""Per-run loopback IP allocator for the XBEN benchmark runner.

Docker Desktop on macOS publishes container ports onto the shared host
``localhost``, so concurrently-running benchmarks collide on ``127.0.0.1`` with
random host ports and the agent cannot tell which port belongs to *its* target
(``nmap localhost`` also bleeds across every running benchmark). The companion
``setup_loopback_pool.sh`` adds a pool of loopback aliases (``127.0.0.2`` …
``127.0.0.N``); this module hands each run its own IP from that pool so the
benchmark's REAL ports (80, 22, …) can be bound to a unique address the agent
scans in isolation — restoring realistic recon and clean concurrency (two VMs
can both serve port 80 because ``127.0.0.5:80`` ≠ ``127.0.0.6:80``).

Leases are atomic lock files under ``benchmarks/.loopback_leases/`` so the
allocator is safe across the *separate* SwarmAttacker processes a sweep may run
in parallel. A lease whose owning PID is no longer alive is reclaimed, so a
crashed run never permanently leaks its IP.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# Pool definition — MUST match benchmarks/setup_loopback_pool.sh.
_BASE = "127.0.0"
_START = 2          # 127.0.0.2 is the first alias; .1 is the real localhost
_COUNT = 20
POOL: tuple[str, ...] = tuple(f"{_BASE}.{i}" for i in range(_START, _START + _COUNT))

_LEASE_DIR = Path(__file__).resolve().parent / ".loopback_leases"

# The companion script that actually creates the lo0 aliases this module
# leases (``ifconfig lo0 alias 127.0.0.X``). macOS drops them on reboot, so it
# must be re-run once per boot; the ``swarm`` TUI exposes it as a menu action
# and checks :func:`pool_status` before a concurrent sweep, so a sweep never
# silently loses isolation and collides on the shared localhost.
SETUP_SCRIPT = Path(__file__).resolve().parent / "setup_loopback_pool.sh"


def _configured_aliases() -> set[str]:
    """Pool IPs actually present on ``lo0`` — i.e. the setup script was run.

    Empty when the pool was never created, which makes :func:`acquire` return
    ``None`` and the caller fall back to the legacy localhost mapping.
    """
    try:
        out = subprocess.run(
            ["ifconfig", "lo0"], capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    present = set(re.findall(r"inet (127\.0\.0\.\d+)", out))
    return {ip for ip in POOL if ip in present}


def pool_status() -> tuple[int, int]:
    """``(present, total)`` — how many pool IPs are currently aliased on ``lo0``.

    ``present == 0`` means the pool was never set up this boot, so
    :func:`acquire` returns ``None`` and the runner falls back to the shared
    ``localhost`` mapping — concurrent benchmarks then collide on one address
    and their agents cross-probe each other. ``present == total`` means full
    isolation is available. Read-only (no sudo).
    """
    return len(_configured_aliases()), len(POOL)


def ensure_pool() -> tuple[int, int]:
    """Make the lo0 alias pool exist so every benchmark run is IP-isolated.

    Called automatically at the start of every run (single and sequential via
    the runner; once, in the launcher, for a concurrent fan-out) so isolation
    is never a manual step. Idempotent and cheap: a no-op when the pool is
    already present (no sudo). Otherwise it runs :data:`SETUP_SCRIPT` via
    ``sudo``, which asks for your password once per boot (macOS drops the
    aliases on reboot). Best-effort: if sudo is declined or unavailable the run
    still proceeds, falling back to the shared-localhost mapping (with the
    existing :func:`acquire` warning). Returns :func:`pool_status` afterwards.
    """
    present, total = pool_status()
    if present >= total:
        return present, total
    if sys.platform != "darwin" or not SETUP_SCRIPT.exists():
        # Linux routes 127.0.0.0/8 to lo without aliases; nothing to set up.
        return present, total
    print(
        f"[loopback] setting up target isolation pool ({present}/{total} present) "
        "— sudo may ask for your password (once per boot)…",
        file=sys.stderr,
    )
    try:
        subprocess.run(["sudo", "bash", str(SETUP_SCRIPT)], check=False)
    except (OSError, KeyboardInterrupt):
        pass
    return pool_status()


def _alive(pid: int) -> bool:
    """True if ``pid`` is a live process (so its lease must be respected)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just not ours to signal
    return True


def acquire() -> str | None:
    """Claim a free pool IP and return it, or ``None`` if none is available.

    ``None`` means either the alias pool was never set up (run
    ``setup_loopback_pool.sh``) or every configured alias is already leased;
    the caller should fall back to the legacy ``localhost:<random>`` behaviour
    and warn. Safe across processes: the lease is an ``O_CREAT|O_EXCL`` lock
    file, and a lease held by a dead PID is reclaimed.
    """
    _LEASE_DIR.mkdir(parents=True, exist_ok=True)
    # Sort by the numeric last octet so allocation goes .2, .3, … .21 rather
    # than the lexical .10, .11, … .2 (cosmetic, but easier to follow in logs).
    for ip in sorted(_configured_aliases(), key=lambda a: int(a.rsplit(".", 1)[1])):
        lock = _LEASE_DIR / ip
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            # Reclaim only if the previous holder is gone.
            try:
                owner = int((lock.read_text().strip() or "-1"))
            except (OSError, ValueError):
                owner = -1
            if owner == -1 or _alive(owner):
                continue
            try:
                lock.unlink()
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except (FileExistsError, OSError):
                continue  # lost the race to another process
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
        return ip
    return None


def release(ip: str | None) -> None:
    """Free a previously acquired IP. No-op for ``None`` / unknown IPs."""
    if not ip:
        return
    try:
        (_LEASE_DIR / ip).unlink()
    except OSError:
        pass
