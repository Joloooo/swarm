"""TEMPORARY / EMERGENCY — switch the active Codex login between accounts.

This is an on-the-side helper, **not** a core feature. It deliberately does
NOT touch the token/provider code in ``src/llm/`` (``codex.py`` /
``provider.py``). It works purely by swapping the one file the Codex client
already reads at run start::

    ~/.codex/auth.json          ← the "live" login (what ChatCodex loads)

Per-account full copies of that file are kept OUTSIDE the repo, because they
contain OAuth access + refresh tokens::

    ~/.codex-accounts/<name>.json

Switching = atomically copy a snapshot over ``~/.codex/auth.json``. The next
``swarm`` run is a fresh subprocess whose ``load_tokens()`` reads the swapped
file, so it picks up the new account with zero changes to the agent code.

To fully revert: delete this module, drop the Tab hook in ``tui.py``, and
remove ``~/.codex-accounts/``. Nothing else depends on it.

CLI usage (handy for capturing a login after signing into it)::

    uv run python -m src.cli.codex_accounts list
    uv run python -m src.cli.codex_accounts active
    uv run python -m src.cli.codex_accounts capture jolocorp
    uv run python -m src.cli.codex_accounts switch  hello-chainmatics
    uv run python -m src.cli.codex_accounts cycle
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from pathlib import Path

CODEX_HOME = Path.home() / ".codex"
LIVE = CODEX_HOME / "auth.json"
SNAP_DIR = Path.home() / ".codex-accounts"

# Display / cycle order. Names not present on disk are skipped, and any
# extra snapshots found on disk are appended (sorted) after these.
PREFERRED_ORDER = ["jolocorp", "hello-chainmatics"]


# ---------------------------------------------------------------------------
# Token introspection (read-only; never prints secrets)
# ---------------------------------------------------------------------------

def _account_id(path: Path) -> str | None:
    """Return the ChatGPT account id stored in an auth.json, or None.

    Prefers the explicit ``tokens.account_id`` field; falls back to the
    ``chatgpt_account_id`` claim inside the (unverified) access-token JWT —
    same resolution order as ``src.llm.codex.load_tokens``.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    tokens = data.get("tokens") or {}
    if tokens.get("account_id"):
        return str(tokens["account_id"])
    tok = tokens.get("access_token", "")
    parts = tok.split(".")
    if len(parts) < 2:
        return None
    try:
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:  # noqa: BLE001 — malformed token → just "unknown"
        return None
    auth = claims.get("https://api.openai.com/auth") or {}
    return auth.get("chatgpt_account_id") or None


# ---------------------------------------------------------------------------
# Snapshot inventory
# ---------------------------------------------------------------------------

def snapshots() -> list[str]:
    """Names of saved accounts (``~/.codex-accounts/<name>.json``).

    Ordered by ``PREFERRED_ORDER`` first, then any extras alphabetically.
    """
    if not SNAP_DIR.is_dir():
        return []
    names = {p.stem for p in SNAP_DIR.glob("*.json")}
    ordered = [n for n in PREFERRED_ORDER if n in names]
    ordered += sorted(names - set(ordered))
    return ordered


def active() -> str | None:
    """Name of the snapshot whose account matches the live ``auth.json``.

    Returns None if there is no live login, or the live login hasn't been
    captured as a snapshot yet (a useful cue to ``capture`` it).
    """
    if not LIVE.exists():
        return None
    live_id = _account_id(LIVE)
    if not live_id:
        return None
    for name in snapshots():
        if _account_id(SNAP_DIR / f"{name}.json") == live_id:
            return name
    return None


# ---------------------------------------------------------------------------
# Mutations (atomic file swaps, 0600 perms, fsync for Drive-backed homes)
# ---------------------------------------------------------------------------

def _atomic_copy(src: Path, dst: Path) -> None:
    """Copy ``src`` → ``dst`` atomically with 0600 perms.

    Writes a temp file in the destination dir, fsyncs it, then
    ``os.replace`` (atomic on POSIX) so a half-written auth.json can never
    be observed by a concurrently-starting run.
    """
    data = src.read_bytes()
    dst.parent.mkdir(mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(dst.parent), prefix=".tmp-auth-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, dst)
        tmp = ""  # replaced — nothing to clean up
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def capture(name: str) -> Path:
    """Save the current live login as snapshot ``name``; return its path."""
    if not LIVE.exists():
        raise FileNotFoundError(
            f"No live login at {LIVE}. Run `codex` and sign in first."
        )
    dst = SNAP_DIR / f"{name}.json"
    _atomic_copy(LIVE, dst)
    return dst


def switch_to(name: str) -> bool:
    """Make snapshot ``name`` the live login. False if it doesn't exist."""
    src = SNAP_DIR / f"{name}.json"
    if not src.exists():
        return False
    _atomic_copy(src, LIVE)
    return True


def cycle() -> str | None:
    """Switch the live login to the next saved account, round-robin.

    No-op (returns the current active name) when fewer than two snapshots
    exist. Returns the newly-active account name on success.
    """
    names = snapshots()
    if len(names) < 2:
        return active()
    cur = active()
    nxt = names[(names.index(cur) + 1) % len(names)] if cur in names else names[0]
    switch_to(nxt)
    return nxt


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "list"

    if cmd == "list":
        names = snapshots()
        act = active()
        if not names:
            print(f"(no snapshots in {SNAP_DIR})")
            return 0
        for n in names:
            acc = _account_id(SNAP_DIR / f"{n}.json") or "?"
            mark = " *active*" if n == act else ""
            print(f"  {n:<20s} account_id=…{acc[-12:]}{mark}")
        if act is None:
            print("  (live login is not one of the saved snapshots)")
        return 0

    if cmd == "active":
        print(active() or "(unknown / not captured)")
        return 0

    if cmd == "capture":
        if len(argv) < 2:
            print("usage: capture <name>", file=sys.stderr)
            return 2
        path = capture(argv[1])
        print(f"captured live login → {path}")
        return 0

    if cmd == "switch":
        if len(argv) < 2:
            print("usage: switch <name>", file=sys.stderr)
            return 2
        if switch_to(argv[1]):
            print(f"live login is now: {argv[1]}")
            return 0
        print(f"no snapshot named {argv[1]!r} in {SNAP_DIR}", file=sys.stderr)
        return 1

    if cmd == "cycle":
        new = cycle()
        print(f"live login is now: {new or '(unknown)'}")
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
