"""TEMPORARY / EMERGENCY — pick which Codex account the next run uses.

This is an on-the-side helper, **not** a core feature. It never touches the
main login and never overwrites ``~/.codex/auth.json``.

Model
-----
* **main**  — the normal login at ``~/.codex/auth.json`` (e.g. *jolocorp*).
  This is the DEFAULT and is left completely untouched. When no extra
  account is selected, the swarm behaves exactly as before.
* **extra accounts** — full ``auth.json`` copies kept OUTSIDE the repo, one
  self-contained CODEX_HOME directory per account::

      ~/.codex-accounts/<name>/auth.json

Switching does **not** move any files. It just sets/clears one env var::

      SWARM_CODEX_HOME = ""                              → main (~/.codex)
      SWARM_CODEX_HOME = ~/.codex-accounts/<name>        → that extra account

A ``swarm`` run is a fresh subprocess that inherits this env
(``runner._spawn`` passes ``env=os.environ.copy()``); ``LLMConfig`` reads
``SWARM_CODEX_HOME`` and hands it to ``ChatCodex(codex_home=...)``, whose
``load_tokens`` reads ``<home>/auth.json``. Unset → ``~/.codex`` → main.

To fully revert: delete this module + the Tab hook in ``tui.py`` + the
``codex_home`` field in ``src/llm/provider.py``, and remove
``~/.codex-accounts/``. The default path is unchanged either way.

CLI::

    uv run python -m src.cli.codex_accounts list
    uv run python -m src.cli.codex_accounts selected
    uv run python -m src.cli.codex_accounts capture <name>   # add an extra account
    uv run python -m src.cli.codex_accounts select  <name>   # or 'main'
    uv run python -m src.cli.codex_accounts cycle
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from pathlib import Path

# The main login — left untouched. Display name is yours to set.
CODEX_HOME = Path.home() / ".codex"
MAIN = "main"
MAIN_LABEL = "jolocorp"

# Extra accounts live here, one CODEX_HOME dir each.
ACCOUNTS_DIR = Path.home() / ".codex-accounts"

# The env var the provider reads to redirect ChatCodex at an extra account.
ENV_VAR = "SWARM_CODEX_HOME"


# ---------------------------------------------------------------------------
# Token introspection (read-only; never prints secrets)
# ---------------------------------------------------------------------------

def _account_id_of(auth_file: Path) -> str | None:
    """ChatGPT account id from an auth.json, or None. Mirrors the resolution
    order in ``src.llm.codex.load_tokens`` (explicit field, then JWT claim)."""
    try:
        data = json.loads(auth_file.read_text())
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
    except Exception:  # noqa: BLE001 — malformed token → "unknown"
        return None
    return (claims.get("https://api.openai.com/auth") or {}).get("chatgpt_account_id") or None


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

def home_for(name: str) -> Path:
    """CODEX_HOME directory for an account name (``main`` → ``~/.codex``)."""
    return CODEX_HOME if name == MAIN else ACCOUNTS_DIR / name


def _auth_file(name: str) -> Path:
    return home_for(name) / "auth.json"


def extra() -> list[str]:
    """Names of saved extra accounts (subdirs with an auth.json), sorted."""
    if not ACCOUNTS_DIR.is_dir():
        return []
    return sorted(
        p.name for p in ACCOUNTS_DIR.iterdir()
        if p.is_dir() and (p / "auth.json").is_file()
    )


def order() -> list[str]:
    """Cycle order: main first, then extra accounts alphabetically."""
    return [MAIN, *extra()]


def display_name(name: str) -> str:
    return f"{MAIN_LABEL} (main)" if name == MAIN else name


def account_id(name: str) -> str | None:
    return _account_id_of(_auth_file(name))


# ---------------------------------------------------------------------------
# Selection (env var only — no files are moved)
# ---------------------------------------------------------------------------

def selected() -> str:
    """Currently-selected account for the NEXT run.

    Reads ``SWARM_CODEX_HOME``: unset/empty → main; a path that matches a
    saved extra account → that name; anything else → main (safe fallback).
    """
    raw = os.environ.get(ENV_VAR, "").strip()
    if not raw:
        return MAIN
    chosen = Path(raw)
    for name in extra():
        if home_for(name) == chosen:
            return name
    return MAIN


def select(name: str) -> None:
    """Choose which account the next run uses. ``main`` clears the override."""
    if name == MAIN:
        os.environ.pop(ENV_VAR, None)
    else:
        os.environ[ENV_VAR] = str(home_for(name))


def cycle() -> str:
    """Advance the selection to the next account, round-robin. Returns it.

    No-op (returns current) when there are no extra accounts to cycle to.
    """
    names = order()
    if len(names) < 2:
        return selected()
    cur = selected()
    nxt = names[(names.index(cur) + 1) % len(names)] if cur in names else MAIN
    select(nxt)
    return nxt


# ---------------------------------------------------------------------------
# Capture an extra account (atomic, 0600, fsync for Drive-backed homes)
# ---------------------------------------------------------------------------

def capture(name: str) -> Path:
    """Save the current live ``~/.codex/auth.json`` as extra account ``name``.

    Used when you've signed into an *additional* account and want to register
    it for switching. Never used for the main login. Refuses ``main``.
    """
    if name == MAIN:
        raise ValueError("refusing to capture over the main login name")
    live = CODEX_HOME / "auth.json"
    if not live.exists():
        raise FileNotFoundError(f"No live login at {live}. Sign in with `codex` first.")
    dst = ACCOUNTS_DIR / name / "auth.json"
    _atomic_copy(live, dst)
    return dst


def _atomic_copy(src: Path, dst: Path) -> None:
    data = src.read_bytes()
    dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(dst.parent), prefix=".tmp-auth-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, dst)
        tmp = ""
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "list"

    if cmd == "list":
        sel = selected()
        for name in order():
            acc = account_id(name) or "?"
            mark = " *selected*" if name == sel else ""
            print(f"  {display_name(name):<22s} account_id=…{acc[-12:]}{mark}")
        if not extra():
            print(f"  (no extra accounts in {ACCOUNTS_DIR} — use `capture <name>`)")
        return 0

    if cmd == "selected":
        print(display_name(selected()))
        return 0

    if cmd == "capture":
        if len(argv) < 2:
            print("usage: capture <name>", file=sys.stderr)
            return 2
        print(f"captured live login → {capture(argv[1])}")
        return 0

    if cmd == "select":
        if len(argv) < 2:
            print("usage: select <name|main>", file=sys.stderr)
            return 2
        name = argv[1]
        if name != MAIN and name not in extra():
            print(f"unknown account {name!r}. known: {', '.join(order())}", file=sys.stderr)
            return 1
        select(name)
        # NOTE: this only affects the current process. The TUI sets it live;
        # from a shell, `export SWARM_CODEX_HOME=...` is the persistent form.
        print(f"selected: {display_name(name)}  ({ENV_VAR}={os.environ.get(ENV_VAR, '<unset → main>')})")
        return 0

    if cmd == "cycle":
        print(f"selected: {display_name(cycle())}")
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
