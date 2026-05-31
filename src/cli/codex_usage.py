"""TEMPORARY / EMERGENCY — show Codex 5-hour + weekly usage per account.

Read-only and standalone, pairs with :mod:`src.cli.codex_accounts`. It GETs
``https://chatgpt.com/backend-api/wham/usage`` with an account's OAuth token —
the same harmless status call the Codex CLI/IDE make constantly. It does NOT
consume model quota and never writes anything.

Response shape (confirmed live)::

    { "email", "plan_type",
      "rate_limit": {
        "primary_window":   {"used_percent", "limit_window_seconds": 18000,  "reset_after_seconds", "reset_at"},
        "secondary_window": {"used_percent", "limit_window_seconds": 604800, "reset_after_seconds", "reset_at"} },
      "credits": {"has_credits", "balance"} }

``primary_window`` is the 5-hour limit; ``secondary_window`` is the weekly one.

To remove: delete this file and the "Codex usage" row + handler in
``tui.py``. Nothing else imports it.

CLI::

    uv run python -m src.cli.codex_usage            # the selected account
    uv run python -m src.cli.codex_usage all        # main + every extra account
    uv run python -m src.cli.codex_usage <name>     # one account ('main' or extra)
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from src.cli import codex_accounts
from src.llm.codex import load_tokens, refresh_access_token

USAGE_ENDPOINT = "https://chatgpt.com/backend-api/wham/usage"


class CodexAccountAuthError(Exception):
    """The account's stored login was revoked or expired server-side.

    Raised on a 401 from either the refresh endpoint or the usage endpoint.
    The fix is always the same: sign into that account again and re-capture
    it (see ``codex_accounts.capture``). Distinguished from generic network
    errors so the UI can show "re-capture" instead of a raw stack string.
    """


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class Window:
    used_percent: float
    window_seconds: int
    reset_after_seconds: int

    @property
    def name(self) -> str:
        """Human name for the window keyed off its length."""
        s = self.window_seconds
        if s == 0:
            return "?"
        if abs(s - 18000) < 600:
            return "5-hour"
        if abs(s - 604800) < 3600:
            return "weekly"
        if s % 86400 == 0:
            return f"{s // 86400}-day"
        if s % 3600 == 0:
            return f"{s // 3600}-hour"
        return f"{s // 60}-min"

    @property
    def reset_human(self) -> str:
        return human_duration(self.reset_after_seconds)


@dataclass
class Usage:
    email: str | None
    plan_type: str | None
    primary: Window | None       # 5-hour window
    secondary: Window | None     # weekly window
    credits_balance: str | None
    has_credits: bool


def human_duration(seconds: int) -> str:
    if seconds <= 0:
        return "now"
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def _window(d: object) -> Window | None:
    if not isinstance(d, dict):
        return None
    return Window(
        used_percent=float(d.get("used_percent", 0) or 0),
        window_seconds=int(d.get("limit_window_seconds", 0) or 0),
        reset_after_seconds=int(d.get("reset_after_seconds", 0) or 0),
    )


def fetch(codex_home: Path | None = None, *, timeout: float = 15.0) -> Usage:
    """Fetch the live usage snapshot for the account at ``codex_home``.

    ``codex_home=None`` → the default ``~/.codex`` (main login). Raises
    ``httpx.HTTPError`` / ``FileNotFoundError`` on failure (callers catch).
    """
    tok = load_tokens(codex_home)
    if tok.expires_at and tok.expires_at < time.time() + 60:
        try:
            tok = refresh_access_token(tok)
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (400, 401):
                raise CodexAccountAuthError(
                    "refresh token revoked or expired — re-login and re-capture"
                ) from e
            raise

    headers = {
        "Authorization": f"Bearer {tok.access_token}",
        "Accept": "application/json",
    }
    if tok.account_id:
        headers["ChatGPT-Account-Id"] = tok.account_id

    resp = httpx.get(USAGE_ENDPOINT, headers=headers, timeout=timeout)
    if resp.status_code == 401:
        raise CodexAccountAuthError(
            "login revoked or expired — re-login and re-capture this account"
        )
    resp.raise_for_status()
    data = resp.json()

    rl = data.get("rate_limit") or {}
    cr = data.get("credits") or {}
    return Usage(
        email=data.get("email"),
        plan_type=data.get("plan_type"),
        primary=_window(rl.get("primary_window")),
        secondary=_window(rl.get("secondary_window")),
        credits_balance=cr.get("balance"),
        has_credits=bool(cr.get("has_credits")),
    )


def fetch_for(name: str) -> Usage:
    """Fetch usage for an account by switcher name ('main' or an extra)."""
    home = None if name == codex_accounts.MAIN else codex_accounts.home_for(name)
    return fetch(home)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _format_plain(name: str, u: Usage) -> str:
    plan = (u.plan_type or "?").lower()
    p = f"{u.primary.used_percent:g}%" if u.primary else "?"
    s = (
        f"{u.secondary.used_percent:g}% (resets {u.secondary.reset_human})"
        if u.secondary else "?"
    )
    who = u.email or ""
    return (
        f"{codex_accounts.display_name(name):<22s} [{plan}] {who}\n"
        f"    5-hour : {p}\n"
        f"    weekly : {s}\n"
        f"    credits: {u.credits_balance if u.has_credits else 'none'}"
    )


def _main(argv: list[str]) -> int:
    target = argv[0] if argv else codex_accounts.selected()
    if target == "all":
        names = codex_accounts.order()
    else:
        names = [target]

    rc = 0
    for name in names:
        try:
            print(_format_plain(name, fetch_for(name)))
        except Exception as e:  # noqa: BLE001
            print(f"{codex_accounts.display_name(name):<22s} ERROR: {type(e).__name__}: {e}")
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
