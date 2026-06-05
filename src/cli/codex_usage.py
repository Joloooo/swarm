"""Show live Codex 5-hour + weekly usage for the ``~/.codex`` login.

Read-only and standalone. It GETs
``https://chatgpt.com/backend-api/wham/usage`` with the stored OAuth token —
the same harmless status call the Codex CLI/IDE make constantly. It does NOT
consume model quota and never writes anything.

Response shape (confirmed live)::

    { "email", "plan_type",
      "rate_limit": {
        "primary_window":   {"used_percent", "limit_window_seconds": 18000,  "reset_after_seconds", "reset_at"},
        "secondary_window": {"used_percent", "limit_window_seconds": 604800, "reset_after_seconds", "reset_at"} },
      "credits": {"has_credits", "balance"} }

``primary_window`` is the 5-hour limit; ``secondary_window`` is the weekly one.

Used by the "Codex usage" row in ``tui.py`` and by :mod:`src.cli.usage_guard`,
which paces benchmark sweeps against the 5-hour window.

CLI::

    uv run python -m src.cli.codex_usage     # the ~/.codex login's usage
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from src.llm.codex import load_tokens, refresh_access_token

USAGE_ENDPOINT = "https://chatgpt.com/backend-api/wham/usage"


class CodexAccountAuthError(Exception):
    """The stored Codex login was revoked or expired server-side.

    Raised on a 401 from either the refresh endpoint or the usage endpoint.
    The fix is always the same: sign in again with ``codex login``.
    Distinguished from generic network errors so the UI can show "re-login"
    instead of a raw stack string.
    """


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class Window:
    used_percent: float
    window_seconds: int
    reset_after_seconds: int
    # Unix epoch (seconds, UTC) at which this window resets. Equals
    # ``now + reset_after_seconds``; kept so the usage guard can fall back to
    # it and render a local reset clock time. Default 0 = not provided.
    reset_at: int = 0

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
        reset_at=int(d.get("reset_at", 0) or 0),
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


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _format_plain(u: Usage) -> str:
    plan = (u.plan_type or "?").lower()
    p = f"{u.primary.used_percent:g}%" if u.primary else "?"
    s = (
        f"{u.secondary.used_percent:g}% (resets {u.secondary.reset_human})"
        if u.secondary else "?"
    )
    who = u.email or "~/.codex"
    return (
        f"{who:<22s} [{plan}]\n"
        f"    5-hour : {p}\n"
        f"    weekly : {s}\n"
        f"    credits: {u.credits_balance if u.has_credits else 'none'}"
    )


def _main(_argv: list[str]) -> int:
    try:
        print(_format_plain(fetch()))
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {type(e).__name__}: {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
