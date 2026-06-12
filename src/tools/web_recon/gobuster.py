"""Typed gobuster directory-enumeration wrapper."""

from __future__ import annotations

import logging
import shlex

from langchain_core.tools import tool

from src.tools.shell import bash_exec
from src.tools.wordlists import resolve_wordlist


_log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 300

@tool
async def gobuster_dir(
    reasoning: str,
    url: str,
    wordlist: str = "common",
    extensions: str | None = None,
    threads: int = 20,
    status_codes: str = "200,204,301,302,307,401,403",
    agent_id: str = "default",
) -> str:
    """Brute-force directories and files under a web root with gobuster.

    Picks the ``dir`` mode (the right one for web-app recon, not DNS or
    vhost) and applies sensible defaults: 20 threads, common HTTP status
    codes treated as "found".

    Args:
        reasoning: Required. State what kind of hidden surface you expect
            (admin panel, backup files, API endpoints) and how a hit
            would change the next attack step.
        url: Web root, e.g. ``http://target/``.
        wordlist: One of "common" / "small" / "medium" / "big" /
            "wp-plugins" (resolved via ``src.tools.wordlists.resolve_wordlist``)
            or an absolute path to a custom wordlist file. ``common`` and
            ``wp-plugins`` always work because a real list ships in the repo's
            ``wordlists/`` dir (``wp-plugins`` enumerates WordPress plugin
            slugs, including known-vulnerable ones, against
            ``/wp-content/plugins/FUZZ/``).
            ``small`` / ``medium`` / ``big`` require SecLists or a Kali
            wordlists install; if neither is present the call raises
            ``FileNotFoundError`` with a hint to run
            ``./scripts/setup.sh --with-seclists``.
        extensions: Comma-separated extension list, e.g. ``php,html,bak``.
            Omit to brute-force directory names only.
        threads: Concurrent requests (default 20). Lower this if the
            target is small or fragile.
        status_codes: HTTP status codes that count as "found".
        agent_id: tmux pane identifier (do not set manually).

    Returns:
        gobuster stdout (each found path on its own line), or a short
        error string if the wordlist can't be resolved.
    """
    try:
        list_path = resolve_wordlist(wordlist)
    except FileNotFoundError as e:
        # Return the error rather than raising — the agent reads the
        # tool output and can adjust (switch to "common" or proceed
        # without gobuster). Raising aborts the worker loop.
        _log.warning("gobuster_dir: wordlist resolve failed: %s", e)
        return f"[gobuster_dir] {e}"

    # gobuster sets a default `-b 404` blacklist that conflicts with
    # an explicit `-s` whitelist (it refuses to run with both). Pass an
    # empty `-b` to override the default and let the whitelist govern.
    parts = [
        "gobuster", "dir",
        "-u", shlex.quote(url),
        "-w", shlex.quote(list_path),
        "-t", str(int(threads)),
        "-s", shlex.quote(status_codes),
        "-b", "''",
        "--no-error",
    ]
    if extensions:
        parts.extend(["-x", shlex.quote(extensions)])
    cmd = " ".join(parts)
    return await bash_exec(
        cmd, agent_id=agent_id, reasoning=reasoning, timeout=_DEFAULT_TIMEOUT
    )
