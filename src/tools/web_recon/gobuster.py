"""Typed gobuster directory-enumeration wrapper."""

from __future__ import annotations

import shlex
from typing import Literal

from langchain_core.tools import tool

from src.tools.shell import bash_exec


_DEFAULT_TIMEOUT = 300

# Common wordlist locations bundled with kali / parrot images. The tool
# accepts either a known short name (resolved here) or a literal path.
_WORDLIST_PRESETS = {
    "common": "/usr/share/wordlists/dirb/common.txt",
    "small": "/usr/share/wordlists/dirb/small.txt",
    "big": "/usr/share/wordlists/dirb/big.txt",
    "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
}


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
        wordlist: One of "common" / "small" / "medium" / "big" (resolves
            to a packaged dirb/dirbuster list) or an absolute path to a
            custom wordlist file.
        extensions: Comma-separated extension list, e.g. ``php,html,bak``.
            Omit to brute-force directory names only.
        threads: Concurrent requests (default 20). Lower this if the
            target is small or fragile.
        status_codes: HTTP status codes that count as "found".
        agent_id: tmux pane identifier (do not set manually).

    Returns:
        gobuster stdout (each found path on its own line).
    """
    list_path = _WORDLIST_PRESETS.get(wordlist, wordlist)
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
