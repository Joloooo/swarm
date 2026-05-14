"""Typed gobuster directory-enumeration wrapper."""

from __future__ import annotations

import logging
import os
import shlex
from pathlib import Path

from langchain_core.tools import tool

from src.tools.shell import bash_exec


_log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 300

# Repo-root-relative bundled wordlists. Resolved at import time so the
# resolver doesn't repeat the filesystem walk on every tool call.
#
#   src/tools/web_recon/gobuster.py   →  <repo>/SwarmAttacker/
#                                        wordlists/common.txt
_REPO_ROOT = Path(__file__).resolve().parents[3]
_BUNDLED_DIR = _REPO_ROOT / "wordlists"

# User-home SecLists cache populated by ``./scripts/setup.sh --with-seclists``.
# Matches the path that script clones into; see setup.sh ``SECLISTS_DIR``.
_USER_SECLISTS = Path.home() / ".swarmattacker" / "seclists"

# Known SecLists / dirb / dirbuster locations to fall back to when the
# operator already has a Kali-style install. Tried in order, first hit wins.
_SYSTEM_SECLISTS_ROOTS = (
    Path("/usr/share/seclists"),
    Path("/usr/local/share/seclists"),
    Path("/opt/seclists"),
)
_SYSTEM_WORDLIST_ROOTS = (
    Path("/usr/share/wordlists"),
)

# Mapping from short preset names to one or more candidate relative paths.
# The resolver tries each candidate under every root above (user SecLists
# first, then system SecLists, then dirb/dirbuster paths, then the bundled
# fallback dir at the repo root) and returns the first match.
#
# The order inside each tuple matters: more authoritative / larger lists
# come first so a Kali install picks up its richer wordlist rather than
# our 150-line bundled smoke-test file.
_PRESETS: dict[str, tuple[str, ...]] = {
    "common": (
        "Discovery/Web-Content/common.txt",     # SecLists (Kali apt + user clone)
        "dirb/common.txt",                      # Kali /usr/share/wordlists
        "common.txt",                           # repo-bundled fallback
    ),
    "small": (
        "Discovery/Web-Content/small.txt",
        "dirb/small.txt",
    ),
    "medium": (
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "dirbuster/directory-list-2.3-medium.txt",
    ),
    "big": (
        "Discovery/Web-Content/raft-large-directories.txt",
        "Discovery/Web-Content/big.txt",
        "dirb/big.txt",
    ),
}


def _resolve_wordlist(name: str) -> str:
    """Resolve a preset name (or absolute path) to a real file on disk.

    Tries roots in this order (first match wins):

    1. ``~/.swarmattacker/seclists/`` — ``setup.sh --with-seclists`` target.
    2. ``/usr/share/seclists/`` and siblings — apt-installed SecLists.
    3. ``/usr/share/wordlists/`` — Kali's dirb / dirbuster paths.
    4. ``<repo>/wordlists/`` — bundled fallback (only has ``common.txt``).

    If ``name`` looks like an absolute path or contains a separator, it
    is returned unchanged so callers can still point at custom files.

    Raises:
        FileNotFoundError: when the preset can't be resolved anywhere.
            The message names the preset and lists the candidate paths
            we tried — operators usually need to run
            ``./scripts/setup.sh --with-seclists``.
    """
    # Pass-through: absolute paths and anything containing a path
    # separator are treated as caller-supplied literals. We still check
    # existence so we can return a useful error if the file is missing.
    if os.path.isabs(name) or "/" in name:
        if Path(name).is_file():
            return name
        raise FileNotFoundError(
            f"gobuster wordlist not found: {name!r}. "
            f"Pass a preset name (common / small / medium / big) or an "
            f"existing file path."
        )

    candidates = _PRESETS.get(name)
    if not candidates:
        # Unknown preset — fall back to checking the bundled dir for a
        # literal filename match (lets future bundled lists be discovered
        # by name without code changes).
        bundled = _BUNDLED_DIR / name
        if bundled.is_file():
            return str(bundled)
        raise FileNotFoundError(
            f"gobuster: unknown wordlist preset {name!r}. "
            f"Known presets: {sorted(_PRESETS)}. "
            f"You can also pass an absolute path."
        )

    tried: list[str] = []

    # 1+2. User cache + system SecLists installs — SecLists-style relative paths.
    for root in (_USER_SECLISTS, *_SYSTEM_SECLISTS_ROOTS):
        for rel in candidates:
            path = root / rel
            tried.append(str(path))
            if path.is_file():
                return str(path)

    # 3. Kali's dirb / dirbuster (different layout — relative path starts
    # with `dirb/` or `dirbuster/`).
    for root in _SYSTEM_WORDLIST_ROOTS:
        for rel in candidates:
            path = root / rel
            tried.append(str(path))
            if path.is_file():
                return str(path)

    # 4. Repo-bundled fallback — single flat dir.
    for rel in candidates:
        path = _BUNDLED_DIR / Path(rel).name
        tried.append(str(path))
        if path.is_file():
            return str(path)

    raise FileNotFoundError(
        f"gobuster wordlist preset {name!r} not found. Tried:\n  "
        + "\n  ".join(tried)
        + "\n\nInstall SecLists with `./scripts/setup.sh --with-seclists` "
          "to enable the larger presets, or pass an absolute path."
    )


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
        wordlist: One of "common" / "small" / "medium" / "big" (resolved
            via the multi-root resolver — see ``_resolve_wordlist``) or
            an absolute path to a custom wordlist file. ``common`` always
            works because a tiny 150-entry list ships in the repo.
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
        list_path = _resolve_wordlist(wordlist)
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
