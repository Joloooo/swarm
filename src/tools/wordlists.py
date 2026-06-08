"""Shared wordlist resolution + the ``get_wordlist`` / ``list_wordlists`` tools.

Single source of truth for where wordlists live — used by ``gobuster_dir``,
``hydra_http_form``, and the agent-facing tools here. Resolution order (first
hit wins): ``~/.swarmattacker/seclists`` → ``/usr/share/seclists`` →
``/usr/share/wordlists`` → ``<repo>/wordlists`` (matched by basename). The
lists are vendored by ``scripts/download_wordlists.sh`` (or the larger
``./scripts/setup.sh --with-seclists`` tree).

Discipline: directory/parameter brute-forcing and wordlist enumeration are a
LAST resort for an LLM agent (it is the most common way a run burns its whole
budget — see the base-prompt enumeration-discipline block). These tools are
therefore bound ONLY to the discovery skills (``recon``, ``fuzzing``); every
other skill is steered away from enumeration in the prompt.
"""

from __future__ import annotations

import os
from pathlib import Path

from langchain_core.tools import tool

# ``src/tools/wordlists.py`` → parents[2] is the SwarmAttacker repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_BUNDLED_DIR = _REPO_ROOT / "wordlists"

# User-home SecLists cache populated by ``./scripts/setup.sh --with-seclists``.
_USER_SECLISTS = Path.home() / ".swarmattacker" / "seclists"
# Kali-style system installs, tried in order.
_SYSTEM_SECLISTS_ROOTS = (
    Path("/usr/share/seclists"),
    Path("/usr/local/share/seclists"),
    Path("/opt/seclists"),
)
_SYSTEM_WORDLIST_ROOTS = (Path("/usr/share/wordlists"),)

# Preset → candidate relative paths, tried under each root above then the
# repo-bundled dir (matched by basename). More authoritative / larger lists
# first so a real SecLists install wins over the small bundled copies.
_PRESETS: dict[str, tuple[str, ...]] = {
    # ── directory / content discovery (gobuster / ffuf / feroxbuster) ──
    "common": (
        "Discovery/Web-Content/common.txt", "dirb/common.txt", "common.txt",
    ),
    "small": ("Discovery/Web-Content/small.txt", "dirb/small.txt", "small.txt"),
    "medium": (
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "dirbuster/directory-list-2.3-medium.txt",
        "raft-medium-directories.txt",
    ),
    "big": (
        "Discovery/Web-Content/raft-large-directories.txt",
        "Discovery/Web-Content/big.txt", "dirb/big.txt",
        "raft-large-directories.txt", "big.txt",
    ),
    "files": (
        "Discovery/Web-Content/raft-medium-files.txt", "raft-medium-files.txt",
    ),
    # ── usernames / passwords (hydra / hashcat / spraying) ──
    "usernames": (
        "Usernames/top-usernames-shortlist.txt", "top-usernames-shortlist.txt",
    ),
    "passwords": (
        "Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
        "passwords-top-100000.txt", "rockyou.txt",
    ),
    "rockyou": ("Passwords/Leaked-Databases/rockyou.txt", "rockyou.txt"),
}


class WordlistNotFound(FileNotFoundError):
    """Raised when a preset can't be resolved on this host."""


def resolve_wordlist(name: str) -> str:
    """Resolve a preset name (or absolute path / path-with-separator) to a file.

    Pass-through: an absolute path or anything containing ``/`` is treated as a
    caller-supplied literal (existence-checked). Otherwise ``name`` is a preset
    from :data:`_PRESETS`. Raises :class:`WordlistNotFound` when nothing
    resolves — the message points at ``download_wordlists.sh``.
    """
    if os.path.isabs(name) or "/" in name:
        if Path(name).is_file():
            return name
        raise WordlistNotFound(f"wordlist not found at literal path: {name!r}")

    candidates = _PRESETS.get(name)
    if not candidates:
        bundled = _BUNDLED_DIR / name
        if bundled.is_file():
            return str(bundled)
        raise WordlistNotFound(
            f"unknown wordlist preset {name!r}. Known: {sorted(_PRESETS)}. "
            "Pass an absolute path, or run ./scripts/download_wordlists.sh."
        )

    for root in (_USER_SECLISTS, *_SYSTEM_SECLISTS_ROOTS, *_SYSTEM_WORDLIST_ROOTS):
        for rel in candidates:
            path = root / rel
            if path.is_file():
                return str(path)
    for rel in candidates:
        path = _BUNDLED_DIR / Path(rel).name
        if path.is_file():
            return str(path)

    raise WordlistNotFound(
        f"wordlist preset {name!r} is not installed on this host. Run "
        "./scripts/download_wordlists.sh (or ./scripts/setup.sh --with-seclists)."
    )


@tool
def list_wordlists() -> str:
    """List the wordlist presets available on this host, with sizes.

    Call this ONLY when enumeration is genuinely warranted (a hidden
    directory/bucket to discover, or a confirmed credential/hash that truly
    needs a list). Returns each preset, whether it resolves here, and its line
    count, so you can pick the smallest list that fits.
    """
    out = ["Wordlist presets (resolve a usable path with get_wordlist):"]
    for name in _PRESETS:
        try:
            path = resolve_wordlist(name)
            with open(path, "rb") as fh:
                n = sum(1 for _ in fh)
            out.append(f"- {name}: {path} ({n} lines)")
        except WordlistNotFound:
            out.append(f"- {name}: NOT INSTALLED (run ./scripts/download_wordlists.sh)")
    return "\n".join(out)


@tool
def get_wordlist(reasoning: str, name: str) -> str:
    """Resolve a wordlist preset (or path) to an absolute file path for a command.

    Pass a preset — ``common`` / ``small`` / ``medium`` / ``big`` / ``files``
    (directory & file discovery), or ``usernames`` / ``passwords`` / ``rockyou``
    (credentials) — or an absolute path. Returns the path you then feed to
    ffuf / gobuster / feroxbuster / hashcat / hydra, etc.

    Enumeration is a LAST resort: only call this when there is a concrete signal
    that content is hidden behind unguessable paths/params (e.g. a task hint to
    find hidden directories, a near-empty app on a large stack), or a confirmed
    credential/hash genuinely needs a list. ``reasoning`` must state that signal.
    """
    try:
        return resolve_wordlist(name)
    except WordlistNotFound as e:
        return f"[get_wordlist] {e}"
