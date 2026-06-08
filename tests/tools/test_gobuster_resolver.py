"""Tier 1 — shared wordlist resolver.

The resolver in :mod:`src.tools.wordlists` decides which file on disk a
wordlist name maps to — used by ``gobuster_dir(wordlist="common")``,
``hydra_http_form``, and the agent-facing ``get_wordlist`` tool. Before
the SecLists rework this was a static dict pointing at Kali paths
(``/usr/share/wordlists/dirb/...``) that don't exist on macOS, so every
gobuster call on a clean Mac failed with a "wordlist not found" error —
wasting an LLM turn per attempt.

The resolver moved out of ``web_recon.gobuster`` into the shared
``src.tools.wordlists`` module (gobuster re-exports it). These tests pin
the current behaviour:

- ``common`` always resolves to *something* on every machine, because the
  repo bundles a ``wordlists/common.txt``.
- ``medium`` now ALSO resolves on every machine — ``raft-medium-
  directories.txt`` is vendored into ``wordlists/`` by
  ``scripts/download_wordlists.sh``. (It used to raise; that changed when
  the SecLists lists were vendored.)
- Absolute paths pass through unchanged when they exist; raise when not.
- Unknown preset names fail with a helpful error listing the known
  presets, not a silent "file not found".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.tools import wordlists as wl_mod
from src.tools.wordlists import WordlistNotFound, resolve_wordlist


def test_common_resolves_from_bundled_fallback():
    """``common`` always works — bundled wordlist is shipped in-repo."""
    path = resolve_wordlist("common")
    assert Path(path).is_file(), f"resolver returned non-existent path: {path}"
    # Must be ``common.txt`` somewhere — whether SecLists, dirb, or bundled.
    assert Path(path).name == "common.txt"


def test_common_falls_back_to_repo_when_no_system_install(monkeypatch, tmp_path):
    """With every system path stubbed out, ``common`` must hit the bundled file.

    Simulates a fresh macOS box: no SecLists anywhere, no Kali wordlist
    paths, no user-home cache. The repo-bundled ``wordlists/common.txt``
    is the only thing keeping gobuster usable in that case.
    """
    nowhere = tmp_path / "does-not-exist"
    monkeypatch.setattr(wl_mod, "_USER_SECLISTS", nowhere)
    monkeypatch.setattr(wl_mod, "_SYSTEM_SECLISTS_ROOTS", (nowhere,))
    monkeypatch.setattr(wl_mod, "_SYSTEM_WORDLIST_ROOTS", (nowhere,))

    path = resolve_wordlist("common")
    # Should be the repo-bundled copy, not a system file.
    assert path.startswith(str(wl_mod._BUNDLED_DIR))
    assert Path(path).is_file()


def test_medium_resolves_from_bundled_vendored_list():
    """``medium`` now resolves on every machine — the SecLists list is vendored.

    ``scripts/download_wordlists.sh`` drops ``raft-medium-directories.txt``
    into ``wordlists/``, so even with no system SecLists install the bundled
    fallback satisfies ``medium``. (This is the inverse of the old behaviour,
    which raised a "--with-seclists" hint.)
    """
    path = resolve_wordlist("medium")
    assert Path(path).is_file(), f"resolver returned non-existent path: {path}"
    # Any of the registered medium candidates' basenames is acceptable; the
    # vendored one is raft-medium-directories.txt.
    expected = {Path(rel).name for rel in wl_mod._PRESETS["medium"]}
    assert Path(path).name in expected


def test_unknown_preset_lists_known_options():
    """Typos like ``wordlist='comon'`` should fail fast with the menu."""
    with pytest.raises(WordlistNotFound) as exc:
        resolve_wordlist("comon")
    msg = str(exc.value)
    assert "unknown wordlist preset" in msg
    assert "common" in msg  # the known-preset list must appear


def test_absolute_path_passthrough(tmp_path):
    """Absolute path to an existing file is returned unchanged."""
    f = tmp_path / "my-list.txt"
    f.write_text("admin\napi\n", encoding="utf-8")
    assert resolve_wordlist(str(f)) == str(f)


def test_absolute_path_missing_raises(tmp_path):
    """Absolute path that doesn't exist must raise, not silently fall back."""
    missing = tmp_path / "nope.txt"
    # WordlistNotFound subclasses FileNotFoundError — assert the base type.
    with pytest.raises(FileNotFoundError):
        resolve_wordlist(str(missing))


def test_bundled_dir_exposes_common():
    """The bundled directory ships ``common.txt`` so ``common`` is always usable."""
    bundled_common = wl_mod._BUNDLED_DIR / "common.txt"
    assert bundled_common.is_file()
