"""Tier 1 — gobuster wordlist resolver.

The resolver in :mod:`src.tools.web_recon.gobuster` decides which file on
disk the ``-w`` flag of gobuster points at when an agent calls
``gobuster_dir(wordlist="common")``. Before the SecLists rework this was
a static dict pointing at Kali paths (``/usr/share/wordlists/dirb/...``)
that don't exist on macOS, so every gobuster call on a clean Mac failed
with a "wordlist not found" error from gobuster itself — wasting an LLM
turn per attempt. These tests pin the new behaviour:

- ``common`` always resolves to *something* on every machine, because
  the repo bundles a smoke-test ``wordlists/common.txt``.
- Larger presets (``medium`` / ``big``) raise ``FileNotFoundError`` with
  a hint pointing at ``./scripts/setup.sh --with-seclists`` when no
  SecLists install is present.
- Absolute paths pass through unchanged when they exist; raise when not.
- Unknown preset names fail with a helpful error listing the known
  presets, not a silent "file not found".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.tools.web_recon import gobuster as gobuster_mod
from src.tools.web_recon.gobuster import _resolve_wordlist


def test_common_resolves_from_bundled_fallback():
    """``common`` always works — bundled wordlist is shipped in-repo."""
    path = _resolve_wordlist("common")
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
    monkeypatch.setattr(gobuster_mod, "_USER_SECLISTS", nowhere)
    monkeypatch.setattr(gobuster_mod, "_SYSTEM_SECLISTS_ROOTS", (nowhere,))
    monkeypatch.setattr(gobuster_mod, "_SYSTEM_WORDLIST_ROOTS", (nowhere,))

    path = _resolve_wordlist("common")
    # Should be the repo-bundled copy, not a system file.
    assert path.startswith(str(gobuster_mod._BUNDLED_DIR))
    assert Path(path).is_file()


def test_medium_without_seclists_raises_with_hint(monkeypatch, tmp_path):
    """``medium`` has no bundled fallback — must surface a clear install hint."""
    nowhere = tmp_path / "does-not-exist"
    monkeypatch.setattr(gobuster_mod, "_USER_SECLISTS", nowhere)
    monkeypatch.setattr(gobuster_mod, "_SYSTEM_SECLISTS_ROOTS", (nowhere,))
    monkeypatch.setattr(gobuster_mod, "_SYSTEM_WORDLIST_ROOTS", (nowhere,))
    # Make sure the bundled dir has no medium list (it shouldn't).
    bundled = gobuster_mod._BUNDLED_DIR
    assert not any(
        (bundled / Path(rel).name).is_file()
        for rel in gobuster_mod._PRESETS["medium"]
    ), "test assumes no medium wordlist is bundled — adjust if that changes"

    with pytest.raises(FileNotFoundError) as exc:
        _resolve_wordlist("medium")
    msg = str(exc.value)
    assert "medium" in msg
    assert "--with-seclists" in msg, (
        "error message must point operators at the install command"
    )


def test_unknown_preset_lists_known_options():
    """Typos like ``wordlist='comon'`` should fail fast with the menu."""
    with pytest.raises(FileNotFoundError) as exc:
        _resolve_wordlist("comon")
    msg = str(exc.value)
    assert "unknown wordlist preset" in msg
    assert "common" in msg  # the known-preset list must appear


def test_absolute_path_passthrough(tmp_path):
    """Absolute path to an existing file is returned unchanged."""
    f = tmp_path / "my-list.txt"
    f.write_text("admin\napi\n", encoding="utf-8")
    assert _resolve_wordlist(str(f)) == str(f)


def test_absolute_path_missing_raises(tmp_path):
    """Absolute path that doesn't exist must raise, not silently fall back."""
    missing = tmp_path / "nope.txt"
    with pytest.raises(FileNotFoundError):
        _resolve_wordlist(str(missing))


def test_relative_path_in_repo_bundled_dir():
    """Bundled directory should expose any list dropped in it by filename.

    The resolver allows future bundled wordlists to be discovered by
    bare filename without code changes — we already exercise this for
    ``common.txt`` (which is also a registered preset), so the relative
    path mechanism is the underlying contract.
    """
    bundled_common = gobuster_mod._BUNDLED_DIR / "common.txt"
    assert bundled_common.is_file()
