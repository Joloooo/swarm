"""Tier 1 — Skill loader integrity tests.

The loader at ``src/skills/loader.py`` is the bridge between SKILL.md
files on disk and the AgentConfig dataclass each node consumes. These
tests assert that the bridge is intact:

- Every SKILL.md under ``src/skills/`` parses without raising.
- Every tool name listed in any SKILL.md frontmatter resolves to a real
  ``BaseTool`` via the tool registry. (This is the test that catches
  typos like ``nmap_fastscan`` vs ``nmap_fast_scan`` BEFORE a benchmark
  run wastes minutes of LLM budget on a broken tool call.)
- Skills with ``metadata.agent_id`` show up in the planner's dispatch
  menu; reference-only skills (e.g. nmap) do NOT.
- The loader's cache returns the same object on repeated lookups.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.skills.loader import (
    SKILLS_DIR,
    list_dispatchable_skills,
    list_skills,
    load_skill,
)
from src.tools.registry import resolve_tool


# Resolve every SKILL.md once so individual tests can be parameterised
# over the discovered set instead of hard-coding skill names.
def _all_skill_dirs() -> list[Path]:
    return sorted(
        d for d in SKILLS_DIR.iterdir()
        if d.is_dir() and (d / "SKILL.md").exists()
    )


SKILL_DIRS = _all_skill_dirs()
SKILL_NAMES = [d.name for d in SKILL_DIRS]


# ── Sanity ────────────────────────────────────────────────────────────


def test_skills_dir_exists():
    assert SKILLS_DIR.is_dir(), f"skills dir missing: {SKILLS_DIR}"


def test_at_least_one_skill_exists():
    assert SKILL_NAMES, "no SKILL.md files found under src/skills/"


# ── Per-skill loading ─────────────────────────────────────────────────


@pytest.mark.parametrize("skill_name", SKILL_NAMES)
def test_skill_loads(skill_name: str):
    """Each SKILL.md must parse into a non-None AgentConfig."""
    cfg = load_skill(skill_name)
    assert cfg is not None, f"loader returned None for {skill_name!r}"
    assert cfg.config_name, f"empty config_name for {skill_name!r}"
    assert cfg.system_prompt, f"empty system_prompt body for {skill_name!r}"


@pytest.mark.parametrize("skill_name", SKILL_NAMES)
def test_skill_tools_resolve(skill_name: str):
    """Every tool name in metadata.tools must resolve via the registry.

    This is the high-value typo-catcher: an unresolvable tool name
    in a SKILL.md normally only surfaces at runtime as a silent
    "tool registry: unknown tool name X — skipped" warning, after
    which the agent runs without that tool.
    """
    skill_path = SKILLS_DIR / skill_name / "SKILL.md"
    text = skill_path.read_text(encoding="utf-8")

    # Re-parse the frontmatter directly so we test against the raw list
    # (the loader silently drops unknown names — we want to catch them).
    if not text.startswith("---"):
        pytest.skip(f"{skill_name} has no frontmatter")
    rest = text[3:].lstrip("\n")
    parts = rest.split("\n---", 1)
    assert len(parts) == 2, f"{skill_name}: malformed frontmatter fences"
    meta = yaml.safe_load(parts[0]) or {}
    tool_names = (meta.get("metadata") or {}).get("tools") or []

    unresolved = [n for n in tool_names if resolve_tool(str(n)) is None]
    assert not unresolved, (
        f"{skill_name}/SKILL.md references unknown tool name(s): "
        f"{unresolved}. Either add them to src/tools/registry.py or "
        f"fix the typo in the SKILL.md frontmatter."
    )


# ── Dispatch menu ────────────────────────────────────────────────────


def test_dispatchable_skills_have_agent_id():
    """The planner's menu only lists skills with metadata.agent_id."""
    dispatchable = dict(list_dispatchable_skills())
    assert dispatchable, "no dispatchable skills — planner has no menu"

    # Reference-only skills should NOT appear (nmap is the canonical
    # example — it's a tool cheatsheet, not an attack vector).
    assert "nmap" not in dispatchable, (
        "nmap SKILL.md must stay reference-only (no metadata.agent_id), "
        "but it appears in the planner dispatch menu"
    )


def test_known_skills_are_dispatchable():
    """Spot-check that the core attack skills show up for the planner."""
    dispatchable = dict(list_dispatchable_skills())
    # These are the load-bearing skills. If the planner can't see them,
    # the graph effectively can't attack anything.
    for expected in ("recon", "sqli", "xss"):
        assert expected in dispatchable, (
            f"{expected!r} missing from list_dispatchable_skills() — "
            f"check that src/skills/{expected}/SKILL.md has "
            f"metadata.agent_id set"
        )


# ── Cache behaviour ──────────────────────────────────────────────────


def test_loader_caches_skills():
    """Two load_skill calls for the same name return the same object."""
    a = load_skill("recon")
    b = load_skill("recon")
    assert a is b, "loader must return cached AgentConfig instance"


def test_list_skills_includes_all_disk_skills():
    """list_skills() must include every SKILL.md found on disk."""
    listed = set(list_skills())
    on_disk = set(SKILL_NAMES)
    missing = on_disk - listed
    assert not missing, f"list_skills() missed: {missing}"
