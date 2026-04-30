"""Skill loader — turns a SKILL.md directory into an AgentConfig.

This module replaces the old ``src/agents/configs/`` registry. Each
attack vector now lives as ``src/skills/<name>/SKILL.md`` in the
agentskills.io format: YAML frontmatter (name, description, metadata)
followed by the Markdown system-prompt body. Optional bulky reference
material lives under ``src/skills/<name>/references/`` and is loaded on
demand via :func:`load_reference`.

The loader caches every parsed skill on first access so the planner and
worker nodes can call :func:`load_skill` repeatedly without re-reading
the disk. Custom skills the planner invents at run-time are registered
through :func:`register_custom_skill`; they live in the same in-memory
cache, so a later ``load_skill(name)`` resolves them just like a
file-backed skill.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from src.agents.base import AgentConfig
from src.tools.registry import resolve_tools

logger = logging.getLogger(__name__)


# Default skills root (this file lives at src/skills/loader.py, so
# Path(__file__).parent IS the skills directory).
SKILLS_DIR = Path(__file__).parent


# Cache: config_name -> AgentConfig. Populated lazily by `load_skill`,
# then augmented at run-time by `register_custom_skill`.
_CACHE: dict[str, AgentConfig] = {}
_FILE_INDEX_BUILT = False


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Split a SKILL.md into (frontmatter dict, body string).

    Accepts the standard ``---\\n<yaml>\\n---\\n<body>`` shape. Returns
    ``({}, text)`` for files without frontmatter so callers don't have
    to special-case it.
    """
    if not text.startswith("---"):
        return {}, text
    # Find the closing fence. The first split on "---\n" eats the leading
    # opener; the remainder splits cleanly into frontmatter + body.
    rest = text[3:].lstrip("\n")
    parts = rest.split("\n---", 1)
    if len(parts) != 2:
        return {}, text
    raw_yaml, body = parts
    try:
        meta = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError as exc:
        logger.warning("skill loader: malformed frontmatter — %s", exc)
        return {}, text
    if not isinstance(meta, dict):
        return {}, text
    return meta, body.lstrip("\n")


def _build_config(skill_name: str, meta: dict, body: str) -> AgentConfig:
    """Construct an AgentConfig from parsed SKILL.md content."""
    md = meta.get("metadata") or {}
    if not isinstance(md, dict):
        md = {}

    tool_names = md.get("tools") or []
    if not isinstance(tool_names, list):
        tool_names = []
    tools = resolve_tools([str(n) for n in tool_names])

    return AgentConfig(
        agent_id=str(md.get("agent_id") or f"skill-{skill_name}"),
        methodology=str(md.get("methodology") or "skill"),
        config_name=str(md.get("config_name") or skill_name),
        system_prompt=body,
        tools=tools,
        max_tool_calls=int(md.get("max_tool_calls") or 50),
        max_iterations=int(md.get("max_iterations") or 30),
    )


def _load_from_disk(name: str) -> AgentConfig | None:
    """Read ``src/skills/<name>/SKILL.md`` and build an AgentConfig.

    Returns None if the directory or SKILL.md doesn't exist.
    """
    path = SKILLS_DIR / name / "SKILL.md"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    meta, body = _split_frontmatter(text)
    return _build_config(name, meta, body)


def _build_file_index() -> None:
    """Eager-load every SKILL.md so list_skills() reflects disk state.

    The first call to list_skills() or load_skill(unknown) walks the
    skills/ directory once. After that, custom skills registered at
    run-time are added to the cache the same way.
    """
    global _FILE_INDEX_BUILT
    if _FILE_INDEX_BUILT:
        return
    _FILE_INDEX_BUILT = True
    if not SKILLS_DIR.exists():
        return
    for child in sorted(SKILLS_DIR.iterdir()):
        if not child.is_dir():
            continue
        if (child / "SKILL.md").exists() and child.name not in _CACHE:
            cfg = _load_from_disk(child.name)
            if cfg is not None:
                _CACHE[cfg.config_name] = cfg


def load_skill(name: str) -> AgentConfig | None:
    """Look up a skill by name. Returns None if not found.

    Resolution order:
        1. In-memory cache (already loaded or registered as custom).
        2. Disk: ``src/skills/<name>/SKILL.md``.
    """
    cached = _CACHE.get(name)
    if cached is not None:
        return cached
    cfg = _load_from_disk(name)
    if cfg is not None:
        _CACHE[cfg.config_name] = cfg
    return cfg


def register_custom_skill(name: str, system_prompt: str) -> AgentConfig:
    """Register an in-memory skill for one of the planner's custom_configs.

    Used by the planner when the LLM invents a tailored config on the
    fly. The custom skill always gets ``run_command`` as its sole tool —
    if the planner needs typed tools it should pick a pre-built skill.
    Idempotent on the same name (overwrites).
    """
    from src.graph import budgets
    from src.tools.terminal import run_command

    cfg = AgentConfig(
        agent_id=f"custom-{name}",
        methodology="custom",
        config_name=name,
        system_prompt=system_prompt,
        tools=[run_command],
        max_tool_calls=budgets.custom_attack_max_tool_calls,
        max_iterations=budgets.custom_attack_max_iterations,
    )
    _CACHE[name] = cfg
    return cfg


def list_skills() -> list[str]:
    """All skill names known to the loader (file-backed + custom)."""
    _build_file_index()
    return sorted(_CACHE.keys())


def load_reference(skill_name: str, reference_file: str) -> str | None:
    """Load a file from ``src/skills/<skill>/references/<file>``.

    Used for progressive-disclosure knowledge — the agent pulls a payload
    library or method reference only when it actually needs it. Returns
    None if the file doesn't exist.
    """
    path = SKILLS_DIR / skill_name / "references" / reference_file
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")
