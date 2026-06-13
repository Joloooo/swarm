"""Central skill-usage policy for cross-skill context access.

This deliberately lives outside ``SKILL.md``. Skills keep the standard
Agentskills shape; SwarmAttacker-specific usage semantics are defined here
as optional overrides. The default is permissive so a newly-added skill still
works without editing this file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable


# Workers need enough routing context to emit useful cross-skill handoffs.
# Default to full frontmatter descriptions; set SWARM_SKILL_INDEX_DESC_CHARS
# to a positive value when running a prompt-size ablation.
_DESC_CHARS = int(os.getenv("SWARM_SKILL_INDEX_DESC_CHARS", "0"))
_SKILL_CONTEXT_CHARS = int(os.getenv("SWARM_SKILL_CONTEXT_CHARS", "18000"))

# Optional central policy. Absence means "normal": visible as context, and
# dispatchability is whatever the loader already parsed from frontmatter.
_HIDDEN_FROM_CONTEXT: set[str] = set()


@dataclass(frozen=True)
class SkillIndexItem:
    name: str
    description: str
    dispatchable: bool
    references: tuple[str, ...]

    @property
    def usage(self) -> str:
        return "agent+context" if self.dispatchable else "context"


def _compact(text: str, limit: int = _DESC_CHARS) -> str:
    body = " ".join(str(text or "").split())
    if limit <= 0:
        return body
    if len(body) > limit:
        return body[: limit - 3].rstrip() + "..."
    return body


def is_context_accessible(skill_name: str) -> bool:
    """True when workers may read this skill as supporting context."""
    name = str(skill_name or "").strip()
    if not name or name in _HIDDEN_FROM_CONTEXT:
        return False
    from src.skills import loader

    return loader.load_skill(name) is not None


def context_skill_index() -> list[SkillIndexItem]:
    """All skills workers may see in their compact cross-skill index."""
    from src.skills import loader

    out: list[SkillIndexItem] = []
    for name, desc, dispatchable in loader.list_skill_descriptions():
        if not is_context_accessible(name):
            continue
        out.append(SkillIndexItem(
            name=name,
            description=_compact(desc),
            dispatchable=dispatchable,
            references=tuple(loader.list_references(name)),
        ))
    return out


def render_context_skill_index(*, current_skill: str = "") -> str:
    """Markdown block injected into workers as a compact skill catalogue."""
    items = context_skill_index()
    if not items:
        return ""

    lines = [
        "## Skill context catalogue",
        "",
        "You may read another skill as supporting context when live evidence "
        "matches its description. This does not spawn that skill and does not "
        "change your primary task. If another skill should take over a "
        "different surface or mechanism, include a cross-skill handoff in "
        "your report; the supervisor deduplicates by skill + surface + "
        "technique.",
        "",
        "Use `read_skill_context` for a skill body and `read_skill_reference` "
        "for one of its reference files. Do not read skills speculatively.",
        "",
    ]
    current = str(current_skill or "").strip()
    for item in items:
        marker = " (current)" if item.name == current else ""
        refs = f"; refs={len(item.references)}" if item.references else ""
        desc = item.description or "(no description)"
        lines.append(
            f"- {item.name}{marker} [{item.usage}{refs}]: {desc}"
        )
    return "\n".join(lines)


def read_skill_context(skill_name: str) -> str:
    """Return a bounded skill body plus its reference index."""
    name = str(skill_name or "").strip()
    if not is_context_accessible(name):
        return f"Skill '{name}' is not available for cross-skill context."

    from src.skills import loader

    cfg = loader.load_skill(name)
    if cfg is None:
        return f"Skill '{name}' was not found."
    desc = loader.get_skill_description(name)
    dispatchable = name in {n for n, _ in loader.list_dispatchable_skills()}
    refs = loader.reference_index(name)

    body = cfg.system_prompt or ""
    truncated = ""
    if len(body) > _SKILL_CONTEXT_CHARS:
        body = body[: _SKILL_CONTEXT_CHARS - 80].rstrip()
        truncated = "\n\n[truncated: use references or a narrower skill if more detail is needed]"

    lines = [
        f"# Skill context: {name}",
        "",
        f"Usage: {'agent+context' if dispatchable else 'context'}",
    ]
    if desc:
        lines.extend(["", f"Description: {desc}"])
    if refs:
        lines.extend(["", "References:"])
        for fname, ref_desc in refs:
            lines.append(f"- {fname}: {ref_desc}")
    lines.extend(["", body + truncated])
    return "\n".join(lines)


def read_skill_reference(skill_name: str, reference_file: str) -> str:
    """Return one reference file from any context-accessible skill."""
    name = str(skill_name or "").strip()
    if not is_context_accessible(name):
        return f"Skill '{name}' is not available for cross-skill references."

    from pathlib import Path
    from src.skills import loader

    safe = Path(str(reference_file or "")).name
    content = loader.load_reference(name, safe)
    if content is None:
        available = loader.list_references(name)
        avail = ", ".join(available) if available else "(none)"
        return (
            f"No reference '{safe}' for skill '{name}'. "
            f"Available references: {avail}"
        )
    return content


def dispatchable_skill_names() -> set[str]:
    """Canonical dispatchable skill names."""
    from src.skills.loader import list_dispatchable_skills

    return {name for name, _desc in list_dispatchable_skills()}


def normalize_skill_names(values: Iterable[str]) -> set[str]:
    """Normalize suffixed agent ids like ``sqli-0`` to dispatch keys."""
    skills = dispatchable_skill_names()
    ordered = sorted(skills, key=len, reverse=True)
    out: set[str] = set()
    for raw in values:
        name = str(raw or "").strip().lower()
        if not name:
            continue
        if name in skills:
            out.add(name)
            continue
        for skill in ordered:
            if name.startswith(f"{skill}-"):
                out.add(skill)
                break
    return out
