"""Skill loading — knowledge layer 2.

Loads full technique documentation files into agent context per phase.
Each skill doc is a markdown file with detailed methodology steps,
tool usage examples, and payload references.

This is heavier than base rules (more tokens) but gives agents deep
technique knowledge. Each agent only loads the skills relevant to its
task, keeping context usage proportional.
"""

from __future__ import annotations

from pathlib import Path

# Default skills directory (relative to package root)
SKILLS_DIR = Path(__file__).parent / "docs"


def load_skill(skill_name: str, skills_dir: Path | None = None) -> str | None:
    """Load a skill document by name.

    Looks for {skill_name}.md in the skills directory.
    Returns the content, or None if not found.
    """
    base = skills_dir or SKILLS_DIR
    path = base / f"{skill_name}.md"
    if path.exists():
        return path.read_text()
    return None


def load_skills(skill_names: list[str], skills_dir: Path | None = None) -> str:
    """Load multiple skill documents and concatenate them.

    Returns a formatted string with all loaded skills, or empty string
    if none were found.
    """
    base = skills_dir or SKILLS_DIR
    parts = []
    for name in skill_names:
        content = load_skill(name, base)
        if content:
            parts.append(f"\n--- Skill: {name} ---\n{content}")
    return "\n".join(parts)


def list_available_skills(skills_dir: Path | None = None) -> list[str]:
    """List all available skill document names."""
    base = skills_dir or SKILLS_DIR
    if not base.exists():
        return []
    return sorted(p.stem for p in base.glob("*.md"))
