"""The ``read_reference`` worker tool — progressive-disclosure reference access.

A dispatched skill's bulky reference material lives under
``src/skills/<name>/references/`` and is deliberately kept OUT of the
always-loaded system prompt. Instead :func:`src.skills.loader.reference_index`
advertises those files in a short ``## References`` index, and this tool lets
the worker page in exactly one of them on demand — the moment a live finding
matches its "Open WHEN" note.

The tool is built per dispatch via :func:`make_read_reference_tool`, closed
over the running skill's name, so the worker passes only a filename. It cannot
read another skill's references or escape the directory: the argument is
reduced to its basename before lookup.
"""

from __future__ import annotations

from pathlib import Path

from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field


class _ReadReferenceArgs(BaseModel):
    reasoning: str = Field(
        description="One line: why you need this reference right now "
        "(e.g. 'confirmed a Jinja2 sink, need Python SSTI test inputs')."
    )
    reference_file: str = Field(
        description="A filename from this skill's ## References section, "
        "filename only (e.g. 'python-engines.md')."
    )


class _ReadSkillContextArgs(BaseModel):
    reasoning: str = Field(
        description=(
            "One line: what live evidence makes this other skill relevant "
            "as context right now."
        )
    )
    skill_name: str = Field(
        description=(
            "Exact skill name from the Skill context catalogue "
            "(e.g. 'error-handling', 'framework-nestjs')."
        )
    )


class _ReadSkillReferenceArgs(BaseModel):
    reasoning: str = Field(
        description=(
            "One line: why this specific cross-skill reference is needed "
            "for the current task."
        )
    )
    skill_name: str = Field(
        description="Exact skill name from the Skill context catalogue."
    )
    reference_file: str = Field(
        description=(
            "Reference filename from that skill's reference list, filename "
            "only."
        )
    )


def make_read_reference_tool(skill_name: str) -> BaseTool:
    """Build a ``read_reference`` tool scoped to ``skill_name``'s references/."""

    def _read(reasoning: str, reference_file: str) -> str:
        # Lazy import avoids an import cycle (loader imports src.nodes.base).
        from src.skills import loader
        # Filename-only: strip any path so a worker can't traverse out of
        # this skill's references/ directory.
        safe = Path(reference_file).name
        content = loader.load_reference(skill_name, safe)
        if content is None:
            available = loader.list_references(skill_name)
            avail = ", ".join(available) if available else "(none)"
            return (
                f"No reference '{safe}' for skill '{skill_name}'. "
                f"Available references: {avail}"
            )
        return content

    return StructuredTool.from_function(
        func=_read,
        name="read_reference",
        description=(
            "Open ONE deep reference file for the current skill — test-input "
            "libraries and engine-specific techniques kept out of the system "
            "prompt for size. Pass only a filename listed in this skill's "
            "## References section. Read one the moment a live finding matches "
            "its 'Open WHEN' note; do not guess filenames."
        ),
        args_schema=_ReadReferenceArgs,
    )


def make_read_skill_context_tool() -> BaseTool:
    """Build a tool that lets a worker read another skill as context only."""

    def _read(reasoning: str, skill_name: str) -> str:
        from src.skills.usage import read_skill_context

        return read_skill_context(skill_name)

    return StructuredTool.from_function(
        func=_read,
        name="read_skill_context",
        description=(
            "Read another skill's main instructions as supporting context. "
            "This does NOT spawn that skill, does NOT change your primary "
            "assignment, and should only be used when live evidence matches "
            "the other skill's catalogue description. If another skill should "
            "continue on a different surface or mechanism, report a structured "
            "cross-skill handoff instead."
        ),
        args_schema=_ReadSkillContextArgs,
    )


def make_read_skill_reference_tool() -> BaseTool:
    """Build a tool for cross-skill reference-file access."""

    def _read(reasoning: str, skill_name: str, reference_file: str) -> str:
        from src.skills.usage import read_skill_reference

        safe = Path(reference_file).name
        return read_skill_reference(skill_name, safe)

    return StructuredTool.from_function(
        func=_read,
        name="read_skill_reference",
        description=(
            "Open ONE reference file from another context-accessible skill. "
            "Pass an exact skill name and a filename listed for that skill. "
            "Use this only after read_skill_context or the catalogue shows "
            "that the reference matches live evidence."
        ),
        args_schema=_ReadSkillReferenceArgs,
    )
