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
