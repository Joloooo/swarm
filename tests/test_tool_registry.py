"""Tier 1 — Tool registry consistency tests.

The registry at ``src/tools/registry.py`` is the single source of truth
that maps tool-name strings (used in SKILL.md frontmatter) to actual
LangChain ``BaseTool`` callables. These tests assert the registry
itself is internally consistent, independent of any SKILL.md.
"""

from __future__ import annotations

import pytest
from langchain_core.tools import BaseTool

from src.tools.registry import (
    _REGISTRY,
    list_tools,
    resolve_tool,
    resolve_tools,
)


REGISTERED_NAMES = sorted(_REGISTRY.keys())


# ── Sanity ────────────────────────────────────────────────────────────


def test_registry_is_non_empty():
    assert REGISTERED_NAMES, "tool registry is empty"


def test_list_tools_matches_registry():
    assert list_tools() == REGISTERED_NAMES


# ── Per-tool invariants ──────────────────────────────────────────────


@pytest.mark.parametrize("name", REGISTERED_NAMES)
def test_registered_value_is_a_basetool(name: str):
    """Every registry entry must be a real LangChain BaseTool.

    Catches the case where someone imports the wrong symbol (e.g. the
    underlying async function instead of the @tool-decorated version).
    """
    tool = _REGISTRY[name]
    assert isinstance(tool, BaseTool), (
        f"registry entry {name!r} is not a BaseTool: got {type(tool)}"
    )


@pytest.mark.parametrize("name", REGISTERED_NAMES)
def test_tool_name_matches_registry_key(name: str):
    """The tool's own ``.name`` attribute must match its registry key.

    LangChain dispatches tool calls by ``.name``, so a mismatch means
    the model emits a tool call the runtime cannot route. SKILL.md
    references the registry key, but execution uses ``.name`` — they
    must be the same string.
    """
    tool = _REGISTRY[name]
    assert tool.name == name, (
        f"registry key {name!r} != tool.name {tool.name!r} — "
        f"the @tool function name must match the registry key"
    )


# ── Resolver behaviour ──────────────────────────────────────────────


def test_resolve_tool_known():
    assert resolve_tool("run_command") is _REGISTRY["run_command"]


def test_resolve_tool_unknown_returns_none():
    assert resolve_tool("definitely_not_a_real_tool") is None


def test_resolve_tools_skips_unknown(caplog):
    """resolve_tools must drop unknowns silently (with a warning) and
    keep going. The planner relies on this — if a single bad name in a
    custom skill aborted the whole resolve, one typo would brick a run.
    """
    import logging

    with caplog.at_level(logging.WARNING):
        resolved = resolve_tools(["run_command", "nope_not_real", "read_file"])

    assert [t.name for t in resolved] == ["run_command", "read_file"]
    assert any("nope_not_real" in rec.message for rec in caplog.records)
