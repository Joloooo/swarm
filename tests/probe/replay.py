"""Level-1 replay: re-invoke the REAL model on a (possibly perturbed) captured
input and return its REAL output. We never write, mock, or truncate the output —
the whole point is to observe the real model's reaction to a changed input
(SKILL §3).

Everything under test is imported from ``src/``: the provider (``get_llm``), the
model id + reasoning (from the live ``LLMConfig``), and the node's real tools
(bound here from ``src/`` by name, because the capture does not store them — F2).
A single ``ainvoke`` reproduces the ONE captured LLM call; the whole-node loop is
Level-2 (see ``level2.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from langchain_core.messages import BaseMessage


@dataclass
class ReplayResult:
    """One real completion: its text, any tool calls it emitted, and the raw msg."""

    text: str
    tool_calls: list[dict]
    raw: Any


def resolve_tools(names: list[str]) -> list:
    """Map tool NAMES to the REAL ``src/`` tool objects (never reconstructed from
    the log, which stores none — F2). Tries the central tool registry first, then
    the node-only tools that aren't registered there (the planner's url tools)."""
    from src.tools.registry import resolve_tool

    out = []
    for name in names or []:
        tool = resolve_tool(name) or _extra_tool(name)
        if tool is None:
            raise LookupError(f"cannot resolve tool {name!r} from src/")
        out.append(tool)
    return out


def _extra_tool(name: str):
    """Tools a node binds directly rather than via the central registry —
    imported as the REAL objects from ``src/`` so binding stays honest."""
    from src.tools import url as _url

    return {
        "normalize_url": _url.normalize_url,
        "validate_website": _url.validate_website,
    }.get(name)


async def replay_once(
    messages: list[BaseMessage], *, tools: list | None = None, llm_config=None
) -> ReplayResult:
    """Send ``messages`` to the real model once and return its real output."""
    from src.llm.provider import LLMConfig, get_llm

    llm = get_llm(llm_config or LLMConfig())
    if tools:
        llm = llm.bind_tools(tools)
    resp = await llm.ainvoke(messages)
    text = resp.content if isinstance(resp.content, str) else str(resp.content)
    tool_calls = [
        {"name": tc.get("name"), "args": tc.get("args")}
        for tc in (getattr(resp, "tool_calls", None) or [])
    ]
    return ReplayResult(text=text, tool_calls=tool_calls, raw=resp)
