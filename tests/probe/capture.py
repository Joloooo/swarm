"""Reconstruct the LangChain message list for a captured reflection point.

Messages-mode: rebuild ``SystemMessage`` / ``HumanMessage`` /
``AIMessage(tool_calls=...)`` / ``ToolMessage`` verbatim from the captured
``request.messages``. This is faithful for the model INPUT. Tools are NOT in the
capture (``request.tools`` is logged empty — the F2 gap), so the node's real
tools are bound separately by :func:`tests.probe.replay.resolve_tools` from
``src/`` using the fixture's ``capture.tools`` names. This module knows the LOG
shape only — never how a prompt is built (that stays in ``src/``).
"""

from __future__ import annotations

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)


def reconstruct_messages(captured_event: dict) -> list[BaseMessage]:
    """Rebuild the verbatim input message list from a captured ``llm_start`` event."""
    raw = (captured_event.get("request") or {}).get("messages") or []
    out: list[BaseMessage] = []
    for m in raw:
        role = m.get("role")
        content = m.get("content") or ""
        if role == "system":
            out.append(SystemMessage(content=content))
        elif role in ("human", "user"):
            out.append(HumanMessage(content=content))
        elif role == "assistant":
            tool_calls = [
                {
                    "name": t.get("name"),
                    "args": t.get("args") or {},
                    "id": t.get("id"),
                    "type": "tool_call",
                }
                for t in (m.get("tool_calls") or [])
            ]
            out.append(AIMessage(content=content, tool_calls=tool_calls))
        elif role == "tool":
            out.append(
                ToolMessage(
                    content=content,
                    tool_call_id=m.get("tool_call_id") or "",
                    name=m.get("name"),
                )
            )
        else:
            # Unknown role — keep the text as a human turn so nothing is silently
            # dropped from the replayed input.
            out.append(HumanMessage(content=content))
    return out
