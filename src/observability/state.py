"""Pure functions that compute the per-node state shape and diff.

These functions don't write anything. They take a LangGraph state dict
(or a node's result dict) and return another dict suitable for handing
to ``observability/writers.py:append_node_event``. The split keeps
"compute what to log" separate from "write it to disk" — the writer
can stay tiny because the heavy lifting happened upstream.

Used exclusively by ``BaseNode.__call__`` (see
``src/nodes/base/__init__.py``) right before each node's
``append_node_event`` call. Pure functions so they can be unit-tested
in isolation without pulling LangGraph or LangChain at all.

The functions here used to live inside ``src/nodes/base.py`` (mixed
in with the node runner). Moved here in the observability refactor
so the nodes package owns the framework, observability owns the
recording — clean separation, no logging code in the node base.
"""

from __future__ import annotations

import json
from typing import Any


def _msg_chars(msg: Any) -> int:
    """Best-effort character count for one message's ``content``.

    Handles strings and multi-part list contents (rare in this codebase
    but technically supported by LangChain). Falls back to ``str(msg)``
    so this never raises and the size series stays well-formed even on
    weird message shapes.
    """
    content = getattr(msg, "content", None)
    if content is None and isinstance(msg, dict):
        content = msg.get("content")
    if content is None:
        return 0
    if isinstance(content, str):
        return len(content)
    if isinstance(content, list):
        # Multi-part — sum each part's JSON size as a proxy.
        try:
            return sum(len(json.dumps(p, default=str, ensure_ascii=False))
                       for p in content)
        except Exception:  # noqa: BLE001
            return sum(len(str(p)) for p in content)
    return len(str(content))


def _msg_role_label(msg: Any) -> str:
    """Map a BaseMessage subclass name to a short role label."""
    return {
        "HumanMessage":  "human",
        "AIMessage":     "assistant",
        "SystemMessage": "system",
        "ToolMessage":   "tool",
    }.get(type(msg).__name__, type(msg).__name__.lower())


def _state_shape(state: dict[str, Any] | None) -> dict[str, Any]:
    """Return a *shape* snapshot of the relevant state fields.

    Counts and character totals, plus a per-role breakdown of message
    content size and a list of finding titles by severity. The result
    is intentionally compact (no full text) — full text lives in the
    ``delta.added_*`` blocks of the diff event so we don't double-count
    bytes.

    Robust to a ``None`` state (e.g. before-snapshot taken when
    ``__call__`` is invoked with no arg) — returns zeroes.
    """
    s = state or {}
    msgs = s.get("messages") or []
    findings = s.get("findings") or []
    agent_results = s.get("agent_results") or []
    active = s.get("active_agents") or []

    role_chars: dict[str, int] = {
        "human": 0, "assistant": 0, "system": 0, "tool": 0,
    }
    role_counts: dict[str, int] = {
        "human": 0, "assistant": 0, "system": 0, "tool": 0,
    }
    total_chars = 0
    for m in msgs:
        role = _msg_role_label(m)
        chars = _msg_chars(m)
        total_chars += chars
        role_chars[role] = role_chars.get(role, 0) + chars
        role_counts[role] = role_counts.get(role, 0) + 1

    findings_by_sev: dict[str, int] = {}
    for f in findings:
        sev = getattr(f, "severity", None)
        sev_str = getattr(sev, "value", None) or str(sev or "info")
        findings_by_sev[sev_str] = findings_by_sev.get(sev_str, 0) + 1

    return {
        "messages_count":      len(msgs),
        "messages_chars":      total_chars,
        "messages_role_chars": role_chars,
        "messages_role_counts": role_counts,
        "findings_count":      len(findings),
        "findings_by_severity": findings_by_sev,
        "agent_results_count": len(agent_results),
        "active_agents":       list(active),
        "planner_iters":       s.get("planner_iters", 0) or 0,
        "next_action":         s.get("next_action"),
        "expected_flag_set":   bool(s.get("expected_flag")),
        "phase1_findings_set": bool(s.get("phase1_findings")),
        "waf_detected":        bool(s.get("waf_detected")),
        "stealth_level":       s.get("stealth_level", 0) or 0,
    }


def _serialize_added_message(msg: Any) -> dict:
    """Convert one *newly added* message to a JSON-safe full-text dict.

    No truncation — the user explicitly asked for "absolutely full
    logs everything" so per-node forensic replay is possible from
    nodes.jsonl alone, without joining final_state.json.

    Preserves tool_call linkage (assistant-side ``tool_calls`` and
    tool-side ``tool_call_id``) so the conversation chain can be
    walked from this file.
    """
    content = getattr(msg, "content", None)
    if content is None and isinstance(msg, dict):
        content = msg.get("content")
    if isinstance(content, list):
        try:
            content_value: Any = [
                p if isinstance(p, dict) else {"text": str(p)}
                for p in content
            ]
        except Exception:  # noqa: BLE001
            content_value = str(content)
    else:
        content_value = "" if content is None else str(content)

    out: dict[str, Any] = {
        "role":    _msg_role_label(msg),
        "content": content_value,
        "chars":   _msg_chars(msg),
    }
    tool_calls = getattr(msg, "tool_calls", None)
    if tool_calls:
        out["tool_calls"] = [
            {
                "name": tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", None),
                "args": tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", None),
                "id":   tc.get("id")   if isinstance(tc, dict) else getattr(tc, "id",   None),
            }
            for tc in tool_calls
        ]
    tool_call_id = getattr(msg, "tool_call_id", None)
    if tool_call_id:
        out["tool_call_id"] = tool_call_id
    name = getattr(msg, "name", None)
    if name:
        out["name"] = name
    additional = getattr(msg, "additional_kwargs", None)
    if additional:
        # Carry forward node tagging, refusal flags, salvage flag, etc.
        # ``reasoning_summary`` (if present) lands here too — its full
        # text in nodes.jsonl is exactly what the user wants for offline
        # analysis of model decisions.
        try:
            out["additional_kwargs"] = dict(additional)
        except Exception:  # noqa: BLE001
            pass
    return out


def _serialize_added_finding(f: Any) -> dict:
    """Convert one *newly added* Finding to a JSON-safe full-content dict."""
    sev = getattr(f, "severity", None)
    sev_str = getattr(sev, "value", None) or str(sev or "info")
    return {
        "title":       getattr(f, "title", "") or "",
        "severity":    sev_str,
        "category":    getattr(f, "category", "") or "",
        "description": getattr(f, "description", "") or "",
        "evidence":    getattr(f, "evidence", "") or "",
        "agent_id":    getattr(f, "agent_id", "") or "",
        "url":         getattr(f, "url", "") or "",
        "cwe":         getattr(f, "cwe", "") or "",
        "reproduced":  bool(getattr(f, "reproduced", False)),
    }


def _serialize_added_agent_result(ar: Any) -> dict:
    """Convert one *newly added* AgentResult to a JSON-safe dict."""
    return {
        "agent_id":     getattr(ar, "agent_id", None),
        "methodology":  getattr(ar, "methodology", None),
        "config_name":  getattr(ar, "config_name", None),
        "phase":        getattr(ar, "phase", None),
        "completed":    bool(getattr(ar, "completed", False)),
        "error":        getattr(ar, "error", None),
        "findings_count": len(getattr(ar, "findings", None) or []),
    }


def _state_diff(
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    duration_ms: int,
    new_messages: list[Any],
    new_findings: list[Any],
    new_agent_results: list[Any],
) -> dict[str, Any]:
    """Build the ``delta`` block: counts + full text of newly added items.

    The ``messages_added`` count compares the *post-execute* state's
    message list length to the snapshot taken before. For nodes that
    return new messages via the LangGraph ``add_messages`` reducer,
    the post-execute state isn't directly visible to us — instead
    we count the messages the node returned in its result dict, which
    is exactly what flows into the reducer.
    """
    duration_s = duration_ms / 1000.0 if duration_ms else 0.0
    chars_added = sum(_msg_chars(m) for m in new_messages)

    role_added: dict[str, int] = {}
    for m in new_messages:
        role = _msg_role_label(m)
        role_added[role] = role_added.get(role, 0) + 1

    return {
        "messages_added":             len(new_messages),
        "messages_chars_added":       chars_added,
        "messages_added_by_role":     role_added,
        "messages_added_full":        [_serialize_added_message(m) for m in new_messages],

        "findings_added":             len(new_findings),
        "findings_added_full":        [_serialize_added_finding(f) for f in new_findings],

        "agent_results_added":        len(new_agent_results),
        "agent_results_added_full":   [_serialize_added_agent_result(a) for a in new_agent_results],

        "growth_rate_chars_per_sec":  (chars_added / duration_s) if duration_s > 0 else 0.0,
    }


def _summarize_node_result(name: str, result: dict) -> str:
    """One-line summary of what a node returned, for the chat trace."""
    if not isinstance(result, dict):
        return "ok"
    parts = []
    if "findings" in result:
        parts.append(f"{len(result['findings'])} findings")
    if "agent_results" in result:
        ars = result["agent_results"] or []
        completed = sum(1 for a in ars if getattr(a, "completed", False))
        parts.append(f"{completed}/{len(ars)} agents ok")
    if result.get("active_agents"):
        parts.append(f"active: {','.join(result['active_agents'])}")
    if result.get("waf_detected"):
        parts.append(f"WAF (level {result.get('stealth_level', 0)})")
    if result.get("next_action"):
        parts.append(f"→ {result['next_action']}")
    if result.get("pending_dispatch"):
        parts.append(f"staged {len(result['pending_dispatch'])} workflow(s)")
    return ", ".join(parts) or "ok"


def _count_worker_iterations(trace: list[Any]) -> int:
    """How many tool-call iterations did the worker actually run?

    Counts ``AIMessage``s that carry tool calls (each one represents the
    worker deciding to invoke a tool). Doesn't count ``AIMessage``s
    without tool calls (the terminal "I'm done" message) or
    ``ToolMessage``s (those are responses, not iterations). Useful
    metadata for the summarizer prompt and for observability.
    """
    # Lazy import — keep the module import-light so nothing wants
    # langchain_core at module-load time.
    from langchain_core.messages import AIMessage

    count = 0
    for m in trace:
        if isinstance(m, AIMessage):
            tcs = getattr(m, "tool_calls", None) or []
            if tcs:
                count += 1
    return count
