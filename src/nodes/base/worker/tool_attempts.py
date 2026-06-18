# Structured tool-outcome extraction + per-skill investigation thread.
# Two jobs: (1) turn a worker's AI tool-calls + ToolMessages into coverage-style
# tool-attempt records (which surfaces a probe actually covered, and whether a
# fallback is needed); (2) compact one dispatch into the skill's continuity
# thread so the next dispatch continues instead of re-deriving.

from __future__ import annotations

import re

from langchain_core.messages import AIMessage, ToolMessage


_TOOL_OUTCOME_IMPORTANT_TOKENS = (
    "wpscan", "ffuf", "gobuster", "sqlmap", "nikto", "nmap", "nuclei",
    "tplmap", "sstimap", "tinja", "hydra", "curl --parallel",
    "xargs -p", "xargs -P", "parallel ", "threadpoolexecutor",
    "concurrent.futures", "asyncio",
)
_TOOL_OUTCOME_MAX_COMMAND_CHARS = 260
_TOOL_OUTCOME_MAX_EXCERPT_CHARS = 500


def _tool_message_text(tool_msg: ToolMessage | None) -> str:
    if tool_msg is None:
        return ""
    content = getattr(tool_msg, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text") or block.get("content") or ""))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content or "")


def _tool_call_arg(tool_call: dict, *names: str) -> str:
    args = tool_call.get("args") if isinstance(tool_call, dict) else {}
    if not isinstance(args, dict):
        return ""
    for name in names:
        value = args.get(name)
        if isinstance(value, str) and value.strip():
            return " ".join(value.split())
    return ""


def _compact_tool_field(value: str, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _tool_exit_code(output: str) -> int | None:
    match = re.search(r"\[.*?\bexit=(-?\d+).*?\]", output, re.DOTALL)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _tool_base_status(output: str, exit_code: int | None) -> tuple[str, str]:
    low = output.lower()
    if "timeout after" in low or "timed out" in low:
        return "timeout", "timeout"
    if "command not found" in low or "no such file or directory" in low:
        return "failed", "command-not-found"
    if exit_code is not None and exit_code != 0:
        return "failed", "nonzero-exit"
    return "success", ""


def _important_tool_surface(tool_name: str, command: str) -> bool:
    blob = f"{tool_name} {command}".lower()
    return any(token.lower() in blob for token in _TOOL_OUTCOME_IMPORTANT_TOKENS)


def _classify_tool_attempt(
    *,
    tool_name: str,
    command: str,
    output: str,
    exit_code: int | None,
    agent_id: str,
    config_name: str,
) -> dict | None:
    # Return a coverage-style tool outcome, or None for routine probes.
    if not _important_tool_surface(tool_name, command):
        return None

    low_cmd = command.lower()
    low_out = output.lower()
    low_blob = f"{low_cmd}\n{low_out}"
    status, error_type = _tool_base_status(output, exit_code)
    surface = tool_name or "tool"
    coverage = "full" if status == "success" else "none"
    covered = status == "success"
    fallback_needed = False

    if "wpscan" in low_blob:
        surface = "wordpress component enumeration"
        wp_abort_markers = (
            "scan aborted", "update required", "database file is missing",
            "you can not run a scan", "cannot run a scan",
            "please run wpscan --update",
        )
        if any(marker in low_out for marker in wp_abort_markers):
            status = "failed"
            covered = False
            coverage = "none"
            fallback_needed = True
            error_type = "wpscan-db-missing-or-aborted"
        else:
            # --enumerate p can miss arbitrary plugins; full coverage needs ap/at.
            enum_full = bool(
                re.search(r"--enumerate\s+[^\s]*\bap\b", low_cmd)
                or re.search(r"--enumerate\s+[^\s]*\bat\b", low_cmd)
            )
            if status == "success" and not enum_full:
                covered = False
                coverage = "partial"
                fallback_needed = True
                error_type = "partial-wordpress-component-enumeration"
            elif status != "success":
                fallback_needed = True
        tool_name = "wpscan"
    elif "wp-content/plugins" in low_blob or "wp-content/themes" in low_blob:
        surface = "wordpress component fallback enumeration"
        coverage = "partial" if status == "success" else "none"
        covered = status == "success"
    elif "sqlmap" in low_blob:
        surface = "sql injection automated probe"
        tool_name = "sqlmap"
    elif "nmap" in low_blob:
        surface = "network/service enumeration"
        tool_name = "nmap"
    elif "nikto" in low_blob:
        surface = "web server known-issue scan"
        tool_name = "nikto"
    elif "ffuf" in low_blob or "gobuster" in low_blob:
        surface = "content/path enumeration"
        tool_name = "ffuf" if "ffuf" in low_blob else "gobuster"
        coverage = "partial" if status == "success" else "none"
    elif any(token in low_blob for token in (
        "curl --parallel", "xargs -p", "threadpoolexecutor",
        "concurrent.futures", "asyncio",
    )):
        surface = "concurrency/race probe"

    if status != "success" and not fallback_needed:
        fallback_needed = True

    return {
        "surface": surface,
        "tool": tool_name or "tool",
        "command": _compact_tool_field(command, _TOOL_OUTCOME_MAX_COMMAND_CHARS),
        "status": status,
        "covered": covered,
        "coverage": coverage,
        "error_type": error_type,
        "fallback_needed": fallback_needed,
        "source_agent": agent_id,
        "config_name": config_name,
        "exit_code": exit_code,
        "output_excerpt": _compact_tool_field(output, _TOOL_OUTCOME_MAX_EXCERPT_CHARS),
    }


def _extract_tool_attempts_from_trace(
    messages: list,
    *,
    agent_id: str,
    config_name: str,
) -> list[dict]:
    # Extract important tool outcomes from AI tool calls + ToolMessages.
    responses: dict[str, ToolMessage] = {}
    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        call_id = str(getattr(msg, "tool_call_id", "") or "")
        if call_id:
            responses[call_id] = msg

    attempts: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        for tool_call in getattr(msg, "tool_calls", []) or []:
            if not isinstance(tool_call, dict):
                continue
            call_id = str(tool_call.get("id") or tool_call.get("tool_call_id") or "")
            tool_name = str(tool_call.get("name") or "").strip()
            command = _tool_call_arg(
                tool_call,
                "command", "cmd", "url", "query", "target", "data",
            )
            if not command:
                continue
            output = _tool_message_text(responses.get(call_id))
            exit_code = _tool_exit_code(output)
            attempt = _classify_tool_attempt(
                tool_name=tool_name,
                command=command,
                output=output,
                exit_code=exit_code,
                agent_id=agent_id,
                config_name=config_name,
            )
            if not attempt:
                continue
            key = (
                str(attempt.get("surface") or ""),
                str(attempt.get("tool") or ""),
                str(attempt.get("command") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            attempts.append(attempt)
    return attempts[-20:]


# ── Per-skill investigation thread (continuity + compaction) ──
# A fresh worker context peaks ~45-87k tokens; carrying prior work forward risks
# crossing the ~120k degradation point, so the thread is compacted to a bounded
# char budget — commands kept verbatim, tool OUTPUTS shrunk to one line.
_THREAD_CHAR_BUDGET = 120_000
_RECORD_CMD_CHARS = 240
_RECORD_OUTPUT_CHARS = 200
_MAX_STEPS_PER_RUN = 40

# Cheap artifact tells worth preserving in a shrunk output summary — what actually
# decides whether a probe progressed.
_OUTPUT_TELLS = (
    "root:x:0:0", "uid=", "gid=", "flag{", "information_schema",
    "union select", "@@version", "traceback", "stack trace", "exception",
    "denied", "forbidden", "not a number", "500 internal", "200 ok",
    "302 found", "401 ", "403 ", "404 ", "no such", "syntax error",
)


def _summarize_output(output: str) -> str:
    # Shrink a tool output to one line: size + first line + decisive artifact tells.
    o = (output or "").strip()
    if not o:
        return "(no output)"
    first_line = next((ln for ln in o.splitlines() if ln.strip()), "")[:120]
    low = o.lower()
    tells = sorted({t for t in _OUTPUT_TELLS if t in low})
    tail = f"  tells={','.join(tells[:5])}" if tells else ""
    return f"[{len(o)}b] {first_line}{tail}"[:_RECORD_OUTPUT_CHARS]


def _compact_run_record(messages: list, verdict_signals: list) -> str:
    # Compact record of ONE dispatch: each command verbatim, its output shrunk to
    # one line, then the closing verdict. The unit the continuity thread accumulates.
    responses: dict[str, ToolMessage] = {}
    for msg in messages:
        if isinstance(msg, ToolMessage):
            cid = str(getattr(msg, "tool_call_id", "") or "")
            if cid:
                responses[cid] = msg

    lines: list[str] = []
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        for tc in getattr(msg, "tool_calls", []) or []:
            if not isinstance(tc, dict):
                continue
            cmd = _tool_call_arg(tc, "command", "cmd", "url", "query", "target", "data")
            if not cmd:
                continue
            cid = str(tc.get("id") or tc.get("tool_call_id") or "")
            out = _tool_message_text(responses.get(cid))
            lines.append(
                f"- `{' '.join(cmd.split())[:_RECORD_CMD_CHARS]}` "
                f"→ {_summarize_output(out)}"
            )
            if len(lines) >= _MAX_STEPS_PER_RUN:
                break
        if len(lines) >= _MAX_STEPS_PER_RUN:
            break

    for s in (verdict_signals or []):
        if str(getattr(s, "source", "")) == "executor_verdict":
            lines.append(f"- VERDICT: {str(getattr(s, 'observation', ''))[:200]}")
            break

    return "\n".join(lines) if lines else "(no tool steps this run)"


def _build_investigation_thread(
    state: dict, config_name: str, messages: list, verdict_signals: list,
) -> dict:
    # Append this dispatch's compacted record to the skill's thread, bump its run
    # count, trim oldest runs until under the char budget. Returns the single-key
    # update for state['investigation_threads'].
    prior = (state.get("investigation_threads") or {}).get(config_name) or {}
    run_count = int(prior.get("run_count", 0)) + 1
    runs = [str(r) for r in (prior.get("runs") or [])]
    runs.append(_compact_run_record(messages, verdict_signals))
    # Drop oldest runs (keep ≥ current) until under budget.
    while len(runs) > 1 and sum(len(r) for r in runs) > _THREAD_CHAR_BUDGET:
        runs.pop(0)
    return {config_name: {"run_count": run_count, "runs": runs}}
