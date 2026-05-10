"""Refusal-replay v3: focused test on the 6 cases where plain × 3
failed in v2. Two new variants based on the diff analysis:

  - **rerun**: same as plain — re-issues the unchanged request 3
    times. (Baseline, just with cleaner naming per user request.)

  - **strip_reasoning**: keeps the conversation structure intact
    (system prompt + every AI tool_call + every tool output) but
    REMOVES the `args.reasoning` field from each AI tool_call. The
    worker still sees what commands were run and what came back, but
    the per-call hypothesis text (which often explicitly says "I'm
    looking for the flag via SQL injection") is gone.

  - **fresh_context**: rebuilds the conversation from scratch with
    only the system prompt + a single condensed message that lists
    "what was tried" (commands only, no reasoning, no payloads
    quoted) + "what came back" (status codes + body sizes only). The
    LLM has to think fresh given the actions/results summary.

For comparison we keep:
  - **compress_old** (rescued executor-0[21] in v2)
  - **redact_sql** (rescued vulntype-idor in v2)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

import src.graph  # noqa: F401

from src.llm.codex import (  # noqa: E402
    CodexCyberPolicyError,
    CodexInvalidPromptError,
    CodexStreamError,
)
from src.llm.provider import LLMConfig, Provider, get_llm  # noqa: E402


# Only the 6 cases that plain × 3 failed in v2 (per user direction).
PLAIN_FAILING = [
    "executor-0__2026-05-09T18-12-35.181.json",
    "executor-2__2026-05-09T18-15-05.544.json",
    "methodology-fuzzing__2026-05-09T18-11-26.488.json",
    "owasp-input-validation__2026-05-09T18-15-12.506.json",
    "vulntype-idor__2026-05-09T18-15-18.379.json",
    "vulntype-information-disclosure__2026-05-09T18-11-44.154.json",
]


def reconstruct_messages(req: dict) -> list:
    msgs: list = []
    for m in req["messages"]:
        role = m["role"]
        content = m.get("content", "") or ""
        if role == "system":
            msgs.append(SystemMessage(content=content))
        elif role in ("user", "human"):
            msgs.append(HumanMessage(content=content))
        elif role == "assistant":
            tool_calls = m.get("tool_calls", []) or []
            msgs.append(AIMessage(content=content, tool_calls=tool_calls))
        elif role == "tool":
            msgs.append(
                ToolMessage(
                    content=content,
                    tool_call_id=m["tool_call_id"],
                    name=m.get("name", "tool"),
                )
            )
    return msgs


# ── Variants ────────────────────────────────────────────────────────────

def variant_rerun(msgs: list) -> list:
    """Same payload — baseline non-determinism check."""
    return msgs


def variant_strip_reasoning(msgs: list) -> list:
    """Remove the `reasoning` arg from each AI tool_call. Worker still
    sees what was run and what came back, but the per-call hypothesis
    text is gone."""
    out = []
    for m in msgs:
        if isinstance(m, AIMessage) and m.tool_calls:
            new_tcs = []
            for tc in m.tool_calls:
                new_args = {k: v for k, v in tc.get("args", {}).items()
                            if k != "reasoning"}
                new_tcs.append({**tc, "args": new_args})
            out.append(AIMessage(content="", tool_calls=new_tcs))
        else:
            out.append(m)
    return out


def _summarize_command(args: dict) -> str:
    """One-line description of what an AI tool_call actually ran."""
    for k in ("command", "url", "data"):
        if k in args:
            v = str(args[k])
            # Squeeze whitespace, take first 100 chars
            v = re.sub(r"\s+", " ", v)[:100]
            return f"{k}={v!r}"
    return "(no command-like arg)"


def _summarize_tool_output(content: str) -> str:
    """Extract status codes + size from a tool output."""
    n = len(content)
    statuses = sorted(set(re.findall(
        r"\b(?:200|201|204|301|302|400|401|403|404|405|500|502|503)\b",
        content
    )))
    flag_present = "flag{" in content.lower() or "FLAG{" in content
    out = f"{n}B"
    if statuses:
        out += " statuses=" + ",".join(statuses)
    if flag_present:
        out += " (response contained the target marker)"
    return out


def variant_fresh_context(msgs: list) -> list:
    """Replace ALL prior reasoning + tool output with a single
    condensed action-log message. Keeps system prompt + adds:
      [Prior actions: command1 → result1; command2 → result2; ...]
    and lets the model reason fresh from there."""
    if len(msgs) <= 1:
        return msgs
    head = [m for m in msgs[:1] if isinstance(m, SystemMessage)] or [msgs[0]]

    # Walk the conversation collecting (command, result) pairs
    pairs = []
    pending_call = None
    for m in msgs[1:]:
        if isinstance(m, AIMessage) and m.tool_calls:
            for tc in m.tool_calls:
                pending_call = _summarize_command(tc.get("args", {}))
        elif isinstance(m, ToolMessage) and pending_call is not None:
            content = m.content if isinstance(m.content, str) else str(m.content)
            pairs.append((pending_call, _summarize_tool_output(content)))
            pending_call = None

    if not pairs:
        return msgs

    log_lines = [f"  {i+1}. {cmd}\n     → {result}"
                 for i, (cmd, result) in enumerate(pairs)]
    summary = HumanMessage(content=(
        "Continuing from a prior session. Here is a condensed log of "
        f"the {len(pairs)} actions taken so far and what came back:\n\n"
        + "\n".join(log_lines)
        + "\n\nDecide the next single action to take."
    ))
    return head + [summary]


def variant_compress_old(msgs: list) -> list:
    """From v2 — rescued executor-0(21) uniquely."""
    if len(msgs) <= 4:
        return msgs
    head = msgs[:1]
    tail = msgs[-2:]
    middle = msgs[1:-2]
    lines = []
    for m in middle:
        if isinstance(m, AIMessage) and m.tool_calls:
            for tc in m.tool_calls:
                args = tc.get("args", {})
                lines.append(f"  - {tc.get('name','?')}: {_summarize_command(args)}")
        elif isinstance(m, ToolMessage):
            content = m.content if isinstance(m.content, str) else str(m.content)
            lines.append("    -> " + _summarize_tool_output(content))
    summary = AIMessage(content=(
        f"[Compressed history of {len(middle)} prior messages:]\n"
        + "\n".join(lines)
    ))
    return head + [summary] + tail


_SQL_KW_RE = re.compile(
    r"\b(OR|AND|UNION|SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|DROP|"
    r"ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|JOIN|INTO|VALUES|EXEC|EXECUTE|"
    r"sleep|benchmark|pg_sleep|randomblob)\b",
    re.IGNORECASE,
)


def _redact_text(text: str) -> str:
    out = _SQL_KW_RE.sub("[KW]", text)
    out = re.sub(r"\b1\s*=\s*1\b", "X=X", out)
    out = re.sub(r"\b1\s*=\s*2\b", "X=Y", out)
    out = re.sub(
        r"\b(injection|sqli|payload|exploit|attack)\w*\b",
        "[REDACTED]",
        out,
        flags=re.IGNORECASE,
    )
    return out


def variant_redact_sql(msgs: list) -> list:
    """From v2 — rescued vulntype-idor uniquely."""
    out = []
    for m in msgs:
        if isinstance(m, ToolMessage):
            content = m.content if isinstance(m.content, str) else str(m.content)
            out.append(ToolMessage(
                content=_redact_text(content),
                tool_call_id=m.tool_call_id,
                name=getattr(m, "name", "tool"),
            ))
        elif isinstance(m, AIMessage) and m.tool_calls:
            new_tcs = []
            for tc in m.tool_calls:
                args = dict(tc.get("args", {}))
                for fname in ("command", "data", "url", "payload", "reasoning"):
                    if fname in args and isinstance(args[fname], str):
                        args[fname] = _redact_text(args[fname])
                new_tcs.append({**tc, "args": args})
            out.append(AIMessage(
                content=m.content if isinstance(m.content, str)
                else str(m.content),
                tool_calls=new_tcs,
            ))
        else:
            out.append(m)
    return out


VARIANTS = [
    ("rerun", variant_rerun, 3),
    ("strip_reasoning", variant_strip_reasoning, 3),
    ("fresh_context", variant_fresh_context, 3),
    ("redact_sql", variant_redact_sql, 2),
    ("compress_old", variant_compress_old, 2),
]


# ── Driver ──────────────────────────────────────────────────────────────

@dataclass
class Outcome:
    variant: str
    attempt: int
    status: str
    error_type: str | None = None
    duration_s: float = 0.0


@dataclass
class CaseResult:
    case_file: str
    agent_id: str
    n_messages: int
    est_tokens: int
    outcomes: list[Outcome] = field(default_factory=list)


async def run_one(llm, msgs: list, variant: str, attempt: int) -> Outcome:
    t0 = time.time()
    try:
        await llm.ainvoke(msgs)
        return Outcome(variant, attempt, "accepted",
                       duration_s=round(time.time() - t0, 2))
    except CodexCyberPolicyError as e:
        return Outcome(variant, attempt, "refused",
                       error_type="CodexCyberPolicyError",
                       duration_s=round(time.time() - t0, 2))
    except CodexInvalidPromptError as e:
        return Outcome(variant, attempt, "refused",
                       error_type="CodexInvalidPromptError",
                       duration_s=round(time.time() - t0, 2))
    except CodexStreamError as e:
        return Outcome(variant, attempt, "error",
                       error_type=type(e).__name__,
                       duration_s=round(time.time() - t0, 2))
    except Exception as e:  # noqa: BLE001
        return Outcome(variant, attempt, "error",
                       error_type=type(e).__name__,
                       duration_s=round(time.time() - t0, 2))


async def run_case(llm, case_path: Path, *,
                   inter_call_delay_s: float) -> CaseResult:
    req = json.loads(case_path.read_text())
    msgs = reconstruct_messages(req)
    agent_id = case_path.stem.split("__")[0]
    res = CaseResult(
        case_file=case_path.name,
        agent_id=agent_id,
        n_messages=req.get("n_messages", len(msgs)),
        est_tokens=req.get("estimated_input_tokens", 0),
    )
    print(
        f"\n=== {agent_id}  msgs={res.n_messages}  "
        f"tokens={res.est_tokens} ===",
        flush=True,
    )

    for variant_name, transform, n_attempts in VARIANTS:
        transformed = transform(msgs)
        for attempt in range(1, n_attempts + 1):
            out = await run_one(llm, transformed, variant_name, attempt)
            res.outcomes.append(out)
            tag = f"{variant_name}#{attempt}"
            print(
                f"  {tag:<22}  {out.status:<10}  "
                f"{(out.error_type or '-'):<28}  {out.duration_s:>6.2f}s",
                flush=True,
            )
            await asyncio.sleep(inter_call_delay_s)
            if out.status == "accepted":
                break
    return res


def write_summary(results: list[CaseResult], out_dir: Path) -> None:
    json_out = out_dir / "_replay_v3_results.json"
    json_out.write_text(json.dumps([asdict(r) for r in results], indent=2))

    md = ["# Refusal Replay v3 Results — focused on plain×3-failing cases",
          ""]
    md.append("Tested ONLY the 6 cases where plain × 3 failed in v2.")
    md.append("Each cell: ✅ if at least one attempt of that variant accepted.")
    md.append("Trailing chars = stopped early on first ✅.")
    md.append("")
    md.append("| agent_id | msgs | rerun×3 | strip_reasoning×3 | fresh_context×3 | redact_sql×2 | compress×2 |")
    md.append("|---|---|---|---|---|---|---|")

    def cell(r: CaseResult, variant: str) -> str:
        outs = [o for o in r.outcomes if o.variant == variant]
        if not outs:
            return "—"
        chars = []
        for o in outs:
            if o.status == "accepted":
                chars.append("✅")
            elif o.status == "refused":
                chars.append("❌")
            else:
                chars.append("⚠️")
        return "".join(chars)

    for r in results:
        md.append(
            f"| `{r.agent_id}` | {r.n_messages} | "
            f"{cell(r, 'rerun')} | {cell(r, 'strip_reasoning')} | "
            f"{cell(r, 'fresh_context')} | "
            f"{cell(r, 'redact_sql')} | {cell(r, 'compress_old')} |"
        )
    md.append("")
    md.append("Legend: ✅ accepted, ❌ refused, ⚠️ other error.")
    (out_dir / "_replay_v3_summary.md").write_text("\n".join(md))


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rejected_dir", type=Path)
    ap.add_argument("--model", default="gpt-5.5")
    ap.add_argument("--inter-call-delay-s", type=float, default=1.5)
    args = ap.parse_args()

    case_files = [args.rejected_dir / fn for fn in PLAIN_FAILING]
    case_files = [f for f in case_files if f.exists()]

    print(f"Will replay {len(case_files)} plain-failing cases against "
          f"model={args.model}\n")

    cfg = LLMConfig(provider=Provider.CODEX, model=args.model)
    llm = get_llm(cfg)

    results: list[CaseResult] = []
    try:
        for case in case_files:
            r = await run_case(
                llm, case,
                inter_call_delay_s=args.inter_call_delay_s,
            )
            results.append(r)
            write_summary(results, args.rejected_dir)
    finally:
        write_summary(results, args.rejected_dir)
    print("\nDONE")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
