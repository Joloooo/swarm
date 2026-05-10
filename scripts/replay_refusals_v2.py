"""Refusal-replay v2: tests the user's hypothesis (drop_last × 3 should
recover everything because we are re-issuing a known-good prompt) and
two new content-preserving variants:

  - **summarize_tool_outputs**: replace each old ToolMessage content
    with a structural summary (size, type, first-line preview). Keeps
    AI tool-call args intact so the worker still sees what it sent.
    Tests whether tool-output content is the trigger.

  - **redact_sql_keywords**: regex-replace SQL-injection keywords
    (OR, AND, UNION, SELECT, etc.) inside BOTH ToolMessage contents
    AND AIMessage tool_call args. Keeps message structure intact.
    Tests whether specific keyword patterns are the trigger.

  - **compress_old_messages**: replace ALL messages between [1] and
    [-2] with one structured summary AIMessage. Most aggressive
    knowledge-preserving compression.

Skips the failed-on-everything variants from v1 (neutral_system and
neutral_system_and_drop_last) since those returned 0/11.
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

import src.graph  # noqa: F401  -- avoid circular import

from src.llm.codex import (  # noqa: E402
    CodexCyberPolicyError,
    CodexInvalidPromptError,
    CodexStreamError,
)
from src.llm.provider import LLMConfig, Provider, get_llm  # noqa: E402


# ── Reconstruction (same as v1) ─────────────────────────────────────────

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

def variant_plain(msgs: list) -> list:
    return msgs


def variant_drop_last(msgs: list) -> list:
    """Drop trailing AI + Tool pair — recreates the prior known-good
    prompt that the LLM successfully responded to one turn ago."""
    if len(msgs) <= 1:
        return msgs
    out = list(msgs)
    while len(out) > 1 and isinstance(out[-1], ToolMessage):
        out.pop()
    if len(out) > 1 and isinstance(out[-1], AIMessage):
        out.pop()
    return out


def _summarize_tool_content(content: str) -> str:
    """One-line structural summary of a tool message content."""
    n = len(content)
    # Pick out HTTP status codes if visible
    statuses = sorted(set(re.findall(r"\b(?:200|201|204|301|302|400|401|403|404|405|500|502|503)\b", content)))
    first_line = content.strip().split("\n", 1)[0][:120]
    parts = [f"{n} bytes"]
    if statuses:
        parts.append("statuses=" + ",".join(statuses))
    if first_line:
        parts.append("first_line=" + repr(first_line))
    return f"[tool output summary: {' | '.join(parts)}]"


def variant_summarize_tool_outputs(msgs: list) -> list:
    """Replace each ToolMessage's content with a one-line structural
    summary. Keeps the AI tool_calls (so the worker remembers what it
    sent) but hides the raw response bodies that may contain the
    triggering content."""
    out = []
    for m in msgs:
        if isinstance(m, ToolMessage):
            summary = _summarize_tool_content(
                m.content if isinstance(m.content, str) else str(m.content)
            )
            out.append(ToolMessage(
                content=summary,
                tool_call_id=m.tool_call_id,
                name=getattr(m, "name", "tool"),
            ))
        else:
            out.append(m)
    return out


_SQL_KW_RE = re.compile(
    r"\b(OR|AND|UNION|SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|DROP|"
    r"ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|JOIN|INTO|VALUES|EXEC|EXECUTE|"
    r"sleep|benchmark|pg_sleep|randomblob)\b",
    re.IGNORECASE,
)
_INJECT_PATTERNS = [
    (re.compile(r"\b1\s*=\s*1\b"), "X=X"),
    (re.compile(r"\b1\s*=\s*2\b"), "X=Y"),
    (re.compile(r"'--"), "QC"),
    (re.compile(r"';"), "QS"),
]


def _redact_text(text: str) -> str:
    out = _SQL_KW_RE.sub("[KW]", text)
    for pat, repl in _INJECT_PATTERNS:
        out = pat.sub(repl, out)
    # Also redact the word "injection" / "sqli" / "payload"
    out = re.sub(
        r"\b(injection|sqli|payload|exploit|attack)\w*\b",
        "[REDACTED]",
        out,
        flags=re.IGNORECASE,
    )
    return out


def variant_redact_sql_keywords(msgs: list) -> list:
    """Replace SQL keywords + injection patterns in ALL tool outputs
    AND in AI tool_call args. Keeps everything else (structure,
    timestamps, status codes) intact."""
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
                # Redact known string-bearing arg fields
                for field_name in ("command", "data", "url", "payload",
                                   "reasoning"):
                    if field_name in args and isinstance(
                        args[field_name], str
                    ):
                        args[field_name] = _redact_text(args[field_name])
                new_tcs.append({**tc, "args": args})
            out.append(AIMessage(
                content=m.content if isinstance(m.content, str)
                else str(m.content),
                tool_calls=new_tcs,
            ))
        else:
            out.append(m)
    return out


def variant_compress_old_messages(msgs: list) -> list:
    """Keep [system, ...latest 2 messages]; replace the middle with
    one summary AIMessage that lists what was tried."""
    if len(msgs) <= 4:
        return msgs
    head = msgs[:1]  # system
    tail = msgs[-2:]  # last AI+Tool pair (or whatever last 2 are)
    middle = msgs[1:-2]
    # Build a structural log of the middle
    lines = []
    for m in middle:
        if isinstance(m, AIMessage) and m.tool_calls:
            for tc in m.tool_calls:
                name = tc.get("name", "?")
                args = tc.get("args", {})
                cmd_preview = ""
                for k in ("command", "data", "url"):
                    if k in args:
                        v = str(args[k])[:80]
                        cmd_preview = f"{k}={v!r}"
                        break
                lines.append(f"  - {name}({cmd_preview})")
        elif isinstance(m, ToolMessage):
            content = m.content if isinstance(m.content, str) else str(m.content)
            lines.append("    → " + _summarize_tool_content(content))
    summary = AIMessage(
        content=(
            "[Compressed history of prior probes — full content "
            f"redacted, {len(middle)} messages omitted, summary below:]\n"
            + "\n".join(lines)
        )
    )
    return head + [summary] + tail


VARIANTS = [
    ("plain", variant_plain, 3),
    ("drop_last", variant_drop_last, 3),
    ("summarize_tools", variant_summarize_tool_outputs, 2),
    ("redact_sql", variant_redact_sql_keywords, 2),
    ("compress_old", variant_compress_old_messages, 2),
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
        f"\n=== {case_path.name}  agent={agent_id}  "
        f"msgs={res.n_messages}  est_tokens={res.est_tokens} ===",
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
            # Optimization: if a variant succeeded, skip remaining
            # attempts for that variant (we only need to know if it
            # CAN pass, not the exact rate).
            if out.status == "accepted":
                break

    return res


def write_summary(results: list[CaseResult], out_dir: Path) -> None:
    json_out = out_dir / "_replay_v2_results.json"
    json_out.write_text(json.dumps([asdict(r) for r in results], indent=2))

    md = ["# Refusal Replay v2 Results", ""]
    md.append("Each cell shows up to N attempts; ✅ = accepted at least once.")
    md.append("")
    md.append("| agent_id | msgs | tokens | plain×3 | drop_last×3 | summarize×2 | redact_sql×2 | compress×2 |")
    md.append("|---|---|---|---|---|---|---|---|")

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
            f"| `{r.agent_id}` | {r.n_messages} | {r.est_tokens} | "
            f"{cell(r, 'plain')} | {cell(r, 'drop_last')} | "
            f"{cell(r, 'summarize_tools')} | {cell(r, 'redact_sql')} | "
            f"{cell(r, 'compress_old')} |"
        )
    md.append("")
    md.append("Legend: ✅ accepted, ❌ refused, ⚠️ other error.  "
              "Trailing chars = stopped early on first ✅.")
    (out_dir / "_replay_v2_summary.md").write_text("\n".join(md))
    print(f"\nWrote results to:\n  {json_out}\n  "
          f"{out_dir / '_replay_v2_summary.md'}")


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rejected_dir", type=Path)
    ap.add_argument("--model", default="gpt-5.5")
    ap.add_argument("--filter", default=None)
    ap.add_argument("--inter-call-delay-s", type=float, default=1.5)
    args = ap.parse_args()

    case_files = sorted([
        f for f in args.rejected_dir.glob("*.json")
        if f.name != "_index.json"
        and not f.name.startswith("_")
        and "__summary__" not in f.name
    ])
    if args.filter:
        case_files = [f for f in case_files if args.filter in f.name]

    if not case_files:
        print("No matching cases found", file=sys.stderr)
        return 2

    print(f"Will replay {len(case_files)} cases against model={args.model}")
    print()

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
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
