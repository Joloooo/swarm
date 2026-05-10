"""Replay rejected Codex requests to test simple-fix hypotheses.

Reads every rejected request dumped under
``logs/run-.../rejected_requests/*.json`` and re-issues each one against
Codex under several variants:

  - **plain retry x N** — same payload, same model. Tests whether the
    classifier is non-deterministic enough that simple retry rescues the
    request.
  - **drop_last_response** — strips the trailing assistant + tool message
    pair, then re-issues. Tests whether the most recent turn is the
    sole trigger.
  - **neutral_system** — replaces the worker's system prompt with a
    minimal benign one, keeps the conversation history intact. Tests
    whether the system-prompt framing is the sole trigger.

Records per-variant outcome (refused / accepted / other-error) into a
JSON results file alongside the input requests, plus a Markdown summary
table for the operator.

Usage::

    uv run python scripts/replay_refusals.py \\
      logs/run-XBEN-006-24__2026-05-09_18h07m14s/rejected_requests
"""

from __future__ import annotations

import argparse
import asyncio
import json
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

# Touch src.graph FIRST to complete the partial-import dance. Without
# this, importing src.llm.provider directly trips a circular import
# because src.graph module-level instantiates planner_node, which in
# turn imports get_llm.
import src.graph  # noqa: F401

from src.llm.codex import (  # noqa: E402
    CodexCyberPolicyError,
    CodexInvalidPromptError,
    CodexStreamError,
)
from src.llm.provider import LLMConfig, Provider, get_llm  # noqa: E402

NEUTRAL_SYSTEM = (
    "You are a helpful assistant. Analyze the prior conversation and "
    "suggest the next single concrete action that would help the "
    "operator continue their task."
)


def reconstruct_messages(req: dict) -> list:
    """Convert the logged request blob back into LangChain messages."""
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
            # LangChain AIMessage accepts tool_calls as list of dicts
            # with keys {name, args, id}. The logged blob already has
            # exactly that shape.
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


def variant_drop_last_response(msgs: list) -> list:
    """Drop the trailing assistant+tool pair (or just the trailing
    assistant if the conversation ended on one).

    Also drop any preceding tool message that pairs with the dropped
    assistant — otherwise the API can complain about an orphan
    tool_call_id.
    """
    if len(msgs) <= 1:
        return msgs
    # Walk backwards: drop trailing tool messages, then the assistant
    # message that emitted those tool_calls. Keep at least the system.
    out = list(msgs)
    # Pop trailing tool messages
    while len(out) > 1 and isinstance(out[-1], ToolMessage):
        out.pop()
    # Pop the trailing assistant
    if len(out) > 1 and isinstance(out[-1], AIMessage):
        out.pop()
    return out


def variant_neutral_system(msgs: list) -> list:
    """Replace the system prompt with a minimal neutral one."""
    if not msgs:
        return msgs
    out = list(msgs)
    if isinstance(out[0], SystemMessage):
        out[0] = SystemMessage(content=NEUTRAL_SYSTEM)
    else:
        out.insert(0, SystemMessage(content=NEUTRAL_SYSTEM))
    return out


def variant_neutral_system_and_drop_last(msgs: list) -> list:
    return variant_drop_last_response(variant_neutral_system(msgs))


VARIANTS = {
    "plain": lambda m: m,
    "drop_last_response": variant_drop_last_response,
    "neutral_system": variant_neutral_system,
    "neutral_system_and_drop_last": variant_neutral_system_and_drop_last,
}


@dataclass
class Outcome:
    variant: str
    attempt: int
    status: str  # "accepted" | "refused" | "error"
    error_type: str | None = None
    error_msg: str | None = None
    duration_s: float = 0.0
    response_chars: int | None = None


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
        response = await llm.ainvoke(msgs)
        content = (
            response.content if isinstance(response.content, str)
            else str(response.content)
        )
        return Outcome(
            variant=variant,
            attempt=attempt,
            status="accepted",
            duration_s=round(time.time() - t0, 2),
            response_chars=len(content),
        )
    except CodexCyberPolicyError as e:
        return Outcome(
            variant=variant,
            attempt=attempt,
            status="refused",
            error_type="CodexCyberPolicyError",
            error_msg=str(e)[:200],
            duration_s=round(time.time() - t0, 2),
        )
    except CodexInvalidPromptError as e:
        return Outcome(
            variant=variant,
            attempt=attempt,
            status="refused",
            error_type="CodexInvalidPromptError",
            error_msg=str(e)[:200],
            duration_s=round(time.time() - t0, 2),
        )
    except CodexStreamError as e:
        return Outcome(
            variant=variant,
            attempt=attempt,
            status="error",
            error_type=type(e).__name__,
            error_msg=str(e)[:200],
            duration_s=round(time.time() - t0, 2),
        )
    except Exception as e:  # noqa: BLE001
        return Outcome(
            variant=variant,
            attempt=attempt,
            status="error",
            error_type=type(e).__name__,
            error_msg=str(e)[:200],
            duration_s=round(time.time() - t0, 2),
        )


async def run_case(
    llm,
    case_path: Path,
    *,
    plain_attempts: int,
    enable_variants: bool,
    inter_call_delay_s: float,
) -> CaseResult:
    req = json.loads(case_path.read_text())
    msgs = reconstruct_messages(req)
    # Strip trailing tool-only conversations are fine — the LLM just
    # generates the next assistant turn.

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

    # Always run plain N times first
    for i in range(plain_attempts):
        out = await run_one(llm, msgs, "plain", i + 1)
        res.outcomes.append(out)
        print(
            f"  plain#{i + 1:<2}  {out.status:<10}  "
            f"{(out.error_type or '-'):<25}  {out.duration_s:>6.2f}s",
            flush=True,
        )
        await asyncio.sleep(inter_call_delay_s)

    # Always run all variants — non-determinism in plain runs makes
    # variant data valuable even when one plain attempt passed.
    if enable_variants:
        for variant_name, transform in VARIANTS.items():
            if variant_name == "plain":
                continue
            transformed = transform(msgs)
            out = await run_one(llm, transformed, variant_name, 1)
            res.outcomes.append(out)
            print(
                f"  {variant_name:<32}  {out.status:<10}  "
                f"{(out.error_type or '-'):<25}  {out.duration_s:>6.2f}s",
                flush=True,
            )
            await asyncio.sleep(inter_call_delay_s)

    return res


def write_summary(results: list[CaseResult], out_dir: Path) -> None:
    # JSON dump
    json_out = out_dir / "_replay_results.json"
    json_out.write_text(json.dumps([asdict(r) for r in results], indent=2))

    # Markdown summary
    md = ["# Refusal Replay Results", ""]
    md.append("| agent_id | msgs | tokens | plain × N | drop_last | neutral_sys | neutral+drop |")
    md.append("|---|---|---|---|---|---|---|")
    for r in results:
        plain = [o for o in r.outcomes if o.variant == "plain"]
        plain_summary = "".join(
            "✅" if o.status == "accepted"
            else "❌" if o.status == "refused"
            else "⚠️"
            for o in plain
        )

        def variant_cell(name: str) -> str:
            outs = [o for o in r.outcomes if o.variant == name]
            if not outs:
                return "—"
            o = outs[0]
            return (
                "✅" if o.status == "accepted"
                else "❌" if o.status == "refused"
                else f"⚠️{o.error_type}"
            )

        md.append(
            f"| `{r.agent_id}` | {r.n_messages} | {r.est_tokens} | "
            f"{plain_summary} | {variant_cell('drop_last_response')} | "
            f"{variant_cell('neutral_system')} | "
            f"{variant_cell('neutral_system_and_drop_last')} |"
        )
    md.append("")
    md.append("Legend: ✅ accepted, ❌ refused (cyber_policy), ⚠️ other error.")
    (out_dir / "_replay_summary.md").write_text("\n".join(md))
    print(f"\nWrote summary to:\n  {json_out}\n  {out_dir / '_replay_summary.md'}")


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rejected_dir", type=Path)
    ap.add_argument("--model", default="gpt-5.5",
                    help="Codex model slug (default: gpt-5.5)")
    ap.add_argument("--plain-attempts", type=int, default=2)
    ap.add_argument("--no-variants", action="store_true")
    ap.add_argument("--include-summary", action="store_true",
                    help="Include the per-worker summarizer refusals too")
    ap.add_argument("--filter", default=None,
                    help="Only run cases whose filename contains this substring")
    ap.add_argument("--inter-call-delay-s", type=float, default=1.5)
    args = ap.parse_args()

    case_files = sorted([
        f for f in args.rejected_dir.glob("*.json")
        if f.name != "_index.json"
        and not f.name.startswith("_")
    ])
    if not args.include_summary:
        case_files = [f for f in case_files if "__summary__" not in f.name]
    if args.filter:
        case_files = [f for f in case_files if args.filter in f.name]

    if not case_files:
        print("No matching cases found", file=sys.stderr)
        return 2

    print(f"Will replay {len(case_files)} cases against model={args.model}")
    print(f"  plain attempts per case: {args.plain_attempts}")
    print(f"  variants enabled: {not args.no_variants}")
    print()

    cfg = LLMConfig(provider=Provider.CODEX, model=args.model)
    llm = get_llm(cfg)

    results: list[CaseResult] = []
    try:
        for case in case_files:
            r = await run_case(
                llm,
                case,
                plain_attempts=args.plain_attempts,
                enable_variants=not args.no_variants,
                inter_call_delay_s=args.inter_call_delay_s,
            )
            results.append(r)
            # Persist incrementally so we don't lose data on crash
            write_summary(results, args.rejected_dir)
    finally:
        write_summary(results, args.rejected_dir)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
