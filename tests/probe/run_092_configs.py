"""Ad-hoc Level-1 driver: replay the 092 planner attack-decision N times and
print the ACTUAL configs/custom_configs/tasks the real model returns each time.

Answers the question "given recon + the deser hypothesis in context, what skills
does the planner LLM pick on its own?" — using only src/ parsers + the harness
primitives (no drift). Run:

    uv run python -m tests.probe.run_092_configs [-n N]
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import json
import pathlib

from .capture import reconstruct_messages
from .loader import FIXTURES_DIR, load_captured_event, load_fixture
from .replay import replay_once, resolve_tools


def json_load(name: str) -> dict:
    p = pathlib.Path(name)
    if not p.is_absolute() and not p.exists():
        p = FIXTURES_DIR / name
    return json.loads(p.read_text())


def _summarize(text: str, tool_calls: list[dict]) -> str:
    from src.nodes.planner import _parse_decision

    if tool_calls:
        names = [tc.get("name") for tc in tool_calls]
        return f"TOOL_CALL {names} (no JSON decision this turn)"
    d = _parse_decision(text)
    if not d:
        return f"UNPARSEABLE (text {len(text)} chars; head: {text[:120]!r})"
    action = d.get("action")
    if action != "attack":
        return f"action={action} (no attack configs)"
    configs = d.get("configs") or []
    customs = [
        c.get("config_name") if isinstance(c, dict) else c
        for c in (d.get("custom_configs") or [])
    ]
    tasks = d.get("tasks") or []
    ntasks = len(tasks) if isinstance(tasks, list) else 0
    deser = any(
        "deser" in str(c).lower() or "phar" in str(c).lower()
        for c in list(configs) + list(customs)
    )
    return (
        f"action=attack configs={configs} custom={customs} ntasks={ntasks} "
        f"| deser_dispatched={deser}"
    )


async def _main(n: int, captured: str | None) -> int:
    fx = load_fixture("092-planner-deser-dispatch.yaml")
    event = (
        json_load(captured) if captured else load_captured_event(fx)
    )
    messages = reconstruct_messages(event)
    tools = resolve_tools(fx.capture.tools)

    print(f"replaying 092 planner attack-decision ×{n} (real model) …\n", file=sys.stderr)
    deser_hits = 0
    for i in range(n):
        r = await replay_once(messages, tools=tools)
        line = _summarize(r.text, r.tool_calls)
        if "deser_dispatched=True" in line:
            deser_hits += 1
        print(f"[sample {i + 1}/{n}] {line}")

    print(f"\n=== deserialization dispatched in {deser_hits}/{n} samples ===")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=5)
    ap.add_argument("--captured", default=None, help="override captured.json (e.g. a later wave)")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(_main(args.n, args.captured)))
