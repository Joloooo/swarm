"""CLI for the agentic-testing harness.

    uv run python -m tests.probe run <fixture> [-n N] [--baseline-only]

Level-1 replay of one fixture: reconstruct the captured input, bind the node's
real tools from src/, replay the baseline N times through the REAL model, score
with the real parser, and — if the fixture declares a crude perturbation — replay
the candidate and report the movement. Real model calls; needs provider auth
(e.g. ~/.codex/auth.json). Level-2 fixtures are run via ``tests.probe.level2``.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .capture import reconstruct_messages
from .level2 import build_initial_state, run_executor_node, run_node_n
from .loader import load_captured_event, load_fixture
from .perturb import crude_splice
from .replay import replay_n, resolve_tools
from .report import render
from .score import aggregate, score_node_once


async def _run(args) -> int:
    fx = load_fixture(args.fixture)
    if fx.level != 1:
        print(
            f"fixture {fx.id} is level {fx.level}; use the Level-2 runner "
            "(tests.probe.level2), not the CLI run path.",
            file=sys.stderr,
        )
        return 2

    event = load_captured_event(fx)
    messages = reconstruct_messages(event)
    tools = resolve_tools(fx.capture.tools)
    n = args.n or (fx.evaluation.n if fx.evaluation else 3)
    criterion = fx.evaluation.criterion
    threshold = fx.evaluation.pass_threshold

    print(f"replaying baseline ×{n} …", file=sys.stderr)
    baseline = aggregate(await replay_n(messages, tools=tools, n=n), criterion, threshold)

    candidate = None
    crude = False
    pert = next((p for p in fx.perturbations if p.mode == "crude"), None)
    if pert and not args.baseline_only:
        crude = True
        print(f"replaying candidate (crude: {pert.name}) ×{n} …", file=sys.stderr)
        cmsgs = crude_splice(messages, pert.splice.get("find", ""), pert.splice.get("replace", ""))
        candidate = aggregate(await replay_n(cmsgs, tools=tools, n=n), criterion, threshold)

    print(render(fx, baseline, candidate, capture_mode=fx.capture.mode, crude=crude))
    return 0


async def _run_node(args) -> int:
    """Level-2 whole-node replay (planner/summarizer offline; executor live target)."""
    fx = load_fixture(args.fixture)
    if fx.level != 2:
        print(f"fixture {fx.id} is level {fx.level}; use 'run' for Level-1.", file=sys.stderr)
        return 2
    n = args.n or (fx.evaluation.n if fx.evaluation else 3)

    if fx.node == "executor":
        print(
            f"provisioning {fx.benchmark_id} + running executor '{fx.config_name}' "
            f"×{n} against the LIVE target …",
            file=sys.stderr,
        )
        results = await run_executor_node(fx, n=n)
    else:
        print(f"running {fx.node} node ×{n} …", file=sys.stderr)
        results = await run_node_n(fx.node, build_initial_state(fx), n=n)

    agg = aggregate(results, fx.evaluation.criterion, fx.evaluation.pass_threshold, scorer=score_node_once)
    print(render(fx, agg, capture_mode="state"))
    for i, r in enumerate(results):
        print(
            f"  sample {i}: next_action={r.get('next_action')} "
            f"findings={len(r.get('findings') or [])} "
            f"agent_results={len(r.get('agent_results') or [])} "
            f"captured_flag={bool(r.get('captured_flag'))}",
            file=sys.stderr,
        )
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tests.probe")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="Level-1 single-call replay of one fixture")
    r.add_argument("fixture", help="fixture id/filename (resolved under fixtures/) or a path")
    r.add_argument("-n", type=int, default=0, help="samples (default: fixture.n)")
    r.add_argument("--baseline-only", action="store_true", help="skip the candidate perturbation")

    rn = sub.add_parser("run-node", help="Level-2 whole-node replay (executor provisions a live target)")
    rn.add_argument("fixture", help="fixture id/filename (resolved under fixtures/) or a path")
    rn.add_argument("-n", type=int, default=0, help="samples (default: fixture.n)")

    args = ap.parse_args(argv)
    if args.cmd == "run":
        return asyncio.run(_run(args))
    if args.cmd == "run-node":
        return asyncio.run(_run_node(args))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
