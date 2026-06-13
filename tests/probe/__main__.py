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
from .loader import load_captured_event, load_fixture
from .perturb import crude_splice
from .replay import replay_n, resolve_tools
from .report import render
from .score import aggregate


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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tests.probe")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Level-1 replay of one fixture")
    r.add_argument("fixture", help="fixture id/filename (resolved under fixtures/) or a path")
    r.add_argument("-n", type=int, default=0, help="samples (default: fixture.n)")
    r.add_argument("--baseline-only", action="store_true", help="skip the candidate perturbation")
    args = ap.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
