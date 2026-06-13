"""Deterministic scoring + N-sampling aggregation.

Where a real ``src/`` parser exists for the decision, the scorer REUSES it (the
planner directive parser, the worker verdict parser) so the harness reads output
exactly the way production does — import-only, drift-free. A criterion is a small
data dict from the fixture; supported kinds:

  {kind: planner_action, equals: <action>}   reuse src.nodes.planner._parse_decision
  {kind: regex, pattern: <re>, negate?: bool} regex over the output text
  {kind: tool_call, name: <tool>, negate?}    a tool with that name was called

Every criterion may set ``negate: true`` to flip the match (e.g. "did NOT refute").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .replay import ReplayResult


def score_once(result: ReplayResult, criterion: dict) -> bool:
    """True if one replay output matches ``criterion`` (after optional negate)."""
    kind = criterion.get("kind")
    if kind == "planner_action":
        from src.nodes.planner import _parse_decision  # real directive parser

        decision = _parse_decision(result.text)
        ok = bool(decision) and decision.get("action") == criterion.get("equals")
    elif kind == "regex":
        ok = bool(re.search(criterion["pattern"], result.text, re.I | re.S))
    elif kind == "tool_call":
        names = [tc.get("name") for tc in result.tool_calls]
        ok = criterion.get("name") in names
    else:
        raise ValueError(f"unknown criterion kind {kind!r}")
    return (not ok) if criterion.get("negate") else ok


@dataclass
class Aggregate:
    """The N-sampling tally for one replay set (baseline or candidate)."""

    passes: int
    n: int
    threshold: int

    @property
    def passed(self) -> bool:
        return self.passes >= self.threshold

    def __str__(self) -> str:
        verdict = "PASS" if self.passed else "fail"
        return f"{self.passes}/{self.n} match (threshold {self.threshold}) → {verdict}"


def aggregate(results: list[ReplayResult], criterion: dict, threshold: int) -> Aggregate:
    """Score N replays against ``criterion`` and tally — N-sampling is mandatory
    (temperature/reasoning variance means one run is a coin flip; SKILL §5)."""
    hits = [score_once(r, criterion) for r in results]
    return Aggregate(passes=sum(hits), n=len(hits), threshold=threshold)
