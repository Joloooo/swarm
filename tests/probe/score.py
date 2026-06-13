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


def score_node_once(result: dict, criterion: dict) -> bool:
    """True if one Level-2 node RESULT dict matches ``criterion`` (after negate).

      {kind: node_action, equals: <action>}   result["next_action"]
      {kind: findings_min, min: <int>}         len(result["findings"]) >= min
      {kind: captured_flag}                     a flag was captured by the node
    """
    result = result or {}
    kind = criterion.get("kind")
    if kind == "node_action":
        ok = result.get("next_action") == criterion.get("equals")
    elif kind == "findings_min":
        ok = len(result.get("findings") or []) >= int(criterion.get("min", 1))
    elif kind == "agent_results_min":
        # "the executor actually engaged the live target" — robust mechanism
        # signal independent of whether a vuln was found.
        ok = len(result.get("agent_results") or []) >= int(criterion.get("min", 1))
    elif kind == "captured_flag":
        ok = bool(result.get("captured_flag")) or bool(result.get("flag_found"))
    else:
        raise ValueError(f"unknown node criterion kind {kind!r}")
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


def aggregate(results: list, criterion: dict, threshold: int, *, scorer=score_once) -> Aggregate:
    """Score N replays against ``criterion`` and tally — N-sampling is mandatory
    (temperature/reasoning variance means one run is a coin flip; SKILL §5).

    ``scorer`` is :func:`score_once` for Level-1 ``ReplayResult``s and
    :func:`score_node_once` for Level-2 node result dicts."""
    hits = [scorer(r, criterion) for r in results]
    return Aggregate(passes=sum(hits), n=len(hits), threshold=threshold)
