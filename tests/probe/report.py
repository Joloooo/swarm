"""Baseline-vs-candidate report + the mandatory honest-limits block.

The report shows the two N-sampling tallies and whether the criterion match-rate
MOVED between them — neutral language, because valence comes from the fixture's
``desired_direction`` (the criterion may encode either the observed decision, for
a baseline-reproduction check, or the desired one, for a steer test).
"""

from __future__ import annotations

from .loader import Fixture
from .score import Aggregate

_LIMITS = """\
Honest limits (state these with every single-decision result):
- A single-decision win may not survive the full loop — Level 1 is a LOCAL what-if.
- Temperature/reasoning nondeterminism is real; N-sampling is mandatory, not optional.
- Counterfactual drift: the captured downstream context was generated under the OLD input.
- This measures decision quality AT A POINT — necessary, not sufficient, for end-to-end."""


def render(
    fixture: Fixture,
    baseline: Aggregate,
    candidate: Aggregate | None = None,
    *,
    capture_mode: str = "messages",
    crude: bool = False,
) -> str:
    """Render a human-readable report for one agentic test."""
    lines = [
        f"# agentic-test: {fixture.id}",
        f"node={fixture.node}  agent_id={fixture.agent_id or '-'}  level={fixture.level}",
        "",
        f"observed:  {fixture.observed_decision}",
        f"desired:   {fixture.desired_direction.strip()}",
        f"criterion: {fixture.evaluation.criterion if fixture.evaluation else '{}'}",
        "",
        f"baseline:  {baseline}",
    ]
    if candidate is not None:
        lines += [
            f"candidate: {candidate}",
            "",
            f"movement:  {_movement(baseline, candidate)}",
        ]
    lines.append("")
    if capture_mode == "messages":
        lines += [
            "⚠ messages-mode capture: input is verbatim; tools are bound from src/ by",
            "  name and the model id + reasoning come from the live LLMConfig.",
        ]
    if crude:
        lines.append(
            "⚠ CRUDE text-splice perturbation — THROWAWAY, never a kept result (SKILL §3)."
        )
    lines += ["", _LIMITS]
    return "\n".join(lines)


def _movement(b: Aggregate, c: Aggregate) -> str:
    if b.passes == c.passes:
        return f"no change at this decision ({b.passes}/{b.n} → {c.passes}/{c.n} match the criterion)"
    direction = "more" if c.passes > b.passes else "fewer"
    return (
        f"decision MOVED: {b.passes}/{b.n} → {c.passes}/{c.n} matches "
        f"({direction} under the candidate). Read valence from 'desired' above."
    )
