"""Tier 1 — base-prompt content guard.

Pins the 2026-06-09 "defense is positive evidence" fix (see
``tests/FAILURES.md``). The base executor prompt's ``DEMONSTRATED_STANDARD``
must keep the rule that a class-specific filter on a canonical probe is
positive evidence the class is present (record SUSPECTED, find the bypass) —
a future prompt edit must not silently drop it, since its absence is exactly
the XBEN-063 dismissal failure mode.

Pure string assertions — no LLM, no network.
"""

from __future__ import annotations

from src.nodes.base.system_prompt import DEMONSTRATED_STANDARD


def test_demonstrated_standard_has_class_specific_filter_rule() -> None:
    text = DEMONSTRATED_STANDARD.lower()
    # the core principle: a class-specific filter is positive evidence
    assert "class-specific filter is positive evidence" in text
    # it must steer to a SUSPECTED finding + bypass, not "safe"
    assert "suspected" in text
    assert "bypass" in text
