"""Tier 1 — Planner decision-block parser tests.

The planner's only output contract is a fenced JSON block with an
``action`` field. ``_parse_decision`` extracts it from the LLM's final
text — and when this regex regresses, every planner turn forces report
because the decision is unparseable. That looks like "the model went
silent" in logs but it's actually a parser bug. These tests pin the
expected behaviour.
"""

from __future__ import annotations

from src.nodes.planner import VALID_ACTIONS, _parse_decision


# ── Happy paths ──────────────────────────────────────────────────────


def test_fenced_json_block_parses():
    text = """\
Here is my reasoning. The recon output shows a login form.

```json
{"action": "attack", "configs": ["sqli"], "target_url": "http://x",
 "reasoning": "login form likely backed by SQL"}
```
"""
    decision = _parse_decision(text)
    assert decision is not None
    assert decision["action"] == "attack"
    assert decision["configs"] == ["sqli"]


def test_unfenced_bare_object_parses():
    """Falls back to a bare object containing 'action' when no fence."""
    text = (
        "I think we should run recon first.\n"
        '{"action": "recon", "target_url": "http://x", "reasoning": "cold start"}'
    )
    decision = _parse_decision(text)
    assert decision is not None
    assert decision["action"] == "recon"


def test_fence_without_json_language_tag():
    text = """\
```
{"action": "report", "reasoning": "enough evidence"}
```
"""
    decision = _parse_decision(text)
    assert decision is not None
    assert decision["action"] == "report"


# ── Negative paths ──────────────────────────────────────────────────


def test_empty_text_returns_none():
    assert _parse_decision("") is None
    assert _parse_decision(None) is None  # type: ignore[arg-type]


def test_no_json_block_returns_none():
    assert _parse_decision("Just prose, no JSON.") is None


def test_invalid_json_inside_fence_returns_none():
    text = """\
```json
{"action": "attack", malformed json here}
```
"""
    assert _parse_decision(text) is None


def test_unknown_action_value_is_rejected():
    """Unknown actions must NOT be returned — the planner has a closed
    set (attack/recon/web_search/report). Anything else is a hallucination
    and forcing report is safer than acting on it."""
    text = '```json\n{"action": "explode", "reasoning": "?"}\n```'
    assert _parse_decision(text) is None


def test_first_valid_block_wins_when_multiple():
    """If the model emits two blocks, the first one drives the run.

    This pins current behaviour. The regex iterates in source order and
    returns the first match whose action is valid; later blocks are
    ignored. If we ever change this, we must update this test
    deliberately, not by accident.
    """
    text = """\
```json
{"action": "recon", "reasoning": "first"}
```
```json
{"action": "attack", "configs": ["sqli"], "reasoning": "second"}
```
"""
    decision = _parse_decision(text)
    assert decision is not None
    assert decision["action"] == "recon"


def test_first_block_invalid_second_block_valid_falls_through():
    """Invalid first block, valid second — the parser skips and uses
    the valid one. This protects against the model producing a stray
    JSON example earlier in its prose."""
    text = """\
```json
{"action": "explode", "reasoning": "decoy"}
```

Final decision:

```json
{"action": "report", "reasoning": "real"}
```
"""
    decision = _parse_decision(text)
    assert decision is not None
    assert decision["action"] == "report"


# ── Contract sanity ──────────────────────────────────────────────────


def test_valid_actions_set_is_what_the_planner_documents():
    """The planner's prompt promises exactly these four actions. If
    we add a new one (e.g. 'pause'), this test reminds us to update
    the prompt and the parser together."""
    assert VALID_ACTIONS == {"attack", "recon", "web_search", "report"}
