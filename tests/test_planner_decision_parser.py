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
from src.observability.decision_parser import (
    _VALID_ACTIONS as PARSER_VALID_ACTIONS,
    parse_planner_decision,
)


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
    """The planner's prompt promises exactly these five actions. If we
    add a new one, this test reminds us to update the prompt and the
    parser together.

    ``submit_flag`` was added in 2026-05 as the explicit flag-submission
    protocol — the routing edge verifies it inline against
    ``state["expected_flag"]`` instead of the previous passive
    regex-scan of free-form messages.
    """
    assert VALID_ACTIONS == {
        "attack", "recon", "web_search", "report", "submit_flag",
    }


def test_parser_whitelist_matches_planner_vocabulary():
    """The strict-mode parser's whitelist (``decision_parser._VALID_ACTIONS``)
    MUST equal the planner's own vocabulary (``planner.VALID_ACTIONS``).

    These are two files that must agree but live in different layers:
    the planner defines the action vocabulary; the strict parser
    rejects any decision whose ``action`` field isn't in its own
    whitelist. When they fall out of sync, the planner can emit
    perfectly-valid JSON for an action it considers legal, and the
    parser silently rejects it — which surfaces as "no parseable JSON
    decision; forcing report" in the logs, looking like an LLM failure
    rather than a code bug.

    History: ``submit_flag`` was added to the planner's vocabulary in
    2026-05 but NOT to ``decision_parser._VALID_ACTIONS``. Every flag
    submission on every benchmark run silently force-reported instead
    of submitting. Discovered in
    ``run-XBEN-006-24__2026-05-25_14h33m29s`` after the
    summarizer-findings-attach fix surfaced the captured flag to the
    planner, which correctly tried to submit it.
    """
    assert PARSER_VALID_ACTIONS == VALID_ACTIONS, (
        f"Parser whitelist {PARSER_VALID_ACTIONS!r} disagrees with planner "
        f"vocabulary {VALID_ACTIONS!r}. Update "
        "src/observability/decision_parser.py:_VALID_ACTIONS to match."
    )


def test_submit_flag_decision_parses_end_to_end():
    """End-to-end: a realistic submit_flag JSON block (matching what
    the planner emits when it decides to submit a captured flag) must
    survive parse_planner_decision in strict mode and return a dict
    with the action and flag fields intact.

    This is the regression test for the 2026-05-25 incident — pin the
    full path the planner uses so a future whitelist drift fails
    loudly here instead of silently killing benchmark runs.
    """
    text = """\
The latest worker captured a flag-shaped value in /jobs response.

```json
{
  "action": "submit_flag",
  "flag": "flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}",
  "reasoning": "owasp-input-validation finding #4 contains the flag verbatim."
}
```
"""
    decision = parse_planner_decision(text, strict=True)
    assert decision is not None, "submit_flag JSON must parse in strict mode"
    assert decision["action"] == "submit_flag"
    assert decision["flag"] == "flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"


def test_submit_flag_with_extra_fields_still_parses():
    """The planner sometimes emits extra fields (mode, target_url,
    target_scope) alongside the required ones. The parser must not
    reject those — JSON-spec-valid extra fields are allowed.
    """
    text = """\
```json
{
  "action": "submit_flag",
  "flag": "flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}",
  "mode": "analyze",
  "target_url": "http://localhost:8000",
  "target_scope": "localhost",
  "reasoning": "Submitting the flag the worker extracted."
}
```
"""
    decision = parse_planner_decision(text, strict=True)
    assert decision is not None
    assert decision["action"] == "submit_flag"
    assert decision["flag"] == "flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"
