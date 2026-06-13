"""Offline smoke tests for the harness mechanics — no LLM, no network, no Docker.

Exercises the parts that must be right BEFORE any real replay: the fixture loads,
the captured input reconstructs to the exact verbatim messages, the node's real
tools resolve from src/, the crude splice rewrites only what it should, and the
scorer reuses the real planner parser. The actual model replay is live-only (a
fake model is forbidden here — SKILL §3), so it is not part of this suite.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, SystemMessage, ToolMessage

from tests.probe.capture import reconstruct_messages
from tests.probe.loader import load_captured_event, load_fixture
from tests.probe.perturb import crude_splice
from tests.probe.replay import ReplayResult, resolve_tools
from tests.probe.score import aggregate, score_once

FIXTURE = "063-planner-recon-dispatch.yaml"


def test_fixture_loads():
    fx = load_fixture(FIXTURE)
    assert fx.node == "planner"
    assert fx.level == 1
    assert fx.capture.mode == "messages"
    assert fx.capture.tools == ["normalize_url", "validate_website"]
    assert fx.evaluation.criterion == {"kind": "planner_action", "equals": "recon"}
    assert fx.evaluation.n == 3 and fx.evaluation.pass_threshold == 2


def test_capture_reconstructs_verbatim_messages():
    fx = load_fixture(FIXTURE)
    msgs = reconstruct_messages(load_captured_event(fx))
    assert len(msgs) == 6
    assert isinstance(msgs[0], SystemMessage)
    # the assistant tool-call turn and its tool result must round-trip exactly
    assert isinstance(msgs[4], AIMessage)
    assert msgs[4].tool_calls and msgs[4].tool_calls[0]["name"] == "normalize_url"
    assert isinstance(msgs[5], ToolMessage)
    assert msgs[5].tool_call_id == "call_xrsEufpoozeHEpHfYUzRPsYB"


def test_tools_resolve_to_real_src_objects():
    fx = load_fixture(FIXTURE)
    tools = resolve_tools(fx.capture.tools)
    assert [t.name for t in tools] == ["normalize_url", "validate_website"]


def test_crude_splice_edits_only_the_match():
    fx = load_fixture(FIXTURE)
    msgs = reconstruct_messages(load_captured_event(fx))
    pert = fx.perturbations[0]
    spliced = crude_splice(msgs, pert.splice["find"], pert.splice["replace"])
    joined = " ".join(m.content for m in spliced if isinstance(m.content, str))
    assert "do NOT dispatch recon again" in joined
    # the system prompt (no match) is untouched
    assert spliced[0].content == msgs[0].content


def test_scorer_reuses_real_planner_parser():
    crit = {"kind": "planner_action", "equals": "recon"}
    recon = ReplayResult(text='{"action": "recon", "reasoning": "fresh target"}', tool_calls=[], raw=None)
    attack = ReplayResult(text='{"action": "attack", "configs": ["sqli"]}', tool_calls=[], raw=None)
    assert score_once(recon, crit) is True
    assert score_once(attack, crit) is False
    # negate flips it
    assert score_once(attack, {**crit, "negate": True}) is True


def test_aggregate_threshold():
    crit = {"kind": "regex", "pattern": "recon"}
    rs = [
        ReplayResult(text="recon", tool_calls=[], raw=None),
        ReplayResult(text="nope", tool_calls=[], raw=None),
        ReplayResult(text="recon", tool_calls=[], raw=None),
    ]
    agg = aggregate(rs, crit, threshold=2)
    assert agg.passes == 2 and agg.n == 3 and agg.passed
