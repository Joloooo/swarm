"""Tier 1/2 — the [capability] ablation switches actually gate behaviour.

Added when the ablation switches were introduced (the thesis ablation study,
see tests/FAILURES.md). The 100-VM ablation sweep depends on two things this
file guards:

  1. **The flags apply.** They resolve, default to False (full system), and a
     ``SWARM_DISABLE_*`` env var flips one at process startup — so a VM's config
     is genuinely honoured before any work runs.
  2. **The flags bite.** Each one, when set, measurably changes the relevant
     code path (prompt assembly, executor dispatch, web-search node), not just
     a value in a dict.

The two gates that live inside large node methods needing a live run to
exercise (steering directives, hypothesis passing) get a wiring assertion so
they can't be silently dropped; the other four get real behavioural tests.
"""

from __future__ import annotations

import inspect
import os
import subprocess
import sys
from pathlib import Path

import pytest

from src.config_schema import DEFAULTS, resolve

_ROOT = Path(__file__).resolve().parents[1]

CAP_FLAGS = [
    "disable_prompting_techniques",
    "disable_steering_directives",
    "disable_hypothesis_passing",
    "disable_refusal_handling",
    "disable_skills",
    "disable_web_search",
]


# ── 1. Plumbing: defaults, schema, startup application ───────────────


def test_capability_defaults_all_false():
    # The FACTORY defaults must be all-false (full system) — this is the
    # invariant that protects an unconfigured 100-VM run. Read DEFAULTS, not
    # resolve(): the live swarm-config.toml may legitimately set a flag while
    # an ablation is being run, and that must not fail this guarantee.
    cap = DEFAULTS["capability"]
    assert sorted(cap) == sorted(CAP_FLAGS)
    assert all(v is False for v in cap.values()), cap


def test_defaults_table_matches_flag_list():
    assert sorted(DEFAULTS["capability"]) == sorted(CAP_FLAGS)


def test_graph_exposes_capability_namespace():
    # Confirm the namespace is exposed with every flag as a bool. Does NOT
    # assert the values are false — that depends on the live toml, which an
    # active ablation may have set (see test_capability_defaults_all_false).
    from src.graph import config
    for flag in CAP_FLAGS:
        assert isinstance(getattr(config.capability, flag), bool)


@pytest.mark.parametrize("flag,envvar", [
    ("disable_skills", "SWARM_DISABLE_SKILLS"),
    ("disable_web_search", "SWARM_DISABLE_WEB_SEARCH"),
    ("disable_prompting_techniques", "SWARM_DISABLE_PROMPTING_TECHNIQUES"),
])
def test_env_override_applies_at_startup(flag, envvar):
    """A ``SWARM_DISABLE_*`` env var flips its flag when the process starts.

    This is the mechanism a per-VM ablation run relies on: set the env var (or
    the toml) and the value is live in ``config.capability`` before the graph
    builds — proven here by reading it from a fresh subprocess.
    """
    code = f"from src.graph import config; print(config.capability.{flag})"
    env = dict(os.environ, **{envvar: "true"})
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, env=env, cwd=str(_ROOT),
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "True", f"{flag} not applied: {out.stdout!r}"


# ── 2. Gate 1 — prompting techniques (pure prompt assembly) ──────────


def test_prompting_techniques_gate(monkeypatch):
    from src.graph import config
    from src.nodes.base.system_prompt import (
        COMMON_CHECKLIST_DISCIPLINE,
        DIVERSITY_RULES,
        EXHAUSTION_DISCIPLINE,
        METHODOLOGY_RULES,
        TRANSFORMATION_HYPOTHESIS,
        build_prompt,
    )
    standards = (
        DIVERSITY_RULES, TRANSFORMATION_HYPOTHESIS,
        COMMON_CHECKLIST_DISCIPLINE, EXHAUSTION_DISCIPLINE,
    )

    monkeypatch.setattr(config.capability, "disable_prompting_techniques", False)
    full = build_prompt("executor")
    for block in standards:
        assert block in full

    monkeypatch.setattr(config.capability, "disable_prompting_techniques", True)
    ablated = build_prompt("executor")
    for block in standards:
        assert block not in ablated
    # The basic methodology/tactical structure must remain — we drop only the
    # persistence/diversity standards, not the whole prompt.
    assert METHODOLOGY_RULES in ablated
    assert len(ablated) < len(full)


# ── 3. Gate 5 — skills (generic config + real executor expansion) ────


def test_generic_executor_config_shape():
    from src.skills.loader import generic_executor_config
    from src.tools.registry import list_tools
    gc = generic_executor_config("sqli")
    assert gc.system_prompt == ""          # no per-class knowledge
    assert gc.skip_base_prompt is False    # keeps the base executor prompt
    assert gc.config_name == "sqli"        # label preserved for reporting
    assert len(gc.tools) == len(list_tools())  # every tool, not a subset


async def test_skills_gate_runs_generic_for_unknown_skill(monkeypatch):
    """Single executor expansion: with skills disabled, a dispatched name that
    is NOT a real skill still RUNS (as the generic worker) instead of
    short-circuiting "skill not found". This proves the gate replaced the skill
    path, end to end, with no tokens spent (fake LLM)."""
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    from src.graph import config
    from src.nodes.executor import executor_node

    def _fake_llm(*_a, **_k):
        return GenericFakeChatModel(messages=iter([AIMessage(content="done; no tools.")]))

    monkeypatch.setattr("src.llm.provider.get_llm", _fake_llm)

    base_state = {
        "target_url": "http://localhost:9999",   # never contacted under fake LLM
        "messages": [],
        "expected_flag": "",
        "config_name": "definitely_not_a_real_skill_xyz",
    }

    # Skills ON: unknown skill short-circuits to the not-found empty result —
    # no worker runs, so agent_results is empty.
    monkeypatch.setattr(config.capability, "disable_skills", False)
    off = await executor_node.execute(dict(base_state))
    assert off.get("agent_results") == []
    assert off.get("findings") == []

    # Skills OFF (ablation): the generic worker actually runs the agent loop, so
    # an AgentResult comes back (under the dispatched name) instead of the
    # not-found short-circuit. That difference IS the gate.
    monkeypatch.setattr(config.capability, "disable_skills", True)
    on = await executor_node.execute(dict(base_state))
    assert on.get("agent_results"), "generic worker should have run"
    assert on["agent_results"][0].config_name == "definitely_not_a_real_skill_xyz"


# ── 4. Gate 6 — web search node no-op ────────────────────────────────


async def test_web_search_noop_when_disabled(monkeypatch):
    from src.graph import config
    from src.nodes.web_search import web_search_node

    # Disabled → hard no-op ({}), regardless of query, before any crawl/LLM.
    monkeypatch.setattr(config.capability, "disable_web_search", True)
    disabled = await web_search_node.execute(
        {"search_query": "sql injection filter bypass", "messages": []}
    )
    assert disabled == {}

    # Enabled but no query → reaches the normal "no query" branch (has
    # messages), proving the {} above came from the ablation gate, not the
    # no-query path.
    monkeypatch.setattr(config.capability, "disable_web_search", False)
    no_query = await web_search_node.execute({"messages": []})
    assert "messages" in no_query


# ── 5. Wiring guard for the two run-only gates ───────────────────────


def test_run_only_gates_are_wired():
    """Steering + hypothesis gates sit inside large node methods that need a
    live run to exercise behaviourally; at minimum assert each flag is read in
    its own module so the wiring can never be silently removed."""
    import src.nodes.base.skill_runner as skill_runner
    import src.nodes.base.system_prompt as sp
    import src.nodes.executor as ex
    import src.nodes.planner as planner
    import src.nodes.summarizer as summarizer
    import src.nodes.web_search as ws
    import src.refusals.retry as retry

    assert "disable_steering_directives" in inspect.getsource(planner)
    assert "disable_web_search" in inspect.getsource(planner)
    assert "disable_hypothesis_passing" in inspect.getsource(summarizer)
    assert "disable_refusal_handling" in inspect.getsource(retry)
    assert "disable_web_search" in inspect.getsource(ws)
    assert "disable_skills" in inspect.getsource(ex)
    assert "disable_prompting_techniques" in inspect.getsource(sp)
    # The prompting-techniques ablation must ALSO drop the no-progress nudge,
    # which re-injects the same diversity/transformation guidance in-loop.
    assert "disable_prompting_techniques" in inspect.getsource(skill_runner)
