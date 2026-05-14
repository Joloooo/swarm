"""Tier 2 — Recon node integration with no live LLM.

Pins down that the recon node still loads and runs end-to-end after the
whatweb removal and the gobuster wordlist resolver rewrite. Specifically:

- The recon SKILL.md still parses and exposes the tools the planner expects.
- ``whatweb`` no longer appears anywhere in the assembled worker
  system prompt — that includes the SKILL.md body, the tool catalogue,
  the inherited base rules, and the methodology / focus headers.
- ``gobuster_dir`` survives and binds to the resolver that returns a
  real on-disk wordlist (the bundled smoke-test list when no SecLists
  is present).
- The whole node executes against a ``GenericFakeChatModel`` that emits
  a single non-tool-call response, exercising the full
  ``run_skill_agent`` path (system-prompt build, agent factory,
  ``create_agent`` loop, no-findings return) without spending a token.

This is the regression test that ensures the next time someone touches
the tool list, removing a tool can't quietly hand-wave through the
``recon`` worker — the prompt-build path will explicitly fail if a
referenced tool name doesn't resolve.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage

from src.nodes.base.system_prompt import _build_system_message
from src.nodes.recon import recon_node
from src.skills.loader import load_skill
from src.tools.registry import resolve_tool
from src.tools.web_recon import gobuster as gobuster_mod


# ── Skill / registry sanity ──────────────────────────────────────────


def test_recon_skill_loads_without_whatweb():
    """recon SKILL.md parses, its tools list excludes whatweb."""
    cfg = load_skill("recon")
    assert cfg is not None
    tool_names = [t.name for t in cfg.tools]
    assert "whatweb" not in tool_names, (
        f"recon tools must not include whatweb after deletion; got {tool_names}"
    )
    # The replacement set must still be there — `fetch_page` + `bash`
    # are what the agent uses for tech fingerprinting now.
    assert "fetch_page" in tool_names
    assert "bash" in tool_names
    assert "gobuster_dir" in tool_names
    assert "nikto_scan" in tool_names


def test_whatweb_not_in_registry():
    """The registry lookup must not resolve whatweb at all."""
    assert resolve_tool("whatweb") is None


# ── Assembled system prompt ──────────────────────────────────────────


def test_recon_system_prompt_has_no_whatweb_references():
    """The full assembled system prompt (what reaches the LLM) must be
    free of whatweb mentions — body, tool catalogue, and base rules.

    Catches the case where someone leaves a stray ``whatweb(url)`` line
    in the SKILL.md body even after removing the tool from the registry:
    the worker would emit a tool call the runtime can't route, wasting
    an LLM turn per attempt.
    """
    cfg = load_skill("recon")
    assert cfg is not None
    prompt = _build_system_message(
        cfg, target_url="http://localhost:8000",
        phase1_findings=None,
    )
    # Belt-and-braces: check the case-insensitive form too.
    lower = prompt.lower()
    assert "whatweb" not in lower, (
        "recon system prompt still references 'whatweb' somewhere — "
        "search the skills, knowledge prompts, and base rules"
    )


def test_recon_system_prompt_mentions_curl_replacement():
    """The replacement guidance (curl header probes) is in the prompt."""
    cfg = load_skill("recon")
    assert cfg is not None
    prompt = _build_system_message(
        cfg, target_url="http://localhost:8000",
        phase1_findings=None,
    )
    # The SKILL.md was rewritten to point at `curl -sI` + the homepage
    # HTML for fingerprinting. The exact phrasing can drift, but at
    # least one of these markers must survive.
    assert "curl -sI" in prompt or "X-Powered-By" in prompt


# ── Gobuster resolver actually works for `common` ────────────────────


def test_gobuster_common_resolves_after_changes():
    """The bundled wordlist is enough to satisfy `wordlist=\"common\"`."""
    path = gobuster_mod._resolve_wordlist("common")
    assert Path(path).is_file()


# ── Node execution against a fake LLM (no tokens spent) ──────────────


@pytest.mark.asyncio
async def test_recon_node_runs_without_collapsing(monkeypatch):
    """End-to-end: ReconNode.execute() with a stubbed LLM finishes cleanly.

    Uses ``GenericFakeChatModel`` — bound tools are ignored, the model
    just returns the canned AI message we hand it. The agent loop sees
    a final assistant message with no tool calls and exits in one step,
    which means we exercise:

      - load_skill("recon")  → AgentConfig
      - _build_system_message  → full prompt (whatweb-free, see above)
      - create_agent(...)      → real LangChain agent
      - astream_with_refusal_retry → at least one model call
      - finding parser         → produces zero findings (canned msg has none)
      - shell cleanup finally  → must not raise

    The test passes if execute() returns the standard worker update dict
    with ``recon_done=True`` set and no exception leaks. That alone proves
    the node is wired correctly after the whatweb removal and resolver
    rewrite.
    """
    canned = AIMessage(
        content=(
            "Recon complete (test stub). No tool calls issued. "
            "No findings emitted by this dry-run worker."
        )
    )
    fake = GenericFakeChatModel(messages=iter([canned]))

    # Swap the real provider for the fake exactly where the worker resolves it.
    monkeypatch.setattr(
        "src.llm.provider.get_llm",
        lambda *_, **__: fake,
    )

    state = {
        "target_url": "http://localhost:9999",  # never contacted under fake LLM
        "messages": [],
        "expected_flag": "",
    }

    result = await recon_node.execute(state)

    # Recon must claim done so the planner doesn't re-dispatch it.
    assert result.get("recon_done") is True

    # The standard worker return shape includes `messages` and either a
    # findings or agent_results key. Both may be empty for a no-op
    # response — we only assert the node didn't crash.
    assert "messages" in result or "agent_results" in result
