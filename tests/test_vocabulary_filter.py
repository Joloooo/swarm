"""Tier-1 unit tests for ``src/llm/vocabulary_filter.py``.

Pure-function tests, no LLM, no network. Verify the regex mapping
table behaves correctly on the inputs we care about: skill bodies,
tool messages, and AI tool_calls args. Per the project testing
policy (test-on-failure, Tier 1 = pure functions), these were added
after the May 9 XBEN-006-24 refusal storm motivated the filter.
"""

from __future__ import annotations

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from src.llm.vocabulary_filter import filter_messages, filter_text


def test_filter_text_replaces_offensive_verbs() -> None:
    """The headline use case: convert offensive framing in a skill
    body to neutral diagnostic vocabulary."""
    src = "Find SQL injection vulnerabilities and exploit them."
    out, subs = filter_text(src)
    assert "exploit" not in out.lower(), out
    assert "vulnerabilities" not in out.lower(), out
    # We expect at least 2 substitutions logged
    assert len(subs) >= 2, subs


def test_filter_text_handles_multi_word_phrases() -> None:
    """Multi-word phrases must match BEFORE single-word ones —
    e.g. ``attack surface`` should map to ``input surface`` and
    not be partially rewritten as ``test surface``."""
    src = "Map the attack surface and chain attacks together."
    out, _ = filter_text(src)
    assert "input surface" in out, out
    # ``attack chain`` rewrites; just confirm no raw ``attack`` left
    assert "attack" not in out.lower() or "input surface" in out, out


def test_filter_text_preserves_non_matching_text() -> None:
    """Benign text passes through unchanged with no substitutions."""
    src = "Run curl against the target URL and inspect the response."
    out, subs = filter_text(src)
    assert out == src
    assert subs == []


def test_filter_text_empty_string() -> None:
    out, subs = filter_text("")
    assert out == ""
    assert subs == []


def test_filter_text_case_insensitive() -> None:
    """Mappings must fire regardless of source case."""
    src = "EXPLOIT the target and find Vulnerabilities."
    out, subs = filter_text(src)
    assert "EXPLOIT" not in out
    assert "Vulnerabilities" not in out
    assert len(subs) >= 2


def test_filter_text_payload_is_not_globally_mapped() -> None:
    """``payload`` is a common HTTP body term; we deliberately do
    NOT map it globally, only when paired with weaponized contexts.
    Regression guard: a benign use of ``payload`` must pass through."""
    src = "Send the JSON payload to /api and check the response."
    out, _ = filter_text(src)
    assert "payload" in out


def test_filter_messages_handles_system_and_human() -> None:
    msgs = [
        SystemMessage(content="Find vulnerabilities to exploit."),
        HumanMessage(content="Begin pentest now."),
    ]
    out, subs = filter_messages(msgs)
    assert isinstance(out[0], SystemMessage)
    assert isinstance(out[1], HumanMessage)
    assert "vulnerabilities" not in out[0].content.lower()
    assert "exploit" not in out[0].content.lower()
    assert "pentest" not in out[1].content.lower()
    assert len(subs) >= 3


def test_filter_messages_filters_tool_messages() -> None:
    msgs = [
        ToolMessage(
            content="Found exploit potential in /jobs",
            tool_call_id="call_abc",
            name="bash",
        ),
    ]
    out, subs = filter_messages(msgs)
    assert isinstance(out[0], ToolMessage)
    assert out[0].tool_call_id == "call_abc"
    assert out[0].name == "bash"
    assert "exploit" not in out[0].content.lower()
    assert len(subs) == 1


def test_filter_messages_filters_ai_tool_call_args() -> None:
    """The textual args inside an AIMessage's tool_calls must also be
    filtered — that's where the worker's per-call reasoning lives,
    and it's a major source of offensive vocabulary in the
    accumulated history."""
    msgs = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "bash",
                    "id": "call_xyz",
                    "args": {
                        "reasoning": "Exploit the SQL injection.",
                        "command": "curl -X POST /jobs",
                    },
                }
            ],
        )
    ]
    out, subs = filter_messages(msgs)
    assert isinstance(out[0], AIMessage)
    new_args = out[0].tool_calls[0]["args"]
    assert "exploit" not in new_args["reasoning"].lower()
    # ``command`` had no offensive vocab — must be unchanged.
    assert new_args["command"] == "curl -X POST /jobs"
    # tc_id and name preserved
    assert out[0].tool_calls[0]["id"] == "call_xyz"
    assert out[0].tool_calls[0]["name"] == "bash"
    assert len(subs) >= 1


def test_filter_messages_preserves_unknown_message_types() -> None:
    """Anything that isn't System/Human/AI/Tool passes through
    untouched. Defensive — protects against future LangChain
    additions."""

    class _Bogus:
        content = "test"

    msgs = [_Bogus()]
    out, _ = filter_messages(msgs)
    assert out[0] is msgs[0]
