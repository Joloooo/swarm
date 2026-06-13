from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage

from src.llm.codex import (
    ChatCodex,
    _resolve_prompt_cache_key,
    _write_cache_shape_log,
)


def test_build_request_kwargs_sets_retention_not_cache_key():
    # ``prompt_cache_key`` is resolved per-call in _generate/_agenerate (it
    # depends on run_id/agent_id from the run_manager), so _build_request_kwargs
    # must NOT emit it — only the instance-level controls.
    model = ChatCodex(
        model="gpt-5.5",
        reasoning_effort="medium",
        reasoning_summary="detailed",
        prompt_cache_retention="24h",
        prompt_cache_key="auto",
    )

    req = model._build_request_kwargs([
        SystemMessage(content="stable instructions"),
        HumanMessage(content="dynamic task"),
    ])

    assert req["prompt_cache_retention"] == "24h"
    assert "prompt_cache_key" not in req
    assert req["reasoning_effort"] == "medium"
    assert req["reasoning_summary"] == "detailed"


def test_resolve_prompt_cache_key_off_by_default():
    # Unset / empty / disable words => no key (the Codex backend ignores the
    # key for routing, so it is opt-in; see _resolve_prompt_cache_key docstring).
    assert _resolve_prompt_cache_key(None, "RUN", "recon") is None
    assert _resolve_prompt_cache_key("", "RUN", "recon") is None
    assert _resolve_prompt_cache_key("off", "RUN", "recon") is None
    assert _resolve_prompt_cache_key("false", "RUN", "recon") is None


def test_resolve_prompt_cache_key_worker_and_summary_share_key():
    # The summariser call (agent_id "<worker>__summary") must resolve to the
    # SAME key as the worker so it routes to the instance that primed the prefix.
    worker = _resolve_prompt_cache_key("auto", "RUN", "recon")
    summary = _resolve_prompt_cache_key("auto", "RUN", "recon__summary")
    assert worker is not None
    assert worker == summary
    assert worker.endswith(":recon")


def test_resolve_prompt_cache_key_isolates_sessions_and_honours_prefix():
    # Distinct run_ids never collide (two concurrent sessions, same agent).
    assert (
        _resolve_prompt_cache_key("auto", "RUN_A", "recon")
        != _resolve_prompt_cache_key("auto", "RUN_B", "recon")
    )
    # A non-enable literal becomes a namespace prefix (and still enables).
    assert _resolve_prompt_cache_key("acctX", "RUN", "recon").startswith("acctX:")
    # Enabled but no identity to key on -> None (don't pin unrelated calls).
    assert _resolve_prompt_cache_key("auto", None, "") is None


def test_codex_cache_shape_logging_records_terminal_and_jsonl(monkeypatch):
    events: list[tuple] = []
    terminal: list[str] = []

    monkeypatch.setattr(
        "src.observability.writers.append_event",
        lambda *args, **kwargs: events.append((args, kwargs)),
    )
    monkeypatch.setattr(
        "src.observability.writers.write_terminal_line",
        lambda line: terminal.append(line),
    )

    _write_cache_shape_log(
        {
            "run_id": "run-1",
            "agent_id": "executor-0__summary",
            "node": "summarizer",
            "lc_run_id": "lc-1",
        },
        {
            "model": "gpt-5.5",
            "input": [{"type": "message", "role": "user", "content": []}],
            "instructions": "stable instructions",
            "store": False,
            "stream": True,
            "include": ["reasoning.encrypted_content"],
            "reasoning": {"effort": "medium", "summary": "detailed"},
            "prompt_cache_retention": "24h",
            "tools": [{"type": "function", "name": "bash"}],
        },
    )

    assert events
    args, kwargs = events[0]
    assert args[:2] == ("run-1", "codex_request_shape")
    assert kwargs["agent_id"] == "executor-0__summary"
    assert kwargs["node"] == "summarizer"
    assert kwargs["cache_shape"]["prompt_cache_retention"] == "24h"
    assert kwargs["cache_shape"]["tools_count"] == 1
    assert terminal
    assert "[llm-cache-shape]" in terminal[0]
    assert "cache_retention=24h" in terminal[0]
    assert "tools=1:" in terminal[0]
