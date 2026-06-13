from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage

from src.nodes import summarizer as summarizer_module
from src.nodes.summarizer import SummarizerNode


@pytest.mark.asyncio
async def test_summarizer_reuses_worker_exit_precomputed_report(monkeypatch):
    async def fail_digest(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("late summarizer digest should not run")

    monkeypatch.setattr(
        summarizer_module,
        "summarize_worker_trace",
        fail_digest,
    )

    node = SummarizerNode(name="summarizer")
    report = AIMessage(
        content="## Status\nsuccess\n\n## Cross-skill handoffs\n[]",
        additional_kwargs={
            "agent_id": "executor-0",
            "kind": "worker_report",
            "config_name": "sqli",
        },
    )

    out = await node._summarize_one(
        inp={
            "agent_id": "executor-0",
            "config_name": "sqli",
            "precomputed_report": report,
            "findings_count": 0,
            "iteration_count": 3,
        },
        model=object(),
        run_id="test-run",
        target_url_default="http://target",
        all_findings=[],
    )

    assert out.content == report.content
    assert out.additional_kwargs["agent_id"] == "executor-0"
    assert out.additional_kwargs["kind"] == "worker_report"
    assert out.additional_kwargs["used_precomputed_report"] is True
