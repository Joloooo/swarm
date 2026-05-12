"""Tier-1 unit tests for the refusal-error type + the post-refactor counter.

Pure-function tests, no LLM. Verify that ``RefusalError`` is
serialisable and that ``count_refusals`` reads ``llm_error`` rows out
of the unified ``full_logs.jsonl`` artefact (the 2026-05 log
consolidation deleted the standalone ``refusals.jsonl`` and folded its
information into ``full_logs.jsonl`` as ``type="llm_error"`` rows).

The ``src.llm.refusal`` module is a back-compat shim that re-exports
``RefusalError`` + a no-op ``log_refusal`` and the new
``count_refusals`` reader; the imports here resolve through it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.llm.refusal import RefusalError, count_refusals, log_refusal


def test_refusal_error_construction_carries_fields() -> None:
    err = RefusalError(
        agent_id="vulntype-sqli",
        skill_name="sqli",
        iteration=7,
        request_size_chars=44_416,
        request_size_tokens=11_104,
        attempts_made=3,
        refusal_message="cyber_policy",
        last_tier="vocab_filter",
    )
    assert err.agent_id == "vulntype-sqli"
    assert err.iteration == 7
    assert err.attempts_made == 3
    assert err.last_tier == "vocab_filter"


def test_refusal_error_summary_includes_key_facts() -> None:
    err = RefusalError(
        agent_id="vulntype-sqli",
        skill_name="sqli",
        iteration=7,
        request_size_chars=44_416,
        request_size_tokens=11_104,
        attempts_made=3,
        refusal_message="cyber_policy",
    )
    msg = str(err)
    assert "vulntype-sqli" in msg
    assert "3" in msg  # attempts


def test_refusal_error_is_raisable() -> None:
    err = RefusalError(
        agent_id="x", skill_name="x", iteration=1,
        request_size_chars=0, request_size_tokens=0,
        attempts_made=1, refusal_message="x",
    )
    with pytest.raises(RefusalError):
        raise err


def test_log_refusal_is_a_noop() -> None:
    """The pre-refactor writer was deleted. ``log_refusal`` is now a
    no-op shim that exists only so older call sites compile. It must
    accept the same arguments and not raise.
    """
    err = RefusalError(
        agent_id="a1", skill_name="sqli", iteration=2,
        request_size_chars=1000, request_size_tokens=250,
        attempts_made=3, refusal_message="cyber_policy",
        last_tier="plain",
    )
    # All three call shapes that lived in the codebase.
    log_refusal(err)
    log_refusal(err, run_id=None)
    log_refusal(err, run_id="any-string")


def test_count_refusals_reads_llm_error_rows_from_full_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: write ``llm_error`` rows with a refusal-shaped message
    into a tmp run dir's ``full_logs.jsonl`` and verify
    ``count_refusals`` returns the correct count.
    """
    run_id = "x"
    rdir = tmp_path / "logs" / f"run-{run_id}"
    rdir.mkdir(parents=True)

    def _fake_run_dir(rid: str) -> Path:
        d = tmp_path / "logs" / f"run-{rid}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # Both ``count_refusals`` and any future writer reach the same
    # path via the central ``run_dir`` resolver.
    monkeypatch.setattr(
        "src.observability.writers.run_dir", _fake_run_dir,
    )

    rows = [
        # A refusal-shaped llm_error — should count.
        {
            "ts": "2026-05-12T18:21:48",
            "type": "llm_error",
            "agent_id": "a1",
            "error_type": "CodexCyberPolicyError",
            "error_msg": "This content was flagged for possible cybersecurity risk.",
        },
        # Another refusal — different agent, also counts.
        {
            "ts": "2026-05-12T18:25:54",
            "type": "llm_error",
            "agent_id": "a2",
            "error_type": "CodexCyberPolicyError",
            "error_msg": "cyber_policy: request rejected",
        },
        # Network error — NOT a refusal, must not count.
        {
            "ts": "2026-05-12T18:30:00",
            "type": "llm_error",
            "agent_id": "a3",
            "error_type": "ReadTimeout",
            "error_msg": "Connection reset by peer.",
        },
        # Normal llm_end row — must not count.
        {
            "ts": "2026-05-12T18:30:01",
            "type": "llm_end",
            "agent_id": "a4",
        },
    ]

    full_logs = rdir / "full_logs.jsonl"
    with full_logs.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    assert count_refusals(run_id) == 2


def test_count_refusals_returns_zero_for_missing_run() -> None:
    assert count_refusals("does-not-exist-nope") == 0


def test_count_refusals_returns_zero_for_none_run_id() -> None:
    assert count_refusals(None) == 0
