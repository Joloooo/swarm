"""Tier-1 unit tests for the refusal-error type and JSONL round-trip.

Pure-function tests, no LLM. Verify that ``RefusalError`` is
serialisable and that the writer + counter round-trip through the
JSONL on-disk format. The writer lives in
``src.observability.writers.append_refusal`` and the counter inlines
into ``src.observability.summary.header.count_refusals`` — the
``src.llm.refusal`` module is a transitional shim that re-exports
both, so the legacy import paths used here still resolve.
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


def test_log_refusal_writes_jsonl_and_count_works(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: log two refusals to a tmp run dir, then count
    them via the public API."""
    # Repoint the writer's path resolver at our tmp dir. ``run_dir`` is
    # the central helper that every JSONL writer (including the refusal
    # appender and the summary's ``count_refusals``) uses to resolve
    # ``logs/run-<id>/...`` — patching it once redirects both.
    repo_root = tmp_path
    (repo_root / "logs").mkdir()

    def _fake_run_dir(run_id: str) -> Path:
        d = repo_root / "logs" / f"run-{run_id}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    monkeypatch.setattr(
        "src.observability.writers.run_dir", _fake_run_dir,
    )

    err1 = RefusalError(
        agent_id="a1", skill_name="sqli", iteration=2,
        request_size_chars=1000, request_size_tokens=250,
        attempts_made=3, refusal_message="cyber_policy",
        last_tier="plain",
    )
    err2 = RefusalError(
        agent_id="a2", skill_name="idor", iteration=5,
        request_size_chars=2000, request_size_tokens=500,
        attempts_made=4, refusal_message="cyber_policy",
        last_tier="vocab_filter",
    )

    # Pre-create the directory; log_refusal mkdirs it but defensive.
    (repo_root / "logs" / "run-x").mkdir(parents=True)
    log_refusal(err1, run_id="x")
    log_refusal(err2, run_id="x")

    assert count_refusals("x") == 2

    # Verify the rows are JSON-decodable with the expected fields.
    path = repo_root / "logs" / "run-x" / "refusals.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert len(rows) == 2
    assert rows[0]["agent_id"] == "a1"
    assert rows[1]["agent_id"] == "a2"
    assert rows[1]["last_tier"] == "vocab_filter"


def test_log_refusal_silent_when_no_run_id() -> None:
    """Best-effort: if run_id is None or unresolvable, log_refusal
    must not raise."""
    err = RefusalError(
        agent_id="x", skill_name="x", iteration=0,
        request_size_chars=0, request_size_tokens=0,
        attempts_made=1, refusal_message="x",
    )
    log_refusal(err, run_id=None)  # should not raise


def test_count_refusals_returns_zero_for_missing_run() -> None:
    assert count_refusals("does-not-exist-nope") == 0
