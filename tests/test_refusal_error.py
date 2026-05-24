"""Tier-1 unit tests for ``RefusalError``.

Pure-function tests, no LLM. Verify that the typed exception
raised by the refusal retry layer (``src/refusals/retry.py``)
carries its fields, summarises usefully, and is raisable like
any other exception.
"""

from __future__ import annotations

import pytest

from src.refusals import RefusalError


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
