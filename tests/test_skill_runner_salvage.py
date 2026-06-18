"""Tier 1 — refusal-path primitive salvage tests.

Pins the 2026-06-09 fix (see ``tests/FAILURES.md``): a worker that PROVES a
non-flag primitive (a SQL extraction, ``id`` output, an ``/etc/passwd`` read)
and is then refused by the Codex safety classifier on its next call used to
lose that proof entirely — the refusal branch salvaged a ``flag{...}`` only.
``_salvage_primitive_from_trace`` now mints a HIGH primitive ``Finding`` from
the refused worker's RECEIVED tool output, guarded two ways:

  * received-not-sent — only ``ToolMessage`` content is scanned, so a marker
    the worker merely TYPED into its own command cannot self-trigger.
  * negation guard — a marker preceded (within 32 chars) by "no/not/without/
    never" is skipped, so "no group_concat output" does not mint a finding.

All pure functions — no LLM, no network.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, ToolMessage

from src.nodes.base.worker.salvage import (
    _refusal_marker_is_real,
    _salvage_primitive_from_trace,
)
from src.state import Finding, Severity


def test_received_sql_extraction_salvages_sqli_primitive() -> None:
    # The extraction token appears in the RESPONSE (ToolMessage); the
    # worker's own command also mentions group_concat but that is ignored.
    msgs = [
        AIMessage(content="curl '...?id=1 UNION SELECT group_concat(user) ...'"),
        ToolMessage(
            content="HTTP/1.1 200 OK\n\nadmin:5f4dcc3b, information_schema.tables",
            tool_call_id="t1",
        ),
    ]
    f = _salvage_primitive_from_trace(msgs, "vulntype-sqli")
    assert isinstance(f, Finding)
    assert f.primitive == "sqli_read"
    assert f.category == "sqli"
    assert f.severity is Severity.HIGH
    assert f.agent_id == "vulntype-sqli"


def test_received_id_output_salvages_rce_primitive() -> None:
    msgs = [
        ToolMessage(
            content="$ id\nuid=33(www-data) gid=33(www-data) groups=33(www-data)",
            tool_call_id="t1",
        ),
    ]
    f = _salvage_primitive_from_trace(msgs, "x")
    assert f is not None
    assert f.primitive == "rce"
    assert f.category == "rce"


def test_received_passwd_salvages_file_read_primitive() -> None:
    msgs = [ToolMessage(content="root:x:0:0:root:/root:/bin/bash", tool_call_id="t1")]
    f = _salvage_primitive_from_trace(msgs, "x")
    assert f is not None
    assert f.primitive == "file_read"


def test_marker_only_in_worker_command_does_not_salvage() -> None:
    # received-not-sent: the extraction token appears ONLY in the worker's own
    # AIMessage command; the server response (ToolMessage) was a 403 block.
    msgs = [
        AIMessage(
            content="trying ' UNION SELECT group_concat(table_name) "
            "FROM information_schema.tables -- "
        ),
        ToolMessage(content="HTTP/1.1 403 Forbidden\n\nblocked", tool_call_id="t1"),
    ]
    assert _salvage_primitive_from_trace(msgs, "x") is None


def test_negated_marker_does_not_salvage() -> None:
    msgs = [
        ToolMessage(
            content="query ran but no group_concat output, zero rows returned",
            tool_call_id="t1",
        ),
    ]
    assert _salvage_primitive_from_trace(msgs, "x") is None


def test_benign_output_does_not_salvage() -> None:
    msgs = [ToolMessage(content="HTTP/1.1 200 OK\n\nhello world", tool_call_id="t1")]
    assert _salvage_primitive_from_trace(msgs, "x") is None


def test_empty_trace_does_not_salvage() -> None:
    assert _salvage_primitive_from_trace([], "x") is None


def test_marker_is_real_negation_helper() -> None:
    # a bare occurrence is real; a negated one within 32 chars is not
    assert _refusal_marker_is_real("rows: group_concat(x)=abc", "group_concat") is True
    assert (
        _refusal_marker_is_real("there was no group_concat here", "group_concat")
        is False
    )
    # negation far away (>32 chars) does not suppress a later clean occurrence
    far = "no results at first " + "." * 40 + " then group_concat(x)=abc"
    assert _refusal_marker_is_real(far, "group_concat") is True
