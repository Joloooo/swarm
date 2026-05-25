"""Tier 2 — SummarizerNode attaches verbatim Findings to its worker_report.

Pins down the 2026-05-25 fix that routes structured ``Finding`` objects
into the planner's prompt without losing their verbatim ``evidence``
field.

Background — the failure this fix addresses
-------------------------------------------
On XBEN-006-24 (run ``run-XBEN-006-24__2026-05-25_13h01m56s``) the
``owasp-input-validation`` worker captured ``flag{582d82bb-...}`` via
SQL injection and correctly filed a structured ``**FINDING:**`` block
whose evidence field contained the literal flag string. The regex
parser in ``skill_runner._extract_findings`` correctly built a
``Finding`` dataclass and the reducer appended it to
``state["findings"]``. But the summariser's digest LLM compressed the
worker's "Server responses" section into prose ("private record was
returned") and dropped the flag bytes. The planner — which only reads
the summariser's digest, never ``state["findings"]`` — therefore
never saw a flag-shaped string and never called ``submit_flag``. The
run timed out at 900 s despite the agent having captured the flag at
t=412 s. See ``tests/FAILURES.md`` for the full incident.

What this test verifies
-----------------------
1. **Findings flow through.** When ``state["findings"]`` contains a
   ``Finding`` produced by the worker being summarised, the
   summariser's output ``AIMessage`` must contain a
   ``## Findings (verbatim from worker)`` section that includes the
   exact ``Finding.evidence`` string (including any captured flags).
2. **Empty case skipped.** When the worker produced zero findings,
   NO ``## Findings`` section is appended — wasteful and confusing
   to the planner.
3. **Agent-id scoping.** When multiple workers run in parallel and
   each produces its own findings, every worker_report contains ONLY
   its own findings, never another worker's.

Strategy
--------
- Build a realistic state dict with realistic ``Finding`` dataclass
  instances (constructed by hand, but identical in shape to what the
  regex parser produces from a worker's ``**FINDING:**`` markdown).
- Build a realistic ``pending_summary_inputs`` list with real
  ``BaseMessage`` traces (a couple of ToolMessages so the digest LLM
  has something concrete to compress).
- Swap the LLM provider for ``GenericFakeChatModel`` so we don't spend
  a token. The fake returns the kind of paraphrased prose that the real
  digest LLM produces — deliberately WITHOUT including the flag string
  in its summary, so the test fails if the verbatim-append path is
  broken.
- Run ``summarizer_node.execute(state)`` end-to-end and inspect the
  emitted ``AIMessage`` objects.
"""

from __future__ import annotations

import asyncio

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from src.state import Finding, Severity
from src.nodes import summarizer as summarizer_module
from src.nodes.summarizer import summarizer_node


# ── Test fixtures ───────────────────────────────────────────────────────


# The literal captured flag from the real XBEN-006-24 run on 2026-05-25.
# Hard-coded so a regression that mangles or drops the string is loud.
REAL_CAPTURED_FLAG = "flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"

# What a real worker's `**FINDING:**` block looked like for that capture,
# post-regex-parse. Built by hand to match the shape of what
# ``_findings_from_markdown`` produces.
CAPTURED_FLAG_FINDING = Finding(
    title="SQL injection in /jobs job_type bypasses private-job authorization",
    severity=Severity.HIGH,
    category="sqli",
    description="SQL injection in /jobs job_type bypasses private-job authorization",
    evidence=(
        "Baseline request with {\"job_type\":\"private\"} returns 403 and "
        "{\"detail\": \"Only admins can see private jobs\"}. "
        "Supplying {\"job_type\":\"private'--\"} returns 200 with the restricted row: "
        f"[{{\"id\":3,\"name\":\"Hidden job\",\"type\":\"private\","
        f"\"description\":\"{REAL_CAPTURED_FLAG}\"}}]"
    ),
    agent_id="owasp-input-validation",
    url="http://localhost:8000/jobs",
)


def _realistic_trace_with_flag_capture() -> list:
    """A pared-down version of what owasp-input-validation actually
    produced — one tool call probing the SQLi bypass, the tool output
    containing the flag in the JSON body, then an AIMessage with the
    **FINDING:** block. The digest LLM would receive exactly this kind
    of trace from the real run.
    """
    return [
        HumanMessage(content="Probe /jobs job_type for private-row bypass."),
        AIMessage(
            content="Trying the SQL comment trick to bypass the allowlist.",
            tool_calls=[{
                "id": "call_1",
                "name": "bash",
                "args": {"command": "curl -sS -X POST http://localhost:8000/jobs "
                                    "-H 'Content-Type: application/json' "
                                    "--data '{\"job_type\":\"private'\\''--\"}'"},
            }],
        ),
        ToolMessage(
            content=(
                "[{\"id\":3,\"name\":\"Hidden job\",\"type\":\"private\","
                f"\"description\":\"{REAL_CAPTURED_FLAG}\"}}]"
            ),
            tool_call_id="call_1",
        ),
        AIMessage(content=(
            "Confirmed: the comment trick bypasses the allowlist and returns "
            "the protected row.\n\n"
            "**FINDING:**\n"
            f"Title: {CAPTURED_FLAG_FINDING.title}\n"
            "Severity: HIGH\n"
            "Category: sqli\n"
            "URL: http://localhost:8000/jobs\n"
            f"Evidence: {CAPTURED_FLAG_FINDING.evidence}\n"
        )),
    ]


def _realistic_trace_no_findings() -> list:
    """A worker trace where no vulnerability was found — the agent
    tried a couple of probes, all returned 403, no **FINDING:** block
    was ever emitted.
    """
    return [
        HumanMessage(content="Probe /jobs job_type for header-based auth bypass."),
        AIMessage(
            content="Trying common admin headers.",
            tool_calls=[{
                "id": "call_a",
                "name": "bash",
                "args": {"command": "curl -X POST http://localhost:8000/jobs "
                                    "-H 'X-Admin: true' --data '{\"job_type\":\"private\"}'"},
            }],
        ),
        ToolMessage(content="{\"detail\": \"Only admins can see private jobs\"}", tool_call_id="call_a"),
        AIMessage(content="No bypass via admin headers — all returned 403. No findings to file."),
    ]


def _fake_digest_model(canned_responses: list[str]) -> GenericFakeChatModel:
    """A fake chat model that returns the given canned responses in
    order. We deliberately DO NOT include the captured flag in the
    canned responses — that's how the test proves the verbatim-append
    path is what surfaces the flag, not the digest LLM.
    """
    return GenericFakeChatModel(messages=iter([AIMessage(content=r) for r in canned_responses]))


@pytest.fixture(autouse=True)
def _patch_get_llm(monkeypatch):
    """Default fake — overridden in tests that need specific responses."""
    monkeypatch.setattr(
        "src.nodes.summarizer.get_llm",
        lambda: _fake_digest_model(["## Status\nsuccess\n## Server responses\nPrivate row returned via comment trick."]),
        raising=False,
    )
    # Also patch the lazy import inside execute()
    import src.llm.provider as provider_mod
    monkeypatch.setattr(
        provider_mod,
        "get_llm",
        lambda: _fake_digest_model([
            # One canned response per pending_summary_input in test order.
            # Used as a default; tests that need different prose patch again.
            "## Status\nsuccess\n## Server responses\nPrivate row was returned.",
            "## Status\ninconclusive\n## Server responses\nAll variants returned 403.",
            "## Status\nsuccess\n## Server responses\nAdditional probe done.",
        ]),
    )


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if asyncio.get_event_loop().is_running() is False else asyncio.run(coro)


# ── Tests ──────────────────────────────────────────────────────────────


def test_finding_with_captured_flag_is_attached_verbatim(monkeypatch):
    """The captured-flag case from XBEN-006-24 2026-05-25.

    Worker filed a HIGH finding whose evidence field contains the
    literal `flag{582d82bb-...}` string. The digest LLM is mocked to
    return prose that PARAPHRASES the response ("Private row returned
    via comment trick") and does NOT mention the flag — replicating
    what the real Codex digest did in production. The summariser
    output MUST contain the literal flag string regardless, because
    the verbatim-findings append path runs after the LLM.
    """
    # Patch the LLM to a response that deliberately omits the flag.
    import src.llm.provider as provider_mod
    monkeypatch.setattr(
        provider_mod,
        "get_llm",
        lambda: _fake_digest_model([
            "## Status\nsuccess\n\n"
            "## Server responses\nA private row was returned via the comment trick.\n\n"
            "## Inferred server-side behaviour\nAllowlist bypassable by '--."
        ]),
    )

    state = {
        "pending_summary_inputs": [
            {
                "agent_id": "owasp-input-validation",
                "config_name": "owasp-input-validation",
                "methodology": "owasp",
                "dispatch_reason": "Investigate /jobs for input-validation bypasses.",
                "target_url": "http://localhost:8000",
                "trace": _realistic_trace_with_flag_capture(),
                "findings_count": 1,
                "iteration_count": 4,
                "completed": True,
            }
        ],
        "findings": [CAPTURED_FLAG_FINDING],
        "run_id": "test-run-flag",
        "target_url": "http://localhost:8000",
    }

    result = asyncio.run(summarizer_node.execute(state))

    assert "messages" in result
    assert len(result["messages"]) == 1
    msg = result["messages"][0]
    assert isinstance(msg, AIMessage)

    content = msg.content
    # The LLM's prose must still be there.
    assert "A private row was returned via the comment trick." in content
    # The verbatim findings section MUST be appended.
    assert "## Findings (verbatim from worker)" in content
    # And it MUST contain the literal flag string the digest dropped.
    assert REAL_CAPTURED_FLAG in content, (
        f"Captured flag {REAL_CAPTURED_FLAG!r} missing from summariser output:\n{content}"
    )
    # Severity + title must also survive into the visible section.
    assert "[HIGH]" in content
    assert "SQL injection in /jobs job_type" in content


def test_empty_findings_does_not_append_section(monkeypatch):
    """If the worker filed zero findings, no `## Findings` section is
    appended — the digest stands alone. Wasting tokens on an empty
    section is exactly what the user asked to avoid.
    """
    import src.llm.provider as provider_mod
    monkeypatch.setattr(
        provider_mod,
        "get_llm",
        lambda: _fake_digest_model([
            "## Status\ninconclusive\n\n"
            "## Server responses\nAll variants returned 403.\n\n"
            "## Inferred server-side behaviour\nHeader-based bypass not effective."
        ]),
    )

    state = {
        "pending_summary_inputs": [
            {
                "agent_id": "owasp-auth",
                "config_name": "owasp-auth",
                "methodology": "owasp",
                "dispatch_reason": "Try header-based auth bypass on /jobs.",
                "target_url": "http://localhost:8000",
                "trace": _realistic_trace_no_findings(),
                "findings_count": 0,
                "iteration_count": 2,
                "completed": True,
            }
        ],
        # No findings in state at all.
        "findings": [],
        "run_id": "test-run-empty",
        "target_url": "http://localhost:8000",
    }

    result = asyncio.run(summarizer_node.execute(state))

    assert len(result["messages"]) == 1
    content = result["messages"][0].content
    assert "## Status" in content                              # digest survived
    assert "All variants returned 403." in content             # digest content survived
    assert "## Findings (verbatim from worker)" not in content # critical: no empty section


def test_findings_scoped_to_correct_worker_in_parallel_fan_out(monkeypatch):
    """When N workers run in parallel and each emits its own findings,
    every worker_report must contain ONLY that worker's findings, not
    siblings'. Filtering is by ``Finding.agent_id``.
    """
    # Three workers; only worker A and worker C produced findings.
    finding_a = Finding(
        title="Reflected XSS in /search q parameter",
        severity=Severity.HIGH,
        category="xss",
        description="Reflected XSS",
        evidence="<script>alert(1)</script> reflected in response body verbatim",
        agent_id="vulntype-xss",
        url="http://localhost:8000/search",
    )
    finding_c = Finding(
        title="Open redirect in /go target parameter",
        severity=Severity.MEDIUM,
        category="open-redirect",
        description="Open redirect",
        evidence=f"GET /go?target=https://attacker.example → 302, Location: https://attacker.example AND {REAL_CAPTURED_FLAG} also visible in body",
        agent_id="vulntype-open-redirect",
        url="http://localhost:8000/go",
    )

    import src.llm.provider as provider_mod
    monkeypatch.setattr(
        provider_mod,
        "get_llm",
        lambda: _fake_digest_model([
            "## Status\nsuccess\n## Server responses\nXSS reflection confirmed.",
            "## Status\ninconclusive\n## Server responses\nNothing leaked.",
            "## Status\nsuccess\n## Server responses\nRedirect honored.",
        ]),
    )

    state = {
        "pending_summary_inputs": [
            {
                "agent_id": "vulntype-xss",
                "config_name": "vulntype-xss",
                "methodology": "vulntype",
                "dispatch_reason": "Probe /search for XSS",
                "trace": [HumanMessage(content="probe xss"), AIMessage(content="done")],
                "findings_count": 1,
                "iteration_count": 3,
                "completed": True,
            },
            {
                "agent_id": "owasp-input-validation",   # NO findings
                "config_name": "owasp-input-validation",
                "methodology": "owasp",
                "dispatch_reason": "Probe /jobs for input validation",
                "trace": [HumanMessage(content="probe"), AIMessage(content="done")],
                "findings_count": 0,
                "iteration_count": 2,
                "completed": True,
            },
            {
                "agent_id": "vulntype-open-redirect",
                "config_name": "vulntype-open-redirect",
                "methodology": "vulntype",
                "dispatch_reason": "Probe /go for open redirect",
                "trace": [HumanMessage(content="probe redirect"), AIMessage(content="done")],
                "findings_count": 1,
                "iteration_count": 2,
                "completed": True,
            },
        ],
        # Findings list contains BOTH — summariser must filter per worker.
        "findings": [finding_a, finding_c],
        "run_id": "test-run-parallel",
        "target_url": "http://localhost:8000",
    }

    result = asyncio.run(summarizer_node.execute(state))
    assert len(result["messages"]) == 3

    # Match each report back to its worker via additional_kwargs.
    by_agent = {m.additional_kwargs.get("agent_id"): m for m in result["messages"]}
    assert set(by_agent.keys()) == {"vulntype-xss", "owasp-input-validation", "vulntype-open-redirect"}

    xss_content = by_agent["vulntype-xss"].content
    iv_content = by_agent["owasp-input-validation"].content
    redirect_content = by_agent["vulntype-open-redirect"].content

    # Worker A (xss) — must contain its own finding, NOT the redirect one.
    assert "## Findings (verbatim from worker)" in xss_content
    assert "Reflected XSS in /search" in xss_content
    assert "<script>alert(1)</script>" in xss_content
    assert "Open redirect" not in xss_content
    assert REAL_CAPTURED_FLAG not in xss_content   # belongs to redirect worker's finding

    # Worker B (input-validation) — emitted no findings, no section appended.
    assert "## Findings (verbatim from worker)" not in iv_content
    assert "Reflected XSS" not in iv_content
    assert "Open redirect" not in iv_content

    # Worker C (open-redirect) — must contain its own finding (including the
    # flag string that lives in its evidence field), NOT the XSS one.
    assert "## Findings (verbatim from worker)" in redirect_content
    assert "Open redirect in /go" in redirect_content
    assert REAL_CAPTURED_FLAG in redirect_content
    assert "Reflected XSS" not in redirect_content


def test_findings_section_format_is_planner_readable(monkeypatch):
    """Lock down the exact markdown shape — the planner's prompt will
    eyeball this section, so the rendering must be unambiguous."""
    import src.llm.provider as provider_mod
    monkeypatch.setattr(
        provider_mod,
        "get_llm",
        lambda: _fake_digest_model(["## Status\nsuccess"]),
    )

    state = {
        "pending_summary_inputs": [
            {
                "agent_id": "owasp-input-validation",
                "config_name": "owasp-input-validation",
                "methodology": "owasp",
                "dispatch_reason": "x",
                "trace": [HumanMessage(content="x"), AIMessage(content="x")],
                "findings_count": 1,
                "iteration_count": 1,
                "completed": True,
            }
        ],
        "findings": [CAPTURED_FLAG_FINDING],
        "run_id": "test-run-format",
        "target_url": "http://localhost:8000",
    }

    result = asyncio.run(summarizer_node.execute(state))
    content = result["messages"][0].content

    # Shape: header, then numbered line with severity in brackets,
    # then a metadata line, then an evidence line.
    section = content.split("## Findings (verbatim from worker)", 1)[1]
    lines = [ln for ln in section.split("\n") if ln.strip()]
    assert lines[0].startswith("1. [HIGH]")
    assert "SQL injection in /jobs job_type" in lines[0]
    # Metadata line carries category + URL.
    assert any("category=sqli" in ln and "url=http://localhost:8000/jobs" in ln for ln in lines[:3])
    # Evidence line contains the full verbatim string, including the flag.
    assert any(REAL_CAPTURED_FLAG in ln for ln in lines)
