"""Tier 1 — Routing edge tests for the supervisor's transitions.

``src/edges/routing.py:route_after_planner`` is the single conditional
edge after the planner node. It maps the planner's chosen
``next_action`` to one of:

* ``"recon"`` / ``"web_search"`` — direct node transition.
* a list of ``Send()`` calls for ``"attack"`` fan-out.
* ``"report"`` for a real engagement, ``END`` for a benchmark report,
  and ``END`` for a verified ``"submit_flag"``.
* ``"planner"`` (loop back) for rejected ``"submit_flag"``.

The ``submit_flag`` branch is the verification edge that replaced
two earlier flag-detection paths: the format-tolerant
``find_flag_in_state`` scan (ended runs on placeholder ``FLAG{...}``
in narration) and the summariser-side tool-output scan with its UUID
fallback (accepted any well-formed flag-shaped string in benchmark
mode whenever exact match missed — i.e. it accepted wrong
submissions). Both were removed; ``submit_flag`` + strict equality
is now the only termination-on-capture path.

These tests pin the explicit-submission behaviour:

1. Verified submission (exact match in benchmark mode) → ``END``.
2. Wrong submission in benchmark mode → ``"planner"``. NO fallback
   accepts arbitrary well-formed flags any more.
3. Defensive: ``submit_flag`` with empty ``submission_attempts``
   defers to the planner rather than crashing.
4. Real-target mode (empty ``expected_flag``) bypasses flag validation and
   builds the engagement report.

Plus a quick smoke pass over the other actions to make sure the
``submit_flag`` branch did not accidentally swallow the existing
routing logic.
"""

from __future__ import annotations

from langgraph.graph import END
from langgraph.types import Send

from src.edges.routing import route_after_planner


# ── submit_flag branch — the heart of the verification edge ──


def test_submit_flag_verified_routes_to_end():
    expected = "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}"
    state = {
        "next_action": "submit_flag",
        "submission_attempts": [expected],
        "expected_flag": expected,
    }
    assert route_after_planner(state) is END


def test_submit_flag_case_insensitive_verified_routes_to_end():
    expected = "FLAG{ABCDEF12345678}"
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["flag{abcdef12345678}"],
        "expected_flag": expected,
    }
    assert route_after_planner(state) is END


def test_submit_flag_wrong_uuid_routes_back_to_planner():
    """The UUID fallback was REMOVED on 2026-05-24. In benchmark mode,
    a well-formed flag with the WRONG inner content must NOT end the
    run — previously the fallback accepted any ``flag{<8+ chars>}``
    whenever expected didn't match exactly, which is how false-positive
    captures slipped through.
    """
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}"],
        "expected_flag": "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}",
    }
    assert route_after_planner(state) == "planner"


def test_submit_flag_placeholder_routes_back_to_planner():
    """The actual false-positive bug: ``FLAG{...}`` must NOT end the run."""
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["FLAG{...}"],
        "expected_flag": "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}",
    }
    assert route_after_planner(state) == "planner"


def test_submit_flag_wrong_well_formed_value_routes_back_to_planner():
    """The exact false-positive surface the UUID fallback used to create."""
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["FLAG{wrongvalue12345}"],
        "expected_flag": "FLAG{rightvalue1234567890abcdef1234567890abcdef1234567890abcdef12}",
    }
    assert route_after_planner(state) == "planner"


def test_submit_flag_short_content_routes_back_to_planner():
    """Short inner content in benchmark mode is rejected (it can't match
    a 64-char sha256 expected flag)."""
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["FLAG{abc}"],
        "expected_flag": "FLAG{rightvalue1234567890abcdef1234567890abcdef1234567890abcdef12}",
    }
    assert route_after_planner(state) == "planner"


def test_submit_flag_empty_attempts_defers_to_planner():
    """Defensive: submit_flag with no recorded submission must not crash."""
    state = {
        "next_action": "submit_flag",
        "submission_attempts": [],
        "expected_flag": "FLAG{rightvalue1234567890abcdef1234567890abcdef1234567890abcdef12}",
    }
    assert route_after_planner(state) == "planner"


def test_submit_flag_real_pentest_mode_routes_to_report():
    """No expected benchmark token means flag validation is disabled."""
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["FLAG{captured-via-prod-sqli-2026}"],
        "expected_flag": "",
    }
    assert route_after_planner(state) == "report"


def test_submit_flag_real_pentest_placeholder_still_routes_to_report():
    """Even a placeholder cannot activate benchmark logic on a real target."""
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["FLAG{...}"],
        "expected_flag": "",
    }
    assert route_after_planner(state) == "report"


def test_submit_flag_uses_latest_attempt():
    """The router compares the most recent attempt, not the first."""
    expected = "FLAG{rightvalue1234567890abcdef1234567890abcdef1234567890abcdef12}"
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["FLAG{wrong1}", "FLAG{...}", expected],
        "expected_flag": expected,
    }
    assert route_after_planner(state) is END


# ── Smoke pass over other actions to ensure they still work ──


def test_attack_with_pending_dispatch_returns_send_list():
    state = {
        "next_action": "attack",
        "pending_dispatch": [
            {
                "agent_id": "a1",
                "config_name": "xss",
                "methodology": "test",
                "mode": "analyze",
                "dispatch_reason": "found reflected input",
            },
        ],
    }
    result = route_after_planner(state)
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], Send)
    assert result[0].node == "executor"


def test_attack_with_empty_dispatch_terminates():
    state = {"next_action": "attack", "pending_dispatch": []}
    assert route_after_planner(state) == "report"


def test_recon_fans_out_to_parallel_dimensions():
    """``recon`` fans out into parallel dimension workers (web + ports).

    Each is a ``Send`` to the dimension-agnostic recon node carrying its
    own ``config_name`` — see ``route_after_planner`` in
    ``src/edges/routing.py``. (Superseded the old single-``"recon"``
    return when recon was split into parallel dimensions.)
    """
    result = route_after_planner({"next_action": "recon"})
    assert isinstance(result, list)
    assert len(result) == 2
    assert all(isinstance(s, Send) for s in result)
    assert all(s.node == "recon" for s in result)
    assert {s.arg["config_name"] for s in result} == {"recon", "recon-ports"}


def test_web_search_returns_web_search_node():
    assert route_after_planner({"next_action": "web_search"}) == "web_search"


def test_report_routes_to_report_node():
    """Real engagements build a report; benchmark runs still bypass it."""
    assert route_after_planner({"next_action": "report"}) == "report"
    assert route_after_planner({
        "next_action": "report",
        "expected_flag": "FLAG{benchmark}",
        "budget_exhausted": True,
    }) is END


def test_unknown_action_terminates_defensively():
    """Defensive real-target failures still produce the final report."""
    assert route_after_planner({"next_action": "bogus_action"}) == "report"
    assert route_after_planner({}) == "report"  # missing action falls through
