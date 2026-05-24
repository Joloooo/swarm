"""Tier 1 — Routing edge tests for the supervisor's transitions.

``src/edges/routing.py:route_after_planner`` is the single conditional
edge after the planner node. It maps the planner's chosen
``next_action`` to one of:

* ``"recon"`` / ``"web_search"`` — direct node transition.
* a list of ``Send()`` calls for ``"attack"`` fan-out.
* ``END`` for ``"report"`` (currently bypassed) and for verified
  ``"submit_flag"``.
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
4. Real-pentest mode (empty ``expected_flag``) accepts a well-formed
   non-placeholder flag.
5. Real-pentest mode still rejects placeholders.

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


def test_submit_flag_real_pentest_mode_accepts_well_formed():
    """No ``expected_flag`` = real pentest. Agent is the authority."""
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["FLAG{captured-via-prod-sqli-2026}"],
        "expected_flag": "",
    }
    assert route_after_planner(state) is END


def test_submit_flag_real_pentest_mode_rejects_placeholder():
    """Placeholder defence applies in real-pentest mode too."""
    state = {
        "next_action": "submit_flag",
        "submission_attempts": ["FLAG{...}"],
        "expected_flag": "",
    }
    assert route_after_planner(state) == "planner"


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
    assert route_after_planner(state) is END


def test_recon_returns_recon_node():
    assert route_after_planner({"next_action": "recon"}) == "recon"


def test_web_search_returns_web_search_node():
    assert route_after_planner({"next_action": "web_search"}) == "web_search"


def test_report_routes_to_end():
    """Report node is currently bypassed via ``_TERMINATE = END``."""
    assert route_after_planner({"next_action": "report"}) is END


def test_unknown_action_terminates_defensively():
    """Defensive: anything outside VALID_ACTIONS routes to END not crash."""
    assert route_after_planner({"next_action": "bogus_action"}) is END
    assert route_after_planner({}) is END  # missing action falls through
