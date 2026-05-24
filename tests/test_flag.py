"""Tier 1 — Flag matching tests.

``src/edges/flag_match.py:flags_match`` is the single source of truth
for "did the agent's submitted flag count as a capture?". It is called
from two sites:

- :func:`src.edges.routing.route_after_planner` — the verification edge
  that decides whether to terminate on a ``submit_flag`` action.
- :func:`benchmarks.xbow_runner` — the post-run benchmark verdict.

## History

The function replaced an earlier ``find_flag_in_state`` tier-5
fallback that silently turned any ``FLAG{...}`` substring in the
planner's narration into a "✓ FLAG FOUND" verdict (XBEN-006-24,
2026-05-12: planner's reasoning text contained the literal
placeholder ``FLAG{...}`` and the run ended victorious despite zero
worker output).

A subsequent "UUID fallback" branch — accept any well-formed
``flag{<8+ chars>}`` whenever ``expected`` was set but didn't match
exactly — was REMOVED on 2026-05-24. It was added under the false
belief that XBEN-006-24 generated its flag randomly at container
startup; checking ``common.mk`` and computing
``sha256("XBEN-006-24")`` confirms every XBow benchmark is fully
deterministic (``FLAG{sha256(BENCHMARK_UPPER)}``). The fallback only
ever accepted *wrong* submissions.

## Pinned behaviour

These tests pin the two-mode contract:

1. Empty / malformed submissions are rejected in both modes.
2. Benchmark mode (``expected`` set) is strict case-insensitive
   equality. Anything else fails — including well-formed flag-shaped
   strings with the wrong inner content.
3. Real-pentest mode (``expected`` empty) accepts any well-formed
   non-placeholder ``flag{...}`` the agent submits.
4. Placeholders (``FLAG{...}``, ``FLAG{x}``, ``FLAG{example}`` …) are
   rejected in both modes.

If any of these flip, future flag-related changes should fail loudly
instead of bringing back the false-positive bug.
"""

from __future__ import annotations

from src.edges.flag_match import FLAG_RE, extract_flags, flags_match

EXPECTED_006 = (
    "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}"
)


# ── False-positive prevention ──────────────────────────────────────────


def test_placeholder_dots_rejected_in_both_modes():
    """The actual failure on 2026-05-12: ``FLAG{...}`` in planner narration."""
    assert not flags_match(submitted="FLAG{...}", expected="")
    assert not flags_match(submitted="FLAG{...}", expected=EXPECTED_006)


def test_other_placeholders_rejected_in_pentest_mode():
    for placeholder in ("FLAG{x}", "FLAG{?}", "flag{example}",
                        "FLAG{placeholder}", "flag{tbd}"):
        assert not flags_match(submitted=placeholder, expected=""), placeholder


def test_empty_submission_rejected():
    assert not flags_match(submitted="", expected="")
    assert not flags_match(submitted="", expected=EXPECTED_006)
    assert not flags_match(submitted="   ", expected=EXPECTED_006)


def test_malformed_submission_rejected():
    """Anything not matching ``[fF][lL][aA][gG]\\{...\\}`` is rejected."""
    for bad in ("not a flag", "FLAG", "FLAG{}", "{abc12345}",
                "the flag is abc12345", "FLAG[abc12345]"):
        assert not flags_match(submitted=bad, expected=""), bad


# ── Benchmark mode: strict equality only ───────────────────────────────


def test_exact_match_accepted():
    assert flags_match(submitted=EXPECTED_006, expected=EXPECTED_006)


def test_case_insensitive_match_accepted():
    expected = "FLAG{ABCDEF12345}"
    assert flags_match(submitted="flag{abcdef12345}", expected=expected)
    assert flags_match(submitted="Flag{AbCdEf12345}", expected=expected)


def test_surrounding_whitespace_ignored():
    expected = "FLAG{abcdef12345}"
    assert flags_match(submitted="  FLAG{abcdef12345}  ", expected=expected)


def test_benchmark_mode_rejects_wrong_well_formed_flag():
    """The bug the UUID fallback used to mask: a well-formed flag with
    the WRONG inner content must be rejected. Previously the fallback
    accepted any ``flag{<8+ chars>}`` when expected didn't match
    exactly — that's how false-positive captures slipped through.
    """
    assert not flags_match(submitted="FLAG{aaaaaaaa}", expected=EXPECTED_006)
    assert not flags_match(
        submitted="flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}",
        expected=EXPECTED_006,
    )
    # Even another deterministic-looking sha256 — but the wrong one — fails.
    assert not flags_match(
        submitted="FLAG{0000000000000000000000000000000000000000000000000000000000000000}",
        expected=EXPECTED_006,
    )


def test_benchmark_mode_rejects_inner_content_match():
    """Submitting the bare inner content (no ``FLAG{...}`` wrapper) loses."""
    inner = EXPECTED_006[len("FLAG{"):-1]
    assert not flags_match(submitted=inner, expected=EXPECTED_006)


# ── Real-pentest mode (expected empty — agent is the authority) ────────


def test_pentest_mode_accepts_well_formed_flags():
    """Outside benchmark mode, any well-formed non-placeholder flag wins."""
    assert flags_match(submitted="FLAG{captured-via-sqli-on-prod-2026}", expected="")
    assert flags_match(submitted="flag{12345678}", expected="")
    # Short flags accepted in pentest mode — some CTFs use ``flag{42}``;
    # there's no ground truth to compare against, so the placeholder
    # filter is the only gate.
    assert flags_match(submitted="FLAG{42}", expected="")


def test_pentest_mode_still_rejects_placeholders():
    """The placeholder defence applies in real-pentest mode too."""
    assert not flags_match(submitted="FLAG{...}", expected="")
    assert not flags_match(submitted="FLAG{example}", expected="")


# ── extract_flags + FLAG_RE — used by salvage in skill_runner ──────────


def test_extract_flags_finds_all_occurrences_in_order():
    text = "first FLAG{abc12345} middle flag{def67890} end"
    assert extract_flags(text) == ["FLAG{abc12345}", "flag{def67890}"]


def test_extract_flags_handles_empty_input():
    assert extract_flags("") == []
    assert extract_flags(None) == []  # type: ignore[arg-type]


def test_flag_re_does_not_match_empty_braces():
    """``FLAG{}`` must not match — ``+`` quantifier requires content."""
    assert FLAG_RE.search("FLAG{}") is None
    assert FLAG_RE.search("flag{}") is None
