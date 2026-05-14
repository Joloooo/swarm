"""Tier 1 — Flag matching tests.

``src/edges/flag_match.py:flags_match`` is the single source of truth
for "did the agent's submitted flag count as a capture?". It is called
from two sites:

- :func:`src.edges.routing.route_after_planner` — the verification edge
  that decides whether to terminate on a ``submit_flag`` action.
- :func:`benchmarks.xbow_runner` — the post-run benchmark verdict.

The function replaced an earlier ``find_flag_in_state`` tier-5
fallback that silently turned any ``FLAG{...}`` substring in the
planner's narration into a "✓ FLAG FOUND" verdict (observed in the
XBEN-006-24 run on 2026-05-12 where the planner's reasoning text
contained the literal placeholder ``FLAG{...}`` and the run ended
victorious despite zero worker output).

These tests pin the comparison ladder:

1. Empty submission is rejected.
2. Malformed input (no ``flag{...}`` shape) is rejected.
3. Inner content that matches a known placeholder
   (:data:`src.edges.flag_match._OBVIOUS_PLACEHOLDERS`) is rejected
   even when expected is empty.
4. Exact match accepted.
5. Case-insensitive exact match accepted.
6. UUID fallback (expected set, exact miss, submitted has ≥ 8 char
   non-placeholder inner content) accepted.
7. UUID fallback refused for short / placeholder inner content.
8. Real-pentest mode (empty expected) accepts well-formed flags.

If any of these flip, future flag-related changes should fail loudly
instead of bringing back the false-positive bug.
"""

from __future__ import annotations

from src.edges.flag_match import FLAG_RE, extract_flags, flags_match


# ── False-positive prevention (the bug that motivated this module) ──


def test_placeholder_dots_rejected_even_with_no_expected():
    """The actual failure on 2026-05-12: ``FLAG{...}`` in planner narration."""
    assert not flags_match(submitted="FLAG{...}", expected="")
    assert not flags_match(
        submitted="FLAG{...}",
        expected="FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}",
    )


def test_other_placeholders_rejected():
    for placeholder in ("FLAG{x}", "FLAG{?}", "flag{example}",
                        "FLAG{placeholder}", "flag{tbd}"):
        assert not flags_match(submitted=placeholder, expected=""), placeholder


def test_empty_submission_rejected():
    assert not flags_match(submitted="", expected="")
    assert not flags_match(submitted="", expected="FLAG{abc12345}")
    assert not flags_match(submitted="   ", expected="FLAG{abc12345}")


def test_malformed_submission_rejected():
    """Anything not matching ``[fF][lL][aA][gG]\\{...\\}`` is rejected."""
    for bad in ("not a flag", "FLAG", "FLAG{}", "{abc12345}",
                "the flag is abc12345", "FLAG[abc12345]"):
        assert not flags_match(submitted=bad, expected=""), bad


# ── Happy paths ──


def test_exact_match_accepted():
    expected = "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}"
    assert flags_match(submitted=expected, expected=expected)


def test_case_insensitive_match_accepted():
    expected = "FLAG{ABCDEF12345}"
    assert flags_match(submitted="flag{abcdef12345}", expected=expected)
    assert flags_match(submitted="Flag{AbCdEf12345}", expected=expected)


def test_surrounding_whitespace_ignored():
    expected = "FLAG{abcdef12345}"
    assert flags_match(submitted="  FLAG{abcdef12345}  ", expected=expected)


# ── UUID fallback (benchmarks where expected can never equal the real flag) ──


def test_uuid_fallback_accepted_when_content_is_real():
    """XBEN-006-24 ships ``flag{<random-uuid>}``. Expected is the
    deterministic SHA-256 prediction and can never match — the fallback
    accepts any well-formed flag with non-placeholder content >= 8 chars.
    """
    expected = "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}"
    assert flags_match(
        submitted="flag{582d82bb-2c1f-4ba5-9357-e8b94217957f}",
        expected=expected,
    )


def test_uuid_fallback_rejects_short_content():
    """Short inner content in benchmark mode is almost always a lucky
    guess or hallucination — refuse it on the fallback path."""
    expected = "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}"
    assert not flags_match(submitted="FLAG{abc}", expected=expected)


def test_uuid_fallback_rejects_placeholders_too():
    expected = "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}"
    for placeholder in ("FLAG{example}", "FLAG{placeholder}", "FLAG{tbd}"):
        assert not flags_match(submitted=placeholder, expected=expected), placeholder


# ── Real-pentest mode (expected is empty — agent is the authority) ──


def test_pentest_mode_accepts_well_formed_flags():
    """Outside benchmark mode, any well-formed non-placeholder flag wins."""
    assert flags_match(submitted="FLAG{captured-via-sqli-on-prod-2026}", expected="")
    assert flags_match(submitted="flag{12345678}", expected="")
    # Even a short real-looking flag is acceptable when expected is empty
    # (some CTFs use short flags); the fallback length check only
    # applies when ``expected`` is set.
    assert flags_match(submitted="FLAG{42}", expected="")


def test_pentest_mode_still_rejects_placeholders():
    """The placeholder defence applies in real-pentest mode too."""
    assert not flags_match(submitted="FLAG{...}", expected="")
    assert not flags_match(submitted="FLAG{example}", expected="")


# ── extract_flags + FLAG_RE — used by salvage in skill_runner ──


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
