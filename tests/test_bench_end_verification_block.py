"""Tier 1 — End-of-bench verification block format tests.

``LIVE.bench_end`` prints a static expected-vs-captured comparison
after the verdict line in benchmark mode. This is the human-facing
post-run check: a glance at the terminal must confirm whether the
runner's predicted ``expected_flag`` matched what the agent actually
submitted, without trusting any LLM narration.

These tests pin the format and the routing logic:

  1. Success case — verdict shows ✓, both values printed, ``✓ match``
     marker appears.
  2. Mismatch — verdict shows ✗, both values printed, ``✗ no match``
     marker appears (the agent submitted SOMETHING but it didn't match
     the answer key).
  3. No submission — verdict shows ✗, ``expected:`` printed,
     ``captured:`` shows the "(no submission attempted)" placeholder.
  4. Real-pentest mode — ``expected_flag`` is empty, no verification
     block prints at all (no ground truth to compare against).
  5. ANSI-stripping smoke test — we capture _emit calls and check
     content, but the strings contain ANSI escape codes for colors.
     The format checks below use ``in`` against the raw strings so
     escape codes don't matter; this comment exists so a future
     refactor that strips colors knows we're operating on coloured
     strings.

History: added 2026-05-25 after the XBEN-006-24 capture succeeded —
the user asked for a static verification line because the verdict
alone ("✓ FLAG FOUND") doesn't tell you WHICH flag was submitted or
whether the runner agrees it matches the expected value. Without the
block, a hypothetical LLM-narration bug that prints "✓ FLAG FOUND" on
a wrong submission would be invisible. The block makes that
impossible — the strict-equality marker is computed by
``flags_match`` directly from the recorded values.
"""

from __future__ import annotations

import pytest

from src.observability import live as live_mod


EXPECTED_006 = "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}"
WRONG_FLAG = "FLAG{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"


@pytest.fixture
def captured_emits(monkeypatch):
    """Capture every ``_emit`` call inside ``live.py`` so tests can
    inspect the rendered terminal output without it actually hitting
    stderr or the displayed_terminal_logs.log sink.
    """
    lines: list[str] = []
    monkeypatch.setattr(live_mod, "_emit", lines.append)
    # Force verbosity to verbose so silent-mode early returns don't skip
    # any of the lines we're testing.
    monkeypatch.setattr(live_mod, "_mode", lambda: "verbose", raising=False)
    return lines


def _joined(lines: list[str]) -> str:
    """Concatenate all emitted lines for easy ``in`` substring checks."""
    return "\n".join(lines)


# ── Case 1 — happy path: capture verified ──────────────────────────────


def test_success_prints_match_marker_and_both_flags(captured_emits):
    """The exact case from XBEN-006-24 2026-05-25_15h51m31s — agent
    submitted the correct flag, verdict is FLAG FOUND, verification
    block must show both values and a ✓ match marker.
    """
    live_mod.LIVE.bench_end(
        "XBEN-006-24",
        ok=True,
        duration_s=318.5,
        findings_n=6,
        summary_path="/tmp/logs/run-XBEN-006-24/displayed_terminal_logs.log",
        error=None,
        expected_flag=EXPECTED_006,
        last_submission=EXPECTED_006,
    )

    out = _joined(captured_emits)
    assert "✓ FLAG FOUND" in out
    assert "XBEN-006-24" in out
    # Duration renders as Xm Ys now (318.5s → 5m 18s), not raw seconds.
    assert "5m 18s" in out and "6 finding" in out
    # Verification block must appear.
    assert "expected:" in out
    assert "captured:" in out
    assert EXPECTED_006 in out
    # The match marker — present on the captured line.
    assert "✓ match" in out
    assert "✗ no match" not in out


# ── Case 2 — agent submitted wrong value ───────────────────────────────


def test_mismatch_prints_no_match_marker(captured_emits):
    """Wrong submission (a real risk before the strict-equality fix):
    the block must clearly show the agent's submission alongside the
    expected value, with the ✗ marker so a human can't miss it.
    """
    live_mod.LIVE.bench_end(
        "XBEN-006-24",
        ok=False,
        duration_s=600.0,
        findings_n=2,
        summary_path="/tmp/logs/x/displayed_terminal_logs.log",
        error=None,
        expected_flag=EXPECTED_006,
        last_submission=WRONG_FLAG,
    )

    out = _joined(captured_emits)
    assert "✗ no flag" in out
    assert "expected:" in out
    assert "captured:" in out
    assert EXPECTED_006 in out
    assert WRONG_FLAG in out
    assert "✗ no match" in out
    assert "✓ match" not in out


# ── Case 3 — agent never submitted ─────────────────────────────────────


def test_no_submission_prints_placeholder(captured_emits):
    """When the agent timed out / forced report without submitting,
    ``last_submission=""`` and the block shows the
    ``(no submission attempted)`` placeholder so the human can tell
    "agent gave up" from "agent submitted a wrong value".
    """
    live_mod.LIVE.bench_end(
        "XBEN-006-24",
        ok=False,
        duration_s=900.0,
        findings_n=0,
        summary_path="/tmp/logs/x/displayed_terminal_logs.log",
        error=None,
        expected_flag=EXPECTED_006,
        last_submission="",
    )

    out = _joined(captured_emits)
    assert "✗ no flag" in out
    assert "expected:" in out
    assert "captured:" in out
    assert EXPECTED_006 in out
    assert "(no submission attempted)" in out
    # Neither match marker is appropriate when there's no submission.
    assert "✓ match" not in out
    assert "✗ no match" not in out


# ── Case 4 — real-pentest mode, no expected_flag ───────────────────────


def test_real_pentest_mode_skips_verification_block(captured_emits):
    """No ``expected_flag`` → no ground truth → no comparison to
    render. Verdict line still prints, but the verification block is
    suppressed entirely so the output stays clean."""
    live_mod.LIVE.bench_end(
        "real-target.example.com",
        ok=True,
        duration_s=120.0,
        findings_n=3,
        summary_path="/tmp/logs/x/displayed_terminal_logs.log",
        error=None,
        expected_flag="",
        last_submission="flag{captured-via-sqli-on-prod-2026}",
    )

    out = _joined(captured_emits)
    assert "✓ FLAG FOUND" in out
    # Verification block must NOT appear.
    assert "expected:" not in out
    assert "captured:" not in out
    assert "✓ match" not in out
    assert "✗ no match" not in out


# ── Case 5 — error verdict still suppresses block ──────────────────────


def test_error_verdict_suppresses_block_when_no_expected(captured_emits):
    """A build/up/down (infra) crash is classified ``api`` and gets a
    ``~ MALFUNCTION`` verdict line — distinct from an ordinary ``✗ no flag``
    failure. If no ``expected_flag`` is propagated (some error paths never
    compute it), the block must stay silent rather than render half-empty
    rows."""
    live_mod.LIVE.bench_end(
        "XBEN-006-24",
        ok=False,
        duration_s=12.3,
        findings_n=0,
        summary_path=None,
        error="phase 'build' timeout after 300s",
        expected_flag="",
        last_submission="",
    )

    out = _joined(captured_emits)
    assert "MALFUNCTION:" in out
    assert "phase 'build' timeout" in out
    assert "expected:" not in out
    assert "captured:" not in out


# ── Sanity — backwards-compat call shape still works ───────────────────


def test_legacy_call_without_new_kwargs_still_works(captured_emits):
    """Callers that haven't been updated yet must keep working — the
    new kwargs default to empty strings, which skips the verification
    block via the existing ``if expected_flag`` guard.
    """
    live_mod.LIVE.bench_end(
        "XBEN-006-24",
        ok=True,
        duration_s=100.0,
        findings_n=1,
        summary_path="/tmp/x.log",
        error=None,
        # no expected_flag, no last_submission
    )

    out = _joined(captured_emits)
    assert "✓ FLAG FOUND" in out
    assert "expected:" not in out
    assert "captured:" not in out
