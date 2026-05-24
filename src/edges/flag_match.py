"""Flag matching — strict equality against the benchmark's expected flag.

Lives in ``src/edges/`` because its only purpose is to support the
routing edge (:func:`src.edges.routing.route_after_planner`): on
``action="submit_flag"`` the edge calls :func:`flags_match` to decide
whether to route to ``END`` or back to ``"planner"``.

## Why this module is deliberately tiny

A previous version did two extra things, and both caused false-positive
captures:

1. It walked ``state["messages"]`` / ``state["findings"]`` /
   ``state["agent_results"]`` looking for any string matching
   ``FLAG{...}`` and called that a capture. Removed because placeholder
   ``FLAG{...}`` strings in planner narration ended the run early.

2. A scan helper (``scan_trace_for_flag``) inspected tool-output
   content for the same pattern, and a "UUID fallback" branch in
   :func:`flags_match` accepted any well-formed ``flag{<8+ chars>}``
   whenever ``expected`` was set but didn't match exactly. The fallback
   was added under the mistaken belief that XBEN-006-24 generated its
   flag randomly at container startup. It does not — every XBow
   benchmark, 006-24 included, computes the flag deterministically as
   ``FLAG{sha256(BENCHMARK_UPPER)}`` in ``common.mk`` and bakes it into
   the image as a build arg. So the fallback only existed to accept
   *wrong* submissions, and was removed alongside the tool-output scan.

The remaining surface is the minimum needed to support two modes:

- **Benchmark mode** (``expected`` is set): strict case-insensitive
  string equality. Nothing else wins.
- **Real-pentest mode** (``expected`` is empty): no ground truth
  exists, so accept any well-formed non-placeholder ``flag{...}`` the
  agent submits. The agent is the authority outside benchmark mode.

Capture is now an explicit agent decision: a worker must surface the
flag string in its findings, the planner must emit
``action="submit_flag"`` with that string, and only then does this
module decide if the run ends.
"""

from __future__ import annotations

import re

# Match ``flag{...}`` / ``FLAG{...}`` / ``Flag{...}`` etc. The character
# class is letter-by-letter (rather than ``(?i)``) so callers can read
# the regex and immediately see what's allowed without consulting flag
# semantics. ``+`` (not ``*``) so an empty ``flag{}`` doesn't count.
FLAG_RE = re.compile(r"[fF][lL][aA][gG]\{[^}]+\}")


# Inner-content strings that are obviously not real flags. Used by the
# real-pentest branch of :func:`flags_match` to refuse "agent gives up
# and submits a placeholder" attempts when no ground truth exists.
# Lowercased; compared case-insensitively.
_OBVIOUS_PLACEHOLDERS: frozenset[str] = frozenset({
    "...",
    "....",
    ".....",
    "x",
    "y",
    "z",
    "?",
    "??",
    "???",
    "tbd",
    "todo",
    "example",
    "placeholder",
    "fill-me-in",
    "fill_me_in",
})


def _inner(s: str) -> str | None:
    """Return the content between ``{`` and ``}`` of a ``FLAG{...}`` string.

    Returns ``None`` if the string does not match the canonical shape.
    """
    m = FLAG_RE.fullmatch(s.strip())
    if not m:
        return None
    inside = m.group(0)
    return inside[inside.index("{") + 1 : inside.rindex("}")]


def flags_match(*, submitted: str, expected: str) -> bool:
    """Decide whether a submitted flag should count as the captured flag.

    Two modes:

    - ``expected`` empty (real pentest) → accept any well-formed
      non-placeholder ``flag{...}``. No ground truth exists; the
      agent is the authority.
    - ``expected`` set (benchmark mode) → strict case-insensitive
      equality. Nothing else wins. The XBow corpus is deterministic
      (``FLAG{sha256(BENCHMARK_UPPER)}``) so the exact expected value
      is always known.

    Both inputs are stripped of surrounding whitespace.

    Returns ``True`` iff the submission should be treated as a captured
    flag.
    """
    sub = (submitted or "").strip()
    exp = (expected or "").strip()
    if not sub:
        return False

    sub_inner = _inner(sub)
    if sub_inner is None:
        return False

    if exp:
        # Benchmark mode: strict equality only. No fallbacks.
        return sub.lower() == exp.lower()

    # Real-pentest mode: no ground truth — reject only obvious
    # placeholders, accept anything else well-formed.
    return sub_inner.strip().lower() not in _OBVIOUS_PLACEHOLDERS


def extract_flags(text: str) -> list[str]:
    """Return every ``flag{...}`` / ``FLAG{...}`` substring in ``text``.

    Useful for diagnostic logging — e.g. surfacing in ``run.log`` a
    list of candidate flags a worker emitted even if the planner did
    not submit any. Not used by routing.

    Order is preserved (left-to-right). Duplicates are kept.
    """
    if not text:
        return []
    return FLAG_RE.findall(text)
