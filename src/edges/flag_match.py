"""Flag matching — strict equality against the benchmark's expected flag(s).

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
  string equality against one OR more candidate values. Nothing else
  wins.
- **Real-pentest mode** (``expected`` is empty / empty tuple): no
  ground truth exists, so accept any well-formed non-placeholder
  ``flag{...}`` the agent submits. The agent is the authority outside
  benchmark mode.

## Why ``expected`` accepts an iterable

XBow benchmarks have two equally legitimate sources of truth for what
flag the container actually serves, and the two can disagree:

- ``common.mk`` formula → ``FLAG{sha256(BENCHMARK_UPPER)}``, passed
  via ``--build-arg`` at build time
- ``<benchmark>/.env`` file → ``FLAG="flag{<uuid>}"``, auto-loaded by
  docker-compose into the build environment

Depending on whether the image was built via ``make build`` or plain
``docker compose build``, one wins over the other. We've observed both
outcomes in the same XBow corpus (XBEN-001 baked sha256; XBEN-002
baked the .env UUID). The runner therefore computes ALL plausible
candidates up front and the matcher accepts any of them — see
:func:`benchmarks.xbow_runner.expected_flag_candidates`.

Capture is now an explicit agent decision: a worker must surface the
flag string in its findings, the planner must emit
``action="submit_flag"`` with that string, and only then does this
module decide if the run ends.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

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


def flags_match(*, submitted: str, expected: str | Iterable[str]) -> bool:
    """Decide whether a submitted flag should count as the captured flag.

    Two modes:

    - ``expected`` empty (real pentest) → accept any well-formed
      non-placeholder ``flag{...}``. No ground truth exists; the
      agent is the authority.
    - ``expected`` set (benchmark mode) → strict case-insensitive
      equality against ANY value in the candidate set. The XBow
      corpus has two equally legitimate flag sources that may diverge
      (sha256-of-bench-id vs the .env file's ``FLAG=`` value), and
      which one is baked depends on which build path Docker Compose
      took. The runner builds the full candidate set up front and any
      one match counts as a capture. See module docstring for the
      full rationale.

    ``expected`` may be passed as a single ``str`` (back-compat) or
    an iterable of strings. Empty strings inside the iterable are
    ignored; if every candidate is empty, falls through to real-pentest
    mode.

    Both inputs are stripped of surrounding whitespace.

    Returns ``True`` iff the submission should be treated as a captured
    flag.
    """
    sub = (submitted or "").strip()
    if not sub:
        return False

    sub_inner = _inner(sub)
    if sub_inner is None:
        return False

    # Normalize ``expected`` into a clean candidate set (drops empties,
    # strips whitespace, dedupes case-insensitively). A single string
    # input becomes a 1-element set; an iterable becomes whatever it
    # contains. Empty input → real-pentest mode.
    if isinstance(expected, str):
        raw_candidates: tuple[str, ...] = (expected,)
    else:
        raw_candidates = tuple(expected or ())
    candidates_lc = {c.strip().lower() for c in raw_candidates if (c or "").strip()}

    if candidates_lc:
        # Benchmark mode: strict equality against any candidate.
        return sub.lower() in candidates_lc

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
