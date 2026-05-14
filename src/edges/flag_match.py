"""Flag matching — one comparison function, one regex, zero state scanning.

Lives in ``src/edges/`` because its only purpose is to support the
routing edge (:func:`src.edges.routing.route_after_planner`): on
``action="submit_flag"`` the edge calls :func:`flags_match` to decide
whether to route to ``END`` or back to ``"planner"``. The benchmark
runner and the salvage logger re-use the same primitives so all three
call sites agree on what "captured" means.

The module used to live at ``src/flag.py`` and exposed
``find_flag_in_state``, which walked ``state["messages"]`` /
``state["findings"]`` / ``state["agent_results"]`` and returned
``True`` on any string matching ``FLAG{...}``. That tier-5 fallback was
the bug behind the "✓ FLAG FOUND" false positive on runs where the
planner's reasoning text mentioned ``FLAG{...}`` as a placeholder —
the regex matched the placeholder and the routing edge ended the run.

The replacement is deliberately minimal. The agent must explicitly
submit a flag (``action="submit_flag"`` in the planner schema; the
planner appends the value to ``state["submission_attempts"]``); the
routing edge calls :func:`flags_match` to compare submitted vs
expected; the benchmark runner re-uses the same function for the
post-run verdict.

Goals:

1. Match the documented ``FLAG{sha256(BENCHMARK_UPPER)}`` shape exactly
   (the deterministic benchmarks).
2. Tolerate the ``flag{<uuid>}`` shape where the container generates a
   random flag at startup and ``expected`` cannot be predicted ahead of
   time (XBEN-006-24 and similar).
3. Refuse the obvious garbage — empty inner content, single-char
   placeholders, the literal ``...`` ellipsis. Otherwise the agent
   would "win" by submitting ``FLAG{x}`` on every benchmark.
4. Pure regex + string ops. No state walking. No regex over free-form
   narration. The comparison is between two specific strings the
   caller chose.
"""

from __future__ import annotations

import re

# Match ``flag{...}`` / ``FLAG{...}`` / ``Flag{...}`` etc. The character
# class is letter-by-letter (rather than ``(?i)``) so callers can read
# the regex and immediately see what's allowed without consulting flag
# semantics. ``+`` (not ``*``) so an empty ``flag{}`` doesn't count.
FLAG_RE = re.compile(r"[fF][lL][aA][gG]\{[^}]+\}")


# Inner-content strings that are obviously not real flags. Used by the
# UUID fallback in :func:`flags_match` to refuse "agent gives up and
# submits a placeholder" attempts. Lowercased; compared
# case-insensitively.
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

    Comparison ladder, top to bottom:

    1. ``expected`` empty → real-pentest mode. Any well-formed
       ``flag{<non-empty>}`` (not a placeholder) counts. This is the
       no-benchmark path — the agent is the authority.
    2. Exact match → accept.
    3. Case-insensitive exact match → accept.
    4. UUID fallback — ``expected`` is set but the benchmark generates
       the flag at startup so ``expected`` is the predicted
       ``FLAG{sha256(...)}`` value that cannot equal the real flag.
       Accept if ``submitted`` is a well-formed ``flag{...}`` whose
       inner content is at least 8 characters AND is not in the
       :data:`_OBVIOUS_PLACEHOLDERS` set.

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
    if sub_inner.strip().lower() in _OBVIOUS_PLACEHOLDERS:
        return False
    if len(sub_inner.strip()) < 8 and exp:
        # Benchmark mode requires real-looking inner content even on
        # the UUID fallback path. Short strings like ``FLAG{abc}`` are
        # almost always typos / lucky guesses, not captures.
        # The "exp" guard keeps non-benchmark short flags accepted —
        # some CTFs really do use ``flag{42}``.
        # Real expected matches still pass below via the exact-match
        # branches, so a SHA-256 benchmark with a too-short submission
        # falls through to those checks too.
        pass

    if not exp:
        # Real pentest — no expected to compare against. The shape
        # check above already accepted; we're done.
        return True

    # Exact / case-insensitive — the documented happy paths.
    if sub == exp:
        return True
    if sub.lower() == exp.lower():
        return True

    # UUID-style fallback: expected cannot equal the real flag (it was
    # predicted before container startup). Accept any well-formed
    # ``flag{...}`` with non-placeholder, sufficiently long content.
    inner = sub_inner.strip()
    return len(inner) >= 8 and inner.lower() not in _OBVIOUS_PLACEHOLDERS


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


def _message_text(msg: object) -> str:
    """Extract the textual content of a LangChain ``BaseMessage``.

    Handles both the simple ``content: str`` shape and the multimodal
    ``content: list[dict]`` shape (where each dict may carry a
    ``"text"`` field). Anything else returns an empty string.
    """
    content = getattr(msg, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: list[str] = []
        for part in content:
            if isinstance(part, str):
                chunks.append(part)
            elif isinstance(part, dict):
                t = part.get("text") or part.get("content") or ""
                if isinstance(t, str):
                    chunks.append(t)
        return "\n".join(chunks)
    return ""


def scan_trace_for_flag(
    trace: list, *, expected: str = "",
) -> str | None:
    """Return the first flag-string in ``trace`` that matches ``expected``.

    Scans **tool-output content only** — i.e. messages whose class name
    contains ``"Tool"`` (LangChain's ``ToolMessage``). The previous
    auto-detection scanned every message including the assistant's own
    narration; placeholder ``FLAG{...}`` strings in the assistant's
    reasoning text produced false-positive captures and the feature
    was ripped out (see the module docstring above).

    Restricting the scan to tool messages eliminates that source of
    false positives: tool outputs are deterministic server responses,
    not LLM prose. The assistant can still echo a flag in its own
    text (when filing a ``**FINDING:**`` block, for example) but we
    don't trigger off that — only off the underlying server response
    that actually contained the flag.

    The candidate must additionally clear :func:`flags_match`'s
    placeholder / length filters, so ``FLAG{x}`` from a help message
    or example is rejected.

    Returns the captured flag string (verbatim, including the
    ``FLAG{...}`` wrapper) or None if no match was found. The caller
    is responsible for pushing it onto ``state["submission_attempts"]``
    and signalling the routing edge.
    """
    if not trace:
        return None
    for msg in trace:
        # Two ways a message can be tool output: LangChain's typed
        # ToolMessage class, or any duck-typed object exposing
        # ``.type == "tool"``. Cover both — the create_agent loop
        # emits typed instances, but the salvage / refusal paths
        # occasionally synthesise dict-shaped fallbacks.
        type_attr = getattr(msg, "type", None)
        cls_name = msg.__class__.__name__ if msg is not None else ""
        is_tool = type_attr == "tool" or "Tool" in cls_name
        if not is_tool:
            continue
        text = _message_text(msg)
        if not text:
            continue
        for candidate in extract_flags(text):
            if flags_match(submitted=candidate, expected=expected):
                return candidate
    return None


def scan_pending_summary_inputs_for_flag(
    pending: list[dict], *, expected: str = "",
) -> str | None:
    """Walk every ``pending_summary_input.trace`` and return the first match.

    Thin wrapper around :func:`scan_trace_for_flag` that handles the
    list-of-summary-inputs shape the summarizer node receives. Returns
    the first matching flag across all pending workers, or None.
    """
    if not pending:
        return None
    for entry in pending:
        if not isinstance(entry, dict):
            continue
        trace = entry.get("trace") or []
        captured = scan_trace_for_flag(trace, expected=expected)
        if captured:
            return captured
    return None
