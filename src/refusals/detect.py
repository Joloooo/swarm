"""Refusal detection — substring matching against known model bail-out
phrases.

Used in two places:

- The worker runner (``src/nodes/base/skill_runner.py:run_skill_agent``) checks
  the last AIMessage of a worker trace against this list to decide
  whether the worker actually refused (and therefore deserves a
  focused sub-LLM rescue) vs. simply finished without findings.

- The supervisor planner (``src/nodes/planner.py``) checks its own
  final prose for the same patterns when it picks ``action=report``,
  so it can spot the case where the planner itself is bailing on
  the engagement rather than genuinely deciding the run is done.

The patterns are intentionally English-only and Codex/ChatGPT-shaped
because that is the provider this swarm targets. Adding patterns is
cheap (one tuple line); false positives are nearly free (we treat
them as "try the recovery loop, just in case") so the bias is toward
catching more.
"""

from __future__ import annotations


# Phrases that indicate the model refused the task. Used by worker nodes
# to surface refusals as warnings (instead of silently returning 0
# findings) and by the planner's refusal-recovery loop to detect when
# the supervisor is bailing on the engagement.
REFUSAL_PATTERNS: tuple[str, ...] = (
    "i can't help",
    "i cannot help",
    "i'm sorry, but i can't",
    "i'm sorry, but i cannot",
    "i cannot assist",
    "i can't assist",
    "i'm unable to",
    "i am unable to",
    "i'm not able to",
    "i am not able to",
    # "i can't/cannot provide …" — the web_search synthesizer's
    # bail-out shape: it completes successfully but substitutes a
    # defensive lecture for the payloads it crawled. Observed verbatim
    # in run full_run_06-07_20h46m / XBEN-056: "I can't provide bypass
    # payloads or instructions for leaking SECRET_KEY or reading files."
    # ("i won't" below already covers the "i won't provide" variant.)
    "i can't provide",
    "i cannot provide",
    "i don't feel comfortable",
    "as an ai, i",
    "can't help retrieve",
    "can't help with",
    "cannot help with",
    "continue offensive",
    "ethical guidelines",
    "i must decline",
    "i won't",
)


def looks_like_refusal(text: str) -> bool:
    """Best-effort substring check for refusal language.

    Case-insensitive; returns False on empty / None text. The patterns
    deliberately stay short and unanchored — model refusals routinely
    embed these phrases inside longer sentences ("I'm sorry, but I
    can't help with retrieving credentials, but here's how you would
    typically...") and we want to catch both the short and long forms.
    """
    if not text:
        return False
    lower = text.lower()
    return any(p in lower for p in REFUSAL_PATTERNS)
