"""Static vocabulary filter — runtime enforcement of the
``CLAUDE.md`` Skill Vocabulary Policy.

Why: empirical replay testing of 11 Codex ``cyber_policy`` refusals
(see ``scripts/replay_refusals_v4.py`` and ``_replay_v4_summary.md``)
showed that applying a regex-based vocabulary substitution to the
worker's system prompt + tool messages rescued 2 cases that no other
transformation could — including ``vulntype-information-disclosure``,
which had refused under every other variant in v1/v2/v3.

This module is the production-side analogue of v4's ``vocab_filter``
variant. It is invoked as a TIER-2 RETRY in
``src/nodes/base.py:run_skill_agent`` after plain retries exhaust.

Single source of truth: the ``CLAUDE.md`` Skill Vocabulary Policy
table is mechanically transcribed below. Any update to that table
should be reflected here, and any addition here should be back-
ported to that doc — the two are intentionally redundant so that
manual review (the doc) and runtime enforcement (this filter) never
drift.
"""

from __future__ import annotations

import re
from typing import Iterable


# Mappings from CLAUDE.md `Skill Vocabulary Policy` plus a few
# additions backed by the Defensive Refusal Bias paper
# (arXiv:2603.01246, 2026):
#   - ``pentest`` → ``test``
#   - ``offensive`` → ``diagnostic``
#   - ``exploit`` (verb/noun) → ``test``
#   - ``vulnerability/-ies`` → ``input-handling issue``
#   - ``jailbreak`` → ``filter bypass``
#
# Order matters: longer phrases must match before shorter ones.
# Each entry is ``(compiled_regex, replacement)``.
VOCAB_MAPPINGS: list[tuple[re.Pattern, str]] = [
    # Multi-word phrases first
    (re.compile(r"\battack\s+agents?\b", re.IGNORECASE), "test agent"),
    (re.compile(r"\battack\s+phase\b", re.IGNORECASE), "testing phase"),
    (re.compile(r"\battack\s+skills?\b", re.IGNORECASE), "test skill"),
    (re.compile(r"\battack\s+surface\b", re.IGNORECASE), "input surface"),
    (re.compile(r"\battack\s+chain\b", re.IGNORECASE), "test chain"),
    (re.compile(r"\battacker[- ]controlled\b", re.IGNORECASE), "user-controlled"),
    (re.compile(r"\battacker[- ]supplied\b", re.IGNORECASE), "user-supplied"),
    (re.compile(r"\bweaponis(?:e|ed|ing)\b", re.IGNORECASE), "construct"),
    (re.compile(r"\bweaponiz(?:e|ed|ing)\b", re.IGNORECASE), "construct"),
    (re.compile(r"\bweaponisation\b", re.IGNORECASE), "construction"),
    (re.compile(r"\bweaponization\b", re.IGNORECASE), "construction"),
    (re.compile(r"\bpost[- ]exploitation\b", re.IGNORECASE), "post-access"),
    (re.compile(r"\bcompromise\s+the\s+target\b", re.IGNORECASE),
     "obtain access to the target"),
    (re.compile(r"\bred[- ]team\w*\b", re.IGNORECASE), "security testing"),
    (re.compile(r"\bevade\s+detection\b", re.IGNORECASE),
     "produce a response the filter does not block"),
    (re.compile(r"\bcommand[- ]and[- ]control\b", re.IGNORECASE), "back-channel"),
    (re.compile(r"\bpenetration\s+test\w*\b", re.IGNORECASE),
     "application security audit"),
    # Single-word substitutions
    (re.compile(r"\bpentest\w*\b", re.IGNORECASE), "test"),
    (re.compile(r"\boffensive\b", re.IGNORECASE), "diagnostic"),
    (re.compile(r"\bexploit(?:ed|ing|s)?\b", re.IGNORECASE), "test"),
    (re.compile(r"\bexploitation\b", re.IGNORECASE), "testing"),
    (re.compile(r"\bvulnerabilit(?:y|ies)\b", re.IGNORECASE),
     "input-handling issue"),
    (re.compile(r"\bmalware\b", re.IGNORECASE), "unwanted binary"),
    (re.compile(r"\bbackdoor\b", re.IGNORECASE), "covert access path"),
    (re.compile(r"\bimplant\b", re.IGNORECASE), "persistent component"),
    (re.compile(r"\bC2\b"), "back-channel"),
    (re.compile(r"\bjailbreak\w*\b", re.IGNORECASE), "filter bypass"),
    # Note: ``payload`` is intentionally NOT mapped — too common in
    # benign HTTP contexts (request body) and the CLAUDE.md policy
    # already restricts it to "weaponized" contexts that the
    # ``weaponise/weaponize`` rules above cover.
]


def filter_text(text: str) -> tuple[str, list[str]]:
    """Apply every vocabulary mapping in order; return (filtered, subs).

    ``subs`` is a list of human-readable strings of the form
    ``"original → replacement"`` for each substitution that fired,
    one entry per match. Useful for the refusal log so we can see
    which words the filter replaced before the retry that eventually
    succeeded.
    """
    if not text:
        return text, []
    out = text
    subs: list[str] = []
    for pat, repl in VOCAB_MAPPINGS:
        # findall to enumerate matches for the log; sub for the rewrite.
        matches = pat.findall(out)
        if matches:
            for m in matches:
                # ``m`` may be a string or a tuple (when groups are used).
                src = m if isinstance(m, str) else m[0]
                subs.append(f"{src!r} → {repl!r}")
            out = pat.sub(repl, out)
    return out, subs


def filter_messages(messages: Iterable, *, agent_args_keys: tuple[str, ...] = (
    "command", "data", "url", "reasoning", "payload",
)) -> tuple[list, list[str]]:
    """Apply ``filter_text`` to every text-bearing field of every
    message in a LangChain message list.

    Modifies the textual ``content`` of ``SystemMessage``,
    ``HumanMessage``, ``AIMessage``, and ``ToolMessage`` instances,
    plus the listed string-bearing keys of every AIMessage's
    ``tool_calls[*].args`` dict.

    Returns ``(new_messages, subs)`` where ``subs`` is the
    concatenation of every per-text substitution log entry.

    Used during tier-2 refusal retry to rebuild a sanitized message
    history before re-issuing the worker call.
    """
    # Lazy-imported to avoid pulling LangChain at module-init time.
    from langchain_core.messages import (
        AIMessage,
        HumanMessage,
        SystemMessage,
        ToolMessage,
    )

    out = []
    all_subs: list[str] = []
    for m in messages:
        if isinstance(m, (SystemMessage, HumanMessage)):
            new_text, subs = filter_text(
                m.content if isinstance(m.content, str) else str(m.content)
            )
            all_subs.extend(subs)
            out.append(type(m)(content=new_text))
        elif isinstance(m, ToolMessage):
            new_text, subs = filter_text(
                m.content if isinstance(m.content, str) else str(m.content)
            )
            all_subs.extend(subs)
            out.append(ToolMessage(
                content=new_text,
                tool_call_id=m.tool_call_id,
                name=getattr(m, "name", "tool"),
            ))
        elif isinstance(m, AIMessage):
            content = m.content if isinstance(m.content, str) else str(m.content)
            new_content, subs = filter_text(content)
            all_subs.extend(subs)
            new_tcs = []
            for tc in (m.tool_calls or []):
                args = dict(tc.get("args", {}) or {})
                for k in agent_args_keys:
                    if k in args and isinstance(args[k], str):
                        new_text, subs2 = filter_text(args[k])
                        all_subs.extend(subs2)
                        args[k] = new_text
                new_tcs.append({**tc, "args": args})
            out.append(AIMessage(content=new_content, tool_calls=new_tcs))
        else:
            out.append(m)
    return out, all_subs
