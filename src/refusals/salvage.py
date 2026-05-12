"""Post-crash salvage — extract a Finding from a worker that died mid-task.

Why this exists
---------------

When a worker (``recon`` / ``executor``'s ``run_skill_agent``) hits the
LangGraph ``recursion_limit`` mid-loop, or its provider raises a
refusal once every retry tier in :mod:`src.refusals.retry` has
exhausted, the LangChain ``create_agent`` graph raises and the parent's
``except`` returns ``0 findings, 0/1 agents ok``. From the planner's
point of view, the worker contributed nothing — even if its scratchpad
demonstrably popped the box.

Concrete example from a real run (XBEN-006-24, 2026-05-04 08:12):

  - ``owasp-recon`` ran 6 batches of probes and found a ``private`'--``
    SQLi confirmation against ``/jobs`` returning the hidden record
    with what looked like a flag-bearing description.
  - On the 7th iteration it hit ``Recursion limit of 20 reached``.
  - The crash handler returned ``error="Recursion limit"`` and
    ``findings=[]``.
  - The planner, blind to the SQLi proof, fanned out a generic
    ``custom-flag-hunt-disclosure`` worker on the next turn — wasted
    six minutes and the rest of the bench timeout.

The salvage path runs whenever the worker crashes with a non-empty
message scratchpad. It pulls the last few ``ToolMessage`` /
``AIMessage`` blocks, sends them to a focused sub-LLM, and asks "did
this scratchpad demonstrate impact? if yes, fill in this Finding
schema." Anything that comes back gets merged into the worker's
``AgentResult`` and stamped ``[salvaged from crashed worker]`` so a
human reading the report can tell the finding was reconstructed
post-hoc rather than emitted by the worker itself.

Why this lives in ``refusals/``
-------------------------------

In production, the dominant trigger for the partial-trace path is the
refusal cascade — Codex ``cyber_policy`` refusals exhausting the tier
ladder, or recursion limits hit because the model kept stalling under
refusal pressure. The recursion-limit example above is real but
uncommon; refusal-driven crashes are the default. Co-locating the
salvage logic with the rest of the refusal-handling package keeps the
post-failure recovery path together: ``recover.py`` for mid-flight
rescue (proposing the next probe), ``salvage.py`` for post-crash
recovery (extracting impact from what was already done).

Cost model
----------

One sub-LLM call per crashed worker. The prompt is bounded in size
(last ~6 ToolMessages, each clipped to 1.5 KB → ~9 KB scratchpad
plus a small instruction header), so the cost is fixed and small
relative to the ~30 calls a typical worker makes. Refusals on the
salvage call itself are caught and treated as "no finding" so the
crash path stays graceful.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, TYPE_CHECKING

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from src.state import Finding, Severity

if TYPE_CHECKING:
    from src.nodes.base import AgentConfig

logger = logging.getLogger(__name__)


# ── Heuristics on the partial trace ──────────────────────────────────────


# Inputs that, when echoed back inside a 5xx response or with a
# ``flag`` / ``FLAG{`` substring, are strong evidence of impact. Used as
# a fast pre-filter so we don't burn an LLM call on a worker trace that
# clearly contained nothing interesting.
_IMPACT_HINTS = (
    "flag{",
    "FLAG{",
    " 200 ", "200 OK",
    "private",
    "union",
    "UNION",
    "select", "SELECT",
    "1=1",
    "'--",
    "\"--",
    " or '",
    "secret",
    "admin",
    "root",
)


def looks_worth_salvaging(messages: list[Any], *, max_tail: int = 12) -> bool:
    """Cheap pre-check before paying for a salvage LLM call.

    Returns True iff the most-recent ``max_tail`` ToolMessages contain
    any of :data:`_IMPACT_HINTS`. The heuristic is intentionally loose:
    false positives just mean we waste one extra LLM call, false
    negatives lose findings we could have salvaged. The bias is toward
    false positives.
    """
    seen = 0
    for msg in reversed(messages):
        if not isinstance(msg, ToolMessage):
            continue
        seen += 1
        content = (
            msg.content if isinstance(msg.content, str) else str(msg.content)
        )
        if any(h in content for h in _IMPACT_HINTS):
            return True
        if seen >= max_tail:
            break
    # Even without a hit, salvage if the trace is large — empty-output
    # tool calls can still represent a confirmed finding (e.g. a
    # successful POST whose response body was suppressed).
    return seen >= 6


# ── Prompt construction ─────────────────────────────────────────────────


_SALVAGE_SYSTEM = (
    "You are a security testing assistant helping classify the partial "
    "trace of a worker that crashed mid-task. The worker hit its "
    "iteration limit and was unable to formalize whatever it had found. "
    "Your job is to read the last few tool-call observations and decide "
    "whether the trace demonstrates a security finding."
    "\n\n"
    "Output strictly one JSON object on a single line, no prose, no "
    "code fences. Use exactly this schema:"
    "\n\n"
    '  {"impact": true|false, "severity": "critical"|"high"|"medium"|"low"|"info", '
    '"category": "<short slug like sqli/xss/idor/info-disclosure>", '
    '"title": "<single-sentence summary>", '
    '"url": "<the URL the impact was demonstrated against, or empty>", '
    '"description": "<2-4 sentence explanation>", '
    '"evidence": "<the most-relevant request/response excerpt, '
    'verbatim, max 800 chars>"}'
    "\n\n"
    "If there's no evidence of impact, output exactly: "
    '{"impact": false}'
)


def _format_tail(messages: list[Any], *, n: int = 8) -> str:
    """Render the trailing N tool/assistant messages as a single block.

    Keeps each ToolMessage ≤ 1500 chars so a noisy nmap output can't
    blow up the salvage prompt. AIMessage narrative content (the
    model's reasoning between tool calls) is kept too because the
    "I just got the flag" thought sometimes appears there before
    the agent crashes mid-formalization.
    """
    tail: list[str] = []
    seen = 0
    for msg in reversed(messages):
        if isinstance(msg, ToolMessage):
            content = (
                msg.content if isinstance(msg.content, str) else str(msg.content)
            )
            tool_name = getattr(msg, "name", "tool") or "tool"
            tail.append(f"### tool[{tool_name}]\n{content[:1500]}")
            seen += 1
        elif isinstance(msg, AIMessage):
            content = (
                msg.content if isinstance(msg.content, str) else str(msg.content)
            )
            if content.strip():
                tail.append(f"### assistant\n{content[:1200]}")
                seen += 1
        if seen >= n:
            break
    return "\n\n".join(reversed(tail))


# ── Sub-LLM call ────────────────────────────────────────────────────────


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_salvage_response(text: str) -> dict | None:
    """Pull the JSON object out of the LLM response.

    The system prompt asks for raw JSON, but Codex sometimes wraps it
    in ```json fences anyway. The regex matches the first {...} span,
    which is robust to fences, leading prose, and trailing newlines.
    Returns None if the JSON is malformed.
    """
    if not text:
        return None
    m = _JSON_BLOCK_RE.search(text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    return obj


_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}

# Cap salvaged severity by default — a salvaged finding hasn't been
# verified by a clean re-run of the worker, so even if the LLM thinks
# it saw "critical" we mark it ``high`` until a follow-up reproduces
# it. The planner can then still see and act on the signal without us
# overstating confidence in summary.md.
_SALVAGE_MAX_SEVERITY = Severity.HIGH


def _cap_severity(sev: Severity) -> Severity:
    if sev == Severity.CRITICAL:
        return _SALVAGE_MAX_SEVERITY
    return sev


async def salvage_finding(
    *,
    messages: list[Any],
    agent_id: str,
    methodology: str,
    config_name: str,
    llm: BaseChatModel,
    target_url: str = "",
    run_id: str | None = None,
) -> Finding | None:
    """Try to extract a Finding from the partial trace of a crashed worker.

    Steps:
        1. Pre-filter via :func:`looks_worth_salvaging` — skip the LLM
           call entirely when there's no plausible signal.
        2. Render the last 8 tool/assistant messages.
        3. One-shot LLM call with the strict-JSON schema in
           :data:`_SALVAGE_SYSTEM`.
        4. Parse, cap severity, stamp the title with
           ``[salvaged from crashed worker]``, return a ``Finding``.

    Returns ``None`` if any step fails (no signal, refusal, parse
    error, or impact=false). Logging is intentionally generous so a
    later reader can audit which crashed workers were salvaged and
    which weren't.
    """
    if not messages:
        logger.info("[%s] salvage skipped: no partial trace", agent_id)
        return None

    if not looks_worth_salvaging(messages):
        logger.info(
            "[%s] salvage skipped: no impact-hint substrings in tail",
            agent_id,
        )
        return None

    tail = _format_tail(messages)
    user_prompt = (
        "The worker's last tool observations are below. Decide whether "
        "they demonstrate a security finding and respond with the JSON "
        "schema described in the system prompt. Do NOT fabricate "
        "impact — if the trace is just enumeration with no working "
        "exploit, return {\"impact\": false}.\n\n"
        f"Target URL (for context): {target_url or 'unknown'}\n\n"
        "## Partial trace (most recent at bottom)\n\n"
        f"{tail}"
    )

    msgs = [
        SystemMessage(content=_SALVAGE_SYSTEM),
        HumanMessage(content=user_prompt),
    ]

    # Route the salvage call through the token logger so the recovery
    # cost shows up in llm_calls.jsonl. The synthetic agent_id
    # ``<agent_id>__salvage`` keeps it visually distinct from the
    # worker's main calls without losing the attribution chain.
    from src.llm.callbacks import make_call_config
    salvage_cfg = make_call_config(
        run_id=run_id,
        agent_id=f"{agent_id}__salvage",
        node="salvage",
    )

    try:
        resp = await llm.ainvoke(msgs, config=salvage_cfg)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "[%s] salvage sub-LLM call failed: %s: %s",
            agent_id, type(e).__name__, str(e)[:160],
        )
        return None

    raw = resp.content if isinstance(resp.content, str) else str(resp.content)
    parsed = _parse_salvage_response(raw)
    if parsed is None:
        logger.warning(
            "[%s] salvage response was not valid JSON: %s",
            agent_id, raw[:300],
        )
        return None

    if not parsed.get("impact"):
        logger.info("[%s] salvage: model says no impact in trace", agent_id)
        return None

    sev_str = str(parsed.get("severity") or "low").lower()
    severity = _SEVERITY_MAP.get(sev_str, Severity.LOW)
    severity = _cap_severity(severity)

    title_raw = str(parsed.get("title") or "(salvaged finding without title)")
    title = f"[salvaged from crashed worker] {title_raw}".strip()

    finding = Finding(
        title=title[:240],
        severity=severity,
        category=str(parsed.get("category") or config_name)[:64],
        description=str(parsed.get("description") or "")[:2000],
        evidence=str(parsed.get("evidence") or "")[:2400],
        agent_id=agent_id,
        url=str(parsed.get("url") or target_url or "")[:500],
        cwe="",
        reproduced=False,  # salvaged → not yet re-confirmed
    )
    logger.info(
        "[%s] salvaged a %s finding from crashed worker: %s",
        agent_id, severity.value, title_raw[:140],
    )
    return finding


async def try_salvage(
    *,
    config: "AgentConfig",
    partial_messages: list,
    target_url: str,
    log: logging.Logger,
    run_id: str | None = None,
) -> Finding | None:
    """Attempt to extract a Finding from a crashed worker's trace.

    Thin wrapper around :func:`salvage_finding` that:

    1. Instantiates a *fresh* LLM (each Codex call is already stateless
       on the wire, but instantiating a clean model here keeps the
       abstraction tidy if we ever swap providers per-task).
    2. Swallows any sub-LLM call failure so the crash path stays
       graceful regardless of whether the salvage attempt succeeded.

    Args:
        config: the worker's AgentConfig — used for ``agent_id``,
            ``methodology``, and ``config_name``.
        partial_messages: the worker's message scratchpad at the
            moment of the crash. Empty list short-circuits to None.
        target_url: pentest target, included as context in the
            salvage prompt.
        log: per-node logger so the warning landed here appears
            under the right node namespace.
        run_id: forwarded through to the LLM callback so the
            salvage call lands in ``llm_calls.jsonl``.

    Returns:
        The salvaged Finding on success, or None if the trace was
        empty, the salvage sub-LLM crashed, or no impact was found.
    """
    if not partial_messages:
        return None
    try:
        from src.llm.provider import get_llm
        llm = get_llm()
        return await salvage_finding(
            messages=partial_messages,
            agent_id=config.agent_id,
            methodology=config.methodology,
            config_name=config.config_name,
            llm=llm,
            target_url=target_url,
            run_id=run_id,
        )
    except Exception as e:  # noqa: BLE001
        log.warning(
            "[%s] salvage attempt itself crashed (%s): %s",
            config.agent_id, type(e).__name__, str(e)[:200],
        )
        return None
