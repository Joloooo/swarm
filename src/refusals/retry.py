"""Tiered refusal retry ladder — wraps ``agent.astream`` with the
production refusal-recovery chain.

When a worker LLM call raises ``CodexCyberPolicyError`` or
``CodexInvalidPromptError``, the API has refused at the safety layer
before any tool call happened. This module retries the call across
two tiers:

  Tier 1: plain retry × N (default 3) — handles the classifier's
          near-threshold non-determinism. Empirical replay sweeps
          (``scripts/replay_refusals_v{2,3,4}.py``, ~150 calls)
          confirmed plain retry rescues 4-5 of 11 refused cases.

  Tier 2: vocabulary filter retry × 1 — applies the runtime
          verb-policy filter (CLAUDE.md table, implemented in
          ``src/refusals/vocabulary.py``) to the system prompt and
          seed messages, then retries once. Rescued 2 unique cases
          in the v4 sweep that no other transform could.

On all-tiers-exhaust, re-raises the last refusal exception. The
caller (``src/nodes/base/skill_runner.py:run_skill_agent``) catches it, logs to
``refusals.jsonl``, and runs the post-crash flag salvage path.

Non-refusal exceptions propagate unchanged so the existing
crash-recovery / salvage path stays intact.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from src.nodes.base import AgentConfig


async def astream_with_refusal_retry(
    *,
    agent_factory: Callable[[str], Any],
    system_msg: str,
    seed_msgs: list,
    call_config: dict,
    config: "AgentConfig",
    log: logging.Logger,
    max_plain_retries: int = 2,
) -> tuple[dict | None, int, str]:
    """Run agent.astream with tiered refusal retry.

    Args:
        agent_factory: callable taking the system prompt and returning
            a freshly-built LangChain agent. Called once per tier so
            the vocab-filtered system prompt can be applied cleanly.
        system_msg: the worker's full system prompt, used unchanged
            in tier 1 and vocabulary-rewritten in tier 2.
        seed_msgs: the initial message list (web-search context,
            prior-history block, the human task), used unchanged in
            tier 1 and vocabulary-rewritten in tier 2.
        call_config: LangChain RunnableConfig forwarded to ``astream``
            so the token-logging callback fires for every LLM call.
        config: the worker's ``AgentConfig`` — only used for the
            ``agent_id`` in log messages.
        log: per-node logger so the retry events appear under the
            node's namespace (``node.executor`` etc.).
        max_plain_retries: how many additional plain attempts after
            the first. Default 2 → 3 plain attempts total before
            tier 2 fires.

    Returns:
        ``(last_snapshot, total_attempts, last_tier_used)`` on success.
        ``last_snapshot`` is the final state value yielded by
        ``astream``; ``total_attempts`` counts every call across both
        tiers; ``last_tier`` is ``"plain"`` or ``"vocab_filter"``.

    Raises:
        The last refusal exception after all tiers exhaust. Two
        attributes are attached to the exception before re-raising
        so the catch site can read them:

          - ``e._swarm_attempts`` — total attempts across all tiers
          - ``e._swarm_last_tier`` — ``"plain"`` or ``"vocab_filter"``

        Without this, the catch site's locals stay at their initial
        values (0 / "plain") because tuple-unpacking the helper's
        return never fires when the helper raises. Verified
        empirically in run-XBEN-006-24__2026-05-10_23h13m42s where
        the first ``refusals.jsonl`` row showed ``attempts_made: 0``
        despite 4 actual attempts in the log.

        Non-refusal exceptions propagate unchanged.
    """
    # Lazy imports — keep cold worker startup cheap and avoid
    # circular-import issues at module-load time.
    from src.llm.codex import (
        CodexCyberPolicyError,
        CodexInvalidPromptError,
    )
    REFUSAL_EXCS = (CodexCyberPolicyError, CodexInvalidPromptError)

    last_snapshot: dict | None = None
    last_exc: Exception | None = None
    total_attempts = 0
    last_tier = "plain"

    # Track per-tier "have we dumped yet" so the live refused-prompt
    # render fires once per tier instead of once per retry. Tier-1
    # plain retries reuse the same seed_msgs / system_msg, so the 3
    # attempts produce near-identical inputs — dumping all of them
    # would just spam the terminal with duplicate red walls.
    tier_dumped = {"plain": False, "vocab_filter": False}

    def _dump_to_live(exc: BaseException, tier: str) -> None:
        if tier_dumped.get(tier):
            return
        req = getattr(exc, "_swarm_request", None)
        if req is None:
            return
        tier_dumped[tier] = True
        # Lazy import keeps the refusals package free of an
        # observability dependency at module-load time.
        try:
            from src.observability.live import LIVE
            LIVE.refused_prompt(
                agent=config.agent_id, tier=tier, request=req,
            )
        except Exception:  # noqa: BLE001
            # Observability is best-effort — never let a broken
            # renderer mask the actual refusal exception we're
            # about to re-raise.
            pass

    # ── Tier 1: plain retry ─────────────────────────────────────
    agent = agent_factory(system_msg)
    for attempt in range(max_plain_retries + 1):
        total_attempts += 1
        try:
            async for snap in agent.astream(
                {"messages": seed_msgs},
                config=call_config,
                stream_mode="values",
            ):
                last_snapshot = snap
            # Success.
            return last_snapshot, total_attempts, last_tier
        except REFUSAL_EXCS as e:
            last_exc = e
            log.warning(
                "[%s] worker refused (tier=plain, attempt=%d/%d): %s",
                config.agent_id, attempt + 1,
                max_plain_retries + 1, str(e)[:160],
            )
            # Dump the offending request payload on the FIRST refusal
            # of this tier — see ``tier_dumped`` comment above for why
            # we don't repeat it on subsequent identical retries.
            _dump_to_live(e, "plain")
            if attempt < max_plain_retries:
                await asyncio.sleep(1.5)
                continue
            # exhausted plain tier, fall through to tier 2
        # any non-refusal exception propagates

    # ── Tier 2: vocabulary filter retry ────────────────────────
    from src.refusals.vocabulary import filter_messages, filter_text
    filtered_sys, sys_subs = filter_text(system_msg)
    filtered_seed, seed_subs = filter_messages(seed_msgs)
    if sys_subs or seed_subs:
        log.info(
            "[%s] tier-2 retry with %d sys + %d seed vocab "
            "substitutions",
            config.agent_id, len(sys_subs), len(seed_subs),
        )
    else:
        log.info(
            "[%s] tier-2 retry: no vocab substitutions matched "
            "(skill may already be neutral)",
            config.agent_id,
        )

    last_tier = "vocab_filter"
    total_attempts += 1
    agent = agent_factory(filtered_sys)
    try:
        async for snap in agent.astream(
            {"messages": filtered_seed},
            config=call_config,
            stream_mode="values",
        ):
            last_snapshot = snap
        return last_snapshot, total_attempts, last_tier
    except REFUSAL_EXCS as e:
        last_exc = e
        log.warning(
            "[%s] worker refused (tier=vocab_filter, attempt=%d): %s",
            config.agent_id, total_attempts, str(e)[:160],
        )
        # Dump the vocab-filtered payload too — its substitutions can
        # be the difference between a refusal and a success, so seeing
        # the actual filtered text in the terminal lets the operator
        # judge whether the policy is being trained against neutral
        # wording or whether more rewrites are needed.
        _dump_to_live(e, "vocab_filter")

    # All tiers exhausted — surface the last refusal so the outer
    # except in ``run_skill_agent`` runs its existing logging /
    # flag-salvage logic.
    assert last_exc is not None
    try:
        last_exc._swarm_attempts = total_attempts  # type: ignore[attr-defined]
        last_exc._swarm_last_tier = last_tier  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        # Some exception classes use ``__slots__``; falling back
        # to the locals at the call site is acceptable.
        pass
    raise last_exc
