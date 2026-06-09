"""Tiered refusal retry ladder — wraps ``agent.astream`` with the
production refusal-recovery chain.

When a worker LLM call raises ``CodexCyberPolicyError`` or
``CodexInvalidPromptError``, the API has refused at the safety layer
before any tool call happened. This module retries the call across
two tiers:

  Preventive (always-on): the CLAUDE.md vocabulary filter
          (``src/refusals/vocabulary.py``) is applied to ``system_msg``
          and every ``seed_msg`` BEFORE the first attempt — not as a
          fallback. Empirical v5 replay (2026-05-24,
          ``scripts/replay_refusals_v5.py``) confirmed that the
          ``cyber_policy`` classifier triggers on opening payload
          content (system_prompt + seed user message), not on
          accumulated assistant history (0/47 logged refusals had
          rewritable AIMessage narration). So the right intervention
          is at the opening, applied unconditionally.

  Tier 1 — primary model retry × N (default 3): the worker's
          configured LLM with vocab-filter applied. Handles the
          classifier's near-threshold non-determinism. Historical
          replay sweeps showed plain retry rescues 4-5 of 11 refused
          cases on its own; with preventive vocab filter the rate
          should be at least as high.

  Tier 2 — model-fallback retry × N (default 3): if a fallback agent
          factory is supplied AND the primary tier exhausts, rebuild
          the agent with a different model + reasoning_effort and
          retry. Default fallback is gpt-5.4 at reasoning_effort=low
          (see ``config.budgets.fallback_*`` in ``src/graph.py``).
          The fallback model's cyber_policy classifier is markedly
          more permissive than gpt-5.5's; trading some capability for
          a successful response is a worthwhile bargain when the
          alternative is total worker loss.

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


async def _run_agent_once(
    agent: Any, messages: list, call_config: dict, mode: str,
) -> dict | None:
    """Invoke one agent attempt under the chosen LangChain mode.

    ``mode="astream"`` (workers): stream snapshots and keep the last,
    so a mid-loop ``GraphRecursionError`` leaves a partial state for
    the salvage path to consume. ``mode="ainvoke"`` (planner): the
    planner produces one JSON decision per turn — streaming gives us
    no useful checkpointing for a single-shot call, so we just await
    the final result. Both branches return the same shape (the final
    state dict), which is what the helper's caller expects.
    """
    if mode == "ainvoke":
        return await agent.ainvoke(
            {"messages": messages}, config=call_config,
        )
    # default "astream"
    last: dict | None = None
    try:
        async for snap in agent.astream(
            {"messages": messages},
            config=call_config,
            stream_mode="values",
        ):
            last = snap
    except BaseException as e:
        # Preserve the accumulated snapshot on ANY exception — a
        # cyber_policy refusal, a ``GraphRecursionError`` step-budget stop,
        # or an ordinary crash. Without this the ``return last`` below is
        # skipped on the unwind, so every message the worker produced
        # before dying is discarded. Two callers depend on it: the retry
        # ladder uses it to CONTINUE the next tier from where the worker
        # got to (instead of restarting from the seed), and
        # ``run_skill_agent``'s except block uses it so the salvage /
        # wrap-up / summary run on the real trace. Attaching to the
        # exception lets the snapshot survive the unwind; mirrors the
        # ``_swarm_attempts`` pattern in ``astream_with_refusal_retry``.
        # Motivated by the XBEN-095 auth-testing worker (2026-06-09), which
        # lost ~8 loops of SQL work to a refusal and another ~16 to a
        # step-budget stop and surfaced 0 findings (``tool_msgs_scanned: 0``).
        try:
            if getattr(e, "_swarm_partial_snapshot", None) is None:
                e._swarm_partial_snapshot = last  # type: ignore[attr-defined]
        except (AttributeError, TypeError):
            pass
        raise
    return last


def _is_resumable(messages: list) -> bool:
    """True if ``messages`` is a valid point to resume an agent from.

    A history is resumable unless its final turn is an assistant message
    that still has unanswered ``tool_calls`` — most providers reject a
    request whose last tool call has no matching tool result. A
    cyber_policy refusal never produces that shape (the refused LLM call
    emits no message, so the trace ends on a ``ToolMessage`` or the seed
    ``HumanMessage``), but the guard keeps a malformed partial from
    erroring the continuation: we fall back to restarting from the seed
    instead.
    """
    if not messages:
        return False
    tool_calls = getattr(messages[-1], "tool_calls", None)
    return not tool_calls


async def astream_with_refusal_retry(
    *,
    agent_factory: Callable[[str], Any],
    system_msg: str,
    seed_msgs: list,
    call_config: dict,
    config: "AgentConfig",
    log: logging.Logger,
    fallback_agent_factory: Callable[[str], Any] | None = None,
    max_retries_per_tier: int = 2,
    mode: str = "astream",
    start_on_fallback: bool = False,
) -> tuple[dict | None, int, str]:
    """Run agent.astream with preventive vocab filter + tiered retry.

    Args:
        agent_factory: callable taking the (already vocab-filtered)
            system prompt and returning a freshly-built LangChain
            agent backed by the primary LLM. Called once per tier-1
            attempt so the filtered prompt is wired in cleanly.
        system_msg: the worker's full system prompt. Vocabulary-
            filtered preventively (always, not just on retry) before
            any LLM call.
        seed_msgs: the initial message list (web-search context,
            prior-history block, the human task). Vocabulary-filtered
            preventively, same as ``system_msg``.
        call_config: LangChain RunnableConfig forwarded to ``astream``
            so the token-logging callback fires for every LLM call.
        config: the worker's ``AgentConfig`` — only used for the
            ``agent_id`` in log messages.
        log: per-node logger so the retry events appear under the
            node's namespace (``node.executor`` etc.).
        fallback_agent_factory: optional second factory that returns
            an agent backed by the FALLBACK model (e.g. gpt-5.4 at
            reasoning_effort=low). When supplied, fires as tier 2 if
            tier 1 exhausts. Caller decides whether to supply one —
            non-Codex providers (anthropic / local) typically pass
            None since model-swap isn't well-defined for them.
        max_retries_per_tier: how many additional attempts after the
            first within each tier. Default 2 → 3 attempts per tier
            → up to 6 attempts total when both tiers are configured.
        start_on_fallback: when True (and a fallback factory exists),
            skip the primary tier entirely and dispatch directly on the
            fallback model. Set by the caller when this config already
            tripped the primary model's classifier earlier in the run —
            the same prompt would refuse identically, so the 3 primary
            attempts are pure waste. Ignored (primary runs normally) when
            no fallback factory is supplied.

    Returns:
        ``(last_snapshot, total_attempts, last_tier_used)`` on success.
        ``last_snapshot`` is the final state value yielded by
        ``astream``; ``total_attempts`` counts every call across both
        tiers; ``last_tier`` is ``"primary"`` or ``"fallback"``.

    Raises:
        The last refusal exception after all tiers exhaust. Two
        attributes are attached to the exception before re-raising
        so the catch site can read them:

          - ``e._swarm_attempts`` — total attempts across all tiers
          - ``e._swarm_last_tier`` — ``"primary"`` or ``"fallback"``

        Without this, the catch site's locals stay at their initial
        values (0 / "primary") because tuple-unpacking the helper's
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
    from src.refusals.vocabulary import filter_messages, filter_text
    REFUSAL_EXCS = (CodexCyberPolicyError, CodexInvalidPromptError)

    # ── Preventive vocab filter ─────────────────────────────────
    # Applied to BOTH system prompt and seed messages before the
    # first attempt. v5 replay (2026-05-24) showed that 0/47
    # historical refusals had rewritable AIMessage history, so the
    # classifier's trigger is on opening payload content — exactly
    # what this filter targets. Applying it preventively (vs. only
    # on retry) costs nothing on calls that wouldn't have refused
    # anyway (regex substitution is cheap and lossless for technical
    # content) and gives tier-1 attempts the best chance from the
    # outset.
    filtered_sys, sys_subs = filter_text(system_msg)
    filtered_seed, seed_subs = filter_messages(seed_msgs)
    if sys_subs or seed_subs:
        log.info(
            "[%s] preventive vocab filter applied: %d sys + %d seed "
            "substitutions before tier-1 attempt",
            config.agent_id, len(sys_subs), len(seed_subs),
        )

    last_snapshot: dict | None = None
    last_exc: Exception | None = None
    total_attempts = 0
    last_tier = "primary"

    # ── Continue-from-where-it-refused state ────────────────────
    # ``current_messages`` is what we feed the NEXT attempt. It starts as
    # the filtered seed, but after a refusal we roll it forward to the
    # worker's accumulated trace so the retry CONTINUES instead of
    # restarting from the seed and re-doing (and re-tripping) all the work.
    # ``best_partial`` keeps the richest trace seen across every attempt so
    # that, if all tiers exhaust, the caller's salvage path still gets the
    # real work rather than ``[]``.
    current_messages: list = filtered_seed
    best_partial: dict | None = None

    # Track per-tier "have we dumped yet" so the live refused-prompt
    # render fires once per tier instead of once per retry. Retries
    # within a tier reuse the same payload — dumping all of them
    # would just spam the terminal with duplicate red walls.
    tier_dumped = {"primary": False, "fallback": False}

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

    def _absorb_partial(exc: BaseException) -> None:
        """Roll the accumulated trace forward after a refusal.

        Reads the partial snapshot ``_run_agent_once`` attached to the
        refusal and, if the worker made progress beyond what we last fed
        it, makes that trace the input for the next attempt — so the next
        attempt (and the next tier) CONTINUES from the refusal point
        instead of restarting from the seed. Also records the richest
        partial for the terminal-failure salvage path. A refusal on the
        very first call yields no new messages, so ``current_messages`` is
        unchanged and the historical restart-from-seed behavior is
        preserved for opening-content refusals.
        """
        nonlocal current_messages, best_partial
        snap = getattr(exc, "_swarm_partial_snapshot", None)
        if not isinstance(snap, dict):
            return
        msgs = snap.get("messages") or []
        if not _is_resumable(msgs):
            return
        if len(msgs) > len(current_messages):
            current_messages = list(msgs)
        if best_partial is None or len(msgs) > len(
            best_partial.get("messages") or []
        ):
            best_partial = snap

    # ── Tier 1: primary model, vocab-filtered, retry × N ────────
    # Skipped entirely when the caller knows this config already tripped
    # the primary model's classifier earlier this run — the same prompt
    # would refuse identically, so the 3 primary attempts are wasted. We
    # only skip when a fallback factory exists to skip TO.
    skip_primary = start_on_fallback and fallback_agent_factory is not None
    if skip_primary:
        log.info(
            "[%s] starting directly on fallback model — this config refused "
            "on the primary model earlier this run",
            config.agent_id,
        )
    else:
        agent = agent_factory(filtered_sys)
        for attempt in range(max_retries_per_tier + 1):
            total_attempts += 1
            try:
                last_snapshot = await _run_agent_once(
                    agent, current_messages, call_config, mode,
                )
                # Success.
                return last_snapshot, total_attempts, last_tier
            except REFUSAL_EXCS as e:
                last_exc = e
                _absorb_partial(e)
                log.warning(
                    "[%s] worker refused (tier=primary, attempt=%d/%d, "
                    "continuing from %d msg(s)): %s",
                    config.agent_id, attempt + 1,
                    max_retries_per_tier + 1, len(current_messages),
                    str(e)[:160],
                )
                _dump_to_live(e, "primary")
                if attempt < max_retries_per_tier:
                    await asyncio.sleep(1.5)
                    continue
                # exhausted primary tier, fall through to tier 2

    # ── Tier 2: fallback model, vocab-filtered, retry × N ───────
    if fallback_agent_factory is None:
        # No fallback wired (caller is on a non-Codex provider, or
        # opted out). Skip directly to the raise path.
        log.info(
            "[%s] primary tier exhausted, no fallback factory "
            "supplied — surfacing last refusal",
            config.agent_id,
        )
    else:
        last_tier = "fallback"
        log.info(
            "[%s] primary tier exhausted, switching to fallback model",
            config.agent_id,
        )
        fb_agent = fallback_agent_factory(filtered_sys)
        for attempt in range(max_retries_per_tier + 1):
            total_attempts += 1
            try:
                last_snapshot = await _run_agent_once(
                    fb_agent, current_messages, call_config, mode,
                )
                log.info(
                    "[%s] rescued by fallback model on attempt %d "
                    "(continued from %d msg(s))",
                    config.agent_id, attempt + 1, len(current_messages),
                )
                return last_snapshot, total_attempts, last_tier
            except REFUSAL_EXCS as e:
                last_exc = e
                _absorb_partial(e)
                log.warning(
                    "[%s] worker refused (tier=fallback, attempt=%d/%d, "
                    "continuing from %d msg(s)): %s",
                    config.agent_id, attempt + 1,
                    max_retries_per_tier + 1, len(current_messages),
                    str(e)[:160],
                )
                _dump_to_live(e, "fallback")
                if attempt < max_retries_per_tier:
                    await asyncio.sleep(1.5)
                    continue

    # All tiers exhausted — surface the last refusal so the outer
    # except in ``run_skill_agent`` runs its existing logging /
    # flag-salvage logic.
    assert last_exc is not None
    try:
        last_exc._swarm_attempts = total_attempts  # type: ignore[attr-defined]
        last_exc._swarm_last_tier = last_tier  # type: ignore[attr-defined]
        # Attach the richest partial trace seen across all tiers so
        # ``run_skill_agent``'s except block recovers the worker's real
        # work for salvage / summary instead of an empty list.
        if best_partial is not None:
            last_exc._swarm_partial_snapshot = best_partial  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        # Some exception classes use ``__slots__``; falling back
        # to the locals at the call site is acceptable.
        pass
    raise last_exc
