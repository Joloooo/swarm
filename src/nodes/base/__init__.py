"""BaseNode — the framework every LangGraph node in SwarmAttacker inherits.

Every concrete node (PlannerNode, ReconNode, ReportNode, SummarizerNode,
WebSearchNode, ExecutorNode) inherits directly from ``BaseNode``.
There is no intermediate class. Cross-cutting capabilities — per-node
logger, skill lookup, the LLM-agent loop that used to live in
``make_agent_node`` — are methods on this base, so any node can call
them via ``self.<capability>``.

``__call__`` itself is instrumented: it times the node, catches
crashes and surfaces them as a visible ``❌`` AIMessage, appends a
boundary ``✅ [name] Xms — summary`` AIMessage so LangGraph Studio
chat shows continuous progress, writes one JSONL line per call to
``logs/run-<run_id>/nodes.jsonl`` for thesis-grade post-run analysis,
and streams a colored, mode-aware view to stderr via
:data:`src.observability.LIVE` (the ``compact``/``verbose``/``silent``
mode lives in ``config.verbosity.mode`` in ``src/graph.py``). None of
that needs per-subclass code — subclasses only override
:meth:`execute`. The graph wires nodes directly:
``graph.add_node("planner", PlannerNode())``.

Package layout:

- ``base/__init__.py`` (this file) — the ``BaseNode`` class itself.
  Also re-exports a few back-compat names (``AgentConfig``,
  ``IDENTITY_PREAMBLE``, ``REFUSAL_PATTERNS``, ``looks_like_refusal``,
  ``_looks_like_refusal``) so existing
  ``from src.nodes.base import X`` imports keep working.
- ``base/system_prompt.py`` — every ``*_RULES`` constant + the
  identity preamble + the system-prompt assembly function. The
  prompt the worker LLM agent sees comes from there.
- ``base/skill_runner.py`` — ``AgentConfig`` + ``run_skill_agent``
  (the worker lifecycle) + finding parsers + worker-memory helpers.

State-shape / diff / serialize helpers used by ``BaseNode.__call__``
to instrument each node finish live in ``src/observability/state.py``
and are imported in below. The "compute what to log" stays in
observability/ alongside "write what we computed" — keeping
nodes/base/ free of disk-shape concerns.

NB: ``src.llm.provider`` and ``src.skills.loader`` are imported lazily
inside the methods that need them. The cycle is
``skills.loader → nodes.base → llm.provider → graph → nodes →
nodes.base``; importing either at module level wedges the loader at
startup. ``src.observability`` is dependency-light (stdlib only) and
safe to import at module level.
"""

from __future__ import annotations

import logging
import re
import time
from abc import ABC, abstractmethod
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.llm.callbacks import make_call_config
from src.observability import (
    LIVE,
    make_run_id,
)
from src.observability.state import _summarize_node_result
from src.refusals.detect import REFUSAL_PATTERNS, looks_like_refusal
from src.refusals.recover import recover_from_refusal
from src.refusals.retry import astream_with_refusal_retry
from src.refusals.salvage import try_salvage

# Re-exported public API so existing call sites keep working unchanged.
from src.nodes.base.skill_runner import (
    AgentConfig,
    FINDING_PATTERN,
    JSON_FINDINGS_PATTERN,
    SEVERITY_MAP,
    _extract_findings,
    _findings_from_json,
    _findings_from_markdown,
)
from src.nodes.base.system_prompt import (
    BENCHMARK_PROGRESS_FOOTER,
    FINDING_FORMAT,
    IDENTITY_PREAMBLE,
    NARRATION_RULES,
    PENTESTING_RULES,
    STEALTH_RULES,
    get_base_prompt,
    get_executor_prompt,
    get_recon_prompt,
    get_universal_prompt,
)

# Back-compat alias: the old private name was ``_looks_like_refusal``.
_looks_like_refusal = looks_like_refusal

__all__ = [
    "AgentConfig",
    "BENCHMARK_PROGRESS_FOOTER",
    "BaseNode",
    "FINDING_FORMAT",
    "FINDING_PATTERN",
    "IDENTITY_PREAMBLE",
    "JSON_FINDINGS_PATTERN",
    "NARRATION_RULES",
    "PENTESTING_RULES",
    "REFUSAL_PATTERNS",
    "SEVERITY_MAP",
    "STEALTH_RULES",
    "_extract_findings",
    "_findings_from_json",
    "_findings_from_markdown",
    "_looks_like_refusal",
    "get_base_prompt",
    "get_executor_prompt",
    "get_recon_prompt",
    "get_universal_prompt",
    "looks_like_refusal",
]


# ────────────────────────────────────────────────────────────────────────────
# State-shape / diff / summary helpers — moved to
# ``src/observability/state.py``. We import what ``BaseNode.__call__``
# needs above and use it inline below; no duplicate definitions live
# in this file any more. Keeps "compute what to log + write it"
# entirely in observability/.
# ────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────
# BaseNode
# ────────────────────────────────────────────────────────────────────────────


class BaseNode(ABC):
    """Abstract base for every SwarmAttacker LangGraph node.

    Subclasses override :meth:`execute`. Instances are callable through
    :meth:`__call__`, which wraps :meth:`execute` with timing,
    crash-to-AIMessage conversion, JSONL run logging, optional
    `SWARM_VERBOSE` streaming, and a boundary message so Studio chat
    stays alive during long-running parallel work. Pass the instance
    straight to ``graph.add_node("planner", PlannerNode())`` — no
    further wrapping required.
    """

    def __init__(self, name: str | None = None) -> None:
        self.name = name or self._default_name()
        self.log = logging.getLogger(f"node.{self.name}")

    def _default_name(self) -> str:
        # ``WebSearchNode`` → ``web_search``; ``PlannerNode`` → ``planner``.
        cls = self.__class__.__name__.removesuffix("Node")
        if not cls:
            return self.__class__.__name__.lower()
        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls).lower()

    @abstractmethod
    async def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        """Subclasses implement node logic here."""

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """Run :meth:`execute` with cross-cutting instrumentation.

        Side effects per call:
            1. Append a boundary ``✅ [name] Xms — summary`` AIMessage
               to ``state.messages`` so Studio shows live progress.
            2. On crash, return a ``❌ [name] crashed`` AIMessage
               instead of propagating the exception (which would kill
               the whole graph).
            3. Stream a colored, mode-aware view of the node transition
               to stderr via :data:`src.observability.LIVE`. The
               ``compact`` / ``verbose`` / ``silent`` mode lives in
               ``config.verbosity.mode`` (see ``src/graph.py``); the
               renderer reads it on every call. The same line is
               teed (ANSI-stripped) to
               ``logs/run-<run_id>/displayed_terminal_logs.log``.

        ``run_id`` is read from state. If absent (e.g. Studio runs that
        bypass the runner), one is derived on the fly from target_url.

        Structured per-event logging lives in
        ``logs/run-<run_id>/full_logs.jsonl`` — one row per LLM call
        and one row per shell command, written by ``llm.callbacks`` and
        ``tools.shell._common.log_event`` respectively. The base class
        no longer maintains a separate ``nodes.jsonl`` shape diff:
        that artefact was never read in practice and the same
        information is reconstructable from ``full_logs.jsonl`` +
        ``displayed_terminal_logs.log``.
        """
        name = self.name
        run_id = (state or {}).get("run_id") or make_run_id(
            target_url=(state or {}).get("target_url"),
        )

        # Early-exit guard for nodes dispatched AFTER the flag has been
        # captured. State.captured_flag is set by the winning worker's
        # update; once it lands in state via the reducer, any node that
        # LangGraph schedules subsequently should bail out immediately
        # rather than burn another LLM call on work the routing edges
        # will discard.
        #
        # Does NOT help in-flight parallel siblings — they're already
        # running and won't re-enter ``__call__`` until they finish.
        # That cancellation path is handled by FlagWatcherCallback's
        # ``on_chat_model_start`` hook checking the module-global
        # ``_CAPTURED_FLAG``. The two mechanisms are complementary,
        # both required — see ``flag_watcher.py`` module docstring.
        if (state or {}).get("captured_flag"):
            self.log.info(
                "[%s] skipping node — flag already captured by a "
                "previous worker (graph will route to END via "
                "route_after_summarizer / route_after_planner)",
                name,
            )
            return {}

        t0 = time.perf_counter()
        try:
            result = await self.execute(state)
        except Exception as e:  # noqa: BLE001 — visibility > strictness here
            dt_ms = int((time.perf_counter() - t0) * 1000)
            self.log.exception("[%s] crashed after %dms", name, dt_ms)
            # Persist the crash event to ``full_logs.jsonl`` BEFORE the
            # marker AIMessage gets filtered out of the planner's input
            # by ``_is_node_boundary_marker``. The marker still lives in
            # state.messages for the TUI / Studio view; this event is
            # the durable long-term record. See planner.py for the
            # filter rationale.
            try:
                from src.observability.writers import append_event
                append_event(
                    run_id,
                    "node_failed",
                    node=name,
                    dt_ms=dt_ms,
                    error=str(e)[:500],
                    error_type=type(e).__name__,
                )
            except Exception:  # noqa: BLE001 — observability must not break the graph
                pass
            return {
                "messages": [
                    AIMessage(
                        content=f"❌ [{name}] crashed after {dt_ms}ms: {e}",
                        additional_kwargs={"node": name, "error": True},
                    )
                ]
            }

        result = result or {}
        dt_ms = int((time.perf_counter() - t0) * 1000)
        summary = _summarize_node_result(name, result)

        # Touch run_id so unused-warning linters stay quiet; the value
        # is read upstream via state, not consumed here.
        _ = run_id

        # Live terminal view — silent/compact/verbose decided by the
        # renderer from config.verbosity.mode. In compact mode the
        # planner's JSON is parsed into a one-line "→ recon ..." trace;
        # in verbose mode the full multi-line dump is reproduced; in
        # silent mode this is a no-op. Findings (if any) get their own
        # colored line so they stand out in the stream.
        new_msgs = list(result.get("messages") or [])
        LIVE.node_finished(name, dt_ms, summary, new_msgs)
        for f in result.get("findings") or []:
            sev = getattr(f, "severity", None)
            sev_str = getattr(sev, "value", None) or str(sev or "info")
            LIVE.finding(
                severity=sev_str,
                title=getattr(f, "title", "") or "",
                agent=getattr(f, "agent_id", None),
                url=getattr(f, "url", None) or None,
                payload=getattr(f, "evidence", None) or None,
            )
        # Persist the success marker to ``full_logs.jsonl`` BEFORE the
        # AIMessage gets filtered out of the planner's input by
        # ``_is_node_boundary_marker``. The marker still lives in
        # state.messages for the TUI / Studio view; this event is the
        # durable long-term record.
        try:
            from src.observability.writers import append_event
            append_event(
                run_id,
                "node_finished",
                node=name,
                dt_ms=dt_ms,
                summary=summary,
                findings_count=len(result.get("findings") or []),
            )
        except Exception:  # noqa: BLE001 — observability must not break the graph
            pass

        msgs = list(result.get("messages") or [])
        msgs.append(
            AIMessage(
                content=f"✅ [{name}] {dt_ms}ms — {summary}",
                additional_kwargs={"node": name},
            )
        )
        return {**result, "messages": msgs}

    # ── Shared capabilities ────────────────────────────────────────────────

    def load_skill(self, name: str) -> AgentConfig | None:
        """Resolve a SKILL.md by name. Lazy import breaks the
        ``skills.loader → nodes.base → llm.provider → graph → nodes``
        circular chain at startup."""
        from src.skills.loader import load_skill
        return load_skill(name)

    async def ask_focused(
        self,
        user_prompt: str,
        *,
        system_prompt: str = "",
        llm: BaseChatModel | None = None,
        agent_id: str = "_focused",
        run_id: str | None = None,
    ) -> str:
        """One-shot LLM call with full control over what is sent.

        No tools, no conversation history, no inherited system prompt
        from the calling agent. Just one optional ``SystemMessage`` and
        one ``HumanMessage``. Returns the raw response text.

        Use this when a node needs a focused answer that the broad
        context of an ongoing agent loop would taint — for example
        when a worker has been refused on a pentest-framed request
        and a narrower technical question would succeed. The caller
        is responsible for crafting both prompts in a way that keeps
        framing minimal.

        ``llm`` defaults to the project's configured provider via
        ``src.llm.provider.get_llm`` — a fresh ``ChatModel`` instance,
        so the call inherits no shared state with other agents.
        """
        if llm is None:
            from src.llm.provider import get_llm
            llm = get_llm()
        msgs: list = []
        if system_prompt:
            msgs.append(SystemMessage(content=system_prompt))
        msgs.append(HumanMessage(content=user_prompt))
        # Token logging — focused sub-calls are bounded but they DO
        # spend tokens, so we route them through the callback. The
        # ``agent_id`` defaults to ``_focused`` so generic uses stay
        # grouped together; refusal-recovery passes the worker's id
        # through so the call lands in the worker's running totals.
        focused_cfg = make_call_config(
            run_id=run_id,
            agent_id=agent_id,
            node=self.name,
        )
        response = await llm.ainvoke(msgs, config=focused_cfg)
        content = response.content
        return content if isinstance(content, str) else str(content)

    async def _recover_from_refusal(
        self,
        *,
        config: AgentConfig,
        messages: list,
        last_text: str,
        run_id: str | None = None,
    ) -> str | None:
        """Try to salvage a refused worker via a focused sub-LLM call.

        Thin wrapper around
        :func:`src.refusals.recover.recover_from_refusal` — the actual
        logic lives there as a free function so the refusal package
        owns its own implementation. We pass ``self.ask_focused`` and
        ``self.log`` as dependencies rather than letting the helper
        import from the node layer (no reverse refusals → nodes import).
        """
        return await recover_from_refusal(
            config=config,
            messages=messages,
            last_text=last_text,
            ask_focused=self.ask_focused,
            log=self.log,
            run_id=run_id,
        )

    async def _try_salvage(
        self,
        *,
        config: AgentConfig,
        partial_messages: list,
        target_url: str,
        run_id: str | None = None,
    ):
        """Attempt to extract a Finding from a crashed worker's trace.

        Thin wrapper around :func:`src.refusals.salvage.try_salvage` —
        the actual logic (instantiate a fresh LLM, call
        ``salvage_finding``, swallow sub-call crashes) lives there. We
        pass ``self.log`` so the warning lands under the right node
        namespace.
        """
        return await try_salvage(
            config=config,
            partial_messages=partial_messages,
            target_url=target_url,
            log=self.log,
            run_id=run_id,
        )

    def detect_repetition(
        self,
        state: dict,
        window: int = 3,
    ) -> str | None:
        """Return a human-readable warning if the swarm is looping at
        the supervisor level, or ``None`` otherwise.

        Reads ``state["agent_results"]`` only — no per-tool-call
        bookkeeping needed because the standard worker-node update dict
        already records every completed agent. The check fires when the
        last ``window`` agent_results all share the same ``config_name``
        AND together produced zero findings, i.e. the planner has been
        hammering the same skill with no progress.

        The intended consumer is :class:`PlannerNode`, which prepends
        the warning to the supervisor's prompt so the LLM can pivot
        (different skill, web search, or report) instead of dispatching
        the same useless attack again.
        """
        results = state.get("agent_results") or []
        if len(results) < window:
            return None
        recent = results[-window:]
        config_names = {getattr(r, "config_name", None) for r in recent}
        if len(config_names) != 1 or None in config_names:
            return None
        total_findings = sum(len(getattr(r, "findings", None) or []) for r in recent)
        if total_findings > 0:
            return None
        cfg = recent[0].config_name
        return (
            f"Loop detected: skill {cfg!r} has run {window} times in a row "
            "with 0 findings. Stop re-running it alone — but do NOT narrow "
            "to a single new skill or jump to report. WIDEN this turn: keep "
            "any still-promising lead and bring the next hypotheses down "
            "your ranked list online together (a web_search first is fine "
            "if you need fresh technique ideas). Pick report only once the "
            "whole ranked list is exhausted."
        )

    # ── Tiered refusal-retry chain ──────────────────────────────────
    #
    # The actual ladder (tier 1 plain × N → tier 2 vocab filter × 1 →
    # exhaust → re-raise with attempt counters attached) lives in
    # ``src/refusals/retry.py`` as a free function. This method is a
    # thin async wrapper that hands the per-node logger to the helper
    # so retry events appear under the right ``node.<name>`` namespace.
    async def _astream_with_refusal_retry(
        self,
        *,
        agent_factory,                # callable: (system_prompt: str) -> create_agent(...)
        system_msg: str,
        seed_msgs: list,
        call_config: dict,
        config: "AgentConfig",
        max_plain_retries: int = 2,
    ) -> tuple[dict | None, int, str]:
        """Run agent.astream with tiered refusal retry.

        Forwards to :func:`src.refusals.retry.astream_with_refusal_retry`.
        Returns ``(last_snapshot, total_attempts, last_tier_used)``.
        Raises the last refusal exception after all tiers exhaust.
        Non-refusal exceptions propagate unchanged.
        """
        return await astream_with_refusal_retry(
            agent_factory=agent_factory,
            system_msg=system_msg,
            seed_msgs=seed_msgs,
            call_config=call_config,
            config=config,
            log=self.log,
            max_plain_retries=max_plain_retries,
        )

    async def run_skill_agent(
        self,
        config: AgentConfig,
        state: dict,
        llm: BaseChatModel | None = None,
    ) -> dict:
        """Run a ``create_agent`` loop with the given skill config.

        Thin wrapper that delegates to
        :func:`src.nodes.base.skill_runner.run_skill_agent` — the actual
        worker lifecycle (system prompt build, agent stream, refusal
        retries, finding parse, salvage) lives there as a free function.
        We forward ``self`` so the runner can use ``node.log``,
        ``node.name``, and ``node.ask_focused``.
        """
        # Lazy import keeps ``__init__.py`` lightweight at module load.
        from src.nodes.base.skill_runner import run_skill_agent as _impl
        return await _impl(self, config, state, llm)
