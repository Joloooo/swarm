"""Skill runner — turn a loaded skill config into an executing LangChain agent.

This module is the heart of every worker dispatch. The flow:

  1. The planner picks an action and stages a list of skill configs in
     ``state.pending_dispatch``. The routing edge fans them out across
     parallel ExecutorNode / ReconNode invocations.
  2. Each worker's ``execute`` calls
     :meth:`src.nodes.base.BaseNode.run_skill_agent`, which is a thin
     wrapper that forwards to :func:`run_skill_agent` here.
  3. This module builds the system prompt
     (``src/nodes/base/system_prompt.py:_build_system_message``), seeds
     the agent with cross-turn context (latest web search, prior
     dispatch's report), runs the LangChain ``create_agent`` loop with
     the tier-1/tier-2 refusal-retry ladder
     (``src/refusals/retry.py``), parses out structured findings from
     the trace, and on crash tries to salvage a finding from the
     partial messages (``src/refusals/salvage.py``).
  4. The result is the standard worker-node update dict
     (``messages`` / ``agent_results`` / ``findings`` /
     ``active_agents`` / ``pending_summary_inputs``) the rest of the
     graph already understands.

The ``AgentConfig`` dataclass that carries skill content
(SKILL.md body, tool list, budgets) lives here too because it is the
runner's input contract — it has nowhere else to belong.

NB: skill *loading* (reading SKILL.md from disk, parsing frontmatter,
resolving tool names to LangChain tool instances) lives in
``src/skills/loader.py``. This module consumes the loaded config; it
does not load.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool

from src.llm.callbacks import make_call_config
from src.nodes.base.flag_watcher import (
    FlagCapturedSignal,
    SiblingCapturedSignal,
)
from src.nodes.base.system_prompt import _build_system_message
from src.observability import make_run_id
from src.observability.state import _count_worker_iterations
from src.refusals.detect import looks_like_refusal
from src.refusals.recover import recover_from_refusal
from src.refusals.retry import astream_with_refusal_retry
from src.refusals.salvage import try_salvage
from src.state import AgentResult, Finding, Severity

if TYPE_CHECKING:
    from src.nodes.base import BaseNode


# ────────────────────────────────────────────────────────────────────────────
# AgentConfig — the in-memory carrier produced by ``src.skills.loader``
# ────────────────────────────────────────────────────────────────────────────


@dataclass
class AgentConfig:
    """Everything that makes one swarm agent different from another.

    Skill content (system_prompt + tool list + caps) comes from SKILL.md
    files under ``src/skills/`` parsed by ``src/skills/loader.py``. This
    dataclass is the in-memory carrier the loader produces.
    """

    # Identity
    agent_id: str  # unique name, e.g. "owasp-auth-testing"
    methodology: str  # "owasp" | "vulntype" | "custom" | "skill"
    config_name: str  # primary key for planner dispatch — matches skill folder

    # Prompt body (the SKILL.md body, minus frontmatter)
    system_prompt: str = ""

    # Tools (LangChain tool instances, resolved from SKILL.md tool names)
    tools: list[BaseTool] = field(default_factory=list)

    # Budget / loop detection
    max_tool_calls: int = 50
    max_iterations: int = 30

    # Prompt assembly opt-out. When True, ``_build_system_message``
    # skips the identity preamble, pentesting-rules block, role
    # framing, and RAG hint — the SKILL.md body is the entire system
    # prompt. Use for skills whose value depends on minimal framing
    # (focused technical Q&A that broad pentest context would taint).
    skip_base_prompt: bool = False

    # Which rule bundle the worker prompt carries.
    #   "executor" (default) — every dispatchable attack skill.
    #     Gets universal blocks + methodology + demonstrated-extraction
    #     + diversity + transformation hypothesis + severity +
    #     finding category guidance.
    #   "recon"             — discovery-phase agents (the recon skill).
    #     Gets universal blocks + a short "what counts as a recon
    #     finding" hint. No payload methodology, no exploit-output
    #     standard — those are exec-phase concerns that empirically
    #     tripped the Codex cyber_policy classifier on recon turns in
    #     ``logs/run-XBEN-006-24__2026-05-13_21h14m49s/``.
    # Set via ``metadata.phase`` in SKILL.md frontmatter.
    phase: str = "executor"


# ────────────────────────────────────────────────────────────────────────────
# Finding extraction from agent output
#
# Two parsers run on every assistant message:
# 1. The structured **FINDING:** / ## Finding format defined in FINDING_FORMAT
# 2. JSON blocks of the form {"findings": [...]} as a forgiving fallback
#
# The structured pattern only requires Title and Severity now (Category, URL,
# Evidence are optional). Bounded `[\s\S]{0,N}?` gaps prevent runaway matches
# across unrelated headings.
# ────────────────────────────────────────────────────────────────────────────


FINDING_PATTERN = re.compile(
    r"(?:\*\*FINDING:?\*\*|##\s+FINDING|##\s+Finding)"
    r"[\s\S]{0,40}?"
    r"Title:\s*(.+?)$"
    r"[\s\S]{0,200}?"
    r"Severity:\s*(\w+)"
    r"(?:[\s\S]{0,200}?Category:\s*([\w-]+))?"
    r"(?:[\s\S]{0,400}?URL:\s*(.+?)$)?"
    r"(?:[\s\S]{0,400}?Evidence:\s*(.+?)$)?",
    re.MULTILINE,
)

# Match a JSON object (non-greedy) that contains a "findings" key. Used as a
# fallback when the model emits {"findings": [...]} instead of the markdown.
JSON_FINDINGS_PATTERN = re.compile(
    r'\{[^{}]*?"findings"\s*:\s*\[[\s\S]*?\]\s*\}',
)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _findings_from_markdown(content: str, agent_id: str) -> list[Finding]:
    """Parse the structured **FINDING:** / ## Finding format."""
    out = []
    for match in FINDING_PATTERN.finditer(content):
        title = match.group(1).strip()
        severity_str = (match.group(2) or "info").strip().lower()
        category = (match.group(3) or "unknown").strip().lower()
        url = (match.group(4) or "").strip()
        evidence = (match.group(5) or "").strip()
        out.append(Finding(
            title=title,
            severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
            category=category,
            description=title,
            evidence=evidence[:500],
            agent_id=agent_id,
            url=url,
        ))
    return out


def _findings_from_json(content: str, agent_id: str) -> list[Finding]:
    """Fallback parser for JSON {"findings": [...]} blocks."""
    out = []
    for match in JSON_FINDINGS_PATTERN.finditer(content):
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
        for item in data.get("findings", []) or []:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "Untitled finding").strip()
            severity_str = str(item.get("severity") or "info").strip().lower()
            category = str(item.get("category") or "unknown").strip().lower()
            url = str(item.get("url") or "").strip()
            evidence = str(item.get("evidence") or item.get("payload") or "")[:500]
            out.append(Finding(
                title=title,
                severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
                category=category,
                description=str(item.get("description") or title),
                evidence=evidence,
                agent_id=agent_id,
                url=url,
            ))
    return out


def _extract_findings(messages: list, agent_id: str) -> list[Finding]:
    """Parse structured findings from agent messages.

    Tries the markdown FINDING format first; falls back to JSON
    {"findings": [...]} blocks. Both parsers run on every AIMessage and
    results are concatenated.
    """
    findings = []
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        findings.extend(_findings_from_markdown(content, agent_id))
        findings.extend(_findings_from_json(content, agent_id))
    return findings


# ── Worker memory: prior-attempts + web-search context injection ────────
#
# By default, every dispatch of ``run_skill_agent`` calls
# ``agent.ainvoke({"messages": []})`` — the worker starts cold with zero
# memory of:
#   1. its own previous run, when the planner re-dispatches the same
#      skill (``vulntype-sqli`` first run → web_search → second SQLi
#      dispatch starts from scratch and re-tries the same payloads), and
#   2. the supervisor's most recent ``web_search`` result, even though
#      the planner explicitly chose to research before dispatching.
#
# These two helpers fix both holes by seeding the create_agent loop with
# a single ``HumanMessage`` that includes:
#   - the latest ``[Web Search]`` synthesis (capped via
#     ``_WEB_SEARCH_INJECT_CHARS``), and
#   - a one-line summary of every prior tool call this agent_id made on
#     this run, paired with its tool-output exit code + trimmed body
#     (capped via ``_PRIOR_HISTORY_MAX_TURNS`` and
#     ``_PRIOR_PROBE_SUMMARY_CHARS``).
#
# Pairing is by ``tool_call_id`` (LangChain's stable round-trip ID), not
# by message order — so out-of-order ToolMessage delivery from parallel
# fan-out doesn't corrupt the summary. ``additional_kwargs.agent_id`` on
# both AIMessage and ToolMessage (set by ``run_skill_agent`` before
# trace propagation) is the per-skill filter.
#
# Returned by:
#   - ``_extract_latest_web_search(state)`` → str | None
#   - ``_collect_prior_skill_history(state, agent_id)`` → str | None
#
# Combined into the seed message inside ``run_skill_agent``.

# Maximum chars per summarized probe in the prior-attempts block.
# Big enough to show the bash command + first/last bytes of output;
# small enough that 12 of these stays under ~5KB of context.
_PRIOR_PROBE_SUMMARY_CHARS = 280

# Cap on tool-call/response pairs included from prior runs of the same
# skill. Older probes past the cap are summarized as a count so the
# worker still knows N earlier attempts existed, even if it can't see
# them all.
_PRIOR_HISTORY_MAX_TURNS = 12

# Maximum chars of the latest web_search synthesis to inject. Tavily +
# crawled-content can be ~10KB; cap so the seed HumanMessage stays
# under ~6KB total regardless of search verbosity.
_WEB_SEARCH_INJECT_CHARS = 5000


def _summarize_tool_call_pair(tool_call: dict, tool_msg: ToolMessage | None) -> str:
    """Render one (tool_call, tool_response) pair as a single probe line.

    Picks the most informative argument field — bash uses ``command``,
    fetch tools use ``url``, etc. — and pairs it with the response's
    exit code (parsed from the bash tool's ``[exit=N | cwd=...]``
    suffix when present) plus a trimmed body so failed and successful
    probes are visually distinguishable.
    """
    name = tool_call.get("name") if isinstance(tool_call, dict) else getattr(tool_call, "name", "tool")
    args = tool_call.get("args") if isinstance(tool_call, dict) else getattr(tool_call, "args", {})

    payload = ""
    if isinstance(args, dict):
        for key in ("command", "url", "data", "query", "payload", "target"):
            v = args.get(key)
            if isinstance(v, str) and v:
                payload = v
                break
        if not payload:
            for k, v in args.items():
                if k == "reasoning":
                    continue
                if isinstance(v, str) and v:
                    payload = f"{k}={v}"
                    break
    payload_str = (payload or "<no args>").strip()
    if len(payload_str) > 140:
        payload_str = payload_str[:137] + "..."

    if tool_msg is None:
        response = "(no response captured)"
    else:
        body = tool_msg.content if isinstance(tool_msg.content, str) else str(tool_msg.content)
        body = body.strip()
        m = re.search(r"\[exit=(-?\d+)", body)
        exit_code = m.group(1) if m else "?"
        # Keep first 100 + last 60 chars for very long outputs so both
        # the start and the end (where flag matches / errors usually
        # appear) are visible.
        if len(body) > 200:
            body = body[:100].replace("\n", " ") + " …trimmed… " + body[-60:].replace("\n", " ")
        else:
            body = body.replace("\n", " ")
        response = f"exit={exit_code} {body}"

    line = f"- {name}({payload_str}) → {response}"
    if len(line) > _PRIOR_PROBE_SUMMARY_CHARS:
        line = line[: _PRIOR_PROBE_SUMMARY_CHARS - 1] + "…"
    return line


def _collect_prior_skill_history(state: dict, agent_id: str) -> str | None:
    """Return the previous summarizer report for this ``agent_id``, or
    ``None`` if there is no prior dispatch.

    Background: in the pre-summarizer-node design this function walked
    ``state['messages']`` looking for raw ``AIMessage``s with matching
    ``agent_id`` and reconstructed a "previous attempts" block from
    their tool calls. After the worker → summarizer hand-off
    (``state.pending_summary_inputs`` + ``SummarizerNode``), those raw
    ``AIMessage``s no longer enter ``state['messages']`` — only the
    summarizer's structured ``worker_report`` does.

    So we just look up the most recent ``worker_report`` for the
    matching ``agent_id``. The report is already in the right format
    and tone (probe enumeration, what-was-NOT-tried, recommended next
    angle) — no per-probe re-formatting needed here.

    See :func:`src.llm.digest.find_prior_worker_report` for the lookup.
    """
    from src.llm.digest import find_prior_worker_report

    report = find_prior_worker_report(state.get("messages") or [], agent_id)
    if report is None:
        return None
    body = report.content if isinstance(report.content, str) else str(report.content)
    if not body.strip():
        return None
    return (
        "## Your prior dispatch's report to the supervisor\n\n"
        "The supervisor previously dispatched you on this target. The "
        "summarizer's report from that run is below — it lists what was "
        "tried, what was NOT tried, and the recommended next angle. Do "
        "NOT repeat probes already tried; pick up from where the "
        "previous run left off.\n\n"
        f"{body}"
    )


def _extract_latest_web_search(state: dict) -> str | None:
    """Return the most recent ``[Web Search] ...`` AIMessage content,
    truncated to ``_WEB_SEARCH_INJECT_CHARS``, or ``None``.

    The web_search node prefixes its synthesis with a literal
    ``[Web Search]`` marker (see ``src/nodes/web_search.py``), which
    makes it cheap to find and disambiguate from worker output.
    """
    msgs = state.get("messages") or []
    for m in reversed(msgs):
        if not isinstance(m, AIMessage):
            continue
        content = m.content if isinstance(m.content, str) else str(m.content or "")
        if content.lstrip().startswith("[Web Search]"):
            if len(content) > _WEB_SEARCH_INJECT_CHARS:
                content = content[:_WEB_SEARCH_INJECT_CHARS] + "\n…[truncated for context budget]"
            return content
    return None


def _persist_worker_trace(
    *,
    trace: list[Any],
    run_id: str,
    agent_id: str,
):
    """No-op shim — worker traces are no longer mirrored to disk.

    The previous behaviour wrote one row per LangChain message into
    ``logs/run-<run_id>/worker_traces.jsonl``. The file was nearly
    redundant with ``full_logs.jsonl`` (every LLM round-trip is already
    captured there with full prompt + response) and was never read by
    a human in practice. Removed as part of the 2026-05 log
    consolidation.

    Kept as a function (instead of being deleted) so call sites in
    ``run_skill_agent`` can keep invoking it without conditional logic.
    Returns ``None`` so any caller that stored the path falls back to
    its empty-path branch.
    """
    del trace, run_id, agent_id  # explicitly unused
    return None


# ────────────────────────────────────────────────────────────────────────────
# The runner itself.
#
# ``run_skill_agent`` is the entire worker lifecycle: build the system
# prompt, seed cross-turn context, run the agent loop with refusal
# retries, parse findings, salvage on crash. ``BaseNode.run_skill_agent``
# is a thin async wrapper that just forwards ``self`` and delegates here.
# ────────────────────────────────────────────────────────────────────────────


async def run_skill_agent(
    node: "BaseNode",
    config: AgentConfig,
    state: dict,
    llm: BaseChatModel | None = None,
) -> dict:
    """Run a ``create_agent`` loop with the given skill config.

    Public entry point. Thin wrapper that guarantees per-worker shell
    cleanup runs whether the implementation succeeded, raised, was
    salvaged, or refused. The actual worker lifecycle lives in
    :func:`_run_skill_agent_impl` immediately below.

    Why the wrapper exists: without it, every worker leaves its tmux
    session and bash subprocess alive in the
    :class:`~src.tools.shell.manager.ShellManager` registry until
    ``atexit`` fires at process death. For benchmark runs with many
    parallel/sequential workers that means dozens of live sessions
    accumulating in one Python process — fine in theory, sloppy in
    practice. The finally-block frees them as each worker finishes.
    """
    try:
        return await _run_skill_agent_impl(node, config, state, llm)
    finally:
        # Best-effort per-worker shell cleanup. Never raise from the
        # finally — a cleanup failure must not mask a successful return
        # or a real exception from the implementation.
        try:
            from src.tools.shell import get_shell_manager
            await get_shell_manager().cleanup_agent(config.agent_id)
        except Exception as e:  # noqa: BLE001
            node.log.warning(
                "[%s] shell cleanup_agent failed (non-fatal): %s",
                config.agent_id, e,
            )


async def _run_skill_agent_impl(
    node: "BaseNode",
    config: AgentConfig,
    state: dict,
    llm: BaseChatModel | None = None,
) -> dict:
    """Run a ``create_agent`` loop with the given skill config.

    Returns the standard worker-node update dict::

        {
            "messages":      [...],   # mirrored agent trace
            "agent_results": [AgentResult(...)],
            "findings":      [Finding, ...],
            "active_agents": [agent_id],
        }

    ``node`` is the BaseNode instance whose method delegated here. We
    use it for ``node.log`` (per-node logger), ``node.name`` (used by
    the LLM call config and for trace persistence), and the focused
    sub-LLM helper ``node.ask_focused`` (which the refusal-recovery
    path needs).

    Called only via :func:`run_skill_agent` (the public entry point
    that adds the per-worker shell cleanup ``finally``).
    """
    if llm is None:
        from src.llm.provider import get_llm  # lazy — see module docstring
        llm = get_llm()

    target_url = state.get("target_url", "")

    # Build system message with phase-appropriate rule bundle. The
    # benchmark-mode addendum used to be appended here when
    # ``state.expected_flag`` was set; it was removed on 2026-05-14
    # because the flag success-criterion language was the strongest
    # cyber_policy refusal trigger in worker prompts. The planner
    # owns flag submission (``action="submit_flag"`` verified by
    # ``src/edges/routing.py:route_after_planner``); workers only
    # need to surface flag-shaped strings in their findings.
    phase1_findings = state.get("phase1_findings")
    system_msg = _build_system_message(
        config, target_url, phase1_findings,
    )

    # NB: agent construction is now deferred to ``_agent_factory``
    # below so the tier-2 refusal-retry can rebuild the agent with
    # a vocab-filtered system prompt without losing any of this
    # call site's wiring.

    # Seed the create_agent loop with whatever cross-turn context
    # we can recover from state["messages"]:
    #   1. The supervisor's most recent web_search synthesis, so a
    #      worker dispatched right after research doesn't have to
    #      re-derive techniques from scratch.
    #   2. This agent_id's own prior tool calls, so a re-dispatched
    #      skill (e.g. vulntype-sqli on its second turn) sees what
    #      it already tried and what each probe returned.
    #
    # Both helpers return None when the relevant context isn't
    # present, so cold first dispatches stay equivalent to the old
    # ``{"messages": []}`` behavior — no behavioral change unless
    # there's actual context to pass through. See the helpers'
    # docstrings for the per-component caps.
    seed_parts: list[str] = []

    web_search_ctx = _extract_latest_web_search(state)
    if web_search_ctx:
        seed_parts.append(
            "## Supervisor's most recent web research\n\n"
            "The supervisor ran a web search before dispatching you. "
            "The synthesis below is drawn from cited public sources — "
            "use it for technique guidance instead of re-deriving "
            "everything from scratch.\n\n"
            f"{web_search_ctx}"
        )

    prior_history = _collect_prior_skill_history(state, config.agent_id)
    if prior_history:
        seed_parts.append(prior_history)

    if seed_parts:
        seed_parts.append(
            "Begin testing now. Use the context above where it "
            "helps; pick up from where the previous run left off "
            "without repeating its probes."
        )
        seed_msgs: list = [HumanMessage(content="\n\n".join(seed_parts))]
        node.log.info(
            "[%s] seeding worker with %d context block(s) "
            "(web_search=%s, prior_history=%s)",
            config.agent_id,
            len(seed_parts) - 1,  # minus the "Begin testing" tail
            bool(web_search_ctx),
            bool(prior_history),
        )
    else:
        seed_msgs = []

    trace: list = []
    findings: list[Finding] = []
    # Resolve the run_id once so every LLM call below logs into the
    # same ``logs/run-<id>/llm_calls.jsonl`` and so on a crash the
    # salvage path knows where to write its output.
    run_id = (state or {}).get("run_id") or make_run_id(
        target_url=target_url,
    )
    # ``call_config`` carries: callbacks (token logger + optional
    # flag watcher), metadata (agent_id / run_id / node — read by the
    # callback to attribute each LLM call), and the recursion_limit
    # budget. Using a helper keeps every LLM call site in the codebase
    # consistent — a missing callback here would silently drop
    # token-cost rows from llm_calls.jsonl.
    #
    # In benchmark mode the FlagWatcherCallback hooks ``on_tool_end``
    # and raises ``FlagCapturedSignal`` the instant a tool returns the
    # expected flag literal. This short-circuits the worker BEFORE the
    # next LLM call is queued — saves 60-90 s of gpt-5.5 reasoning per
    # capture and unblocks the LangGraph fan-in much faster (other
    # parallel workers then also stop on the same capture via the
    # ``state.captured_flag`` reducer). See the module docstring of
    # ``src.nodes.base.flag_watcher`` for the full incident retro.
    from src.nodes.base.flag_watcher import FlagWatcherCallback
    expected_flag_for_callback = (state or {}).get("expected_flag") or ""
    worker_callbacks: list = []
    if expected_flag_for_callback:
        worker_callbacks.append(FlagWatcherCallback(
            expected_flag=expected_flag_for_callback,
            agent_id=config.agent_id,
        ))
    call_config = make_call_config(
        run_id=run_id,
        agent_id=config.agent_id,
        node=node.name,
        recursion_limit=config.max_iterations,
        extra_callbacks=worker_callbacks or None,
    )

    # Stream rather than ainvoke so a partial state snapshot
    # survives crashes. ``stream_mode="values"`` yields successive
    # full-state snapshots; we keep the latest one. When LangGraph
    # raises ``GraphRecursionError`` mid-loop, ``last_snapshot``
    # holds the messages accumulated up to the last successful
    # step — which is exactly what salvage_finding() consumes.
    #
    # The agent is reconstructed inside the retry helper because
    # vocab-filter / tier-2 model-swap both rebuild it from scratch.
    def _agent_factory(sys_prompt: str):
        return create_agent(
            model=llm,
            tools=config.tools,
            system_prompt=sys_prompt,
        )

    # Tier-2 fallback factory — only wired when the primary provider
    # is Codex (model-swap to gpt-5.4 isn't meaningful for anthropic
    # / local / openrouter routes). See ``src/refusals/retry.py`` for
    # the tier ladder and ``config.budgets.fallback_*`` env knobs for
    # tuning the fallback model + reasoning_effort.
    from src.llm.provider import LLMConfig as _LLMConfig
    from src.llm.provider import Provider as _Provider
    fallback_factory: Any = None
    _primary_cfg = _LLMConfig()
    if _primary_cfg.provider == _Provider.CODEX:
        # Lazy import — skill_runner is imported transitively from
        # src.graph during its own initialization, so a top-level
        # ``from src.graph import config`` would re-enter the module
        # while it's still binding ``config``. Reading via the module
        # object at call-time (after graph.py has finished) avoids
        # that.
        from src import graph as _graph_module
        _fallback_model = getattr(
            _graph_module.config.budgets, "fallback_model", "gpt-5.4",
        )
        _fallback_effort = getattr(
            _graph_module.config.budgets, "fallback_reasoning_effort", "low",
        )

        def _fallback_agent_factory(sys_prompt: str):
            from src.llm.provider import get_llm as _get_llm
            fb_llm = _get_llm(_LLMConfig(
                provider=_Provider.CODEX,
                model=_fallback_model,
                reasoning_effort=_fallback_effort,
            ))
            return create_agent(
                model=fb_llm,
                tools=config.tools,
                system_prompt=sys_prompt,
            )

        fallback_factory = _fallback_agent_factory

    last_snapshot: dict | None = None
    worker_attempts = 0
    worker_last_tier = "primary"
    flag_watcher_capture: str | None = None
    sibling_captured_value: str = ""
    try:
        # Inner try catches the FlagWatcher's short-circuit signals so
        # they never reach the outer ``except Exception`` (which would
        # mis-classify them as refusals). Two distinct signals:
        #
        #   * FlagCapturedSignal — THIS worker matched the flag in its
        #     own tool output. We synthesise a ToolMessage so the
        #     downstream auto-verify scan picks the flag up via its
        #     existing extract_flags + flags_match path, then build a
        #     normal worker-result dict. captured_flag lands in state
        #     via the reducer.
        #
        #   * SiblingCapturedSignal — ANOTHER worker captured while we
        #     were mid-LLM-call. We exit cleanly with an empty-findings
        #     update so the fan-in can complete fast and the routing
        #     edge ``route_after_summarizer`` can route to END. We do
        #     NOT set captured_flag (the winning worker already did).
        #
        # Single code path for the WINNING worker — capture via
        # FlagWatcher (early, milliseconds after tool returns) and the
        # end-of-worker fallback scan (late, after the agent loop ends
        # naturally) both feed the same downstream auto-verify block.
        try:
            (
                last_snapshot,
                worker_attempts,
                worker_last_tier,
            ) = await astream_with_refusal_retry(
                agent_factory=_agent_factory,
                fallback_agent_factory=fallback_factory,
                system_msg=system_msg,
                seed_msgs=seed_msgs,
                call_config=call_config,
                config=config,
                log=node.log,
            )
        except FlagCapturedSignal as sig:
            flag_watcher_capture = sig.flag
            node.log.info(
                "[%s] FlagWatcher captured flag in %s output: %s — "
                "short-circuiting worker (saves Codex spend + unblocks "
                "fan-in)",
                config.agent_id, sig.tool_name or "tool", sig.flag,
            )
            # Append a synthetic ToolMessage with the captured value
            # to the last partial snapshot. The downstream auto-verify
            # scan iterates ``last_snapshot["messages"]`` and matches
            # ``extract_flags(content) → flags_match(...)``; this
            # synthetic entry is exactly what that scan expects.
            #
            # Why the snapshot is partial: the FlagWatcher raises
            # inside ``on_tool_end``, which fires AFTER the tool
            # returns but BEFORE LangGraph yields the next state
            # snapshot. So ``last_snapshot`` holds the state from
            # before the flag-producing tool call. The synthetic
            # message bridges that gap without us needing to
            # reconstruct the missing snapshot ourselves.
            snap = dict(last_snapshot or {})
            msgs = list(snap.get("messages") or [])
            msgs.append(ToolMessage(
                content=sig.flag,
                tool_call_id="_flag_watcher_synthetic",
                name=sig.tool_name or "_flag_watcher",
            ))
            snap["messages"] = msgs
            last_snapshot = snap
        except SiblingCapturedSignal as sig:
            # Sibling worker captured first; this worker exits with
            # an empty update so fan-in completes fast. Routing reads
            # state.captured_flag (set by the winning worker) to drive
            # termination — we don't touch it here.
            sibling_captured_value = sig.captured_flag
            node.log.info(
                "[%s] sibling worker captured the flag (%s) — "
                "exiting cleanly to unblock fan-in",
                config.agent_id, sig.captured_flag,
            )

        result = last_snapshot or {}
        messages = result.get("messages", [])
        findings = _extract_findings(messages, config.agent_id)

        # If the FlagWatcher fired, also synthesise a CRITICAL Finding
        # so the worker reports ``1 finding`` instead of ``0`` and the
        # summarizer's per-worker digest has something concrete to
        # echo. Capture itself routes through ``captured_flag`` (set
        # by the downstream auto-verify block); this Finding is the
        # human-readable companion to that machine-readable signal.
        if flag_watcher_capture and not findings:
            findings = [
                Finding(
                    title=f"Flag captured: {flag_watcher_capture}",
                    severity=Severity.CRITICAL,
                    category="flag-capture",
                    description=(
                        "Worker tool output contained the expected "
                        "flag literal. The FlagWatcher callback "
                        "strict-equal matched it against "
                        "state.expected_flag and short-circuited the "
                        "worker loop to save downstream Codex spend."
                    ),
                    evidence=f"Captured flag: {flag_watcher_capture}",
                    agent_id=config.agent_id,
                    url=target_url or "",
                    cwe="",
                    reproduced=True,
                )
            ]

        # Mirror the inner agent trace up to the parent so Studio chat
        # shows every tool call (`run_command("curl ...")`) and the
        # corresponding ToolMessage response inline. Without this the
        # entire conversation is hidden inside the create_agent
        # sub-graph and the parent chat looks frozen.
        trace = [m for m in messages if isinstance(m, (AIMessage, ToolMessage))]
        for m in trace:
            # Tag each message with the agent_id so Studio (and
            # downstream consumers) can group / filter by agent.
            try:
                m.additional_kwargs.setdefault("agent_id", config.agent_id)
            except Exception:
                pass

        # Refusal detection — if 0 findings AND the last assistant
        # message reads like a safety refusal, surface it explicitly
        # instead of letting it get swallowed as "0 findings".
        #
        # Skip this entire block when ``sibling_captured_value`` is
        # set: the worker exited early because another worker captured
        # the flag, not because of any refusal or anomalous output.
        # Treating it as "0 findings — looks like a refusal" would
        # trigger an unnecessary recovery sub-call AND emit a
        # misleading warning to the operator.
        last_text = ""
        for m in reversed(messages):
            if isinstance(m, AIMessage):
                last_text = (
                    m.content if isinstance(m.content, str) else str(m.content)
                )
                break

        refused = (not findings) and looks_like_refusal(last_text)
        if not findings and not sibling_captured_value:
            node.log.warning(
                f"[{config.agent_id}] produced 0 findings — "
                f"last output: {last_text[:500]!r}"
            )
        if refused and not sibling_captured_value:
            node.log.warning(
                f"[{config.agent_id}] looks like a model refusal — "
                "attempting focused-sub-call recovery"
            )
            recovered = await recover_from_refusal(
                config=config,
                messages=messages,
                last_text=last_text,
                ask_focused=node.ask_focused,
                log=node.log,
                run_id=run_id,
            )
            if recovered:
                node.log.info(
                    f"[{config.agent_id}] refusal recovery returned a "
                    "focused suggestion"
                )
                trace.append(AIMessage(
                    content=(
                        f"[focused-followup for {config.agent_id}] "
                        "The agent's primary response read as a "
                        "refusal. A narrow-framing sub-call returned "
                        f"this suggestion instead:\n\n{recovered}"
                    ),
                    additional_kwargs={
                        "agent_id": config.agent_id,
                        "recovered": True,
                    },
                ))
                # Treat as not-refused so AgentResult.completed=True
                # and the planner sees the suggestion in the trace
                # as actionable evidence for its next turn.
                refused = False
            else:
                node.log.warning(
                    f"[{config.agent_id}] refusal recovery also "
                    "failed (no probes to summarize, or sub-LLM "
                    "also refused)"
                )
                trace.append(AIMessage(
                    content=(
                        f"⚠️ [{config.agent_id}] model refused the task. "
                        f"Last output: {last_text[:300]}"
                    ),
                    additional_kwargs={
                        "agent_id": config.agent_id,
                        "refusal": True,
                    },
                ))

        # Sibling-cancelled workers are not refusals and not crashes —
        # they're a clean cooperative exit. Surface them on a distinct
        # ``error`` channel so the planner / triage tooling can tell
        # the difference between "this worker tried and failed" and
        # "this worker stood down because another worker won".
        if sibling_captured_value:
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                completed=False,
                error="sibling captured first",
            )
        else:
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                completed=not refused,
                error="model refused" if refused else None,
            )
    except Exception as e:
        # Cyber-policy / invalid-prompt failures from the Codex API
        # are *refusals*, not crashes. Surface them on the
        # ``error="model refused"`` channel so the planner's
        # repetition + refusal logic can pick a different skill
        # rather than treating this as a hard exception. We also
        # try a focused-recovery sub-call: if the agent had already
        # made any probes via ``create_agent`` before the API
        # rejected the next request, we may have a partial trace
        # with usable observations.
        #
        # Lazy-imported to keep the planner / executor import dance
        # working — see ``src/graph.py``'s ordering note.
        try:
            from src.llm.codex import (
                CodexCyberPolicyError,
                CodexInvalidPromptError,
            )
            refusal_exc_types = (
                CodexCyberPolicyError,
                CodexInvalidPromptError,
            )
        except ImportError:
            refusal_exc_types = ()

        # Pull whatever messages survived the crash into the trace
        # so the parent chat / nodes.jsonl still show what the
        # worker did before dying. Without this, recursion-limit
        # crashes look like the worker did literally nothing.
        partial_messages = (last_snapshot or {}).get("messages", []) or []

        if refusal_exc_types and isinstance(e, refusal_exc_types):
            node.log.warning(
                "[%s] API-level refusal (%s) after %d retry attempts "
                "(last tier: %s): %s — surfacing as model refusal so "
                "the planner can pivot.",
                config.agent_id, type(e).__name__,
                worker_attempts, worker_last_tier, str(e)[:200],
            )

            trace = [
                m for m in partial_messages
                if isinstance(m, (AIMessage, ToolMessage))
            ]
            # Refusal-time flag salvage. The Codex API can refuse
            # mid-run after the worker has already executed a few
            # tool calls — and one of those ToolMessage responses
            # may contain a captured ``flag{...}`` string. Without
            # this scan, the refusal branch wipes ``findings = []``
            # and the planner never learns the worker actually
            # won. Concrete example: XBEN-006-24 run on
            # 2026-05-09, where ``owasp-input-validation`` extracted
            # ``flag{582d82bb-...}`` at iteration 5 and got refused
            # at iteration 6, dropping the win.
            #
            # Lazy import so the ``src.edges.flag_match`` module is only
            # loaded on the refusal path (it is also imported at routing
            # time, but defensive imports here keep startup costs
            # tied to actual usage).
            findings = []
            try:
                from src.edges.flag_match import extract_flags

                # Stringify partial messages inline. The old code used a
                # private ``_stringify_messages`` helper from ``src.flag``;
                # that helper was deleted in the 2026-05 refactor that
                # replaced state scanning with explicit ``submit_flag``.
                # Salvage still legitimately scans the partial trace of a
                # refused worker, so the stringifier lives here now —
                # narrower scope, no public API surface for state scans.
                parts: list[str] = []
                for m in partial_messages:
                    c = getattr(m, "content", None)
                    if isinstance(c, str):
                        parts.append(c)
                    elif isinstance(c, list):
                        for block in c:
                            if isinstance(block, dict):
                                parts.append(str(block.get("text") or ""))
                haystack = "\n".join(parts)
                flag_hits = extract_flags(haystack)
                if flag_hits:
                    flag_value = flag_hits[0]
                    # Pull a short evidence excerpt around the
                    # match so a human reading the report can
                    # eyeball the request that produced it.
                    idx = haystack.find(flag_value)
                    excerpt_start = max(0, idx - 240)
                    excerpt_end = min(
                        len(haystack), idx + len(flag_value) + 240,
                    )
                    excerpt = haystack[excerpt_start:excerpt_end]
                    findings = [
                        Finding(
                            title=(
                                "[salvaged from refused worker] "
                                f"flag captured before refusal: "
                                f"{flag_value}"
                            )[:240],
                            severity=Severity.CRITICAL,
                            category="flag-capture",
                            description=(
                                "The worker hit a Codex policy "
                                "refusal mid-run, but its partial "
                                "tool trace already contained a "
                                "flag-pattern match. The matched "
                                "string is the actual flag string "
                                "captured during testing."
                            ),
                            evidence=excerpt[:2400],
                            agent_id=config.agent_id,
                            url="",
                            cwe="",
                            reproduced=False,
                        )
                    ]
                    node.log.warning(
                        "[%s] refusal-path flag salvage: captured "
                        "%r from partial trace before discard.",
                        config.agent_id, flag_value[:80],
                    )
            except Exception as salv_err:  # noqa: BLE001
                # Salvage must never make the refusal path worse;
                # log and fall through with empty findings.
                node.log.warning(
                    "[%s] refusal-path flag salvage failed: %s: %s",
                    config.agent_id,
                    type(salv_err).__name__,
                    str(salv_err)[:160],
                )
            trace.append(AIMessage(
                content=(
                    f"⚠️ [{config.agent_id}] model refused the task at "
                    f"the API safety layer ({type(e).__name__}). The "
                    "request was rejected before any tool calls could "
                    "be made. Recommend the planner pick a different "
                    "skill or rephrase the goal more narrowly."
                    + (
                        f"\n\n[salvage] Captured flag pattern in "
                        f"partial trace before refusal: "
                        f"{findings[0].evidence[:200]!r}"
                        if findings
                        else ""
                    )
                ),
                additional_kwargs={
                    "agent_id": config.agent_id,
                    "refusal": True,
                    "refusal_kind": "api_cyber_policy",
                    "salvaged_flag": bool(findings),
                },
            ))
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                # If we salvaged a flag, treat the worker as
                # completed for planner-loop accounting — its
                # contribution was real, even though the API
                # rejected the next iteration.
                completed=bool(findings),
                error="model refused" if not findings else None,
            )
        else:
            node.log.error(f"Agent {config.agent_id} failed: {e}")
            # Try to salvage a finding from the partial trace before
            # we throw it away. This is the recovery path for
            # ``GraphRecursionError`` and similar mid-loop crashes
            # — see src/refusals/salvage.py for the rationale and the
            # XBEN-006-24 incident that motivated it. The salvage
            # call is bounded (one sub-LLM call, ~9 KB prompt) and
            # silently returns None on failure, so this never makes
            # the crash path worse.
            salvaged = await try_salvage(
                config=config,
                partial_messages=partial_messages,
                target_url=target_url,
                log=node.log,
                run_id=run_id,
            )
            trace = [
                m for m in partial_messages
                if isinstance(m, (AIMessage, ToolMessage))
            ]
            trace.append(AIMessage(
                content=(
                    f"❌ [{config.agent_id}] crashed: {e}"
                    + (
                        f"\n\n[salvage] Recovered a "
                        f"{salvaged.severity.value} finding from the "
                        f"partial trace: {salvaged.title}"
                        if salvaged
                        else ""
                    )
                ),
                additional_kwargs={
                    "agent_id": config.agent_id,
                    "error": True,
                    "salvaged_finding": bool(salvaged),
                },
            ))
            findings = [salvaged] if salvaged else []
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                error=str(e),
                # A salvaged finding lets the planner act, so we
                # report completed=True for that case so the
                # repetition-loop detector counts it as a real turn.
                completed=bool(salvaged),
            )

    # Persist the full trace to disk for forensics. The planner will
    # never see this file directly — it's the per-worker forensic
    # artefact (and a fallback the salvage path can re-read). The
    # summarizer node consumes the in-memory ``trace`` we hand back
    # via ``pending_summary_inputs`` below, so the disk path is
    # primarily for human debugging after the run.
    trace_path = _persist_worker_trace(
        trace=trace,
        run_id=run_id,
        agent_id=config.agent_id,
    )

    # Resolve the dispatch reason from state — set by the planner
    # via ``pending_dispatch[i]["dispatch_reason"]`` and forwarded
    # through the routing edge. Empty for cold runs (initialize →
    # recon, before the planner has spoken) and that's fine — the
    # summarizer prompt handles missing reason gracefully.
    dispatch_reason = (
        state.get("dispatch_reason")
        or state.get("dispatch_focus")
        or ""
    )

    # The summary input that the SummarizerNode will consume. Each
    # parallel worker writes a singleton list; the
    # ``_summary_inputs_reducer`` accumulates them so the
    # SummarizerNode (the synchronization point after fan-out) sees
    # one entry per worker. See ``src/state.py`` for the reducer
    # and ``src/nodes/summarizer.py`` for the consumer.
    summary_input: dict = {
        "agent_id": config.agent_id,
        "config_name": config.config_name,
        "methodology": config.methodology,
        "dispatch_reason": dispatch_reason,
        "trace": trace,                    # in-memory, not mirrored to messages
        "trace_path": str(trace_path) if trace_path else "",
        "completed": getattr(agent_result, "completed", False),
        "error": getattr(agent_result, "error", None),
        "refused": (getattr(agent_result, "error", None) == "model refused"),
        "findings_count": len(findings),
        "iteration_count": _count_worker_iterations(trace),
        "target_url": target_url,
    }

    # ── Success-path flag auto-verification ─────────────────────
    # In benchmark mode (``expected_flag`` set), scan the worker's
    # tool messages for ``flag{...}`` substrings and strict-equal
    # them against ``expected_flag``. On a match, surface the
    # captured value via ``state.captured_flag`` (consumed by
    # ``route_after_summarizer`` to terminate the graph) AND push
    # it onto ``submission_attempts`` (consumed by ``xbow_runner``
    # as the verdict source of truth).
    #
    # Why this exists: prior to 2026-05-25 the only termination
    # path was the planner explicitly emitting ``submit_flag`` with
    # a flag-shaped string. The summarizer's digest LLM was
    # observed (XBEN-006-24 on 2026-05-25, see tests/FAILURES.md)
    # to rewrite the "Server responses" prose and DROP literal
    # ``flag{...}`` strings — so the planner never saw the
    # capture, never submitted, run timed out.
    #
    # Why this is SAFE despite the 2026-05-24 removal of the old
    # regex-only auto-terminate: the strict-equality gate
    # against ``expected_flag`` is itself the false-positive
    # filter. Swagger ``flag{example}`` examples, README
    # placeholders, and the agent's own ``python3 -c "flag=…"``
    # script literals all FAIL strict equality with the
    # deterministic ``FLAG{sha256(BENCHMARK_UPPER)}`` value, so
    # they never set this field. Only the actual served flag does.
    #
    # In real-pentest mode (``expected_flag`` empty), this block
    # is a no-op — capture remains planner-driven.
    captured_flag_value: str | None = None
    expected_flag = (state or {}).get("expected_flag") or ""
    # Counters that always end up in the auto-verify summary event,
    # so post-mortem can see "we scanned N tool messages, looked at
    # K candidate flag-shaped strings, matched 0" without re-reading
    # the entire worker trace.
    tool_msgs_scanned = 0
    candidates_seen = 0
    if expected_flag and last_snapshot:
        from src.edges.flag_match import extract_flags, flags_match
        scanned_msgs = last_snapshot.get("messages", []) or []
        for m in scanned_msgs:
            if not isinstance(m, ToolMessage):
                continue
            tool_msgs_scanned += 1
            c = getattr(m, "content", None)
            if isinstance(c, str):
                content_str = c
            elif isinstance(c, list):
                # ToolMessage content can be a list of content blocks
                # under certain provider shapes — flatten to text.
                content_str = "\n".join(
                    str((block or {}).get("text") or block)
                    if isinstance(block, dict) else str(block)
                    for block in c
                )
            else:
                continue
            for candidate in extract_flags(content_str):
                candidates_seen += 1
                if flags_match(submitted=candidate, expected=expected_flag):
                    captured_flag_value = candidate
                    node.log.info(
                        "[%s] auto-verified flag in tool output: %s "
                        "(matches expected_flag)",
                        config.agent_id, candidate,
                    )
                    break
            if captured_flag_value:
                break

    # Structured record of the scan — fires whether or not we matched,
    # so the post-mortem can answer "did the scan even run?" with a
    # single ``jq`` query rather than reconstructing it from logger
    # output that may have been dropped by compact mode. The 2026-05-25
    # XBEN-006-24 incident is the canonical case: three workers had the
    # flag in tool output but no on-disk artefact recorded whether the
    # scan matched, so it was unclear whether the bug was detection
    # (scan didn't fire / didn't match) or routing (matched but graph
    # didn't terminate from inside a fan-out).
    if expected_flag:
        try:
            from src.observability.writers import append_event
            run_id = (state or {}).get("run_id")
            append_event(
                run_id,
                "flag_auto_verified",
                agent_id=config.agent_id,
                node=node.name,
                expected_flag=expected_flag,
                captured_flag=captured_flag_value or "",
                matched=captured_flag_value is not None,
                tool_msgs_scanned=tool_msgs_scanned,
                candidates_seen=candidates_seen,
                last_snapshot_present=last_snapshot is not None,
            )
        except Exception:  # noqa: BLE001
            pass

    update: dict[str, Any] = {
        # NOTE: no ``"messages": trace`` — that was the cause of the
        # global-prompt explosion. The full trace stays on disk and
        # in ``pending_summary_inputs[*].trace`` until the
        # SummarizerNode replaces it with one ``AIMessage`` digest.
        "pending_summary_inputs": [summary_input],
        "agent_results": [agent_result],
        "findings": findings,
        "active_agents": [config.agent_id],
    }
    if captured_flag_value is not None:
        update["captured_flag"] = captured_flag_value
        # Mirror onto submission_attempts so xbow_runner.run_one's
        # existing verdict path (which reads submission_attempts[-1])
        # sees the capture without any change to that consumer. The
        # graph terminates via the normal route_after_summarizer →
        # END path: this update's captured_flag lands in state via
        # the reducer; sibling workers exit fast via the FlagWatcher
        # callback's sibling-cancel path (see flag_watcher module
        # docstring); fan-in completes; summarizer fires;
        # route_after_summarizer reads captured_flag → END.
        update["submission_attempts"] = [captured_flag_value]
    return update
