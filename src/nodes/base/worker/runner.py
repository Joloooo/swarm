# Skill runner — turn a loaded skill config into an executing LangChain agent.
# Each worker dispatch builds the prompt, seeds cross-turn context, runs the
# create_agent loop with the refusal-retry ladder, parses findings, salvages on
# crash. AgentConfig (the input contract) lives here; loading is in skills/loader.
#
# This module is the worker lifecycle proper. The pure helpers it leans on were
# split by concern into the sibling worker modules (findings / verdicts / salvage
# / seed_context / tool_attempts) and are imported below.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool

from src.llm.callbacks import make_call_config
from src.nodes.base.flag_watcher import (
    FlagCapturedSignal,
    SiblingCapturedSignal,
)
from src.nodes.base.prompt_builder import _build_system_message
from src.nodes.base.system_prompt import BENCHMARK_PROGRESS_FOOTER
from src.nodes.base.worker.findings import _extract_findings
from src.nodes.base.worker.salvage import _salvage_primitive_from_trace
from src.nodes.base.worker.seed_context import (
    _collect_prior_skill_history,
    _extract_latest_web_search,
    _format_dispatch_reason,
    _format_findings,
    _format_hypotheses,
    _format_investigation_thread,
    _format_recon_summary,
    _format_relevant_summary,
    _format_skill_context_catalogue,
    _format_tool_attempts,
)
from src.nodes.base.worker.tool_attempts import (
    _build_investigation_thread,
    _extract_tool_attempts_from_trace,
)
from src.nodes.base.worker.verdicts import _extract_verdicts
from src.observability import make_run_id
from src.observability.state import _count_worker_iterations
from src.refusals.detect import looks_like_refusal
from src.refusals.recover import recover_from_refusal
from src.refusals.retry import astream_with_refusal_retry
from src.refusals.salvage import try_salvage
from src.state import AgentResult, Finding, Severity, Signal

if TYPE_CHECKING:
    from src.nodes.base import BaseNode


# ── AgentConfig — in-memory carrier produced by src.skills.loader ──


@dataclass
class AgentConfig:
    # What makes one swarm agent different from another. Skill content
    # (system_prompt + tools + caps) is parsed from SKILL.md by skills/loader.py;
    # this is the in-memory carrier the loader produces.

    agent_id: str  # unique name, e.g. "owasp-auth-testing"
    methodology: str  # "owasp" | "vulntype" | "custom" | "skill"
    config_name: str  # primary key for planner dispatch — matches skill folder
    system_prompt: str = ""  # the SKILL.md body, minus frontmatter
    tools: list[BaseTool] = field(default_factory=list)  # LangChain instances resolved from SKILL.md tool names
    max_iterations: int = 20  # worker budget in REAL tool rounds; → recursion_limit (~3 super-steps/round); fallback default only
    skip_base_prompt: bool = False  # True → skip preamble/rules/role/RAG, SKILL.md body is the whole prompt
    phase: str = "executor"  # rule bundle: "executor" (full methodology) | "recon" (universal + recon hint, no exploit blocks)


def _persist_worker_trace(
    *,
    trace: list[Any],
    run_id: str,
    agent_id: str,
):
    # No-op shim — worker traces are no longer mirrored to disk (the old
    # worker_traces.jsonl was redundant with full_logs.jsonl). Kept as a function
    # so call sites need no conditional; returns None.
    del trace, run_id, agent_id  # explicitly unused
    return None


# ── The runner ──
# run_skill_agent is the entire worker lifecycle: build the prompt, seed context,
# run the agent loop with refusal retries, parse findings, salvage on crash.
# BaseNode.run_skill_agent is a thin async wrapper that forwards here.


async def run_skill_agent(
    node: "BaseNode",
    config: AgentConfig,
    state: dict,
    llm: BaseChatModel | None = None,
) -> dict:
    # Public entry point. Thin wrapper around _run_skill_agent_impl that guarantees
    # per-worker shell cleanup runs in a finally — otherwise each worker leaks its
    # tmux session + bash subprocess in the ShellManager until atexit.
    try:
        return await _run_skill_agent_impl(node, config, state, llm)
    finally:
        # Best-effort per-worker shell cleanup. Never raise from the finally — a
        # cleanup failure must not mask a successful return or a real exception.
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
    # Run a create_agent loop with the given skill config. Returns the standard
    # worker-node update dict (messages / agent_results / findings / active_agents).
    # node supplies node.log, node.name, node.ask_focused. Called only via
    # run_skill_agent (which adds the shell-cleanup finally).
    if llm is None:
        from src.llm.provider import get_llm  # lazy — see module docstring
        llm = get_llm()

    target_url = state.get("target_url", "")

    # Build the system message with the phase-appropriate rule bundle. The old
    # benchmark flag-criterion addendum was removed (2026-05-14) as the strongest
    # cyber_policy trigger; the planner owns flag submission. is_benchmark gates
    # the BENCHMARK_GUIDANCE addendum (executor-only).
    is_benchmark = bool(
        (state or {}).get("expected_flag")
        or (state or {}).get("expected_flag_candidates")
    )
    system_msg = _build_system_message(
        config, target_url, is_benchmark=is_benchmark,
    )

    # Agent construction is deferred to _agent_factory below so tier-2 refusal-retry
    # can rebuild it with a vocab-filtered prompt without losing this call's wiring.

    # Seed the loop with cross-turn context as a single HumanMessage. Order matters
    # for focus + prompt caching: stable/heavy first (skill_catalogue, findings,
    # recon), volatile state next, the concrete assignment last. Each helper returns
    # None when empty, so cold first dispatches start cold (back-compat).
    seed_parts: list[str] = []

    skill_catalogue_block = _format_skill_context_catalogue(config.config_name)
    if skill_catalogue_block:
        seed_parts.append(skill_catalogue_block)

    findings_block = _format_findings(state)
    if findings_block:
        seed_parts.append(findings_block)

    recon_block = _format_recon_summary(state)
    if recon_block:
        seed_parts.append(recon_block)

    relevant_block = _format_relevant_summary(state)
    if relevant_block:
        seed_parts.append(relevant_block)

    hypotheses_block = _format_hypotheses(state)
    if hypotheses_block:
        seed_parts.append(hypotheses_block)

    tool_attempts_block = _format_tool_attempts(state)
    if tool_attempts_block:
        seed_parts.append(tool_attempts_block)

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

    thread_block = _format_investigation_thread(state, config.config_name)
    if thread_block:
        seed_parts.append(thread_block)

    prior_history = _collect_prior_skill_history(state, config.agent_id)
    if prior_history:
        seed_parts.append(prior_history)

    dispatch_block = _format_dispatch_reason(state)
    if dispatch_block:
        seed_parts.append(dispatch_block)

    if seed_parts:
        seed_parts.append(
            "Begin testing now. Build on the context above; do not "
            "re-discover what's already mapped or re-probe what's "
            "already been confirmed."
        )

    # Benchmark status footer — appended LAST so it's the final thing the worker
    # reads. Capture is static (FlagWatcher ends the run on the real token), so this
    # keeps a worker from concluding early. Mirrors the planner footer.
    if is_benchmark:
        seed_parts.append(BENCHMARK_PROGRESS_FOOTER)

    if seed_parts:
        seed_msgs: list = [HumanMessage(content="\n\n".join(seed_parts))]
        node.log.info(
            "[%s] seeding worker with %d context block(s) "
            "(dispatch_reason=%s, findings=%s, recon_summary=%s, "
            "relevant_summary=%s, tool_attempts=%s, skill_catalogue=%s, "
            "web_search=%s, prior_history=%s, benchmark_footer=%s)",
            config.agent_id,
            sum(bool(b) for b in (
                dispatch_block, findings_block, recon_block,
                relevant_block, tool_attempts_block, skill_catalogue_block,
                web_search_ctx, prior_history,
            )),
            bool(dispatch_block),
            bool(findings_block),
            bool(recon_block),
            bool(relevant_block),
            bool(tool_attempts_block),
            bool(skill_catalogue_block),
            bool(web_search_ctx),
            bool(prior_history),
            is_benchmark,
        )
    else:
        seed_msgs = []

    trace: list = []
    findings: list[Finding] = []
    verdict_signals: list[Signal] = []
    # Resolve run_id once so every LLM call logs into the same llm_calls.jsonl and
    # the salvage path knows where to write.
    run_id = (state or {}).get("run_id") or make_run_id(
        target_url=target_url,
    )
    # call_config carries callbacks (token logger + optional flag watcher), metadata
    # (agent_id/run_id/node), and the recursion_limit budget. In benchmark mode the
    # FlagWatcherCallback hooks on_tool_end and raises FlagCapturedSignal the instant
    # a tool returns the expected flag — short-circuiting before the next LLM call.
    from src.nodes.base.flag_watcher import FlagWatcherCallback
    # Pass the full candidate set to the watcher — benchmarks can legitimately have
    # multiple expected values. Falls back to the single expected_flag field.
    expected_flag_candidates_for_callback: tuple[str, ...] = tuple(
        (state or {}).get("expected_flag_candidates") or ()
    )
    if not expected_flag_candidates_for_callback:
        single = (state or {}).get("expected_flag") or ""
        if single:
            expected_flag_candidates_for_callback = (single,)
    worker_callbacks: list = []
    if expected_flag_candidates_for_callback:
        worker_callbacks.append(FlagWatcherCallback(
            expected_flag=expected_flag_candidates_for_callback,
            agent_id=config.agent_id,
        ))
    # max_iterations is the budget in REAL tool rounds; LangGraph's recursion_limit
    # counts super-steps (~3/round: nudge before_model + model + tools). Convert
    # rounds → super-steps (3*rounds + 1) so config, budget, and
    # _count_worker_iterations all speak in real-round units.
    recursion_limit = config.max_iterations * 3 + 1
    call_config = make_call_config(
        run_id=run_id,
        agent_id=config.agent_id,
        node=node.name,
        recursion_limit=recursion_limit,
        extra_callbacks=worker_callbacks or None,
    )

    # Stream (not ainvoke) so a partial snapshot survives crashes: stream_mode=
    # "values" yields full-state snapshots, we keep the latest. On GraphRecursionError
    # last_snapshot holds messages up to the last step — what salvage consumes. The
    # agent is rebuilt inside the retry helper (vocab-filter / tier-2 swap).
    #
    # The no-progress nudge middleware (shared across primary + fallback factories)
    # fires only on byte-identical tool outputs and only re-surfaces existing
    # DIVERSITY_RULES guidance — it never stops the worker.
    from src.nodes.base.prompt_builder import NoProgressNudgeMiddleware
    _no_progress_mw = NoProgressNudgeMiddleware(
        agent_id=config.agent_id, log=node.log,
    )
    # Ablation: the nudge re-injects DIVERSITY_RULES / TRANSFORMATION_HYPOTHESIS in
    # loop, so it IS a dynamically-delivered prompting technique. When prompting
    # techniques are ablated, drop it too, else a stuck worker is still rescued by
    # the exact guidance the ablation removes. Read via module object (import cycle).
    from src import graph as _graph_module
    _prompting_off = bool(getattr(
        getattr(_graph_module.config, "capability", None),
        "disable_prompting_techniques", False,
    ))
    _middleware = [] if _prompting_off else [_no_progress_mw]

    # Per-dispatch progressive-disclosure tool: when this skill ships reference files,
    # bind a scoped read_reference tool. Wrapped defensively — reference wiring must
    # never break a run.
    _run_tools = list(config.tools)
    try:
        from src.skills.loader import list_references
        from src.tools.references import (
            make_read_reference_tool,
            make_read_skill_context_tool,
            make_read_skill_reference_tool,
        )
        if list_references(config.config_name):
            _run_tools.append(make_read_reference_tool(config.config_name))
        _run_tools.append(make_read_skill_context_tool())
        _run_tools.append(make_read_skill_reference_tool())
    except Exception as _ref_exc:
        node.log.debug("reference/context tool wiring skipped: %s", _ref_exc)

    def _agent_factory(sys_prompt: str):
        return create_agent(
            model=llm,
            tools=_run_tools,
            system_prompt=sys_prompt,
            middleware=_middleware,
        )

    # Tier-2 fallback factory — only wired when the primary provider is Codex
    # (model-swap to gpt-5.4 isn't meaningful for other routes). See
    # src/refusals/retry.py for the tier ladder and config.budgets.fallback_* knobs.
    from src.llm.provider import LLMConfig as _LLMConfig
    from src.llm.provider import Provider as _Provider
    fallback_factory: Any = None
    _fallback_model: str | None = None
    _fallback_effort: str | None = None
    _primary_cfg = _LLMConfig()
    if _primary_cfg.provider == _Provider.CODEX:
        # Lazy import — skill_runner is imported transitively from src.graph
        # during init, so a top-level import would re-enter while config is still
        # binding. Read via the module object at call-time.
        from src import graph as _graph_module
        _fallback_model = str(getattr(
            _graph_module.config.budgets, "fallback_model", "gpt-5.4",
        ))
        _fallback_effort = str(getattr(
            _graph_module.config.budgets, "fallback_reasoning_effort", "low",
        ))

        def _fallback_agent_factory(sys_prompt: str):
            from src.llm.provider import get_llm as _get_llm
            fb_llm = _get_llm(_LLMConfig(
                provider=_Provider.CODEX,
                model=_fallback_model,
                reasoning_effort=_fallback_effort,
            ))
            return create_agent(
                model=fb_llm,
                tools=_run_tools,
                system_prompt=sys_prompt,
                middleware=_middleware,
            )

        fallback_factory = _fallback_agent_factory

    last_snapshot: dict | None = None
    worker_attempts = 0
    worker_last_tier = "primary"
    flag_watcher_capture: str | None = None
    sibling_captured_value: str = ""

    # Sticky fallback: if this config's prompt already tripped the primary's
    # cyber_policy classifier this run, start on the fallback model — the primary
    # would refuse again, wasting 3 retries. (No-op when no fallback is wired.)
    start_on_fallback = (
        fallback_factory is not None
        and config.config_name in set((state or {}).get("fallback_configs") or [])
    )
    if start_on_fallback:
        node.log.info(
            "[%s] config %r refused on the primary model earlier this run — "
            "dispatching directly on the fallback model",
            config.agent_id, config.config_name,
        )
    try:
        # Inner try catches the FlagWatcher's short-circuit signals so they don't
        # reach the outer except (mis-classified as refusals). FlagCapturedSignal:
        # THIS worker matched → synthesise a ToolMessage for the auto-verify scan.
        # SiblingCapturedSignal: another worker won → exit clean, don't set captured_flag.
        try:
            (
                last_snapshot,
                worker_attempts,
                worker_last_tier,
            ) = await astream_with_refusal_retry(
                agent_factory=_agent_factory,
                fallback_agent_factory=fallback_factory,
                fallback_model_label=(
                    str(_fallback_model) if fallback_factory is not None else None
                ),
                system_msg=system_msg,
                seed_msgs=seed_msgs,
                call_config=call_config,
                config=config,
                log=node.log,
                start_on_fallback=start_on_fallback,
            )
        except FlagCapturedSignal as sig:
            flag_watcher_capture = sig.flag
            node.log.info(
                "[%s] FlagWatcher captured flag in %s output: %s — "
                "short-circuiting worker (saves Codex spend + unblocks "
                "fan-in)",
                config.agent_id, sig.tool_name or "tool", sig.flag,
            )
            # Append a synthetic ToolMessage with the captured value to the partial
            # snapshot — the downstream auto-verify scan expects exactly this. The
            # snapshot is partial because FlagWatcher raises in on_tool_end, before
            # LangGraph yields the next snapshot; this bridges the gap.
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
            # Sibling captured first; exit with an empty update so fan-in completes.
            # Routing reads state.captured_flag (set by the winner) — not touched here.
            sibling_captured_value = sig.captured_flag
            node.log.info(
                "[%s] sibling worker captured the flag (%s) — "
                "exiting cleanly to unblock fan-in",
                config.agent_id, sig.captured_flag,
            )

        result = last_snapshot or {}
        messages = result.get("messages", [])
        findings = _extract_findings(messages, config.agent_id)
        verdict_signals = _extract_verdicts(
            messages, config.agent_id, config.config_name,
        )

        # If the FlagWatcher fired, synthesise a CRITICAL Finding so the worker
        # reports 1 finding, not 0. Capture itself routes via captured_flag; this is
        # the human-readable companion.
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

        # Mirror the inner agent trace to the parent so Studio chat shows every tool
        # call + response inline; otherwise the conversation is hidden in the
        # create_agent sub-graph and the parent looks frozen.
        trace = [m for m in messages if isinstance(m, (AIMessage, ToolMessage))]
        for m in trace:
            # Tag each message with agent_id so consumers can group/filter by agent.
            try:
                m.additional_kwargs.setdefault("agent_id", config.agent_id)
            except Exception:
                pass

        # Refusal detection — if 0 findings AND the last assistant message reads like
        # a safety refusal, surface it explicitly instead of swallowing it as "0
        # findings". Skipped when sibling_captured_value is set (clean early exit, not
        # a refusal — treating it as one would trigger a needless recovery sub-call).
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
                # Treat as not-refused so completed=True and the planner sees the
                # suggestion as actionable evidence.
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

        # Sibling-cancelled workers are a clean cooperative exit, not a refusal or
        # crash — surface on a distinct error channel so triage can tell "tried and
        # failed" from "stood down because another worker won".
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
        # Rate-limit (429) / quota errors are NOT salvageable — this run never got a
        # fair attempt, so re-raise to abort; xbow_runner marks it crashed and the
        # usage guard pauses the sweep. Everything else keeps the salvage path below.
        try:
            from src.llm.codex import (
                CodexQuotaExceededError as _CodexQuota,
                CodexRateLimitError as _CodexRateLimit,
            )
            _rate_limit_types: tuple = (_CodexQuota, _CodexRateLimit)
        except ImportError:
            _rate_limit_types = ()
        if _rate_limit_types and isinstance(e, _rate_limit_types):
            raise

        # The refusal-retry ladder tags the exception with the tier it reached. On a
        # terminal refusal the tuple-unpack never ran, so recover the real tier here
        # so the sticky-fallback record fires when the fallback was exhausted too.
        worker_last_tier = getattr(e, "_swarm_last_tier", worker_last_tier)

        # Cyber-policy / invalid-prompt failures from Codex are refusals, not crashes.
        # Surface on error="model refused" so the planner can pivot, and try a focused
        # recovery sub-call in case the agent made usable probes before the API
        # rejected the next request. Lazy import for the planner/executor import dance.
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

        # Pull whatever messages survived the crash into the trace so the chat /
        # nodes.jsonl still show what the worker did. On a terminal refusal / budget
        # stop / crash the tuple-unpack never ran, so last_snapshot is None — recover
        # the richest partial trace the retry helper attached to the exception.
        if last_snapshot is None:
            _recovered = getattr(e, "_swarm_partial_snapshot", None)
            if isinstance(_recovered, dict):
                last_snapshot = _recovered
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
            # Refusal-time flag salvage: Codex can refuse mid-run after the worker
            # already executed tool calls, one of whose responses may hold a captured
            # flag{...}. Without this the refusal branch wipes findings and the planner
            # never learns the worker won (XBEN-006-24, 2026-05-09). Lazy import.
            findings = []
            try:
                from src.edges.flag_match import extract_flags

                # Stringify partial messages inline. The old src.flag helper was
                # deleted in the 2026-05 refactor; salvage still scans a refused
                # worker's partial trace, so the stringifier lives here now.
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
                    # Short evidence excerpt around the match so a human can eyeball
                    # the request that produced it.
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
                # Salvage must never make the refusal path worse; log and fall through.
                node.log.warning(
                    "[%s] refusal-path flag salvage failed: %s: %s",
                    config.agent_id,
                    type(salv_err).__name__,
                    str(salv_err)[:160],
                )

            # Refusal-path PRIMITIVE salvage: if no flag, the worker may still have
            # PROVEN a non-flag capability in the refused output. Mint a HIGH primitive
            # finding so the planner can drive it to the flag later. Scans received
            # tool output only, negation-guarded; never raises.
            salvaged_primitive = False
            if not findings:
                try:
                    prim = _salvage_primitive_from_trace(
                        partial_messages, config.agent_id,
                    )
                    if prim is not None:
                        findings = [prim]
                        salvaged_primitive = True
                        node.log.warning(
                            "[%s] refusal-path primitive salvage: "
                            "recovered a %r primitive from the partial "
                            "trace before discard.",
                            config.agent_id, prim.primitive,
                        )
                except Exception as prim_err:  # noqa: BLE001
                    node.log.warning(
                        "[%s] refusal-path primitive salvage failed: "
                        "%s: %s",
                        config.agent_id,
                        type(prim_err).__name__,
                        str(prim_err)[:160],
                    )

            trace.append(AIMessage(
                content=(
                    f"⚠️ [{config.agent_id}] model refused the task at "
                    f"the API safety layer ({type(e).__name__}). "
                    "Recommend the planner pick a different skill or "
                    "rephrase the goal more narrowly."
                    + (
                        f"\n\n[salvage] Recovered a "
                        f"{findings[0].severity.value} finding from the "
                        f"partial trace before refusal: {findings[0].title}"
                        if findings
                        else ""
                    )
                ),
                additional_kwargs={
                    "agent_id": config.agent_id,
                    "refusal": True,
                    "refusal_kind": "api_cyber_policy",
                    "salvaged_flag": bool(findings) and not salvaged_primitive,
                    "salvaged_primitive": salvaged_primitive,
                },
            ))
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                # If we salvaged a flag, treat the worker as completed for planner
                # accounting — its contribution was real despite the API rejection.
                completed=bool(findings),
                error="model refused" if not findings else None,
            )
        elif (
            "recursion limit" in str(e).lower()
            or type(e).__name__ == "GraphRecursionError"
        ):
            # ── Step-budget stop (NOT a crash) ──
            # The worker exhausted its recursion_limit; the model is still reachable,
            # it just ran out of turns. So no post-crash salvage guesser. Instead:
            # recover the FINDING blocks already written, then make ONE forced wrap-up
            # call. See src/nodes/base/prompt_builder.py.
            node.log.warning(
                "[%s] reached its step budget (%s) — forcing a graceful "
                "wrap-up instead of discarding the run.",
                config.agent_id, str(e)[:160],
            )
            from src.nodes.base.prompt_builder import force_wrapup_summary

            own_findings = _extract_findings(partial_messages, config.agent_id)
            wrapup_msg = await force_wrapup_summary(
                config=config,
                partial_messages=partial_messages,
                target_url=target_url,
                log=node.log,
                run_id=run_id,
            )
            wrapup_findings = (
                _extract_findings([wrapup_msg], config.agent_id)
                if wrapup_msg else []
            )
            # Dedup by (title, url) — the worker often re-emits in the wrap-up a
            # finding it already wrote in the trace.
            findings = []
            _seen_keys: set = set()
            for f in own_findings + wrapup_findings:
                key = (getattr(f, "title", ""), getattr(f, "url", ""))
                if key in _seen_keys:
                    continue
                _seen_keys.add(key)
                findings.append(f)

            trace = [
                m for m in partial_messages
                if isinstance(m, (AIMessage, ToolMessage))
            ]
            if wrapup_msg:
                trace.append(wrapup_msg)
            trace.append(AIMessage(
                content=(
                    f"⏱ [{config.agent_id}] reached its step budget and "
                    f"was asked to wrap up ({e}). This is a completed pass "
                    f"that ran out of room, not a crash — "
                    f"{len(findings)} finding(s) recovered from its work. "
                    "If its lead looked promising, re-dispatch it "
                    "(optionally with a larger budget) rather than "
                    "treating it as a dead end."
                ),
                additional_kwargs={
                    "agent_id": config.agent_id,
                    "budget_stop": True,
                    "findings_recovered": len(findings),
                },
            ))
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                # Informative but NOT "model refused", so the planner's refusal/
                # repetition logic doesn't mis-handle it. A budget stop is a real
                # completed pass — count it as a turn.
                error="stopped at step budget",
                completed=True,
            )
        else:
            node.log.error(f"Agent {config.agent_id} failed: {e}")
            # Genuine crash — not a refusal or budget stop (tool blew up, transport
            # error, unexpected exception). The trace may hold impact the worker never
            # formalized, so fall back to the post-crash salvage guesser (one bounded
            # sub-LLM call, returns None on failure). See src/refusals/salvage.py.
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
                # A salvaged finding lets the planner act, so completed=True so the
                # repetition detector counts it as a real turn.
                completed=bool(salvaged),
            )

    # Persist the full trace to disk for forensics — the planner never reads it
    # directly; the summarizer consumes the in-memory trace via pending_summary_inputs.
    # Primarily for human debugging after the run.
    trace_path = _persist_worker_trace(
        trace=trace,
        run_id=run_id,
        agent_id=config.agent_id,
    )

    # Resolve the dispatch reason from state (set by the planner, forwarded through
    # the routing edge). Empty for cold runs — the summarizer handles that gracefully.
    dispatch_reason = (
        state.get("dispatch_reason")
        or state.get("dispatch_focus")
        or ""
    )

    tool_attempts = _extract_tool_attempts_from_trace(
        trace,
        agent_id=config.agent_id,
        config_name=config.config_name,
    )
    if tool_attempts:
        node.log.info(
            "[%s] extracted %d structured tool outcome(s)",
            config.agent_id, len(tool_attempts),
        )
        try:
            from src.observability.writers import append_event
            append_event(
                run_id,
                "tool_attempts_extracted",
                agent_id=config.agent_id,
                config_name=config.config_name,
                attempts=tool_attempts,
            )
        except Exception:  # noqa: BLE001
            pass

    # The worker's effective system prompt (after the preventive vocab filter the
    # retry helper always applies). Propagated into summary_input so the summariser
    # replays it byte-identically for a prompt-cache hit. filter_text is deterministic.
    # Lazy import to avoid a cycle through src.refusals at load.
    from src.refusals.vocabulary import (
        filter_messages as _filter_messages,
        filter_text as _filter_text,
    )
    worker_system_prompt_used, _ = _filter_text(system_msg)
    worker_seed_msgs_used, _ = _filter_messages(seed_msgs)

    # Reconstruct the exact worker conversation prefix for the summarizer: filtered
    # seed message(s) + the AI/Tool trace. Prefer the full snapshot (it includes
    # middleware-injected notes); append synthetic wrap-up/salvage messages added after.
    snapshot_messages = []
    if isinstance(last_snapshot, dict):
        snapshot_messages = [
            m for m in (last_snapshot.get("messages") or [])
            if isinstance(m, BaseMessage)
        ]
    if snapshot_messages:
        worker_messages_for_summary = list(snapshot_messages)
        seen_msg_ids = {id(m) for m in worker_messages_for_summary}
        for msg in trace:
            if isinstance(msg, BaseMessage) and id(msg) not in seen_msg_ids:
                worker_messages_for_summary.append(msg)
                seen_msg_ids.add(id(msg))
    else:
        worker_messages_for_summary = [
            m for m in list(worker_seed_msgs_used) + list(trace)
            if isinstance(m, BaseMessage)
        ]

    # The summary input the SummarizerNode consumes. Each parallel worker writes a
    # singleton list; _summary_inputs_reducer accumulates them so the summarizer (the
    # fan-out sync point) sees one entry per worker.
    summary_input: dict = {
        "agent_id": config.agent_id,
        "config_name": config.config_name,
        "methodology": config.methodology,
        "dispatch_reason": dispatch_reason,
        "trace": trace,                    # in-memory, not mirrored to messages
        "worker_messages": worker_messages_for_summary,
        "trace_path": str(trace_path) if trace_path else "",
        "completed": getattr(agent_result, "completed", False),
        "error": getattr(agent_result, "error", None),
        "refused": (getattr(agent_result, "error", None) == "model refused"),
        "findings_count": len(findings),
        "iteration_count": _count_worker_iterations(trace),
        "target_url": target_url,
        "tool_attempts": tool_attempts,
        # Keep the summarizer request cache-compatible with the worker: Codex's
        # prompt cache includes tool schemas, so replaying with tools removed misses it.
        "summary_tools": list(_run_tools),
        # The exact system prompt the worker's LLM saw — so the summariser shares
        # the worker's cached prefix.
        "worker_system_prompt": worker_system_prompt_used,
    }
    if worker_last_tier == "fallback" and _fallback_model:
        summary_input["summary_model"] = _fallback_model
        summary_input["summary_reasoning_effort"] = _fallback_effort or "low"

    # ── Success-path flag auto-verification ──
    # In benchmark mode, scan the worker's tool messages for flag{...} and strict-
    # equal them against expected_flag. On a match, surface via state.captured_flag
    # (terminates the graph) and push onto submission_attempts (xbow_runner's verdict).
    # Strict equality is the false-positive filter; in real-pentest mode this is a no-op.
    captured_flag_value: str | None = None
    expected_flag = (state or {}).get("expected_flag") or ""
    # Full candidate set the matcher accepts — benchmarks can have multiple legitimate
    # values. Falls back to the single expected_flag (back-compat).
    expected_flag_candidates: tuple[str, ...] = tuple(
        (state or {}).get("expected_flag_candidates") or ()
    )
    if not expected_flag_candidates and expected_flag:
        expected_flag_candidates = (expected_flag,)
    # Counters that always end up in the auto-verify event, so post-mortem can see
    # "scanned N messages, K candidates, matched 0" without re-reading the trace.
    tool_msgs_scanned = 0
    candidates_seen = 0
    if expected_flag_candidates and last_snapshot:
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
                # ToolMessage content can be a list of content blocks — flatten to text.
                content_str = "\n".join(
                    str((block or {}).get("text") or block)
                    if isinstance(block, dict) else str(block)
                    for block in c
                )
            else:
                continue
            for candidate in extract_flags(content_str):
                candidates_seen += 1
                if flags_match(
                    submitted=candidate,
                    expected=expected_flag_candidates,
                ):
                    captured_flag_value = candidate
                    node.log.info(
                        "[%s] auto-verified flag in tool output: %s "
                        "(matches any of %d expected candidates)",
                        config.agent_id, candidate,
                        len(expected_flag_candidates),
                    )
                    break
            if captured_flag_value:
                break

    # Structured record of the scan — fires whether or not we matched, so post-mortem
    # can answer "did the scan run?" with one jq query. The 2026-05-25 XBEN-006-24
    # incident: workers had the flag in output but no artefact recorded whether the
    # scan matched, so detection vs routing was ambiguous.
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
                expected_flag_candidates=list(expected_flag_candidates),
                captured_flag=captured_flag_value or "",
                matched=captured_flag_value is not None,
                tool_msgs_scanned=tool_msgs_scanned,
                candidates_seen=candidates_seen,
                last_snapshot_present=last_snapshot is not None,
            )
        except Exception:  # noqa: BLE001
            pass

    # Build the worker digest now, while the prompt prefix is still hot in the provider
    # cache, instead of waiting for the slowest sibling at the fan-in barrier. Skip
    # LLM digesting on capture/cancel paths so a solved benchmark isn't delayed.
    if captured_flag_value is not None:
        summary_input["skip_digest_reason"] = "flag captured"
        summary_input["precomputed_report"] = AIMessage(
            content=(
                "## Status\nsuccess — flag captured\n\n"
                f"## Target\n{target_url}\n\n"
                "## Inputs tried\nThe worker captured the expected flag "
                "during tool execution; see the raw worker trace for the "
                "exact request/response.\n\n"
                f"## Server responses\nCaptured flag: {captured_flag_value}\n\n"
                "## Inferred server-side behaviour\nThe exercised path "
                "returned the benchmark token.\n\n"
                "## NOT tried\nNot applicable after verified capture.\n\n"
                "## Recommended next dispatch\nNone — verified capture.\n\n"
                "## Cross-skill handoffs\n[]\n\n"
                "## Next skill suggestions\n[]"
            ),
            additional_kwargs={
                "agent_id": config.agent_id,
                "kind": "worker_report",
                "config_name": config.config_name,
                "methodology": config.methodology,
                "status": "success",
                "iteration_count": int(summary_input.get("iteration_count") or 0),
                "findings_count": len(findings),
                "precomputed_at_worker_exit": True,
                "skip_digest_reason": "flag captured",
            },
        )
    elif sibling_captured_value:
        summary_input["skip_digest_reason"] = "sibling captured"
        summary_input["precomputed_report"] = AIMessage(
            content=(
                "## Status\nstopped — sibling worker captured the flag\n\n"
                f"## Target\n{target_url}\n\n"
                "## Inputs tried\nThis worker exited early after another "
                "worker captured the expected flag.\n\n"
                "## Server responses\nNo additional response summary was "
                "generated after sibling capture.\n\n"
                "## Inferred server-side behaviour\nNot applicable.\n\n"
                "## NOT tried\nNot applicable after verified capture.\n\n"
                "## Recommended next dispatch\nNone — another worker already "
                "captured the flag.\n\n"
                "## Cross-skill handoffs\n[]\n\n"
                "## Next skill suggestions\n[]"
            ),
            additional_kwargs={
                "agent_id": config.agent_id,
                "kind": "worker_report",
                "config_name": config.config_name,
                "methodology": config.methodology,
                "status": "sibling_captured",
                "iteration_count": int(summary_input.get("iteration_count") or 0),
                "findings_count": len(findings),
                "precomputed_at_worker_exit": True,
                "skip_digest_reason": "sibling captured",
            },
        )
    else:
        try:
            from src.llm.digest import (
                bind_tools_for_summary_cache,
                summarize_worker_trace,
            )

            summary_llm: Any = llm
            if worker_last_tier == "fallback" and _fallback_model:
                try:
                    from src.llm.provider import get_llm as _get_llm
                    summary_llm = _get_llm(_LLMConfig(
                        provider=_Provider.CODEX,
                        model=_fallback_model,
                        reasoning_effort=_fallback_effort or "low",
                    ))
                except Exception as e:  # noqa: BLE001
                    node.log.debug(
                        "[%s] fallback summary model rebuild failed; "
                        "using primary model for digest: %s",
                        config.agent_id,
                        e,
                    )
            summary_llm = bind_tools_for_summary_cache(summary_llm, _run_tools)

            summary_input["precomputed_report"] = await summarize_worker_trace(
                trace=list(summary_input.get("trace") or []),
                worker_messages=list(summary_input.get("worker_messages") or []),
                worker_system_prompt=str(
                    summary_input.get("worker_system_prompt") or ""
                ),
                agent_id=config.agent_id,
                config_name=config.config_name,
                methodology=config.methodology,
                dispatch_reason=str(summary_input.get("dispatch_reason") or ""),
                target_url=str(summary_input.get("target_url") or target_url or ""),
                findings_count=len(findings),
                iteration_count=int(summary_input.get("iteration_count") or 0),
                completed=bool(getattr(agent_result, "completed", False)),
                error=getattr(agent_result, "error", None),
                refused=bool(getattr(agent_result, "error", None) == "model refused"),
                model=summary_llm,
                run_id=(state or {}).get("run_id"),
                node_name="summarizer",
            )
            akw = dict(
                getattr(summary_input["precomputed_report"], "additional_kwargs", {})
                or {}
            )
            akw["precomputed_at_worker_exit"] = True
            summary_input["precomputed_report"].additional_kwargs = akw
        except Exception as e:  # noqa: BLE001
            node.log.warning(
                "[%s] worker-exit digest failed (%s: %s); "
                "SummarizerNode will retry at fan-in",
                config.agent_id,
                type(e).__name__,
                str(e)[:200],
            )

    update: dict[str, Any] = {
        # NOTE: no "messages": trace — that caused the global-prompt explosion. The
        # trace stays on disk and in pending_summary_inputs[*].trace until the
        # SummarizerNode replaces it with one AIMessage digest.
        "pending_summary_inputs": [summary_input],
        "agent_results": [agent_result],
        "findings": findings,
        "active_agents": [config.agent_id],
    }
    if verdict_signals:
        # The worker's closing self-assessment — deciding-probe feedback that lets the
        # synthesis pass recalibrate belief (confirm crosses COMMIT, refute drives down).
        # See _extract_verdicts.
        update["signals"] = verdict_signals
        node.log.info(
            "[%s] verdict: %s",
            config.agent_id,
            "; ".join(
                f"{s.vuln_class}={'+' if s.weight >= 0 else ''}{s.weight:.1f}({s.kind})"
                for s in verdict_signals
            ),
        )
    if tool_attempts:
        update["tool_attempts"] = tool_attempts
    # Continuity: append this dispatch's compacted record to the skill's investigation
    # thread so the NEXT dispatch continues instead of re-deriving. See _build_investigation_thread.
    try:
        update["investigation_threads"] = _build_investigation_thread(
            state, config.config_name, messages, verdict_signals,
        )
    except Exception as e:  # noqa: BLE001 — continuity must never break a run
        node.log.warning(
            "[%s] investigation-thread build failed (%s) — skipping",
            config.agent_id, e,
        )
    # Sticky-fallback bookkeeping: if this dispatch used the fallback model, record the
    # config so its NEXT dispatch this run skips the doomed primary tier.
    if start_on_fallback or worker_last_tier == "fallback":
        update["fallback_configs"] = [config.config_name]
    if captured_flag_value is not None:
        update["captured_flag"] = captured_flag_value
        # Mirror onto submission_attempts so xbow_runner's verdict path (reads [-1])
        # sees the capture unchanged. The graph terminates via the normal route_after_
        # summarizer → END path: captured_flag lands via the reducer, siblings exit fast,
        # fan-in completes, summarizer fires, routing reads captured_flag → END.
        update["submission_attempts"] = [captured_flag_value]
    return update
