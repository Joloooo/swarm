# prompt_builder — assemble and deliver the worker's prompt across its lifecycle.
# build_prompt + PHASE_BLOCKS compose a phase's rule blocks; _build_system_message
# wraps them with per-worker context; the nudges re-inject guidance mid-loop and at
# wrap-up. The prompt TEXT itself lives in system_prompt.py — this module assembles it.

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from src.nodes.base.flag_watcher import _coerce_to_text
from src.nodes.base.system_prompt import (
    BEHAVIOR_MODEL_RULES,
    BENCHMARK_GUIDANCE,
    COMMON_CHECKLIST_DISCIPLINE,
    DEMONSTRATED_STANDARD,
    DIVERSITY_RULES,
    ENUMERATION_DISCIPLINE,
    EXHAUSTION_DISCIPLINE,
    FINDING_CATEGORY_GUIDANCE,
    FINDING_NOVELTY_RULE,
    FINDING_SCHEMA,
    IDENTITY_PREAMBLE,
    METHODOLOGY_RULES,
    NARRATION_RULES,
    RECON_FINDINGS_HINT,
    SCOPE_RULES,
    SEVERITY_RULES,
    STEALTH_RULES,
    TOOL_USAGE_RULES,
    TRANSFORMATION_HYPOTHESIS,
    VERDICT_SCHEMA,
)

if TYPE_CHECKING:
    from src.nodes.base import AgentConfig

logger = logging.getLogger(__name__)


# ── What each phase's prompt is made of (read top-to-bottom) ──────────────
# Composition manifest: each phase is a list of the rule-block constants imported
# above. build_prompt joins the chosen list; the ablation drops the _STANDARDS subset.
_UNIVERSAL = [IDENTITY_PREAMBLE, NARRATION_RULES, SCOPE_RULES, TOOL_USAGE_RULES, FINDING_SCHEMA]
_STANDARDS = [EXHAUSTION_DISCIPLINE, DIVERSITY_RULES, ENUMERATION_DISCIPLINE,
              COMMON_CHECKLIST_DISCIPLINE, TRANSFORMATION_HYPOTHESIS]   # dropped by ablation
_EXECUTOR = [METHODOLOGY_RULES, DEMONSTRATED_STANDARD, *_STANDARDS, BEHAVIOR_MODEL_RULES,
             SEVERITY_RULES, FINDING_CATEGORY_GUIDANCE, VERDICT_SCHEMA, FINDING_NOVELTY_RULE]

PHASE_BLOCKS = {
    "universal": _UNIVERSAL,
    "recon": _UNIVERSAL + [RECON_FINDINGS_HINT],
    "executor": _UNIVERSAL + _EXECUTOR,
}


# ── Prompt assembly ──────────────────────────────────────────────────────


def _prompting_techniques_disabled() -> bool:
    # Ablation gate (thesis "Prompting Standards"): drop the five standards
    # blocks when the run sets capability.disable_prompting_techniques.
    try:
        from src.graph import config as _rt
        return bool(getattr(_rt.capability, "disable_prompting_techniques", False))
    except Exception:  # noqa: BLE001 — never let the gate break prompt assembly
        return False


def build_prompt(phase: str = "executor", stealth_level: int = 0) -> str:
    # Assemble a phase's prompt from PHASE_BLOCKS (defined at the BOTTOM of this
    # file — the manifest lists the block constants, so it must come after them;
    # build_prompt reads it at call time, so the forward reference is fine).
    # Ablation drops the _STANDARDS subset; STEALTH_RULES is inserted right after
    # the universal head when a WAF/IDS has been tripped.
    blocks = list(PHASE_BLOCKS[phase])
    if stealth_level >= 1:
        blocks.insert(len(_UNIVERSAL), STEALTH_RULES)
    if _prompting_techniques_disabled():
        blocks = [b for b in blocks if b not in _STANDARDS]
    return "\n\n".join(blocks)


def _build_system_message(
    config: "AgentConfig",  # noqa: F821 — forward reference; defined in skill_runner
    target_url: str,
    is_benchmark: bool = False,
) -> str:
    # Assemble the full system prompt. skip_base_prompt → SKILL.md body alone; else:
    # identity header + phase rules + skill body + refs + benchmark addendum + RAG hint.
    if config.skip_base_prompt:
        parts = []
        if config.system_prompt:
            parts.append(config.system_prompt)
        return "\n\n".join(parts)

    parts = []
    phase = getattr(config, "phase", "executor") or "executor"

    # Role identity header. Recon gets a target-only line: the swarm/methodology/focus
    # framing was itself the strongest cyber_policy refusal trigger on benign recon.
    if phase == "recon":
        parts.append(f"Target: {target_url}\n")
    else:
        parts.append(
            f"You are a security testing agent (ID: {config.agent_id}) "
            f"in the SwarmAttacker swarm.\n"
            f"Methodology: {config.methodology}\n"
            f"Focus area: {config.config_name}\n"
            f"Target: {target_url}\n"
        )

    parts.append(build_prompt("recon" if phase == "recon" else "executor", 0))

    # SKILL.md body (phase-specific objectives / methodology).
    if config.system_prompt:
        parts.append(config.system_prompt)

    # Progressive-disclosure references: advertise the skill's reference files so the
    # worker can page one in on demand with read_reference. Index built from each H1.
    try:
        from src.skills.loader import reference_index
        _refs = reference_index(config.config_name)
    except Exception:
        _refs = []
    if _refs:
        _ref_lines = [
            "## References",
            "Additional reference material for this skill (test inputs and "
            "engine-specific techniques), kept out of this prompt for size. "
            "Open ONE on demand with the read_reference tool (pass the filename "
            "only) when a finding matches its \"Open WHEN\" note:",
        ]
        _ref_lines += [f"- `{fn}` — {desc}" for fn, desc in _refs]
        parts.append("\n".join(_ref_lines))

    # Benchmark addendum — executor + benchmark only, placed last so "the app is the
    # referee, submit and read its reply" is the final behavioural instruction.
    if is_benchmark and phase != "recon":
        parts.append(BENCHMARK_GUIDANCE)

    # RAG hint (retrieval happens at query time).
    parts.append(
        "\n--- Dynamic Knowledge ---\n"
        "If you need specific CVE details, bypass techniques, or tool syntax "
        "that you're unsure about, describe what you need and the system will "
        "provide relevant knowledge snippets.\n"
    )

    return "\n\n".join(parts)


# ── No-progress nudge (mid-loop) ──────────────────────────────────────────


def _threshold() -> int:
    # Consecutive byte-identical tool outputs required before nudging. Env
    # override SWARM_NOPROGRESS_THRESHOLD (default 3); values < 2 coerce to 3.
    try:
        n = int(os.getenv("SWARM_NOPROGRESS_THRESHOLD", "3"))
    except (TypeError, ValueError):
        return 3
    return n if n >= 2 else 3


# Injected reminder: restates DIVERSITY_RULES in-loop in neutral vocabulary and
# says BROADEN, not give up — the only "stop" is conditional on exhausted categories.
_NUDGE_TEMPLATE = (
    "[automatic system note — not from the operator] Your last {n} tool "
    "responses came back byte-for-byte identical. Identical responses "
    "mean your inputs are carrying SOMETHING the server recognises and "
    "rejects the same way every time — sending more variants of the same "
    "idea will keep returning the same response. Stop and broaden: list "
    "at least 5 different CATEGORIES of variation that could matter for "
    "this input type (shape/format, case, encoding, character "
    "substitution, structural splits, boundary values, a different "
    "transformation stage), and try a few from EACH category in ONE "
    "batched command — instead of going deeper on the category you are "
    "already in. If you have genuinely exhausted the categories, switch "
    "tactic or report what you have established. Do not simply repeat the "
    "same shape again."
)


class NoProgressNudgeMiddleware(AgentMiddleware):
    # One-time "broaden, don't deepen" nudge on byte-identical tool outputs.
    # One instance per worker run; _last_nudged prevents re-nudging the same plateau.

    def __init__(
        self,
        *,
        agent_id: str = "",
        log: Any = None,
        threshold: int | None = None,
    ):
        super().__init__()
        self.agent_id = agent_id
        self._log = log
        self._threshold = threshold if threshold is not None else _threshold()
        # Tool-output value we last nudged on; compared verbatim so a NEW plateau
        # re-arms the nudge while a CONTINUING one stays quiet.
        self._last_nudged: str = ""

    # Both sync and async so the middleware works whichever path create_agent drives.
    def before_model(self, state: Any, runtime: Any = None) -> dict | None:
        return self._maybe_nudge(state)

    async def abefore_model(self, state: Any, runtime: Any = None) -> dict | None:
        return self._maybe_nudge(state)

    def _maybe_nudge(self, state: Any) -> dict | None:
        messages = _get_messages(state)
        if not messages:
            return None
        # Tool outputs only, in order — their trailing run signals a plateau.
        tool_texts = [
            _coerce_to_text(m.content)
            for m in messages
            if isinstance(m, ToolMessage)
        ]
        if len(tool_texts) < self._threshold:
            return None
        last = tool_texts[-1]
        # An empty/blank output is not a meaningful plateau signal.
        if not last.strip():
            return None
        run = 0
        for t in reversed(tool_texts):
            if t == last:
                run += 1
            else:
                break
        if run < self._threshold:
            return None
        # Already nudged for this exact plateau — stay quiet until the value changes.
        if last == self._last_nudged:
            return None
        self._last_nudged = last
        if self._log is not None:
            try:
                self._log.info(
                    "[%s] no-progress nudge: %d byte-identical tool "
                    "responses in a row — re-surfacing DIVERSITY_RULES",
                    self.agent_id,
                    run,
                )
            except Exception:  # noqa: BLE001 — logging must never break a worker
                pass
        return {"messages": [HumanMessage(content=_NUDGE_TEMPLATE.format(n=run))]}


def _get_messages(state: Any) -> list:
    # Read the message list from either a dict-shaped or attr-shaped state.
    if isinstance(state, dict):
        return state.get("messages") or []
    return getattr(state, "messages", None) or []


# ── Graceful wrap-up (step-budget exhaustion) ─────────────────────────────
# The LLM is still reachable — the worker just ran out of turns. Make ONE more
# call asking it to stop and summarize its own work (+ any unformalized FINDINGs)
# rather than discard the run. (Salvage, by contrast, is for a dead/refused LLM.)


_WRAPUP_SYSTEM = (
    "You are a security testing assistant. The trace below is your own "
    "work on an authorized test target. You have reached the step budget "
    "for this pass and must stop testing now — do not request any more "
    "tool calls. Summarize what you did and report any findings you "
    "confirmed, using the **FINDING:** schema for each one. Be concise "
    "and accurate: report only what the trace actually shows, and never "
    "invent impact you did not observe.\n\n"
    "CRITICAL — do not let a proven capability die with this pass: if your "
    "tool outputs show you DEMONSTRATED an exploit primitive — code "
    "execution or template evaluation (e.g. a payload that returned a "
    "computed value like 49), arbitrary file read, an injection that "
    "returned database/query data, or a recovered credential or privileged "
    "session — even if you did NOT finish driving it to the objective, you "
    "MUST write it as a **FINDING:** with `Severity: high` and a final "
    "`Primitive: <tag>` line naming the capability (rce / file_read / "
    "sqli_read / auth_bypass / ssrf). The lead uses that Primitive line to "
    "keep an executor driving it to the flag; a proven primitive left only "
    "in your scratch output is a lost result."
)


def _format_tail(messages: list[Any], *, n: int = 16) -> str:
    # Trailing N tool/assistant messages as one text block. ToolMessage clipped to
    # 1500, AIMessage narration to 1200 (kept — "I just confirmed X" often lives there).
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


async def force_wrapup_summary(
    *,
    config: "AgentConfig",
    partial_messages: list,
    target_url: str = "",
    log: logging.Logger | None = None,
    run_id: str | None = None,
) -> AIMessage | None:
    # Ask a budget-stopped worker to wrap up its own work in one call. Returns an
    # AIMessage with its forced summary (+ any FINDING blocks), or None when there
    # was no partial trace or the call failed; caller runs _extract_findings over it.
    log = log or logger
    if not partial_messages:
        return None
    try:
        from src.llm.provider import get_llm
        from src.llm.callbacks import make_call_config

        llm = get_llm()
        tail = _format_tail(partial_messages)
        user_prompt = (
            "You reached your step budget and must stop now. Do NOT ask "
            "for more tool calls.\n\n"
            "Write two things:\n"
            "1. Any confirmed finding you have not yet written up — each as "
            "a **FINDING:** block (Title / Severity / Category / URL / "
            "Evidence / Primitive). Only real, observed results. If a tool "
            "output shows you PROVED an exploit primitive (code execution / "
            "template evaluation / file read / a data-returning injection / a "
            "recovered credential or session) — even if unfinished — it MUST "
            "be one of these blocks, `Severity: high`, with a final "
            "`Primitive: <rce|file_read|sqli_read|auth_bypass|ssrf>` line.\n"
            "2. A short summary for the lead: what you tested, what worked, "
            "what looked promising but unfinished, and the single most "
            "useful next step.\n\n"
            f"Target (for context): {target_url or 'unknown'}\n\n"
            "## Your work so far (most recent at the bottom)\n\n"
            f"{tail}"
        )
        # Distinct synthetic agent_id so the wrap-up call is visible in
        # llm_calls.jsonl without losing the attribution chain.
        cfg = make_call_config(
            run_id=run_id,
            agent_id=f"{config.agent_id}__wrapup",
            node="wrapup",
        )
        resp = await llm.ainvoke(
            [
                SystemMessage(content=_WRAPUP_SYSTEM),
                HumanMessage(content=user_prompt),
            ],
            config=cfg,
        )
    except Exception as e:  # noqa: BLE001
        # The wrap-up call must never make the stop path worse — fall back to
        # whatever findings the worker already wrote before the budget ran out.
        log.warning(
            "[%s] forced wrap-up call failed (%s): %s",
            config.agent_id, type(e).__name__, str(e)[:160],
        )
        return None

    text = resp.content if isinstance(resp.content, str) else str(resp.content)
    return AIMessage(
        content=text,
        additional_kwargs={
            "agent_id": config.agent_id,
            "kind": "forced_wrapup",
        },
    )
