"""Debug-hints rules engine for summary.md.

Each rule is a pure function over ``(nodes, llm_rows, final_state,
error, flag_found)`` keyword arguments. It returns either a single
human-readable hint string (if it detected an anomaly) or ``None``
(if not). The aggregator :func:`_render_debug_hints` runs every rule,
collects the non-None returns, and emits them as a markdown bullet
list under the "If you're debugging" section near the top of
``summary.md``.

Why "header"? The debug-hints section appears in the summary's
header area — it's the first thing the reader sees if a run failed,
right under the quick-facts block. The actual quick-facts rendering
lives in :mod:`observability.summary.builder` because it doesn't
warrant its own file.

Adding a new rule:

  1. Write a new ``_rule_<short_name>(*, nodes, llm_rows, final_state,
     error, flag_found, **_) -> str | None`` function. Use ``**_`` so
     future kwargs don't break the existing signature.
  2. Add the function to ``_DEBUG_HINT_RULES`` below.
  3. Smoke-test against the run that motivated it; the rule should fire.

Rule etiquette:

  * Defensive — any rule that raises is silently skipped.
  * Specific — name the offending node / agent / call by id so the
    reader can jump straight there.
  * Actionable — say what to check or change next, not just "this
    looks wrong".
"""

from __future__ import annotations

import os
from typing import Any

from src.observability.summary._helpers import (
    _ev_field,
    _fmt_tokens_short,
    _severity_str,
)


def _rule_recursion_limit(
    *, nodes: list[dict], **_: Any,
) -> str | None:
    """Worker hit LangGraph's recursion_limit before the graph could
    complete. Common cause: skill cap too tight, or worker stuck in a
    no-progress probing loop."""
    for i, n in enumerate(nodes, 1):
        err = str(n.get("error") or "")
        if "Recursion limit" in err or "GRAPH_RECURSION_LIMIT" in err:
            name = n.get("node") or "?"
            active = (n.get("after") or {}).get("active_agents") or []
            agent = active[0] if active else "?"
            return (
                f"⚠️ Node {i} `{name}` (agent `{agent}`) hit the LangGraph "
                f"recursion limit. The skill's iteration cap was "
                f"exhausted before the worker could reach a stop "
                f"condition; bump `max_iterations` in its SKILL.md or "
                f"strengthen the skill's stop-on-impact rule."
            )
    return None


def _rule_repeated_empty_dispatches(
    *, nodes: list[dict], **_: Any,
) -> str | None:
    """3+ consecutive worker turns with the same agent_id and zero
    findings — the planner is hammering one skill that isn't
    progressing."""
    worker_runs = []
    for n in nodes:
        if (n.get("node") or "") not in ("executor", "recon"):
            continue
        active = (n.get("after") or {}).get("active_agents") or []
        if not active:
            continue
        findings_added = (n.get("delta") or {}).get("findings_added") or 0
        worker_runs.append((active[0], findings_added))
    # Sliding window of 3.
    for i in range(len(worker_runs) - 2):
        a0, _ = worker_runs[i]
        a1, _ = worker_runs[i + 1]
        a2, _ = worker_runs[i + 2]
        if a0 == a1 == a2:
            total = sum(f for _, f in worker_runs[i:i + 3])
            if total == 0:
                return (
                    f"⚠️ Skill `{a0}` was dispatched 3 times in a row "
                    f"with 0 findings each time. Planner may be stuck "
                    f"on this skill instead of pivoting; check the "
                    f"loop-detection logic in `src/nodes/base/__init__.py:"
                    f"BaseNode.detect_repetition`."
                )
    return None


def _rule_context_rot_crossed(
    *, llm_rows: list[dict], **_: Any,
) -> str | None:
    """Any single LLM call's input_tokens crossed 100k. Codex / o-series
    quality degrades visibly past ~128k."""
    peaks: list[tuple[str, int]] = []
    for r in llm_rows:
        if r.get("phase") != "end":
            continue
        try:
            n = int(r.get("input_tokens") or 0)
        except (TypeError, ValueError):
            continue
        if n >= 100_000:
            peaks.append((str(r.get("agent_id") or "?"), n))
    if not peaks:
        return None
    peaks.sort(key=lambda t: -t[1])
    a, n = peaks[0]
    extra = f" (and {len(peaks) - 1} more call(s) above 100k)" if len(peaks) > 1 else ""
    return (
        f"⚠️ Agent `{a}` sent {_fmt_tokens_short(n)} input tokens in a "
        f"single LLM call{extra}. Quality degrades visibly past ~128k; "
        f"consider stopping and re-dispatching a fresh worker."
    )


def _rule_api_refusal(
    *, llm_rows: list[dict], **_: Any,
) -> str | None:
    """Any LLM phase=error with a cyber-policy / invalid-prompt error
    type. Means the prompt classifier blocked the call, not that the
    target was hardened."""
    refusals: dict[str, int] = {}
    for r in llm_rows:
        if r.get("phase") != "error":
            continue
        et = str(r.get("error_type") or "")
        if any(k in et for k in ("CyberPolicy", "InvalidPrompt", "ContentFilter")):
            agent = str(r.get("agent_id") or "?")
            refusals[agent] = refusals.get(agent, 0) + 1
    if not refusals:
        return None
    top = max(refusals.items(), key=lambda kv: kv[1])
    extra = f" across {len(refusals)} agent(s)" if len(refusals) > 1 else ""
    return (
        f"⚠️ Detected {sum(refusals.values())} API-level refusal(s) "
        f"(top: `{top[0]}` × {top[1]}){extra}. The model rejected "
        f"these calls at the safety layer — the worker prompt may "
        f"need rewording, or switch to a more permissive model "
        f"(`SWARM_MODEL=gpt-5.4-mini`)."
    )


def _rule_salvage_without_finding(
    *, llm_rows: list[dict], final_state: dict, **_: Any,
) -> str | None:
    """A salvage call fired but no salvaged finding made it into the
    final state. Means the crashed worker's scratchpad didn't show
    demonstrated impact."""
    salvage_called = any(
        "__salvage" in str(r.get("agent_id") or "")
        for r in llm_rows if r.get("phase") in ("end", "error")
    )
    if not salvage_called:
        return None
    findings = final_state.get("findings") or []
    salvaged = sum(
        1 for f in findings
        if "[salvaged" in str(_ev_field(f, "title", ""))
    )
    if salvaged == 0:
        return (
            f"ℹ️ A salvage call fired (a worker crashed mid-loop) but "
            f"no salvaged finding was extracted. The crashed worker's "
            f"scratchpad showed no *demonstrated* impact (only "
            f"signals). Check the crash node's tool-call groups — "
            f"if a working exploit was within reach, raise the "
            f"skill's `max_iterations` cap."
        )
    return None


def _rule_bench_timeout(
    *, error: str | None, flag_found: bool | None, **_: Any,
) -> str | None:
    """The bench-level wall-clock timeout fired before the planner
    could close the loop with action=report."""
    if not error:
        return None
    if "timeout" in str(error).lower():
        return (
            f"⚠️ Wall-clock timeout fired before the planner reached "
            f"action=report. Check whether the executor was making "
            f"progress (per-node tokens / findings in the timeline) "
            f"or stuck in low-yield probing; consider raising "
            f"`RUN_TIMEOUT_S` in `benchmarks/xbow_runner.py`."
        )
    return None


def _rule_finding_without_flag(
    *, final_state: dict, flag_found: bool | None, **_: Any,
) -> str | None:
    """High-severity finding identified but the flag wasn't captured."""
    if flag_found:
        return None
    findings = final_state.get("findings") or []
    if not findings:
        return None
    high_sev = [
        f for f in findings
        if _severity_str(f).lower() in ("critical", "high")
    ]
    if not high_sev:
        return None
    titles = [str(_ev_field(f, "title", ""))[:80] for f in high_sev[:2]]
    suffix = f" (+ {len(high_sev) - 2} more)" if len(high_sev) > 2 else ""
    title_str = "; ".join(t for t in titles if t)
    return (
        f"ℹ️ {len(high_sev)} high/critical finding(s) identified but "
        f"the flag was not captured: _{title_str}_{suffix}. The "
        f"vulnerability was diagnosed but not weaponised — check if "
        f"the executor specialised on extraction after the recon "
        f"finding fired."
    )


_DEBUG_HINT_RULES = (
    _rule_recursion_limit,
    _rule_repeated_empty_dispatches,
    _rule_context_rot_crossed,
    _rule_api_refusal,
    _rule_salvage_without_finding,
    _rule_bench_timeout,
    _rule_finding_without_flag,
)


def _render_debug_hints(
    *,
    nodes: list[dict],
    llm_rows: list[dict],
    final_state: dict,
    error: str | None,
    flag_found: bool | None,
) -> str:
    """Run every rule, collect non-None hints, render as a markdown block.

    Defensive: any rule that raises is silently skipped — the writer
    must never break on a buggy rule. ``SWARM_LIVE_DEBUG_HINTS=0``
    disables the section entirely (renders just a one-line "_disabled_"
    note so the user knows it's intentional).
    """
    if os.environ.get("SWARM_LIVE_DEBUG_HINTS") == "0":
        return "_(debug hints disabled via SWARM_LIVE_DEBUG_HINTS=0)_"
    hints: list[str] = []
    for rule in _DEBUG_HINT_RULES:
        try:
            r = rule(
                nodes=nodes,
                llm_rows=llm_rows,
                final_state=final_state,
                error=error,
                flag_found=flag_found,
            )
        except Exception:  # noqa: BLE001
            continue
        if r:
            hints.append(f"- {r}")
    if not hints:
        return "_No anomalies detected._"
    return "\n".join(hints)


def count_refusals(run_id: str) -> int:
    """Count rows in ``logs/run-<id>/refusals.jsonl``.

    Used by the run-summary header. Returns 0 when the file is missing
    or unreadable, never raises.

    Inlined here from the now-deleted ``src/llm/refusal.py:count_refusals``
    because this is the only consumer. The plan flagged
    ``refusals.jsonl`` itself as a deletion candidate — see
    ``src/observability/writers.py:append_refusal`` for the rationale.
    """
    from src.observability.writers import run_dir
    path = run_dir(run_id) / "refusals.jsonl"
    if not path.exists():
        return 0
    try:
        with path.open("r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0
