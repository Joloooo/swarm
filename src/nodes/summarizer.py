"""SummarizerNode — converts each worker's trace into one report message.

This node is the **synchronization point** after parallel worker
fan-out. The graph topology is::

    planner --Send()--> executor (×N parallel)  ──┐
                      → recon (when not part of attack fan-out)  ──┤
                                                                    ↓
                                                                summarizer  (runs ONCE)
                                                                    ↓
                                                                planner

How it works
============

1. Each parallel worker (``ExecutorNode``, ``ReconNode``) returns a
   single-item list under ``state["pending_summary_inputs"]``. The
   reducer ``_summary_inputs_reducer`` (in ``src/state.py``)
   accumulates all parallel writes into one list.

2. Each worker normally precomputes its own structured ``AIMessage``
   report at worker exit, while the worker prompt prefix is still hot
   in the provider cache. After all worker branches converge here, the
   summarizer reads those reports. Legacy / failed-precompute entries
   are digested here as a fallback, still in parallel via
   ``asyncio.gather``.

3. The reports are appended to ``state["messages"]`` and the
   ``pending_summary_inputs`` field is cleared via the reducer's
   ``None`` sentinel.

4. The planner then runs and reads only digests + its own decisions —
   the raw worker traces never enter its prompt.

Why this matters
================

Pre-summarizer-node design: each worker mirrored its full trace
(60 iterations × ~4 KB ≈ 240 KB) into ``state["messages"]``. A planner
running after a 4-way fan-out saw ~1 MB of mirrored trace, and the
prompt blew through Codex's 256 K window within ~3 cycles.

This node compresses each trace into a ~5 KB structured report that
preserves the high-fidelity probe enumeration the planner needs (what
was tried, what was NOT tried, recommended next angle) and drops the
raw bytes the planner does not.

Failure modes
=============

If the worker-exit or fallback summarizer call fails (provider error,
timeout), the ``digest`` module returns a deterministic stub report so
the planner still sees *something* coherent for that worker. Better a
placeholder than a hole.

If ``pending_summary_inputs`` is empty when the node runs (e.g. the
``initialize`` → ``planner`` cold-start path that skips workers
entirely), this node returns an empty update and yields directly to
the planner — zero LLM cost when there is nothing to summarize.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage

from src.llm.digest import bind_tools_for_summary_cache, summarize_worker_trace
from src.nodes.base import BaseNode
from src.state import Finding

logger = logging.getLogger(__name__)

_NEXT_SKILL_SECTION_RE = re.compile(
    r"(?ims)^##\s*Next skill suggestions\s*\n(?P<body>.*?)(?=^##\s+|\Z)"
)
_HANDOFF_SECTION_RE = re.compile(
    r"(?ims)^##\s*Cross-skill handoffs\s*\n(?P<body>.*?)(?=^##\s+|\Z)"
)
_FENCED_JSON_ARRAY_RE = re.compile(
    r"(?is)```(?:json)?\s*(\[[\s\S]*?\])\s*```"
)
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
_MAX_SUGGESTED_NEXT_MOVES = 12
_MAX_SUGGESTION_FIELD_CHARS = 180
_OPTIONAL_SUGGESTION_FIELDS = (
    "signal",
    "possible_vuln_class",
    "reason",
    "source",
)
_OPTIONAL_HANDOFF_FIELDS = (
    "signal",
    "possible_vuln_class",
    "reason",
    "evidence_excerpt",
    "reproduction",
    "source",
)


def _dispatchable_skill_aliases() -> dict[str, str]:
    """Return normalized skill-name aliases -> canonical dispatch key."""
    try:
        from src.skills.loader import list_dispatchable_skills
    except Exception as e:  # noqa: BLE001
        logger.warning("summarizer: cannot load dispatchable skill list: %s", e)
        return {}

    aliases: dict[str, str] = {}
    for name, _desc in list_dispatchable_skills():
        canonical = str(name).strip()
        if not canonical:
            continue
        variants = {
            canonical,
            canonical.lower(),
            canonical.replace("_", "-"),
            canonical.replace(" ", "-"),
            canonical.lower().replace("_", "-").replace(" ", "-"),
        }
        for variant in variants:
            aliases[variant] = canonical
    return aliases


def _compact_field(value: Any) -> str:
    text = " ".join(str(value or "").split())
    if len(text) > _MAX_SUGGESTION_FIELD_CHARS:
        text = text[: _MAX_SUGGESTION_FIELD_CHARS - 3].rstrip() + "..."
    return text


def _message_text(msg: Any) -> str:
    """Best-effort text extraction for deterministic trace triage."""
    content = getattr(msg, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text") or block.get("content") or ""))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content or "")


def _balanced_json_array(text: str) -> str | None:
    """Return the first balanced JSON array substring in ``text``."""
    start = text.find("[")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escaped = False
    for i, ch in enumerate(text[start:], start):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _json_arrays_from_section(section: str) -> list[list[Any]]:
    arrays: list[list[Any]] = []
    candidates = [m.group(1) for m in _FENCED_JSON_ARRAY_RE.finditer(section)]
    balanced = _balanced_json_array(section)
    if balanced:
        candidates.append(balanced)

    seen: set[str] = set()
    for raw in candidates:
        raw = raw.strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list):
            arrays.append(parsed)
    return arrays


def _normalize_next_move_item(
    raw: Any,
    *,
    source_agent: str = "",
    skill_aliases: dict[str, str] | None = None,
) -> dict[str, str] | None:
    if not isinstance(raw, dict):
        return None
    aliases = (
        skill_aliases
        if skill_aliases is not None
        else _dispatchable_skill_aliases()
    )

    raw_skill = _compact_field(raw.get("skill") or raw.get("suggested_skill"))
    skill_key = raw_skill.lower().replace("_", "-").replace(" ", "-")
    skill = aliases.get(raw_skill) or aliases.get(skill_key)
    if not skill:
        return None

    where = _compact_field(
        raw.get("where") or raw.get("surface") or raw.get("target")
    )
    next_move = _compact_field(
        raw.get("next_move") or raw.get("technique") or raw.get("move")
    )
    if not (where or next_move):
        return None

    confidence = _compact_field(raw.get("confidence")).lower()
    if confidence not in _CONFIDENCE_RANK:
        confidence = "medium"

    item = {
        "where": where,
        "next_move": next_move,
        "skill": skill,
        "confidence": confidence,
        "source_agent": _compact_field(
            source_agent or raw.get("source_agent")
        ),
    }
    for field in _OPTIONAL_SUGGESTION_FIELDS:
        value = _compact_field(raw.get(field))
        if value:
            item[field] = value
    if "source" not in item:
        item["source"] = "summarizer"
    return item


def _extract_next_skill_suggestions(
    report_messages: list[AIMessage],
) -> list[dict[str, str]]:
    """Parse validated ``## Next skill suggestions`` arrays from reports."""
    aliases = _dispatchable_skill_aliases()
    if not aliases:
        return []

    out: list[dict[str, str]] = []
    for msg in report_messages:
        content = (
            msg.content if isinstance(msg.content, str) else str(msg.content or "")
        )
        match = _NEXT_SKILL_SECTION_RE.search(content)
        if not match:
            continue
        source_agent = str((msg.additional_kwargs or {}).get("agent_id") or "")
        for array in _json_arrays_from_section(match.group("body")):
            for raw in array:
                item = _normalize_next_move_item(
                    raw,
                    source_agent=source_agent,
                    skill_aliases=aliases,
                )
                if item:
                    out.append(item)
    return out


def _normalize_handoff_item(
    raw: Any,
    *,
    source_agent: str = "",
    skill_aliases: dict[str, str] | None = None,
) -> dict[str, str] | None:
    if not isinstance(raw, dict):
        return None
    aliases = (
        skill_aliases
        if skill_aliases is not None
        else _dispatchable_skill_aliases()
    )

    raw_skill = _compact_field(raw.get("suggested_skill") or raw.get("skill"))
    skill_key = raw_skill.lower().replace("_", "-").replace(" ", "-")
    skill = aliases.get(raw_skill) or aliases.get(skill_key)
    if not skill:
        return None

    surface = _compact_field(
        raw.get("surface") or raw.get("where") or raw.get("target")
    )
    technique = _compact_field(
        raw.get("technique") or raw.get("next_move") or raw.get("move")
    )
    if not (surface or technique):
        return None

    confidence = _compact_field(raw.get("confidence")).lower()
    if confidence not in _CONFIDENCE_RANK:
        confidence = "medium"

    item = {
        "suggested_skill": skill,
        "surface": surface,
        "technique": technique,
        "confidence": confidence,
        "source_agent": _compact_field(
            source_agent or raw.get("source_agent")
        ),
    }
    for field in _OPTIONAL_HANDOFF_FIELDS:
        value = _compact_field(raw.get(field))
        if value:
            item[field] = value
    if "source" not in item:
        item["source"] = "summarizer"
    return item


def _extract_cross_skill_handoffs(
    report_messages: list[AIMessage],
) -> list[dict[str, str]]:
    """Parse validated ``## Cross-skill handoffs`` arrays from reports."""
    aliases = _dispatchable_skill_aliases()
    if not aliases:
        return []

    out: list[dict[str, str]] = []
    for msg in report_messages:
        content = (
            msg.content if isinstance(msg.content, str) else str(msg.content or "")
        )
        match = _HANDOFF_SECTION_RE.search(content)
        if not match:
            continue
        source_agent = str((msg.additional_kwargs or {}).get("agent_id") or "")
        for array in _json_arrays_from_section(match.group("body")):
            for raw in array:
                item = _normalize_handoff_item(
                    raw,
                    source_agent=source_agent,
                    skill_aliases=aliases,
                )
                if item:
                    out.append(item)
    return out


def _handoffs_from_next_moves(
    moves: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Promote high-confidence deterministic next moves into handoffs."""
    aliases = _dispatchable_skill_aliases()
    if not aliases:
        return []
    out: list[dict[str, str]] = []
    for move in moves:
        if not isinstance(move, dict):
            continue
        if str(move.get("confidence") or "").strip().lower() != "high":
            continue
        item = _normalize_handoff_item(
            {
                "suggested_skill": move.get("skill") or move.get("suggested_skill"),
                "surface": move.get("where") or move.get("surface"),
                "technique": move.get("next_move") or move.get("technique"),
                "confidence": move.get("confidence"),
                "signal": move.get("signal"),
                "possible_vuln_class": move.get("possible_vuln_class"),
                "reason": move.get("reason"),
                "source_agent": move.get("source_agent"),
                "source": move.get("source"),
            },
            skill_aliases=aliases,
        )
        if item:
            out.append(item)
    return out


def _merge_suggested_next_moves(
    existing: list[dict] | None,
    new: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Deduplicate suggestions, preserving the highest-confidence copy."""
    aliases = _dispatchable_skill_aliases()
    merged: dict[tuple[str, str, str], dict[str, str]] = {}
    for raw in list(existing or []) + list(new or []):
        item = _normalize_next_move_item(raw, skill_aliases=aliases)
        if not item:
            continue
        key = (
            item["skill"],
            item["where"].lower(),
            item["next_move"].lower(),
        )
        prior = merged.get(key)
        if (
            prior is None
            or _CONFIDENCE_RANK[item["confidence"]]
            > _CONFIDENCE_RANK[prior["confidence"]]
        ):
            merged[key] = item

    ranked = sorted(
        merged.values(),
        key=lambda item: (
            -_CONFIDENCE_RANK[item["confidence"]],
            item["skill"],
            item["where"],
            item["next_move"],
        ),
    )
    return ranked[:_MAX_SUGGESTED_NEXT_MOVES]


def _detect_auth_session_race(
    text: str,
    *,
    source_agent: str,
    skill_aliases: dict[str, str],
) -> dict[str, str] | None:
    """Detect the generic auth TOCTOU pattern that routes to race testing."""
    low = text.lower()
    failed_login = bool(
        re.search(r"\b(failed|invalid|unsuccessful)\b.{0,80}\blogin\b", low)
        or re.search(r"\blogin\b.{0,80}\b(failed|invalid|unsuccessful)\b", low)
    )
    session_state = (
        "session" in low
        and any(token in low for token in (
            "username", "password_hash", "user_id", "partial",
            "server-side session", "session state",
        ))
    )
    identity_without_auth = any(token in low for token in (
        "without user_id", "no user_id", "partial session",
        "before validation", "before password", "before verifying",
        "failed-login state",
    ))
    privileged_route = any(token in low for token in (
        "admin_panel", "/admin", "admin panel", "privileged",
        "dashboard", "role", "permission check",
    ))
    if not (failed_login and session_state and identity_without_auth and privileged_route):
        return None
    return _normalize_next_move_item(
        {
            "signal": (
                "failed login writes identity-like values into server-side "
                "session state before the login is fully valid"
            ),
            "possible_vuln_class": "race condition / auth TOCTOU",
            "where": "login flow and privileged session-checked routes",
            "next_move": (
                "test concurrent failed-login and privileged-route requests "
                "with warmed/shared sessions to see whether partial state is consumed"
            ),
            "skill": "race-conditions",
            "confidence": "high",
            "reason": (
                "state is modified before validation and a later privileged "
                "route appears to read the same session state"
            ),
            "source": "detector",
        },
        source_agent=source_agent,
        skill_aliases=skill_aliases,
    )


def _detect_ssti_filter_followup(
    text: str,
    *,
    source_agent: str,
    skill_aliases: dict[str, str],
) -> dict[str, str] | None:
    """Detect filter-aware SSTI follow-up without naming a benchmark payload."""
    low = text.lower()
    template_context = any(token in low for token in (
        "ssti", "template", "jinja", "twig", "nunjucks", "mako",
        "server-side template",
    ))
    expression_blocked = "{{" in text and any(token in low for token in (
        "blocked", "blacklist", "stripped", "rejected", "filtered",
        "neutralized", "neutralised",
    ))
    statement_signal = "{%" in text or "statement tag" in low or "control tag" in low
    if not (template_context and expression_blocked and statement_signal):
        return None
    return _normalize_next_move_item(
        {
            "signal": (
                "template-expression delimiters are filtered while another "
                "template grammar family is reaching the sink"
            ),
            "possible_vuln_class": "server-side template injection",
            "where": "the same reflected/rendered template sink",
            "next_move": (
                "switch delimiter families and engine primitives on the same "
                "sink; test statement/control tags, comments, filters, and "
                "file-read primitives instead of only {{...}} expressions"
            ),
            "skill": "ssti",
            "confidence": "high",
            "reason": (
                "a class-specific filter is positive evidence of a template "
                "sink; the next step is grammar switching, not abandoning SSTI"
            ),
            "source": "detector",
        },
        source_agent=source_agent,
        skill_aliases=skill_aliases,
    )


def _detect_php_path_deser(
    text: str,
    *,
    source_agent: str,
    skill_aliases: dict[str, str],
) -> dict[str, str] | None:
    """Detect generic PHP path/file handling that should route to PHAR/deser."""
    low = text.lower()
    php_runtime = "php" in low or "composer" in low or "vendor/" in low
    file_surface = any(token in low for token in (
        "file_exists", "file_get_contents", "fopen", "is_file", "is_dir",
        "getimagesize", "unlink", "phar://", "upload", "filename",
        "path parameter", "filesystem", "import", "restore",
    ))
    user_control = any(token in low for token in (
        "user-controlled", "parameter", "request", "upload", "ssrf",
        "internal", "endpoint", "body", "url",
    ))
    if not (php_runtime and file_surface and user_control):
        return None
    return _normalize_next_move_item(
        {
            "signal": (
                "PHP application appears to feed user-influenced path or "
                "file bytes into filesystem handling"
            ),
            "possible_vuln_class": "PHP deserialization / PHAR metadata path sink",
            "where": "PHP file/path processing surface",
            "next_move": (
                "test whether a controlled upload/path can be reached via "
                "phar:// or serialized-object formats; pair upload and path sinks"
            ),
            "skill": "deserialization",
            "confidence": "high",
            "reason": (
                "PHAR metadata deserialization is triggered by ordinary PHP "
                "filesystem functions on attacker-influenced paths"
            ),
            "source": "detector",
        },
        source_agent=source_agent,
        skill_aliases=skill_aliases,
    )


def _detect_evidence_next_moves(
    pending: list[dict],
    report_messages: list[AIMessage],
) -> list[dict[str, str]]:
    """Rule-based routing hints from trace/report evidence.

    These hints complement the LLM-generated ``Next skill suggestions``. They
    only fire on generic mechanism patterns, and still use the normal
    suggested_next_moves transport so the planner owns the final dispatch.
    """
    aliases = _dispatchable_skill_aliases()
    if not aliases:
        return []

    reports_by_agent = {
        str((msg.additional_kwargs or {}).get("agent_id") or ""): _message_text(msg)
        for msg in report_messages
    }
    out: list[dict[str, str]] = []
    detectors = (
        _detect_auth_session_race,
        _detect_ssti_filter_followup,
        _detect_php_path_deser,
    )
    for inp in pending:
        if not isinstance(inp, dict):
            continue
        source_agent = str(inp.get("agent_id") or "")
        trace = inp.get("trace") or []
        trace_text = "\n".join(_message_text(m) for m in trace)
        haystack = "\n".join(
            part for part in (reports_by_agent.get(source_agent, ""), trace_text)
            if part
        )
        if not haystack.strip():
            continue
        for detector in detectors:
            item = detector(
                haystack,
                source_agent=source_agent,
                skill_aliases=aliases,
            )
            if item:
                out.append(item)
    return out


def _tool_attempt_suggestions(
    attempts: list[dict] | None,
) -> list[dict[str, str]]:
    """Convert uncovered tool outcomes into fallback routing hints."""
    aliases = _dispatchable_skill_aliases()
    if not aliases:
        return []
    out: list[dict[str, str]] = []
    for attempt in attempts or []:
        if not isinstance(attempt, dict):
            continue
        tool = str(attempt.get("tool") or "").lower()
        surface = _compact_field(attempt.get("surface"))
        fallback_needed = bool(attempt.get("fallback_needed"))
        covered = bool(attempt.get("covered"))
        if "wpscan" in tool and fallback_needed and not covered:
            item = _normalize_next_move_item(
                {
                    "signal": (
                        "WPScan did not complete a full WordPress component "
                        "enumeration"
                    ),
                    "possible_vuln_class": "CMS component discovery gap",
                    "where": surface or "WordPress plugins/themes",
                    "next_move": (
                        "fallback-enumerate /wp-content/plugins/FUZZ/ and "
                        "/wp-content/themes/FUZZ/ with a component slug list, "
                        "then read readme/style version files"
                    ),
                    "skill": "fuzzing",
                    "confidence": "high",
                    "reason": (
                        "a failed or partial scanner run is not coverage of "
                        "the component surface"
                    ),
                    "source": "detector",
                    "source_agent": attempt.get("source_agent"),
                },
                skill_aliases=aliases,
            )
            if item:
                out.append(item)
    return out


def _summary_model_for_input(base_model: Any, inp: dict) -> Any:
    """Return a summary model with the worker's cache-relevant shape."""
    model = base_model
    summary_model = str(inp.get("summary_model") or "")
    if summary_model:
        try:
            from src.llm.provider import LLMConfig, Provider, get_llm

            model = get_llm(LLMConfig(
                provider=Provider.CODEX,
                model=summary_model,
                reasoning_effort=str(
                    inp.get("summary_reasoning_effort") or "low"
                ),
            ))
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "summarizer: could not rebuild summary model %r: %s",
                summary_model,
                e,
            )
    return bind_tools_for_summary_cache(
        model,
        list(inp.get("summary_tools") or []),
    )


class SummarizerNode(BaseNode):
    """Convert pending worker traces into structured planner-facing reports."""

    async def execute(self, state: dict) -> dict:
        pending = list(state.get("pending_summary_inputs") or [])
        if not pending:
            # No workers to summarize — happens on cold-start paths
            # (initialize → planner without a worker in between) and on
            # any subsequent planner cycle that didn't dispatch a
            # worker (e.g. planner → web_search → planner). Returning
            # an empty update is the cheapest correct behavior.
            self.log.debug(
                "summarizer: no pending_summary_inputs — yielding empty update"
            )
            return {}

        # Termination-on-capture is now driven by ``state.captured_flag``
        # (set by ``src/nodes/base/skill_runner.py`` on the success
        # path when a worker's tool output contained a ``flag{...}``
        # substring that strict-equals ``expected_flag``). The
        # ``route_after_summarizer`` conditional edge reads that field
        # and routes to ``END`` on a verified capture.
        #
        # This module deliberately does NOT do any flag scanning of
        # its own — by the time the summarizer runs, the worker has
        # already done the strict-equality verification upstream. We
        # just transform pending traces into digests for the planner.
        # In real-pentest mode (``expected_flag`` empty) the skill
        # runner never sets ``captured_flag``, so termination remains
        # planner-driven via ``action="submit_flag"``.

        run_id = state.get("run_id")
        target_url = state.get("target_url", "")

        # Build one report coroutine per pending worker. Most entries already
        # carry a worker-exit precomputed report; legacy / failed-precompute
        # entries fall back to the digest LLM here. Run all fallbacks in
        # parallel so a mixed fan-out still costs ~one digest latency.
        # Per-call failures are handled inside summarize_worker_trace (it
        # returns a deterministic stub on LLM error), so gather() should not
        # raise here.
        from src.llm.provider import get_llm  # lazy — see base.py docstring
        model = get_llm()

        # Snapshot the global findings list once before fan-out so each
        # parallel _summarize_one sees a consistent view (the reducer
        # in state.py never mutates this list in place, but reading it
        # once avoids any chance of mid-coroutine reassignment).
        all_findings = list(state.get("findings") or [])

        coros = [
            self._summarize_one(
                inp=inp,
                model=model,
                run_id=run_id,
                target_url_default=target_url,
                all_findings=all_findings,
            )
            for inp in pending
        ]
        try:
            reports = await asyncio.gather(*coros, return_exceptions=True)
        except Exception as e:  # defensive — gather itself shouldn't raise
            self.log.exception("summarizer.gather raised: %s", e)
            reports = []

        report_messages: list[AIMessage] = []
        for inp, rep in zip(pending, reports):
            if isinstance(rep, AIMessage):
                report_messages.append(rep)
            elif isinstance(rep, BaseException):
                # Should be rare — the helper handles its own errors.
                # Surface a one-liner so the planner still sees the
                # worker happened.
                self.log.warning(
                    "summarizer: worker %r digest raised %s: %s",
                    inp.get("agent_id"), type(rep).__name__, str(rep)[:200],
                )
                report_messages.append(self._error_placeholder(inp, rep))
            else:
                # Unexpected return type (None, dict, ...). Skip with a
                # placeholder rather than dropping the worker silently.
                self.log.warning(
                    "summarizer: unexpected digest return type %r for %r",
                    type(rep).__name__, inp.get("agent_id"),
                )
                report_messages.append(self._error_placeholder(inp, None))

        self.log.info(
            "summarizer: produced %d worker_report message(s) for %d pending input(s)",
            len(report_messages), len(pending),
        )

        update: dict[str, Any] = {
            "messages": report_messages,
            # Sentinel: the reducer (_summary_inputs_reducer) treats
            # ``None`` as "clear the list" so subsequent worker fan-outs
            # don't see stale entries from this turn.
            "pending_summary_inputs": None,
        }

        llm_next_moves = _extract_next_skill_suggestions(report_messages)
        detector_next_moves = _detect_evidence_next_moves(pending, report_messages)
        tool_next_moves = _tool_attempt_suggestions(state.get("tool_attempts") or [])
        next_moves = _merge_suggested_next_moves(
            list(state.get("suggested_next_moves") or []),
            llm_next_moves + detector_next_moves + tool_next_moves,
        )
        explicit_handoffs = _extract_cross_skill_handoffs(report_messages)
        inferred_handoffs = _handoffs_from_next_moves(
            detector_next_moves + tool_next_moves
        )
        handoffs = explicit_handoffs + inferred_handoffs
        if handoffs:
            update["skill_handoffs"] = handoffs
            self.log.info(
                "summarizer: emitted %d cross-skill handoff(s) "
                "(explicit=%d, inferred=%d)",
                len(handoffs), len(explicit_handoffs), len(inferred_handoffs),
            )
        if next_moves or state.get("suggested_next_moves"):
            update["suggested_next_moves"] = next_moves
        if next_moves:
            self.log.info(
                "summarizer: retained %d next-skill suggestion(s) "
                "(llm=%d, detector=%d, tool=%d)",
                len(next_moves), len(llm_next_moves),
                len(detector_next_moves), len(tool_next_moves),
            )

        # Consolidation pass — dedup/merge the raw findings into a
        # canonical view, stamp conversion ``status`` + an ``attempts``
        # log on primitives, score ``lead_priority``, and route negative /
        # status results out into ``exhausted_ledger``. One extra LLM call
        # per cycle; ``consolidate_findings`` falls back to a deterministic
        # consolidation on any LLM failure, so it never blocks the run.
        # The planner directives and worker seeds read ``canonical_findings``
        # (with a ``findings`` fallback) — see src/llm/consolidate.py.
        try:
            from src.llm.consolidate import consolidate_findings
            consolidation = await consolidate_findings(
                raw_findings=all_findings,
                prior_canonical=list(state.get("canonical_findings") or []),
                prior_ledger=dict(state.get("exhausted_ledger") or {}),
                worker_digests=[
                    str(getattr(m, "content", "") or "") for m in report_messages
                ],
                model=model,
                run_id=run_id,
                node_name=self.name,
            )
        except Exception as e:  # noqa: BLE001 — never let consolidation break the run
            self.log.warning("summarizer: consolidation failed (%s) — skipping", e)
            consolidation = {}
        if consolidation.get("canonical_findings"):
            update["canonical_findings"] = consolidation["canonical_findings"]
        if consolidation.get("exhausted_ledger"):
            update["exhausted_ledger"] = consolidation["exhausted_ledger"]
        if consolidation.get("canonical_findings") is not None:
            self.log.info(
                "summarizer: consolidated %d raw -> %d canonical finding(s), "
                "%d exhausted-ledger entr(ies)",
                len(all_findings),
                len(consolidation.get("canonical_findings") or []),
                len(consolidation.get("exhausted_ledger") or {}),
            )

        # Unified signal/hypothesis channel — convert this cycle's routing
        # outputs into Signal atoms and re-synthesize the ranked
        # hypotheses. Runs alongside the legacy ``suggested_next_moves`` /
        # ``skill_handoffs`` channels during migration (it does not replace
        # them yet). The synthesis pass is deterministic and LLM-free, so
        # it never blocks the run.
        try:
            from src.llm.hypotheses import (
                build_surface_canon,
                routing_rules_from_specs,
                signal_from_routing_dict,
                synthesize_hypotheses,
            )
            from src.skills.loader import list_skill_signal_specs
            skill_rules = routing_rules_from_specs(list_skill_signal_specs())
            fresh_items = (
                llm_next_moves + detector_next_moves + tool_next_moves
                + handoffs
            )
            new_signals = [
                sig for sig in (
                    signal_from_routing_dict(item, default_source="summarizer")
                    for item in fresh_items
                ) if sig is not None
            ]
            if new_signals:
                update["signals"] = new_signals
            all_signals = list(state.get("signals") or []) + new_signals
            canonical_for_synth = (
                update.get("canonical_findings")
                or list(state.get("canonical_findings") or [])
            )
            # LLM merge of duplicate/similar surfaces (Step 3) — the model
            # groups "/sku_add.php sku" vs "…fields" vs "…parameters" into
            # one sink so the hypothesis list stops fragmenting. Belief math
            # stays deterministic; falls back to normalize_surface on failure.
            surface_canon = await build_surface_canon(
                signals=all_signals, model=model, run_id=run_id,
                node_name=self.name,
            )
            hypotheses = synthesize_hypotheses(
                signals=all_signals,
                canonical_findings=canonical_for_synth,
                prior_hypotheses=list(state.get("hypotheses") or []),
                extra_rules=skill_rules or None,
                surface_canon=surface_canon,
            )
            if hypotheses:
                update["hypotheses"] = hypotheses
                self.log.info(
                    "summarizer: synthesized %d hypothesis(es) from %d signal(s); "
                    "top: %s",
                    len(hypotheses), len(all_signals),
                    ", ".join(
                        f"{h.vuln_class}@{h.surface or '*'}={h.priority}"
                        f"({h.state})"
                        for h in hypotheses[:3]
                    ),
                )
        except Exception as e:  # noqa: BLE001 — synthesis must never break the run
            self.log.warning("summarizer: hypothesis synthesis failed (%s) — skipping", e)

        # Capture the recon worker's summary once, into
        # ``state["recon_summary"]``. The seed builder in
        # ``src/nodes/base/skill_runner.py:_format_recon_summary``
        # renders it as "## Application map" for every subsequent
        # worker so they don't re-walk the application.
        #
        # We only write when:
        #   1. ``state["recon_summary"]`` is empty (first recon pass), AND
        #   2. one of this turn's pending entries was the recon worker.
        # The reducer in ``src/state.py:_recon_summary_reducer`` is
        # first-non-empty-wins so a hypothetical second recon dispatch
        # cannot overwrite the canonical first map either.
        if not (state.get("recon_summary") or "").strip():
            recon_text = _pick_recon_report_body(pending, reports)
            if recon_text:
                update["recon_summary"] = recon_text
                self.log.info(
                    "summarizer: captured recon_summary (%d chars) into state",
                    len(recon_text),
                )

        return update

    async def _summarize_one(
        self,
        *,
        inp: dict,
        model: Any,
        run_id: str | None,
        target_url_default: str,
        all_findings: list[Finding],
    ) -> AIMessage:
        """Produce one report ``AIMessage`` for one pending worker entry.

        Wraps :func:`src.llm.digest.summarize_worker_trace` with a
        try/except so a single worker's failure can't take down the
        whole batch — gather() then assembles per-worker results into
        the final messages list.

        After the digest LLM returns, this method appends a
        ``## Findings (verbatim from worker)`` section to the report's
        content for any ``Finding`` objects this worker emitted. The
        digest LLM compresses prose ("private record returned") and
        will paraphrase away byte-exact strings (captured flags, leaked
        credentials, raw SQL error fragments) that the planner needs to
        see verbatim — the regex-parsed Finding objects already
        preserve them in ``Finding.evidence``, so we just route that
        data to the planner alongside the prose digest. The append is a
        pure Python concatenation: no LLM round-trip, no risk of
        paraphrasing, no false-positive surface from pattern matching.
        Empty findings → no section, so the digest stands alone.
        """
        worker_agent_id = str(inp.get("agent_id") or "_unknown")
        precomputed = inp.get("precomputed_report")
        if isinstance(precomputed, AIMessage):
            report = precomputed
            akw = dict(getattr(report, "additional_kwargs", {}) or {})
            akw.setdefault("agent_id", worker_agent_id)
            akw.setdefault("kind", "worker_report")
            akw.setdefault("config_name", str(inp.get("config_name") or ""))
            akw["used_precomputed_report"] = True
            report.additional_kwargs = akw
            self.log.debug(
                "summarizer: using worker-exit precomputed report for %r",
                worker_agent_id,
            )
        else:
            if inp.get("skip_digest_reason"):
                self.log.debug(
                    "summarizer: %r requested digest skip (%s) but did not "
                    "provide a valid precomputed report; emitting placeholder",
                    worker_agent_id,
                    inp.get("skip_digest_reason"),
                )
                report = self._skip_placeholder(
                    inp, str(inp.get("skip_digest_reason") or "skipped")
                )
            else:
                try:
                    summary_model = _summary_model_for_input(model, inp)
                    report = await summarize_worker_trace(
                        trace=list(inp.get("trace") or []),
                        worker_messages=list(inp.get("worker_messages") or []),
                        worker_system_prompt=str(inp.get("worker_system_prompt") or ""),
                        agent_id=worker_agent_id,
                        config_name=str(inp.get("config_name") or ""),
                        methodology=str(inp.get("methodology") or ""),
                        dispatch_reason=str(inp.get("dispatch_reason") or ""),
                        target_url=str(inp.get("target_url") or target_url_default or ""),
                        findings_count=int(inp.get("findings_count") or 0),
                        iteration_count=int(inp.get("iteration_count") or 0),
                        completed=bool(inp.get("completed")),
                        error=inp.get("error"),
                        refused=bool(inp.get("refused")),
                        model=summary_model,
                        run_id=run_id,
                        node_name=self.name,
                    )
                except Exception as e:  # noqa: BLE001
                    self.log.warning(
                        "summarizer: digest for %r failed (%s) — placeholder will be emitted",
                        worker_agent_id, e,
                    )
                    report = self._error_placeholder(inp, e)

        worker_findings = [
            f for f in all_findings
            if getattr(f, "agent_id", None) == worker_agent_id
        ]
        if worker_findings:
            return _attach_findings_section(report, worker_findings)
        return report

    @staticmethod
    def _skip_placeholder(inp: dict, reason: str) -> AIMessage:
        """Deterministic report for workers that intentionally skipped digesting."""
        agent_id = str(inp.get("agent_id") or "?")
        config_name = str(inp.get("config_name") or "?")
        return AIMessage(
            content=(
                f"## Status\nstopped — {reason}\n\n"
                f"## Target\nworker {agent_id} ({config_name}) did not need "
                f"an LLM digest because {reason}.\n\n"
                "## Inputs tried\n(see raw worker trace on disk if needed)\n\n"
                "## Server responses\n(unavailable in skipped digest)\n\n"
                "## Inferred server-side behaviour\n(unavailable in skipped digest)\n\n"
                "## NOT tried\n(unavailable in skipped digest)\n\n"
                "## Recommended next dispatch\nNone from this skipped digest.\n\n"
                "## Cross-skill handoffs\n[]\n\n"
                "## Next skill suggestions\n[]"
            ),
            additional_kwargs={
                "agent_id": agent_id,
                "kind": "worker_report",
                "config_name": config_name,
                "status": "digest_skipped",
                "iteration_count": int(inp.get("iteration_count") or 0),
                "findings_count": int(inp.get("findings_count") or 0),
                "skip_digest_reason": reason,
            },
        )

    @staticmethod
    def _error_placeholder(inp: dict, err: BaseException | None) -> AIMessage:
        """Last-resort placeholder when both the digest LLM and its own
        deterministic-stub fallback fail.

        Should be unreachable in practice — :func:`summarize_worker_trace`
        returns a stub on its own LLM failures. This exists so the
        planner is guaranteed to receive *one* ``AIMessage`` per
        pending entry, no matter what.
        """
        agent_id = str(inp.get("agent_id") or "?")
        config_name = str(inp.get("config_name") or "?")
        return AIMessage(
            content=(
                f"## Status\ncrashed — summariser internal error\n\n"
                f"## Target\nworker {agent_id} ({config_name}) "
                f"completed without producing a summary."
                + (f" Error: {err}" if err else "")
                + f"\n\n## Inputs tried\n(see "
                f"`logs/run-<id>/worker_traces.jsonl` on disk; "
                f"filter by `.agent_id == \"{agent_id}\"`)"
                f"\n\n## Server responses\n(unavailable)"
                f"\n\n## Inferred server-side behaviour\n(unavailable)"
                f"\n\n## NOT tried\n(unavailable)"
                f"\n\n## Recommended next dispatch\nRe-dispatch a different "
                f"skill — this worker's output could not be summarised."
                f"\n\n## Cross-skill handoffs\n[]"
                f"\n\n## Next skill suggestions\n[]"
            ),
            additional_kwargs={
                "agent_id": agent_id,
                "kind": "worker_report",
                "config_name": config_name,
                "status": "summariser_error",
                "iteration_count": int(inp.get("iteration_count") or 0),
                "findings_count": int(inp.get("findings_count") or 0),
            },
        )


def _pick_recon_report_body(
    pending: list[dict],
    reports: list[Any],
) -> str | None:
    """Return the report body for the recon worker in ``pending``, if any.

    Walks the paired (pending, reports) lists looking for the entry whose
    ``config_name`` is ``"recon"``. Returns the matching report's
    ``content`` as a string, or ``None`` when no recon entry exists or
    the matched report did not produce text (e.g. a digest exception
    that even the placeholder couldn't catch).

    The pairing is by index — ``asyncio.gather`` preserves input order,
    so ``reports[i]`` is the digest for ``pending[i]``.
    """
    for inp, rep in zip(pending, reports):
        if str(inp.get("config_name") or "").lower() != "recon":
            continue
        if not isinstance(rep, AIMessage):
            continue
        body = rep.content if isinstance(rep.content, str) else str(rep.content or "")
        body = body.strip()
        if body:
            return body
    return None


def _render_findings(findings: list[Finding]) -> str:
    """Render Finding dataclasses as a verbatim markdown block.

    Used by :func:`_attach_findings_section` to build the planner-facing
    ``## Findings (verbatim from worker)`` section. Format is plain
    markdown — title + severity on the lead line, URL / category on
    line 2, full evidence on line 3. Evidence is NOT truncated here
    (the regex parser in skill_runner already caps it at 500 chars)
    so the planner sees what the worker actually wrote.
    """
    lines: list[str] = []
    for i, f in enumerate(findings, 1):
        sev = getattr(f.severity, "name", str(f.severity))
        lines.append(f"{i}. [{sev}] {f.title}")
        meta_bits = []
        if f.category:
            meta_bits.append(f"category={f.category}")
        if f.url:
            meta_bits.append(f"url={f.url}")
        if meta_bits:
            lines.append(f"   {'  '.join(meta_bits)}")
        if f.evidence:
            lines.append(f"   evidence: {f.evidence}")
    return "\n".join(lines)


def _attach_findings_section(report: AIMessage, findings: list[Finding]) -> AIMessage:
    """Return a new ``AIMessage`` with the verbatim findings block
    appended to the digest content. Preserves ``additional_kwargs`` so
    downstream code that reads ``kind="worker_report"`` / ``agent_id``
    keeps working.
    """
    body = report.content if isinstance(report.content, str) else str(report.content or "")
    appended = body.rstrip() + "\n\n## Findings (verbatim from worker)\n" + _render_findings(findings)
    return AIMessage(
        content=appended,
        additional_kwargs=dict(report.additional_kwargs or {}),
    )


summarizer_node = SummarizerNode()
