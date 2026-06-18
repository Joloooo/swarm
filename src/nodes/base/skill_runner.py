# Skill runner — back-compat shim.
#
# The worker lifecycle and its helpers used to live here as one ~2.3k-line
# module. They now live in the ``src.nodes.base.worker`` package, split by
# concern (findings / verdicts / salvage / seed_context / tool_attempts /
# runner). This module re-exports the public surface — and the private helpers
# that existing call sites (``src/nodes/base/__init__.py``, the test suite, the
# decision-replay probes) import by name — so every
# ``from src.nodes.base.skill_runner import …`` keeps resolving unchanged.
#
# Ablation note: the worker honours ``capability.disable_prompting_techniques``
# (it drops the in-loop no-progress nudge, which would otherwise re-inject the
# diversity / transformation guidance the ablation removes). The flag is read in
# ``worker/runner.py`` now; this line keeps that wiring discoverable from the
# historical module path.

from __future__ import annotations

from src.nodes.base.worker.findings import (
    FINDING_PATTERN,
    JSON_FINDINGS_PATTERN,
    SEVERITY_MAP,
    _extract_findings,
    _findings_from_json,
    _findings_from_markdown,
)
from src.nodes.base.worker.runner import (
    AgentConfig,
    _persist_worker_trace,
    _run_skill_agent_impl,
    run_skill_agent,
)
from src.nodes.base.worker.salvage import (
    _REFUSAL_NEGATION_CUES,
    _REFUSAL_PRIMITIVE_MARKERS,
    _refusal_marker_is_real,
    _salvage_primitive_from_trace,
)
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
    _render_finding_attempts,
)
from src.nodes.base.worker.tool_attempts import (
    _build_investigation_thread,
    _classify_tool_attempt,
    _compact_run_record,
    _compact_tool_field,
    _extract_tool_attempts_from_trace,
    _important_tool_surface,
    _summarize_output,
    _tool_base_status,
    _tool_call_arg,
    _tool_exit_code,
    _tool_message_text,
)
from src.nodes.base.worker.verdicts import (
    VERDICT_PATTERN,
    _CLASS_ALIASES,
    _extract_verdicts,
    _norm_class,
    _redirect_class,
    _REDIRECT_CLASSES,
    _VERDICT_OUTCOME,
    _worker_owns_class,
)

# The documented public surface. Private helpers above remain importable for
# back-compat but are intentionally kept out of ``__all__``.
__all__ = [
    "AgentConfig",
    "FINDING_PATTERN",
    "JSON_FINDINGS_PATTERN",
    "SEVERITY_MAP",
    "_extract_findings",
    "_findings_from_json",
    "_findings_from_markdown",
    "run_skill_agent",
]
