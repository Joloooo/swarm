# Worker package — the skill-runner worker lifecycle, split by concern.
#
# Modules, lowest-level first:
#
# - ``findings``      — finding parsers (markdown + JSON) and severity map.
# - ``verdicts``      — closing-VERDICT parsing + the specialist-refutation gate.
# - ``salvage``       — refusal-path primitive salvage from a partial trace.
# - ``seed_context``  — prompt-seed renderers for cross-turn worker context.
# - ``tool_attempts`` — structured tool-outcome extraction + investigation thread.
# - ``skill_runner``  — ``AgentConfig`` + ``run_skill_agent`` (the whole lifecycle).
#
# The orchestrator (``BaseNode`` in ``src/nodes/base/__init__.py``) sits a level
# ABOVE and drives this package via ``run_skill_agent``. The public surface is
# re-exported here, so call sites import ``from src.nodes.base.worker import …``.

from __future__ import annotations

from src.nodes.base.worker.findings import (
    FINDING_PATTERN,
    JSON_FINDINGS_PATTERN,
    SEVERITY_MAP,
    _extract_findings,
    _findings_from_json,
    _findings_from_markdown,
)
from src.nodes.base.worker.skill_runner import (
    AgentConfig,
    run_skill_agent,
)

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
