# Worker package — the skill-runner worker lifecycle, split by concern.
#
# This package was carved out of the former monolithic
# ``src/nodes/base/skill_runner.py`` (which is now a thin back-compat
# shim that re-exports from here). Modules, lowest-level first:
#
# - ``findings``      — finding parsers (markdown + JSON) and severity map.
# - ``verdicts``      — closing-VERDICT parsing + the specialist-refutation gate.
# - ``salvage``       — refusal-path primitive salvage from a partial trace.
# - ``seed_context``  — prompt-seed renderers for cross-turn worker context.
# - ``tool_attempts`` — structured tool-outcome extraction + investigation thread.
# - ``runner``        — ``AgentConfig`` + ``run_skill_agent`` (the whole lifecycle).
#
# The public surface lives in ``runner`` and ``findings``; import from
# those (or from the ``skill_runner`` shim) rather than reaching into the
# other modules directly. Re-exports are added here as each module lands.

from __future__ import annotations

from src.nodes.base.worker.findings import (
    FINDING_PATTERN,
    JSON_FINDINGS_PATTERN,
    SEVERITY_MAP,
    _extract_findings,
    _findings_from_json,
    _findings_from_markdown,
)

__all__ = [
    "FINDING_PATTERN",
    "JSON_FINDINGS_PATTERN",
    "SEVERITY_MAP",
    "_extract_findings",
    "_findings_from_json",
    "_findings_from_markdown",
]
