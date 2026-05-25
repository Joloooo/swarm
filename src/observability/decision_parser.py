"""Shared planner-decision JSON parser.

Both the supervisor planner (``src/nodes/planner.py``) and the live
stderr renderer (``src/observability/live.py``) need to extract the
planner's JSON decision from its final AIMessage. They used to have
two separate regex-based parsers that diverged slightly in robustness
(planner is strict on the ``action`` field; live tolerates trailing
commas). This module is the one shared implementation.

Strict mode (``strict=True`` — the planner's path) requires the
parsed JSON to contain an ``action`` key whose value is one of the
known supervisor actions. Lax mode (``strict=False`` — the live
renderer's path) accepts any well-formed JSON object containing an
``action`` key, and additionally cleans up trailing commas before
parsing — the renderer prefers a partially-valid decision to no
decision at all.

Step 6 of the refactor populates this module by inlining the two
parsers and removing the duplicates from planner.py and live.py.
This is currently a placeholder so the package layout is in place.
"""

from __future__ import annotations

import json
import re

# Match a fenced ```json``` block first, fall back to a bare object
# containing an "action" key. The two-alternative regex is deliberate:
# it's the same shape both legacy parsers used independently.
_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_BARE_OBJECT = re.compile(r"(\{[^{}]*\"action\"[^{}]*\})", re.DOTALL)

# Set of valid actions. Kept in sync MANUALLY with
# ``src.nodes.planner.VALID_ACTIONS`` — these are two files that must
# agree but live in different layers (the planner defines the action
# vocabulary; this parser validates output against it). When a new
# action is added to the planner, it MUST be added here too, otherwise
# the strict parser will silently reject every decision that uses it.
#
# History: ``submit_flag`` was added to the planner's vocabulary but
# not here, which made every flag submission produce "no parseable
# JSON decision" → force-report, killing benchmark runs where the
# agent had actually captured the flag (XBEN-006-24,
# ``run-XBEN-006-24__2026-05-25_14h33m29s``).
#
# Imported lazily (not via ``from src.nodes.planner``) so this module
# doesn't pull the planner at import time — the duplication is the
# price of breaking that import cycle.
_VALID_ACTIONS = frozenset({"attack", "recon", "web_search", "report", "submit_flag"})


def parse_planner_decision(text: str, *, strict: bool = True) -> dict | None:
    """Extract the supervisor's JSON decision from a final message.

    Args:
        text: the planner's final AIMessage content.
        strict: if True (default), require ``action`` to be one of the
            known supervisor actions. If False, accept any well-formed
            JSON object that contains an ``action`` key, and clean up
            trailing commas before parsing.

    Returns:
        The parsed dict, or ``None`` if no parseable JSON was found.
    """
    if not text:
        return None

    # Try fenced ```json``` first; fall back to a bare {...action...} block.
    candidates: list[str] = []
    fence_match = _JSON_FENCE.search(text)
    if fence_match:
        candidates.append(fence_match.group(1))
    for bare_match in _BARE_OBJECT.finditer(text):
        candidates.append(bare_match.group(1))

    for raw in candidates:
        if not raw:
            continue
        # Lax mode: tolerate trailing commas before } / ].
        if not strict:
            raw = re.sub(r",\s*([}\]])", r"\1", raw)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        if strict:
            if parsed.get("action") in _VALID_ACTIONS:
                return parsed
        else:
            if "action" in parsed:
                return parsed
    return None
