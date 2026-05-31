"""Worker middleware: nudge the model when it plateaus on identical outputs.

Background
----------
The executor system prompt already contains the cure (``DIVERSITY_RULES``
in ``src/nodes/base/system_prompt.py``): when probes return the same
response repeatedly, stop deepening one idea and broaden to new
categories of variation. But that guidance is *self-assessed* — it only
works if the model NOTICES it has plateaued, and a model stuck in a
local optimum is exactly the one that doesn't notice.

The 2026-05-31 XBEN-011 run is the canonical failure: 30–50+ payloads
fired across ~9 minutes, almost all returning a byte-identical
``Failed! Try again!``, with no pivot — straight into the 1200 s wall.

This middleware closes that gap deterministically. It watches the tool
outputs flowing back to the model and, when the last N are
byte-for-byte identical, injects a ONE-TIME reminder that re-surfaces
the DIVERSITY_RULES guidance at the moment it's needed — implemented as
a LangChain v1 ``AgentMiddleware`` ``before_model`` hook, so it touches
ONLY the message stream and never the tool-execution path.

Why this is safe for the "double down" principle
------------------------------------------------
It fires ONLY on byte-identical responses (zero new information). In a
productive investigation — SQLi probing a filter, IDOR sweeping an ID
range, a wordlist enumeration — responses vary (different errors,
lengths, timings, rows), so the detector never fires and persistence is
untouched. Its action is also NOT "give up": it tells the model to
broaden categories (try harder, smarter), and only suggests changing
tactic if the categories are genuinely exhausted. It never stops the
worker, never reduces the iteration budget, never short-circuits the
loop.

The dedup guard (``_last_nudged``) means the nudge fires at most once
per plateau: after nudging for a given identical-output value, it stays
quiet until the output value CHANGES (the model tried something new) and
a *fresh* plateau forms — so a model that ignores the nudge is not
spammed every turn.
"""

from __future__ import annotations

import os
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import HumanMessage, ToolMessage

from src.nodes.base.flag_watcher import _coerce_to_text


def _threshold() -> int:
    """Consecutive byte-identical tool outputs required before nudging.

    Configurable via ``SWARM_NOPROGRESS_THRESHOLD`` (default 3). Values
    below 2 are coerced to 3 — a single repeat is not a plateau.
    """
    try:
        n = int(os.getenv("SWARM_NOPROGRESS_THRESHOLD", "3"))
    except (TypeError, ValueError):
        return 3
    return n if n >= 2 else 3


# The injected reminder. Restates DIVERSITY_RULES in-loop, in neutral
# vocabulary (no "attack"/"exploit"/"payload" framing — see the Skill
# Vocabulary Policy in CLAUDE.md). Crucially it says BROADEN, not give
# up: the only "stop" it offers is conditional on the categories being
# genuinely exhausted.
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
    """Inject a one-time 'broaden, don't deepen' nudge on identical outputs.

    Attach via ``create_agent(..., middleware=[NoProgressNudgeMiddleware(...)])``.
    One instance per worker run (the natural pattern, since ``agent_id``
    and the plateau state are per-worker). Stateless except for
    ``_last_nudged``, which prevents re-nudging on the same plateau.
    """

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
        # The tool-output value we last nudged on. Empty until first
        # nudge. Compared verbatim so a NEW plateau (different value)
        # re-arms the nudge but a CONTINUING plateau stays quiet.
        self._last_nudged: str = ""

    # Both sync and async are provided so the middleware works whichever
    # path ``create_agent`` drives (async is the live path in the swarm).
    def before_model(self, state: Any, runtime: Any = None) -> dict | None:
        return self._maybe_nudge(state)

    async def abefore_model(self, state: Any, runtime: Any = None) -> dict | None:
        return self._maybe_nudge(state)

    def _maybe_nudge(self, state: Any) -> dict | None:
        messages = _get_messages(state)
        if not messages:
            return None
        # Tool outputs only, in order. The trailing run of these is what
        # tells us the model is plateauing on the same observation.
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
        # Already nudged for this exact plateau — stay quiet until the
        # output value changes and a fresh plateau forms.
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
    """Read the message list from either a dict-shaped or attr-shaped state."""
    if isinstance(state, dict):
        return state.get("messages") or []
    return getattr(state, "messages", None) or []
