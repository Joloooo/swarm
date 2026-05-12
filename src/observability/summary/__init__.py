"""summary.md generator — split into four files for navigation.

Public surface is just :func:`write_summary` from
:mod:`observability.summary.builder`. The other modules
(``_helpers``, ``findings``, ``timeline``, ``header``) are internal
to this sub-package and exist purely so a 1 500-line file becomes
five files of 100–700 lines each, each with one clear concern.

Read the modules in this order to follow how a summary is built:

  1. :mod:`builder` — the orchestrator.
  2. :mod:`header`  — debug-hints rules engine.
  3. :mod:`timeline` — per-node detail-section renderers.
  4. :mod:`findings` — single-finding rendering.
  5. :mod:`_helpers` — formatters, JSONL readers, LLM-call pairing.
"""

from __future__ import annotations

from src.observability.summary.builder import write_summary
from src.observability.summary.header import count_refusals

__all__ = [
    "count_refusals",
    "write_summary",
]
