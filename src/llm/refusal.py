"""Transitional shim — the writer moved to observability.writers.

The typed ``RefusalError`` and the vocabulary filter live under
:mod:`src.refusals` (a top-level package). The disk writer
(``log_refusal``) and its companion reader (``count_refusals``) now
live under :mod:`src.observability` (the writer in
``observability/writers.py:append_refusal``, the reader inlined into
``observability/summary/header.py:count_refusals``).

This file is kept solely so existing imports
(``from src.llm.refusal import RefusalError, log_refusal,
count_refusals``) keep working without churn at every call site. It
will be removed once the import sites have been migrated.
"""

from __future__ import annotations

from src.observability.summary import count_refusals
from src.observability.writers import append_refusal as _append_refusal
from src.refusals.errors import RefusalError

__all__ = [
    "RefusalError",
    "count_refusals",
    "log_refusal",
]


def log_refusal(err: RefusalError, *, run_id: str | None = None) -> None:
    """Append one JSONL row describing the refusal.

    Best-effort: never raises. Forwards to
    :func:`src.observability.writers.append_refusal` — the actual
    file write lives there alongside every other JSONL appender.
    """
    _append_refusal(err, run_id=run_id)
