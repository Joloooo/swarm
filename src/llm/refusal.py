"""Back-compat shim — the typed ``RefusalError`` lives in ``src.refusals``.

Pre-refactor this project also wrote one row per API-level refusal to
``logs/run-<run_id>/refusals.jsonl``. That file got deleted as part of
the 2026-05 log consolidation: it duplicated information already
captured by ``llm_error`` rows in ``full_logs.jsonl`` (which carry the
exact refusal message and the prompt that triggered it), and the
``refusal_message`` field was identical generic Codex boilerplate on
every row.

This module is kept solely so existing imports
(``from src.llm.refusal import RefusalError, log_refusal,
count_refusals``) keep working. ``log_refusal`` is a no-op;
``count_refusals`` reads ``llm_error`` rows out of ``full_logs.jsonl``
on demand.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.refusals.errors import RefusalError

__all__ = [
    "RefusalError",
    "count_refusals",
    "log_refusal",
]


def log_refusal(err: "RefusalError", *, run_id: str | None = None) -> None:
    """No-op. Refusals are already captured as ``llm_error`` rows in
    ``logs/run-<run_id>/full_logs.jsonl`` via the LangChain callback at
    ``src/llm/callbacks.py:TokenLoggingCallback.on_llm_error``.

    Signature preserved so existing call sites compile unchanged.
    """
    del err, run_id  # explicitly unused
    return None


def count_refusals(run_id: str | None) -> int:
    """Return how many LLM-layer refusals were recorded for ``run_id``.

    Counts rows in ``logs/run-<run_id>/full_logs.jsonl`` where
    ``type == "llm_error"`` and the error message contains the
    canonical Codex refusal phrase. Best-effort: returns ``0`` if the
    file is missing or unreadable.
    """
    if not run_id:
        return 0
    try:
        from src.observability.writers import full_logs_path

        path: Path = full_logs_path(run_id)
        if not path.exists():
            return 0
        n = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("type") != "llm_error":
                continue
            msg = str(row.get("error_msg") or "").lower()
            if "cybersecurity risk" in msg or "cyber_policy" in msg:
                n += 1
        return n
    except Exception:
        return 0
