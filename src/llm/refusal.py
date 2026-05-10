"""Typed refusal error + structured observability.

The Codex API rejects ~80% of worker LLM calls in the SwarmAttacker
swarm with ``cyber_policy``. Until 2026-05-10, those rejections were
silently swallowed into a synthetic ``"⚠️ model refused"`` AIMessage.
That made it impossible to answer questions like "X of Y workers
refused, broken down by skill / iteration / request size" — which
is exactly what diagnostics needs after a regression.

This module provides:

  - ``RefusalError`` — a typed exception with structured fields so
    the catch site can attach context BEFORE re-raising.
  - ``log_refusal`` — append a JSONL row to
    ``logs/run-<id>/refusals.jsonl`` per refusal so a run-level
    summary can count and group them.

Wired in at the worker LLM call site in
``src/nodes/base.py:run_skill_agent`` (after the tier-3 retry chain
exhausts). Provider-agnostic: the catch site translates whatever
provider-specific refusal exception (today
``CodexCyberPolicyError``) into a ``RefusalError`` before raising.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class RefusalError(Exception):
    """Worker LLM call refused at the API safety layer.

    Raised after the worker's local refusal-recovery chain (plain
    retry × N → vocab_filter retry) has exhausted. Carries enough
    context for ``log_refusal`` to produce a useful diagnostic row
    without needing to traverse partial state.

    Fields are intentionally serialisable: every value is a
    primitive (str, int, or None) so ``asdict()`` produces a JSON-
    safe payload directly.
    """

    agent_id: str
    skill_name: str
    iteration: int
    request_size_chars: int
    request_size_tokens: int
    attempts_made: int
    refusal_message: str
    # Optional — set if the catch site knows which retry tier was
    # last attempted (e.g. "plain" vs "vocab_filter").
    last_tier: str | None = None

    def __post_init__(self) -> None:
        # Exception requires args; populate via the formatted message.
        Exception.__init__(self, self._summary())

    def _summary(self) -> str:
        return (
            f"[{self.agent_id}] cyber_policy refusal after "
            f"{self.attempts_made} attempts (last tier: "
            f"{self.last_tier or 'plain'}, request "
            f"~{self.request_size_tokens} tokens)"
        )


def _refusals_log_path(run_id: str | None) -> Path | None:
    """Resolve the per-run refusals.jsonl path.

    Mirrors how ``src/llm/callbacks.py`` resolves run-scoped log
    paths so the new file lands beside ``llm_calls.jsonl`` and
    ``terminal_events.jsonl``. Returns None if no run_id is set —
    in that case the caller should still raise the error but skip
    the disk log.
    """
    if not run_id:
        return None
    repo_root = Path(__file__).resolve().parents[2]
    log_dir = repo_root / "logs" / f"run-{run_id}"
    if not log_dir.exists():
        # Some run-id flavours don't pre-create the dir; create it.
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
    return log_dir / "refusals.jsonl"


def log_refusal(err: RefusalError, *, run_id: str | None = None) -> None:
    """Append one JSONL row describing the refusal.

    Best-effort: never raises. If the path can't be resolved or the
    write fails, logs a warning and returns. The error itself is
    raised by the caller separately — this function only handles
    persisting diagnostic context.
    """
    path = _refusals_log_path(run_id)
    if path is None:
        return
    payload = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "run_id": run_id,
        **asdict(err),
    }
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except OSError as e:  # noqa: BLE001
        logger.warning(
            "Could not append to refusals log %s: %s", path, e
        )


def count_refusals(run_id: str) -> int:
    """Count refusal rows for a run. Used by the run summary.

    Returns 0 when the file is missing or unreadable, never raises.
    """
    path = _refusals_log_path(run_id)
    if path is None or not path.exists():
        return 0
    try:
        with path.open("r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0
