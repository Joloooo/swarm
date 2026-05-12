"""Typed refusal exception.

The Codex API rejects a sizeable fraction of worker LLM calls in the
SwarmAttacker swarm with ``cyber_policy``. Until 2026-05-10, those
rejections were silently swallowed into a synthetic
``"⚠️ model refused"`` AIMessage. That made it impossible to answer
questions like "X of Y workers refused, broken down by skill /
iteration / request size" — which is exactly what diagnostics needs
after a regression.

This module defines ``RefusalError`` — the typed exception raised by
the retry layer (``src/refusals/retry.py``) once every plain and
vocabulary-filtered retry tier has exhausted. It carries enough
structured context (agent_id, skill_name, iteration, request size,
attempts made, last tier attempted, raw refusal message) to identify
the worker / call site at the point of failure. Pre-refactor a
dedicated ``refusals.jsonl`` writer consumed these fields; that
artefact was removed in the 2026-05 log consolidation because the
same information already appears on the ``llm_error`` row in
``full_logs.jsonl`` produced by the LangChain callback. The
``RefusalError`` type is still useful for shaping which retry tier
runs next in ``src/refusals/retry.py``.

Provider-agnostic: the catch site translates whatever provider-
specific refusal exception (today ``CodexCyberPolicyError``) into a
``RefusalError`` before raising.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RefusalError(Exception):
    """Worker LLM call refused at the API safety layer.

    Raised after the worker's local refusal-recovery chain (plain
    retry × N → vocab_filter retry) has exhausted. Carries enough
    context for the observability writer to produce a useful
    diagnostic row without needing to traverse partial state.

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
