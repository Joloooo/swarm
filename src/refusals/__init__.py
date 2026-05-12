"""Refusal-handling logic for SwarmAttacker.

When the worker LLM (typically Codex on the ChatGPT backend) refuses
a security-testing request at the ``cyber_policy`` safety layer, the
swarm needs to recover without losing the engagement. This package
holds every piece of *logic* that detects, retries past, recovers
from, or salvages value out of a refusal.

What lives here vs. elsewhere:

- ``refusals/`` (this package) owns the **logic** of refusal handling
  — the typed error, the detector, the retry ladder, the focused-LLM
  re-frame, and the post-crash finding salvage. These are imported
  by node call sites at the moments where refusals can happen.

- ``observability/writers.py`` owns the **capture** of refusals to
  disk (`refusals.jsonl`). It imports ``RefusalError`` from here as
  the schema. This is the same separation the rest of the project
  uses — refusal logic is one concern, refusal recording is another.

- ``observability/summary/header.py`` owns the count of recorded
  refusals shown in the run summary, inlined as a one-liner.

The public surface is intentionally small — most consumers only need
``RefusalError`` (the typed exception) and the vocabulary filter.
The retry / recover / salvage helpers are imported directly from
their submodules at the call site so the import line itself names
which recovery tier is being used.
"""

from __future__ import annotations

from src.refusals.detect import REFUSAL_PATTERNS, looks_like_refusal
from src.refusals.errors import RefusalError
from src.refusals.recover import recover_from_refusal
from src.refusals.retry import astream_with_refusal_retry
from src.refusals.salvage import salvage_finding, try_salvage
from src.refusals.vocabulary import filter_messages, filter_text

__all__ = [
    "REFUSAL_PATTERNS",
    "RefusalError",
    "astream_with_refusal_retry",
    "filter_messages",
    "filter_text",
    "looks_like_refusal",
    "recover_from_refusal",
    "salvage_finding",
    "try_salvage",
]
