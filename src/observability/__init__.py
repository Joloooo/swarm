"""Per-run observability: one folder per graph invocation.

For each run we write everything under ``logs/run-<run_id>/``:

    nodes.jsonl           one line per BaseNode.__call__ — duration, summary,
                          full state shape before/after, full text of every
                          newly added message/finding/agent_result. This is
                          the file you read when answering "what did node X
                          do?" — both the timeline and the per-node forensic
                          replay live here.
    llm_calls.jsonl       two lines per LLM call: one ``phase=start`` row
                          with the full prompt sent, and one ``phase=end``
                          row (or ``phase=error``) with usage tokens,
                          duration, and response. Same file so live tail
                          shows both sides of every round-trip.
    terminal_events.jsonl tool-call log (redirected from src/tools/shell/)
    refusals.jsonl        one row per cyber_policy refusal, flagged as a
                          deletion candidate — see writers.py:append_refusal
    worker_traces.jsonl   one row per LangChain message in a worker's trace
    final_state.json      graph.ainvoke() return value, in full
    summary.md            human-readable digest of the whole run

The run_id embeds the benchmark id (or target host) so that ``ls logs/``
tells you immediately which run hit which target.

Nothing is truncated. Disk is cheap; thesis analysis needs the full record.

Package layout:

  * ``writers.py``       — every JSONL appender + the final state writer.
                           One function per artefact, sharing one
                           ``_JsonlWriter`` helper.
  * ``state.py``         — pure functions that compute the per-node state
                           shape and diff (consumed by writers.append_node_event).
  * ``live.py``          — the ``LIVE`` singleton: stderr rendering with
                           silent / compact / verbose modes.
  * ``decision_parser.py`` — shared planner-JSON extractor used by both
                             ``live.py`` and ``src/nodes/planner.py``.
  * ``summary/``         — the post-run summary.md generator, split into
                           four small files. Public surface is
                           ``summary.write_summary``.

History note: prior to the consolidation in 2026-05 we wrote separate
``state_diffs.jsonl`` (per-node shape diff) and ``llm_requests.jsonl``
(per-call prompts). Both were folded into the files above so the run
dir has 6 artefacts instead of 8. The shape-diff data is still there
under each ``nodes.jsonl`` row's ``before`` / ``after`` / ``delta``
keys; the request bodies are still there under ``llm_calls.jsonl``
``phase=start`` rows.
"""

from __future__ import annotations

# Disk writers — one function per artefact.
from src.observability.writers import (
    LOGS_ROOT,
    append_llm_event,
    append_node_event,
    append_refusal,
    append_terminal_event,
    append_worker_trace,
    make_run_id,
    run_dir,
    write_final_state,
)

# Live stderr renderer + stdlib logging adapters.
from src.observability.live import (
    HttpxQuietFilter,
    LIVE,
    LiveLogHandler,
)

# Summary builder.
from src.observability.summary import count_refusals, write_summary

__all__ = [
    "HttpxQuietFilter",
    "LIVE",
    "LOGS_ROOT",
    "LiveLogHandler",
    "append_llm_event",
    "append_node_event",
    "append_refusal",
    "append_terminal_event",
    "append_worker_trace",
    "count_refusals",
    "make_run_id",
    "run_dir",
    "write_final_state",
    "write_summary",
]
