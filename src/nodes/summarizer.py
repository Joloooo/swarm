"""SummarizerNode — converts each worker's trace into one report message.

This node is the **synchronization point** after parallel worker
fan-out. The graph topology is::

    planner --Send()--> executor (×N parallel)  ──┐
                      → recon (when not part of attack fan-out)  ──┤
                                                                    ↓
                                                                summarizer  (runs ONCE)
                                                                    ↓
                                                                planner

How it works
============

1. Each parallel worker (``ExecutorNode``, ``ReconNode``) returns a
   single-item list under ``state["pending_summary_inputs"]``. The
   reducer ``_summary_inputs_reducer`` (in ``src/state.py``)
   accumulates all parallel writes into one list.

2. After all worker branches converge here, the summarizer reads the
   list and produces ONE structured ``AIMessage`` report per worker —
   in parallel via ``asyncio.gather`` so a fan-out of 4 workers costs
   roughly one summarizer LLM-call latency, not four.

3. The reports are appended to ``state["messages"]`` and the
   ``pending_summary_inputs`` field is cleared via the reducer's
   ``None`` sentinel.

4. The planner then runs and reads only digests + its own decisions —
   the raw worker traces never enter its prompt.

Why this matters
================

Pre-summarizer-node design: each worker mirrored its full trace
(60 iterations × ~4 KB ≈ 240 KB) into ``state["messages"]``. A planner
running after a 4-way fan-out saw ~1 MB of mirrored trace, and the
prompt blew through Codex's 256 K window within ~3 cycles.

This node compresses each trace into a ~5 KB structured report that
preserves the high-fidelity probe enumeration the planner needs (what
was tried, what was NOT tried, recommended next angle) and drops the
raw bytes the planner does not.

Failure modes
=============

If the per-worker summarizer call fails (provider error, timeout), the
``digest`` module returns a deterministic stub report so the planner
still sees *something* coherent for that worker. Better a placeholder
than a hole.

If ``pending_summary_inputs`` is empty when the node runs (e.g. the
``initialize`` → ``planner`` cold-start path that skips workers
entirely), this node returns an empty update and yields directly to
the planner — zero LLM cost when there is nothing to summarize.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage

from src.llm.digest import summarize_worker_trace
from src.nodes.base import BaseNode
from src.state import Finding

logger = logging.getLogger(__name__)


class SummarizerNode(BaseNode):
    """Convert pending worker traces into structured planner-facing reports."""

    async def execute(self, state: dict) -> dict:
        pending = list(state.get("pending_summary_inputs") or [])
        if not pending:
            # No workers to summarize — happens on cold-start paths
            # (initialize → planner without a worker in between) and on
            # any subsequent planner cycle that didn't dispatch a
            # worker (e.g. planner → web_search → planner). Returning
            # an empty update is the cheapest correct behavior.
            self.log.debug(
                "summarizer: no pending_summary_inputs — yielding empty update"
            )
            return {}

        # Termination-on-capture is now driven by ``state.captured_flag``
        # (set by ``src/nodes/base/skill_runner.py`` on the success
        # path when a worker's tool output contained a ``flag{...}``
        # substring that strict-equals ``expected_flag``). The
        # ``route_after_summarizer`` conditional edge reads that field
        # and routes to ``END`` on a verified capture.
        #
        # This module deliberately does NOT do any flag scanning of
        # its own — by the time the summarizer runs, the worker has
        # already done the strict-equality verification upstream. We
        # just transform pending traces into digests for the planner.
        # In real-pentest mode (``expected_flag`` empty) the skill
        # runner never sets ``captured_flag``, so termination remains
        # planner-driven via ``action="submit_flag"``.

        run_id = state.get("run_id")
        target_url = state.get("target_url", "")

        # Build one summariser coroutine per pending worker. Run all in
        # parallel via asyncio.gather so a 4-way fan-out costs ~one
        # summariser LLM-call latency, not four sequential calls.
        # Per-call failures are handled inside summarize_worker_trace
        # (it returns a deterministic stub on LLM error), so gather()
        # never raises here.
        from src.llm.provider import get_llm  # lazy — see base.py docstring
        model = get_llm()

        # Snapshot the global findings list once before fan-out so each
        # parallel _summarize_one sees a consistent view (the reducer
        # in state.py never mutates this list in place, but reading it
        # once avoids any chance of mid-coroutine reassignment).
        all_findings = list(state.get("findings") or [])

        coros = [
            self._summarize_one(
                inp=inp,
                model=model,
                run_id=run_id,
                target_url_default=target_url,
                all_findings=all_findings,
            )
            for inp in pending
        ]
        try:
            reports = await asyncio.gather(*coros, return_exceptions=True)
        except Exception as e:  # defensive — gather itself shouldn't raise
            self.log.exception("summarizer.gather raised: %s", e)
            reports = []

        report_messages: list[AIMessage] = []
        for inp, rep in zip(pending, reports):
            if isinstance(rep, AIMessage):
                report_messages.append(rep)
            elif isinstance(rep, BaseException):
                # Should be rare — the helper handles its own errors.
                # Surface a one-liner so the planner still sees the
                # worker happened.
                self.log.warning(
                    "summarizer: worker %r digest raised %s: %s",
                    inp.get("agent_id"), type(rep).__name__, str(rep)[:200],
                )
                report_messages.append(self._error_placeholder(inp, rep))
            else:
                # Unexpected return type (None, dict, ...). Skip with a
                # placeholder rather than dropping the worker silently.
                self.log.warning(
                    "summarizer: unexpected digest return type %r for %r",
                    type(rep).__name__, inp.get("agent_id"),
                )
                report_messages.append(self._error_placeholder(inp, None))

        self.log.info(
            "summarizer: produced %d worker_report message(s) for %d pending input(s)",
            len(report_messages), len(pending),
        )

        update: dict[str, Any] = {
            "messages": report_messages,
            # Sentinel: the reducer (_summary_inputs_reducer) treats
            # ``None`` as "clear the list" so subsequent worker fan-outs
            # don't see stale entries from this turn.
            "pending_summary_inputs": None,
        }

        # Capture the recon worker's summary once, into
        # ``state["recon_summary"]``. The seed builder in
        # ``src/nodes/base/skill_runner.py:_format_recon_summary``
        # renders it as "## Application map" for every subsequent
        # worker so they don't re-walk the application.
        #
        # We only write when:
        #   1. ``state["recon_summary"]`` is empty (first recon pass), AND
        #   2. one of this turn's pending entries was the recon worker.
        # The reducer in ``src/state.py:_recon_summary_reducer`` is
        # first-non-empty-wins so a hypothetical second recon dispatch
        # cannot overwrite the canonical first map either.
        if not (state.get("recon_summary") or "").strip():
            recon_text = _pick_recon_report_body(pending, reports)
            if recon_text:
                update["recon_summary"] = recon_text
                self.log.info(
                    "summarizer: captured recon_summary (%d chars) into state",
                    len(recon_text),
                )

        return update

    async def _summarize_one(
        self,
        *,
        inp: dict,
        model: Any,
        run_id: str | None,
        target_url_default: str,
        all_findings: list[Finding],
    ) -> AIMessage:
        """Produce one report ``AIMessage`` for one pending worker entry.

        Wraps :func:`src.llm.digest.summarize_worker_trace` with a
        try/except so a single worker's failure can't take down the
        whole batch — gather() then assembles per-worker results into
        the final messages list.

        After the digest LLM returns, this method appends a
        ``## Findings (verbatim from worker)`` section to the report's
        content for any ``Finding`` objects this worker emitted. The
        digest LLM compresses prose ("private record returned") and
        will paraphrase away byte-exact strings (captured flags, leaked
        credentials, raw SQL error fragments) that the planner needs to
        see verbatim — the regex-parsed Finding objects already
        preserve them in ``Finding.evidence``, so we just route that
        data to the planner alongside the prose digest. The append is a
        pure Python concatenation: no LLM round-trip, no risk of
        paraphrasing, no false-positive surface from pattern matching.
        Empty findings → no section, so the digest stands alone.
        """
        worker_agent_id = str(inp.get("agent_id") or "_unknown")
        try:
            report = await summarize_worker_trace(
                trace=list(inp.get("trace") or []),
                agent_id=worker_agent_id,
                config_name=str(inp.get("config_name") or ""),
                methodology=str(inp.get("methodology") or ""),
                dispatch_reason=str(inp.get("dispatch_reason") or ""),
                target_url=str(inp.get("target_url") or target_url_default or ""),
                findings_count=int(inp.get("findings_count") or 0),
                iteration_count=int(inp.get("iteration_count") or 0),
                completed=bool(inp.get("completed")),
                error=inp.get("error"),
                refused=bool(inp.get("refused")),
                model=model,
                run_id=run_id,
                node_name=self.name,
            )
        except Exception as e:  # noqa: BLE001
            self.log.warning(
                "summarizer: digest for %r failed (%s) — placeholder will be emitted",
                worker_agent_id, e,
            )
            report = self._error_placeholder(inp, e)

        worker_findings = [
            f for f in all_findings
            if getattr(f, "agent_id", None) == worker_agent_id
        ]
        if worker_findings:
            return _attach_findings_section(report, worker_findings)
        return report

    @staticmethod
    def _error_placeholder(inp: dict, err: BaseException | None) -> AIMessage:
        """Last-resort placeholder when both the digest LLM and its own
        deterministic-stub fallback fail.

        Should be unreachable in practice — :func:`summarize_worker_trace`
        returns a stub on its own LLM failures. This exists so the
        planner is guaranteed to receive *one* ``AIMessage`` per
        pending entry, no matter what.
        """
        agent_id = str(inp.get("agent_id") or "?")
        config_name = str(inp.get("config_name") or "?")
        return AIMessage(
            content=(
                f"## Status\ncrashed — summariser internal error\n\n"
                f"## Target\nworker {agent_id} ({config_name}) "
                f"completed without producing a summary."
                + (f" Error: {err}" if err else "")
                + f"\n\n## Inputs tried\n(see "
                f"`logs/run-<id>/worker_traces.jsonl` on disk; "
                f"filter by `.agent_id == \"{agent_id}\"`)"
                f"\n\n## Server responses\n(unavailable)"
                f"\n\n## Inferred server-side behaviour\n(unavailable)"
                f"\n\n## NOT tried\n(unavailable)"
                f"\n\n## Recommended next dispatch\nRe-dispatch a different "
                f"skill — this worker's output could not be summarised."
            ),
            additional_kwargs={
                "agent_id": agent_id,
                "kind": "worker_report",
                "config_name": config_name,
                "status": "summariser_error",
                "iteration_count": int(inp.get("iteration_count") or 0),
                "findings_count": int(inp.get("findings_count") or 0),
            },
        )


def _pick_recon_report_body(
    pending: list[dict],
    reports: list[Any],
) -> str | None:
    """Return the report body for the recon worker in ``pending``, if any.

    Walks the paired (pending, reports) lists looking for the entry whose
    ``config_name`` is ``"recon"``. Returns the matching report's
    ``content`` as a string, or ``None`` when no recon entry exists or
    the matched report did not produce text (e.g. a digest exception
    that even the placeholder couldn't catch).

    The pairing is by index — ``asyncio.gather`` preserves input order,
    so ``reports[i]`` is the digest for ``pending[i]``.
    """
    for inp, rep in zip(pending, reports):
        if str(inp.get("config_name") or "").lower() != "recon":
            continue
        if not isinstance(rep, AIMessage):
            continue
        body = rep.content if isinstance(rep.content, str) else str(rep.content or "")
        body = body.strip()
        if body:
            return body
    return None


def _render_findings(findings: list[Finding]) -> str:
    """Render Finding dataclasses as a verbatim markdown block.

    Used by :func:`_attach_findings_section` to build the planner-facing
    ``## Findings (verbatim from worker)`` section. Format is plain
    markdown — title + severity on the lead line, URL / category on
    line 2, full evidence on line 3. Evidence is NOT truncated here
    (the regex parser in skill_runner already caps it at 500 chars)
    so the planner sees what the worker actually wrote.
    """
    lines: list[str] = []
    for i, f in enumerate(findings, 1):
        sev = getattr(f.severity, "name", str(f.severity))
        lines.append(f"{i}. [{sev}] {f.title}")
        meta_bits = []
        if f.category:
            meta_bits.append(f"category={f.category}")
        if f.url:
            meta_bits.append(f"url={f.url}")
        if meta_bits:
            lines.append(f"   {'  '.join(meta_bits)}")
        if f.evidence:
            lines.append(f"   evidence: {f.evidence}")
    return "\n".join(lines)


def _attach_findings_section(report: AIMessage, findings: list[Finding]) -> AIMessage:
    """Return a new ``AIMessage`` with the verbatim findings block
    appended to the digest content. Preserves ``additional_kwargs`` so
    downstream code that reads ``kind="worker_report"`` / ``agent_id``
    keeps working.
    """
    body = report.content if isinstance(report.content, str) else str(report.content or "")
    appended = body.rstrip() + "\n\n## Findings (verbatim from worker)\n" + _render_findings(findings)
    return AIMessage(
        content=appended,
        additional_kwargs=dict(report.additional_kwargs or {}),
    )


summarizer_node = SummarizerNode()
