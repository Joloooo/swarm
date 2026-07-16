"""Durable working-state checkpoints for long real-target engagements.

The polished report node remains terminal. During a long live campaign the
summarizer calls :func:`write_live_checkpoint` after every worker barrier so a
process crash does not erase confirmed findings or the swarm's compressed
working memory.  Benchmark runs never call this writer.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
from enum import Enum
from pathlib import Path
from typing import Any

from src.observability.writers import artifact_path


def _plain(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return _plain(dataclasses.asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "model_dump"):
        try:
            return _plain(value.model_dump())
        except Exception:  # noqa: BLE001
            pass
    return str(value)


def _message_record(message: Any) -> dict[str, Any]:
    return {
        "type": type(message).__name__,
        "content": _plain(getattr(message, "content", str(message))),
        "metadata": _plain(getattr(message, "additional_kwargs", {}) or {}),
    }


def _atomic_write(path: Path, content: str) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(content, encoding="utf-8")
    os.replace(temp, path)


def _finding_lines(findings: list[Any]) -> list[str]:
    if not findings:
        return [
            "No vulnerabilities have been confirmed at this checkpoint. "
            "This is an interim status, not a clean bill of health.",
        ]
    lines: list[str] = []
    for index, finding in enumerate(findings, 1):
        item = _plain(finding)
        severity = str(item.get("severity") or "info").upper()
        lines.extend(
            [
                f"### {index}. [{severity}] {item.get('title') or 'Untitled finding'}",
                "",
                f"- Category: {item.get('category') or 'unspecified'}",
                f"- URL: {item.get('url') or 'not recorded'}",
                f"- Found by: {item.get('agent_id') or 'unknown'}",
                f"- Reproduced: {'yes' if item.get('reproduced') else 'not confirmed'}",
                "",
                str(item.get("description") or "").strip(),
                "",
            ]
        )
        evidence = str(item.get("evidence") or "").strip()
        if evidence:
            lines.extend(["```text", evidence[:4000].replace("```", "'''"), "```", ""])
    return lines


def write_live_checkpoint(
    state: dict,
    update: dict,
    worker_reports: list[Any],
) -> int:
    """Write an accumulated JSON snapshot and readable Markdown checkpoint.

    Returns the new checkpoint sequence number. Any filesystem error is left
    for the caller to log and ignore; checkpointing must never stop testing.
    """
    run_id = str(state.get("run_id") or "").strip()
    if not run_id:
        return int(state.get("checkpoint_seq") or 0)

    cycle = int(state.get("checkpoint_seq") or 0) + 1
    now = dt.datetime.now(dt.timezone.utc)
    started = float(state.get("engagement_started_at") or 0.0)
    deadline = float(state.get("engagement_deadline_at") or 0.0)
    now_epoch = now.timestamp()
    findings = list(state.get("findings") or [])
    canonical = list(
        update.get("canonical_findings")
        or state.get("canonical_findings")
        or findings
    )

    prior_worker_reports = [
        message
        for message in list(state.get("messages") or [])
        if (getattr(message, "additional_kwargs", {}) or {}).get("kind")
        == "worker_report"
    ]
    all_worker_reports = prior_worker_reports + list(worker_reports)

    snapshot = {
        "checkpoint_sequence": cycle,
        "saved_at": now.isoformat(),
        "run_id": run_id,
        "target_url": state.get("target_url") or "",
        "target_scope": state.get("target_scope") or "",
        "traffic_profile": state.get("traffic_profile") or "",
        "engagement_started_at": started,
        "engagement_deadline_at": deadline,
        "elapsed_seconds": max(0.0, now_epoch - started) if started else 0.0,
        "remaining_seconds": max(0.0, deadline - now_epoch) if deadline else 0.0,
        "planner_iterations": int(state.get("planner_iters") or 0),
        "findings": _plain(findings),
        "canonical_findings": _plain(canonical),
        "agent_results": _plain(list(state.get("agent_results") or [])),
        "recon_summary": update.get("recon_summary") or state.get("recon_summary") or "",
        "relevant_summary": _plain(state.get("relevant_summary") or {}),
        "exhausted_ledger": _plain(
            update.get("exhausted_ledger") or state.get("exhausted_ledger") or {}
        ),
        "hypotheses": _plain(update.get("hypotheses") or state.get("hypotheses") or []),
        "worker_reports": [_message_record(message) for message in all_worker_reports],
    }

    _atomic_write(
        artifact_path(run_id, "live-checkpoint.json"),
        json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n",
    )

    elapsed_minutes = snapshot["elapsed_seconds"] / 60
    remaining_minutes = snapshot["remaining_seconds"] / 60
    markdown = [
        "# SwarmAttacker Live Checkpoint",
        "",
        "> Interim crash-recovery artifact. The client report is updated when "
        "the session ends, is paused, or reaches a configured report interval.",
        "",
        f"- Run: `{run_id}`",
        f"- Saved: {now.astimezone().isoformat(timespec='seconds')}",
        f"- Target: {state.get('target_url') or 'not resolved'}",
        f"- Elapsed: {elapsed_minutes:.1f} minutes",
        f"- Remaining campaign budget: {remaining_minutes:.1f} minutes",
        f"- Summary cycles completed: {cycle}",
        f"- Confirmed findings recorded: {len(findings)}",
        "",
        "## Accumulated findings",
        "",
        *_finding_lines(findings),
        "## Working summary",
        "",
        "```json",
        json.dumps(_plain(state.get("relevant_summary") or {}), indent=2, ensure_ascii=False),
        "```",
        "",
        "## Latest worker summaries",
        "",
    ]
    for message in worker_reports:
        metadata = getattr(message, "additional_kwargs", {}) or {}
        markdown.extend(
            [
                f"### {metadata.get('agent_id') or 'worker'} "
                f"({metadata.get('config_name') or 'unknown skill'})",
                "",
                str(getattr(message, "content", "") or "").strip(),
                "",
            ]
        )
    _atomic_write(
        artifact_path(run_id, "live-checkpoint.md"),
        "\n".join(markdown).rstrip() + "\n",
    )

    history = artifact_path(run_id, "checkpoint-history.jsonl")
    event = {
        "saved_at": now.isoformat(),
        "sequence": cycle,
        "findings": len(findings),
        "canonical_findings": len(canonical),
        "worker_reports": len(worker_reports),
        "planner_iterations": int(state.get("planner_iters") or 0),
    }
    with history.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")
    return cycle


__all__ = ["write_live_checkpoint"]
