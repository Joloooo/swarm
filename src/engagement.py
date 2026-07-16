"""Durable lifecycle state for real-target engagements.

The JSONL event log is the audit trail.  This module owns two small mutable
files beside it:

* ``engagement.json`` -- operator-facing identity, timing, and status.
* ``resume state.json`` -- the latest safe, typed graph-state snapshot.

Snapshots are written atomically after completed graph supersteps.  They do
not attempt to resume an in-flight tool call; continuation restarts at the
planner from the last completed barrier, which is predictable and keeps the
format transparent instead of requiring a database checkpointer.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    message_to_dict,
    messages_from_dict,
)

from src.observability.writers import (
    artifact_path,
    make_run_id,
    register_run_dir,
)
from src.state import AgentResult, Finding, Hypothesis, Severity, Signal


RESUME_VERSION = 1
MANIFEST_VERSION = 1


@dataclasses.dataclass
class ExistingEngagement:
    """A selected engagement restored and registered in the current process."""

    directory: Path
    run_id: str
    artifact_prefix: str
    manifest: dict[str, Any]
    state: dict[str, Any]
    source_directory: Path | None = None

_RESUME_FIELDS = (
    "run_id",
    "target_url",
    "target_scope",
    "traffic_profile",
    "output_dir",
    "artifact_prefix",
    "report_stem",
    "messages",
    "findings",
    "agent_results",
    "canonical_findings",
    "exhausted_ledger",
    "waf_detected",
    "stealth_level",
    "mode",
    "crawl_mode",
    "planner_iters",
    "fallback_configs",
    "recon_done",
    "forced_recoveries",
    "checkpoint_seq",
    "recon_summary",
    "relevant_summary",
    "suggested_next_moves",
    "skill_handoffs",
    "routed_skill_handoffs",
    "tool_attempts",
    "signals",
    "hypotheses",
    "investigation_threads",
    "report_markdown_path",
    "report_pdf_path",
    "report_pdf_error",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _plain(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return _plain(dataclasses.asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _serialize_state(state: dict[str, Any]) -> dict[str, Any]:
    serialized: dict[str, Any] = {}
    for key in _RESUME_FIELDS:
        if key not in state:
            continue
        value = state.get(key)
        if key == "messages":
            serialized[key] = [message_to_dict(item) for item in list(value or [])]
        else:
            serialized[key] = _plain(value)
    return serialized


def _dataclass_from_dict(cls: type, value: Any) -> Any:
    if isinstance(value, cls):
        return value
    if not isinstance(value, dict):
        return value
    allowed = {item.name for item in dataclasses.fields(cls)}
    return cls(**{key: item for key, item in value.items() if key in allowed})


def _finding(value: Any) -> Finding:
    if isinstance(value, Finding):
        return value
    data = dict(value or {})
    severity_value = str(data.get("severity") or Severity.INFO.value).lower()
    try:
        data["severity"] = Severity(severity_value)
    except ValueError:
        data["severity"] = Severity.INFO
    return _dataclass_from_dict(Finding, data)


def _agent_result(value: Any) -> AgentResult:
    if isinstance(value, AgentResult):
        return value
    data = dict(value or {})
    data["findings"] = [_finding(item) for item in list(data.get("findings") or [])]
    return _dataclass_from_dict(AgentResult, data)


def _restore_state(serialized: dict[str, Any]) -> dict[str, Any]:
    state = dict(serialized or {})
    message_dicts = list(state.get("messages") or [])
    if message_dicts:
        try:
            state["messages"] = messages_from_dict(message_dicts)
        except Exception:  # noqa: BLE001 - preserve recovery via plain messages
            state["messages"] = [
                HumanMessage(content=str(item)) for item in message_dicts
            ]
    else:
        state["messages"] = []
    # A terminal report is a generated artifact, not investigation memory.
    # Keeping its full Markdown in the resumed planner history wastes tens of
    # thousands of prompt characters and can make the planner reason about its
    # own old deliverable. Preserve the original instruction, planner choices,
    # and compact worker reports; drop report output/boundary messages.
    state["messages"] = [
        message
        for message in state["messages"]
        if not (
            str(getattr(message, "content", "") or "").lstrip().startswith(
                "# SwarmAttacker Penetration Test Report"
            )
            or (getattr(message, "additional_kwargs", {}) or {}).get("node")
            == "report"
        )
    ]
    state["findings"] = [_finding(item) for item in list(state.get("findings") or [])]
    state["canonical_findings"] = [
        _finding(item) for item in list(state.get("canonical_findings") or [])
    ]
    state["agent_results"] = [
        _agent_result(item) for item in list(state.get("agent_results") or [])
    ]
    state["signals"] = [
        _dataclass_from_dict(Signal, item)
        for item in list(state.get("signals") or [])
    ]
    state["hypotheses"] = [
        _dataclass_from_dict(Hypothesis, item)
        for item in list(state.get("hypotheses") or [])
    ]

    # A resumed invocation always re-enters at START -> planner. Never carry
    # transient fan-out or a prior terminal decision into that fresh graph.
    state["active_agents"] = []
    state["pending_dispatch"] = []
    state["pending_summary_inputs"] = []
    state["next_action"] = ""
    state["budget_exhausted"] = False
    state["captured_flag"] = None
    return state


def create_manifest(
    *,
    run_id: str,
    directory: Path,
    artifact_prefix: str,
    target_name: str,
    instruction: str,
    target_scope: str,
    session_budget_seconds: int,
    report_interval_seconds: int,
) -> dict[str, Any]:
    now = _now_iso()
    return {
        "version": MANIFEST_VERSION,
        "run_id": run_id,
        "artifact_prefix": artifact_prefix,
        "directory": str(Path(directory).resolve()),
        "target_name": target_name,
        "target_url": "",
        "target_scope": target_scope,
        "instruction": instruction,
        "created_at": now,
        "updated_at": now,
        "status": "running",
        "allocated_seconds_total": int(session_budget_seconds),
        "active_seconds_total": 0.0,
        "current_session_budget_seconds": int(session_budget_seconds),
        "report_interval_seconds": int(report_interval_seconds),
        "checkpoint_sequence": 0,
        "last_error": "",
    }


def manifest_path(run_id: str) -> Path:
    return artifact_path(run_id, "engagement.json")


def resume_state_path(run_id: str) -> Path:
    return artifact_path(run_id, "resume-state.json")


def write_manifest(run_id: str, manifest: dict[str, Any]) -> Path:
    manifest = dict(manifest)
    manifest["updated_at"] = _now_iso()
    path = manifest_path(run_id)
    _atomic_json(path, manifest)
    return path


def update_manifest(run_id: str, manifest: dict[str, Any], **changes: Any) -> dict[str, Any]:
    updated = dict(manifest)
    updated.update(changes)
    write_manifest(run_id, updated)
    return updated


def write_resume_state(run_id: str, state: dict[str, Any]) -> Path | None:
    """Atomically save a safe state snapshot; skip in-flight worker fan-in."""
    if state.get("pending_summary_inputs"):
        return None
    payload = {
        "version": RESUME_VERSION,
        "saved_at": _now_iso(),
        "state": _serialize_state(state),
    }
    path = resume_state_path(run_id)
    _atomic_json(path, payload)
    return path


def _find_file(directory: Path, exact: str, glob_pattern: str) -> Path | None:
    direct = directory / exact
    if direct.is_file():
        return direct
    matches = sorted(directory.glob(glob_pattern))
    return matches[0] if matches else None


def _find_files_recursive(
    directory: Path,
    exact: str,
    glob_pattern: str,
) -> list[Path]:
    """Find legacy artifacts below a selected engagement folder.

    Older live runs placed reports in a parent folder and checkpoints in a
    nested ``run-*`` directory.  Report regeneration is allowed to recover
    from that layout, while normal continuation deliberately remains rooted
    in the exact selected directory.
    """
    folder = Path(directory).expanduser().resolve()
    found: dict[Path, None] = {}
    direct = _find_file(folder, exact, glob_pattern)
    if direct is not None:
        found[direct] = None
    try:
        for path in folder.rglob(exact):
            if path.is_file():
                found[path] = None
        for path in folder.rglob(glob_pattern):
            if path.is_file():
                found[path] = None
    except OSError:
        pass
    return sorted(
        found,
        key=lambda path: path.stat().st_mtime if path.exists() else 0.0,
        reverse=True,
    )


def load_manifest(directory: Path) -> dict[str, Any] | None:
    folder = Path(directory).expanduser().resolve()
    path = _find_file(folder, "engagement.json", "* engagement.json")
    if path is None:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _legacy_checkpoint_state(directory: Path) -> tuple[dict[str, Any], Path] | None:
    checkpoint = _find_file(
        directory, "live-checkpoint.json", "* live checkpoint.json"
    )
    if checkpoint is None:
        return None
    snapshot = json.loads(checkpoint.read_text(encoding="utf-8"))
    state = {
        key: snapshot.get(key)
        for key in _RESUME_FIELDS
        if key in snapshot
    }
    worker_reports = list(snapshot.get("worker_reports") or [])
    state["messages"] = [
        AIMessage(
            content=str(item.get("content") or ""),
            additional_kwargs=dict(item.get("metadata") or {}),
        )
        for item in worker_reports
        if isinstance(item, dict) and item.get("content")
    ]
    return _restore_state(state), checkpoint


def load_resume_state(directory: Path) -> tuple[dict[str, Any], Path]:
    folder = Path(directory).expanduser().resolve()
    path = _find_file(folder, "resume-state.json", "* resume state.json")
    if path is not None:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return _restore_state(dict(payload.get("state") or {})), path
    legacy = _legacy_checkpoint_state(folder)
    if legacy is not None:
        return legacy
    raise FileNotFoundError(
        "No resume state or live checkpoint was found in the selected folder."
    )


def _state_from_professional_markdown(path: Path) -> dict[str, Any] | None:
    """Recover structured findings from a generated Markdown companion."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("# SwarmAttacker Penetration Test Report"):
        return None

    def table_value(field: str, source: str = text) -> str:
        match = re.search(
            rf"^\|\s*{re.escape(field)}\s*\|\s*(.*?)\s*\|\s*$",
            source,
            flags=re.I | re.M,
        )
        return match.group(1).strip() if match else ""

    headings = list(re.finditer(r"^## F-\d+\s+[^\w\n]*\s*(.+)$", text, re.M))
    findings: list[Finding] = []
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        block = text[heading.end():end]
        severity_text = table_value("Severity", block).split(" ", 1)[0].lower()
        try:
            severity = Severity(severity_text)
        except ValueError:
            severity = Severity.INFO
        validation = table_value("Validation status", block).lower()

        def section(name: str) -> str:
            match = re.search(
                rf"^###\s+{re.escape(name)}\s*$\n+(.*?)(?=^###\s|^##\s|^#\s|\Z)",
                block,
                flags=re.I | re.M | re.S,
            )
            return match.group(1).strip() if match else ""

        description = section("Technical description and root cause")
        description = re.sub(r"\n*\*\*Root cause:\*\*.*$", "", description, flags=re.S).strip()
        if validation == "unverified":
            description = f"Unverified. {description}".strip()
        evidence = section("Raw evidence")
        evidence = re.sub(r"^```(?:text)?\s*|\s*```$", "", evidence, flags=re.I | re.S).strip()
        findings.append(Finding(
            title=heading.group(1).strip(),
            severity=severity,
            category=table_value("Category", block) or "unspecified",
            description=description,
            evidence=evidence,
            agent_id="report-import",
            url="" if table_value("Affected target", block).lower() == "not recorded" else table_value("Affected target", block),
            cwe="" if table_value("CWE", block).lower() == "not mapped" else table_value("CWE", block),
            reproduced=validation == "confirmed",
            status=validation if validation in {"confirmed", "demonstrated"} else "",
        ))
    return _restore_state({
        "target_url": table_value("Target"),
        "target_scope": table_value("Authorized scope"),
        "traffic_profile": table_value("Traffic profile"),
        "findings": findings,
        "canonical_findings": findings,
        "messages": [],
    })


def _state_from_checkpoint_markdown(path: Path) -> dict[str, Any] | None:
    """Recover the basic finding feed when only the readable checkpoint remains."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("# SwarmAttacker Live Checkpoint"):
        return None
    headings = list(re.finditer(r"^###\s+\d+\.\s+\[([^]]+)]\s+(.+)$", text, re.M))
    findings: list[Finding] = []
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        block = text[heading.end():end]

        def bullet(name: str) -> str:
            match = re.search(rf"^-\s+{re.escape(name)}:\s*(.*)$", block, re.I | re.M)
            return match.group(1).strip() if match else ""

        try:
            severity = Severity(heading.group(1).strip().lower())
        except ValueError:
            severity = Severity.INFO
        before_evidence = block.split("```text", 1)[0]
        description_lines = [
            line.strip() for line in before_evidence.splitlines()
            if line.strip() and not line.lstrip().startswith("-")
        ]
        evidence_match = re.search(r"```text\s*(.*?)```", block, re.S | re.I)
        reproduced_text = bullet("Reproduced").lower()
        findings.append(Finding(
            title=heading.group(2).strip(),
            severity=severity,
            category=bullet("Category") or "unspecified",
            description=" ".join(description_lines),
            evidence=evidence_match.group(1).strip() if evidence_match else "",
            agent_id=bullet("Found by") or "checkpoint-import",
            url="" if bullet("URL").lower() == "not recorded" else bullet("URL"),
            reproduced=reproduced_text == "yes",
            status="confirmed" if reproduced_text == "yes" else "demonstrated",
        ))
    target_match = re.search(r"^-\s+Target:\s*(.*)$", text, re.I | re.M)
    return _restore_state({
        "target_url": target_match.group(1).strip() if target_match else "",
        "findings": findings,
        "canonical_findings": findings,
        "messages": [],
    })


def load_report_state(directory: Path) -> tuple[dict[str, Any], Path]:
    """Load enough durable evidence to regenerate a report.

    Unlike :func:`load_resume_state`, this searches legacy nested run folders
    and may reconstruct a report-only state from Markdown.  It is intentionally
    not used by the continuation path because Markdown does not contain exact
    planner execution state.
    """
    folder = Path(directory).expanduser().resolve()
    if not folder.is_dir():
        raise NotADirectoryError(f"Engagement folder does not exist: {folder}")

    candidates: list[tuple[Path, str]] = []
    for path in _find_files_recursive(folder, "resume-state.json", "* resume state.json"):
        candidates.append((path, "resume"))
    for path in _find_files_recursive(folder, "live-checkpoint.json", "* live checkpoint.json"):
        candidates.append((path, "checkpoint"))
    candidates.sort(key=lambda item: item[0].stat().st_mtime, reverse=True)
    for path, kind in candidates:
        try:
            if kind == "resume":
                payload = json.loads(path.read_text(encoding="utf-8"))
                return _restore_state(dict(payload.get("state") or {})), path
            checkpoint = _legacy_checkpoint_state(path.parent)
            if checkpoint is not None:
                return checkpoint
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue

    markdown_candidates = [
        path for path in folder.rglob("*.md")
        if path.is_file() and path.name not in {"engagement.json", "resume-state.json"}
    ]
    markdown_candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    for path in markdown_candidates:
        try:
            state = _state_from_professional_markdown(path)
            if state is None:
                state = _state_from_checkpoint_markdown(path)
            if state is not None:
                return state, path
        except OSError:
            continue
    raise FileNotFoundError(
        "No report evidence was found. Select a folder containing a resume "
        "snapshot, live checkpoint, or SwarmAttacker Markdown report (nested legacy run folders are supported)."
    )


def _infer_artifact_prefix(directory: Path, state: dict[str, Any]) -> str:
    configured = str(state.get("artifact_prefix") or "").strip()
    if configured:
        return configured
    reports = sorted(directory.glob("* pentest report.md"))
    if reports:
        return reports[0].name.removesuffix(" pentest report.md")
    name = re.sub(r"\s+pentest report(?: \(\d+\))?$", "", directory.name).strip()
    return name or "swarmattacker"


def _infer_report_stem(directory: Path) -> str:
    """Preserve an existing client-facing report filename when possible."""
    ignored = {"live-checkpoint", "resume-state", "engagement"}
    markdown = {path.stem: path for path in directory.glob("*.md")}
    pdf = {path.stem: path for path in directory.glob("*.pdf")}
    paired = [stem for stem in markdown.keys() & pdf.keys() if stem.lower() not in ignored]
    if paired:
        return max(paired, key=lambda stem: max(markdown[stem].stat().st_mtime, pdf[stem].stat().st_mtime))
    reports = [path for path in directory.glob("*.md") if path.stem.lower() not in ignored]
    return max(reports, key=lambda path: path.stat().st_mtime).stem if reports else ""


def _infer_target_name(state: dict[str, Any], directory: Path) -> str:
    raw = str(state.get("target_url") or state.get("target_scope") or "").strip()
    if raw:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        if parsed.hostname:
            return parsed.hostname.lower()
    prefix = _infer_artifact_prefix(directory, state)
    # Human prefixes end in "<day> <mon>". Removing that suffix recovers the
    # target label for legacy folders without requiring the planner.
    return re.sub(r"\s+\d{1,2}\s+[a-z]{3}$", "", prefix, flags=re.I) or "target"


def load_existing_engagement(directory: Path) -> ExistingEngagement:
    """Restore one folder and bind all future writes back to that folder.

    Legacy live-checkpoint folders are upgraded in place with a manifest and
    transparent resume snapshot; no new engagement directory is created.
    """
    folder = Path(directory).expanduser().resolve()
    if not folder.is_dir():
        raise NotADirectoryError(f"Engagement folder does not exist: {folder}")
    state, _ = load_resume_state(folder)
    manifest = load_manifest(folder) or {}
    target_name = str(manifest.get("target_name") or "").strip()
    if not target_name:
        target_name = _infer_target_name(state, folder)
    run_id = str(manifest.get("run_id") or state.get("run_id") or "").strip()
    if not run_id:
        run_id = make_run_id(
            target_url=str(state.get("target_url") or f"https://{target_name}")
        )
    artifact_prefix = str(
        manifest.get("artifact_prefix") or _infer_artifact_prefix(folder, state)
    ).strip()
    register_run_dir(run_id, folder, artifact_prefix=artifact_prefix)

    state.update({
        "run_id": run_id,
        "output_dir": str(folder),
        "artifact_prefix": artifact_prefix,
    })
    if not manifest:
        manifest = create_manifest(
            run_id=run_id,
            directory=folder,
            artifact_prefix=artifact_prefix,
            target_name=target_name,
            instruction="",
            target_scope=str(state.get("target_scope") or ""),
            session_budget_seconds=0,
            report_interval_seconds=0,
        )
        manifest["status"] = "paused"
        manifest["target_url"] = str(state.get("target_url") or "")
    else:
        manifest = dict(manifest)
        manifest.update({
            "directory": str(folder),
            "run_id": run_id,
            "artifact_prefix": artifact_prefix,
            "target_name": target_name,
        })
    write_manifest(run_id, manifest)
    # Upgrade a legacy checkpoint immediately so the next resume no longer
    # depends on its lossy worker-report reconstruction.
    write_resume_state(run_id, state)
    return ExistingEngagement(
        directory=folder,
        run_id=run_id,
        artifact_prefix=artifact_prefix,
        manifest=manifest,
        state=state,
        source_directory=folder,
    )


def load_reportable_engagement(directory: Path) -> ExistingEngagement:
    """Restore report evidence and bind regenerated artifacts to the selected folder."""
    folder = Path(directory).expanduser().resolve()
    state, source = load_report_state(folder)
    source_folder = source.parent
    manifest = load_manifest(folder) or load_manifest(source_folder) or {}
    target_name = str(manifest.get("target_name") or "").strip() or _infer_target_name(state, folder)
    run_id = str(manifest.get("run_id") or state.get("run_id") or "").strip()
    if not run_id:
        run_id = make_run_id(target_url=str(state.get("target_url") or f"https://{target_name}"))
    report_stem = str(state.get("report_stem") or _infer_report_stem(folder)).strip()
    artifact_prefix = str(
        manifest.get("artifact_prefix")
        or (re.sub(r"\s+pentest report$", "", report_stem, flags=re.I) if report_stem else "")
        or _infer_artifact_prefix(folder, state)
    ).strip()
    register_run_dir(run_id, folder, artifact_prefix=artifact_prefix)
    state.update({
        "run_id": run_id,
        "output_dir": str(folder),
        "artifact_prefix": artifact_prefix,
        "report_stem": report_stem,
    })
    if not manifest:
        manifest = create_manifest(
            run_id=run_id,
            directory=folder,
            artifact_prefix=artifact_prefix,
            target_name=target_name,
            instruction="",
            target_scope=str(state.get("target_scope") or ""),
            session_budget_seconds=0,
            report_interval_seconds=0,
        )
        manifest["status"] = "paused"
    manifest = dict(manifest)
    manifest.update({
        "directory": str(folder),
        "run_id": run_id,
        "artifact_prefix": artifact_prefix,
        "target_name": target_name,
        "target_url": str(state.get("target_url") or manifest.get("target_url") or ""),
        "report_stem": report_stem,
        "report_source": str(source),
    })
    write_manifest(run_id, manifest)
    # Upgrading the selected parent folder makes all later report regenerations
    # direct. It also enables an exact continuation only when the source itself
    # was a real JSON state/checkpoint rather than reconstructed Markdown.
    if source.suffix.lower() == ".json":
        write_resume_state(run_id, state)
    return ExistingEngagement(
        directory=folder,
        run_id=run_id,
        artifact_prefix=artifact_prefix,
        manifest=manifest,
        state=state,
        source_directory=source_folder,
    )


def discover_engagement_directories(root: Path) -> list[Path]:
    """Return resumable/reportable engagement folders, newest first."""
    folder = Path(root).expanduser().resolve()
    candidates: list[Path] = []
    if folder.is_dir():
        candidates.append(folder)
        try:
            candidates.extend(item for item in folder.iterdir() if item.is_dir())
        except OSError:
            pass

    def has_state(item: Path) -> bool:
        patterns = (
            "engagement.json",
            "* engagement.json",
            "resume-state.json",
            "* resume state.json",
            "live-checkpoint.json",
            "* live checkpoint.json",
        )
        return any(any(item.glob(pattern)) for pattern in patterns)

    found = [item for item in candidates if has_state(item)]
    return sorted(
        set(found),
        key=lambda item: item.stat().st_mtime if item.exists() else 0.0,
        reverse=True,
    )


__all__ = [
    "ExistingEngagement",
    "create_manifest",
    "discover_engagement_directories",
    "load_existing_engagement",
    "load_reportable_engagement",
    "load_manifest",
    "load_report_state",
    "load_resume_state",
    "manifest_path",
    "resume_state_path",
    "update_manifest",
    "write_manifest",
    "write_resume_state",
]
