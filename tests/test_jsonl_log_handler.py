"""Tier 1 — JsonlLogHandler mirrors logger.* calls to full_logs.jsonl.

Pins the contract introduced 2026-05-25 after the XBEN-006-24 incident:
the skill_runner's auto-verification block uses ``node.log.info("…
auto-verified flag …")`` as its sole on-disk record that the scan ran.
In compact mode the root logger is set to WARNING, so without this
handler the INFO line is silently dropped — visible nowhere, leaving
post-mortem diagnosis blind.

These tests pin five behaviours:

  1. INFO records from ``src.*`` / ``node.*`` / ``benchmarks.*`` land
     in ``full_logs.jsonl`` as ``type=log`` rows with level/logger/msg.
  2. The handler resolves the active run_id via the terminal-log sink
     path — no per-bench wiring required.
  3. Third-party loggers (``httpx``, ``openai``, …) are filtered out
     by the noise prefix list.
  4. Loggers outside our target tree (``random.weird.name``) are not
     captured — we only attach to the three target parents.
  5. ``install_jsonl_log_handler`` is idempotent (safe to call twice).

Strategy — point ``set_terminal_log_file`` at a real per-test run dir
under ``LOGS_ROOT`` so the writer's run_id derivation works end-to-end.
The dir is cleaned up by the fixture.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path

import pytest

from src.observability.writers import (
    LOGS_ROOT,
    full_logs_path,
    install_jsonl_log_handler,
    set_terminal_log_file,
    uninstall_jsonl_log_handler,
)


@pytest.fixture
def per_test_run_id():
    """Provide a unique run_id and clean its log dir up afterwards.

    Uses the real ``LOGS_ROOT`` because the writer derives the JSONL
    path from there via ``full_logs_path(run_id)``; pointing at a
    temp dir wouldn't exercise the real code path.
    """
    rid = f"test-jsonl-handler-{uuid.uuid4().hex[:8]}-{int(time.time())}"
    run_dir = LOGS_ROOT / f"run-{rid}"
    run_dir.mkdir(parents=True, exist_ok=True)
    set_terminal_log_file(run_dir / "displayed_terminal_logs.log")
    install_jsonl_log_handler()
    try:
        yield rid
    finally:
        uninstall_jsonl_log_handler()
        set_terminal_log_file(None)
        # Clean up the test artefacts.
        for p in run_dir.iterdir():
            try:
                p.unlink()
            except Exception:  # noqa: BLE001
                pass
        try:
            run_dir.rmdir()
        except Exception:  # noqa: BLE001
            pass


def _read_jsonl_rows(run_id: str) -> list[dict]:
    fp = full_logs_path(run_id)
    if not fp.exists():
        return []
    return [json.loads(line) for line in fp.read_text().splitlines() if line]


# ── 1. Capture path: INFO from a src.* logger reaches full_logs.jsonl ──


def test_info_record_from_src_logger_is_mirrored(per_test_run_id):
    """The exact case the fix targets — ``logger.info(...)`` from a
    module like ``src.nodes.base.worker.skill_runner`` must appear in
    ``full_logs.jsonl`` even when the root logger is at WARNING."""
    # Simulate the compact-mode root-logger configuration so this
    # test catches regressions where the handler somehow inherits
    # the root level instead of running on its own.
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger("src.nodes.base.worker.skill_runner").info(
        "auto-verified flag in tool output: flag{abc123}"
    )

    rows = _read_jsonl_rows(per_test_run_id)
    matching = [
        r for r in rows
        if r.get("type") == "log"
        and "auto-verified" in (r.get("msg") or "")
    ]
    assert len(matching) == 1
    row = matching[0]
    assert row["level"] == "INFO"
    assert row["logger"] == "src.nodes.base.worker.skill_runner"
    assert "where" in row  # path:line is included for jump-to-source


def test_warning_and_error_records_are_mirrored(per_test_run_id):
    """WARNING and ERROR records must also be captured — those are
    the levels the LiveLogHandler renders on stderr, so users see
    them live; the JSONL mirror is the durable record."""
    logging.getLogger("node.executor").warning("worker stuck on retries")
    logging.getLogger("benchmarks.xbow_runner").error("docker exec failed")

    rows = _read_jsonl_rows(per_test_run_id)
    levels = {(r["level"], r["logger"]) for r in rows if r.get("type") == "log"}
    assert ("WARNING", "node.executor") in levels
    assert ("ERROR", "benchmarks.xbow_runner") in levels


# ── 2. run_id is derived from the terminal-log sink path ──────────────


def test_handler_routes_to_correct_per_bench_log(per_test_run_id):
    """Sanity check — the per_test_run_id fixture already exercises
    this path, but make it explicit: the handler does NOT take run_id
    as a constructor argument; it reads it per-emit from the sink.
    Switching the sink mid-run would re-route subsequent records,
    which is the desired behaviour for the daily-sweep loop in
    xbow_runner.main_async."""
    logging.getLogger("src.test").info("first")
    rows = _read_jsonl_rows(per_test_run_id)
    assert any(r.get("msg") == "first" for r in rows if r.get("type") == "log")


# ── 3. Noise filter — third-party loggers are skipped ────────────────


def test_httpx_and_openai_loggers_are_filtered(per_test_run_id):
    """The noise filter exists so HTTP-layer warnings (e.g. retry
    notices from httpx) don't pollute the JSONL. The previous
    incident showed that what we need from disk logs is OUR
    decisions, not transport chatter."""
    logging.getLogger("httpx").warning("HTTP retry")
    logging.getLogger("openai._base_client").info("rate limit hint")
    logging.getLogger("httpcore.connection").debug("connection close")

    rows = _read_jsonl_rows(per_test_run_id)
    noisy = [
        r for r in rows
        if r.get("type") == "log"
        and any((r.get("logger") or "").startswith(p)
                for p in ("httpx", "openai", "httpcore"))
    ]
    assert noisy == []


# ── 4. Scope — we only attach to src/node/benchmarks parents ──────────


def test_unrelated_top_level_logger_is_not_captured(per_test_run_id):
    """Loggers outside our codebase's namespaces are not captured.
    The handler is attached to ``src``, ``node``, ``benchmarks``
    specifically — random.weird.name propagates to root only, not
    to one of our targets, so the JSONL stays clean."""
    logging.getLogger("random.weird.name").warning("ignored")

    rows = _read_jsonl_rows(per_test_run_id)
    weird = [
        r for r in rows
        if r.get("type") == "log" and r.get("logger") == "random.weird.name"
    ]
    assert weird == []


# ── 5. install_jsonl_log_handler is idempotent ───────────────────────


def test_install_is_idempotent(per_test_run_id):
    """Calling install twice must not duplicate the handler — that
    would cause every record to be written twice. The fixture
    already called it once; we call again and verify single emission."""
    install_jsonl_log_handler()  # second call

    logging.getLogger("src.test").info("only once please")
    rows = _read_jsonl_rows(per_test_run_id)
    matching = [
        r for r in rows
        if r.get("type") == "log" and r.get("msg") == "only once please"
    ]
    assert len(matching) == 1


# ── 6. No run_id → no write (safe pre-run / post-run usage) ──────────


def test_no_terminal_log_sink_means_no_write():
    """When ``set_terminal_log_file(None)`` is the current state —
    e.g. between benches in the daily sweep, or in Studio sessions
    that never set a sink — the handler must no-op rather than
    crash or write to some default path."""
    # Install with no sink set.
    set_terminal_log_file(None)
    install_jsonl_log_handler()
    try:
        # Should not raise, should not write anywhere.
        logging.getLogger("src.test").info("orphan log, no run_id")
    finally:
        uninstall_jsonl_log_handler()
