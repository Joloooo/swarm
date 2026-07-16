"""One-shot natural-language CLI flow.

Invoked when the user passes a positional argument to ``swarm`` /
``swarmattacker``. The argument is free-form user input, not a URL —
the supervisor planner reads it from ``state["messages"]`` on turn 1,
calls ``normalize_url`` / ``validate_website`` as needed, and decides
the first action.

    swarmattacker "test example.com for sqli"
    swarmattacker example.com
    swarmattacker "scan 192.168.1.10 — docker-compose lab"

The previous standalone ``src/cli.py`` ran its own argparse; this
module is now called by ``src.cli.__init__:main``, which parses the
shared argparse for BOTH this one-shot mode AND the new TUI mode.
``run(...)`` itself is unchanged — same graph invocation, same final
print — and is still re-exported from ``src.cli`` so any old import
``from src.cli import run`` keeps working.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path


_REPORT_STATE_FIELDS = (
    "report_markdown",
    "report_markdown_path",
    "report_pdf_path",
    "report_pdf_error",
)


def main(args: argparse.Namespace) -> None:
    """Run the one-shot natural-language flow with pre-parsed args."""
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    asyncio.run(run(
        user_input=args.user_input,
        target_scope=args.scope,
    ))


async def execute_engagement(
    user_input: str,
    target_scope: str = "",
    *,
    session_budget_seconds: int | None = None,
    report_interval_seconds: int = 0,
) -> tuple[str, str, str, str]:
    """Execute one live engagement and return report content/artifact paths.

    Return shape: ``(markdown, markdown_path, pdf_path, pdf_error)``.

    No benchmark fields are seeded here.  In particular, ``expected_flag``
    and its candidates remain empty, which keeps all benchmark-only discovery,
    scoring, and forced-continuation behaviour disabled.
    """
    from langchain_core.messages import HumanMessage

    from src.engagement import create_manifest, write_manifest, write_resume_state
    from src.live_output import create_live_output_layout
    from src.observability.writers import (
        install_jsonl_log_handler,
        make_run_id,
        register_run_dir,
        set_terminal_log_file,
        terminal_log_path,
    )
    from src.traffic import (
        DEFAULT_LIVE_ENGAGEMENT_SECONDS,
        REMOTE_SAFE_PROFILE,
    )

    budget = (
        DEFAULT_LIVE_ENGAGEMENT_SECONDS
        if session_budget_seconds is None
        else int(session_budget_seconds)
    )
    if budget <= 0:
        raise ValueError("session_budget_seconds must be positive")
    report_interval_seconds = max(0, int(report_interval_seconds or 0))

    # Pin the live artifact folder before importing the graph. Every existing
    # event/checkpoint writer resolves paths through run_dir(), so this one
    # registration co-locates the complete run without touching benchmark
    # storage or requiring path plumbing through every node and tool.
    output_layout = create_live_output_layout(user_input, target_scope)
    run_id = make_run_id(target_url=f"https://{output_layout.target_name}")
    output_dir = register_run_dir(
        run_id,
        output_layout.directory,
        artifact_prefix=output_layout.artifact_prefix,
    )
    set_terminal_log_file(terminal_log_path(run_id), run_id=run_id)
    install_jsonl_log_handler()

    initial_messages = [HumanMessage(content=user_input)]
    if target_scope:
        initial_messages.append(
            HumanMessage(
                content=(
                    f"Scope constraint from the user: {target_scope}. "
                    "Honor this when setting target_scope."
                )
            )
        )

    initial_state: dict = {
        "messages": initial_messages,
        "findings": [],
        "agent_results": [],
        "active_agents": [],
        "run_id": run_id,
        "output_dir": str(output_dir),
        "artifact_prefix": output_layout.artifact_prefix,
        "traffic_profile": REMOTE_SAFE_PROFILE,
        "checkpoint_seq": 0,
    }
    if target_scope:
        initial_state["target_scope"] = target_scope
    manifest = create_manifest(
        run_id=run_id,
        directory=output_dir,
        artifact_prefix=output_layout.artifact_prefix,
        target_name=output_layout.target_name,
        instruction=user_input,
        target_scope=target_scope,
        session_budget_seconds=budget,
        report_interval_seconds=report_interval_seconds,
    )
    write_manifest(run_id, manifest)
    write_resume_state(run_id, initial_state)
    try:
        result = await _run_graph_session(
            initial_state,
            manifest,
            session_budget_seconds=budget,
            report_interval_seconds=report_interval_seconds,
            lifecycle_event="engagement_started",
        )
        return _report_tuple(result)
    finally:
        set_terminal_log_file(None)


async def continue_engagement(
    directory: Path,
    additional_seconds: int,
    *,
    report_interval_seconds: int | None = None,
) -> tuple[str, str, str, str]:
    """Continue an existing folder with an additional active-time budget."""
    from langchain_core.messages import HumanMessage

    from src.engagement import load_existing_engagement, update_manifest
    from src.observability.writers import (
        install_jsonl_log_handler,
        set_terminal_log_file,
        terminal_log_path,
    )

    budget = int(additional_seconds)
    if budget <= 0:
        raise ValueError("additional_seconds must be positive")
    existing = load_existing_engagement(directory)
    set_terminal_log_file(
        terminal_log_path(existing.run_id), run_id=existing.run_id
    )
    install_jsonl_log_handler()
    interval = (
        int(existing.manifest.get("report_interval_seconds") or 0)
        if report_interval_seconds is None
        else max(0, int(report_interval_seconds))
    )
    state = dict(existing.state)
    state["messages"] = list(state.get("messages") or []) + [HumanMessage(
        content=(
            "The operator resumed this engagement with "
            f"{_format_duration(budget)} of additional active testing time. "
            "Continue from the preserved findings and investigation state."
        )
    )]
    manifest = update_manifest(
        existing.run_id,
        existing.manifest,
        status="running",
        allocated_seconds_total=int(
            existing.manifest.get("allocated_seconds_total") or 0
        ) + budget,
        current_session_budget_seconds=budget,
        report_interval_seconds=interval,
        last_error="",
    )
    try:
        result = await _run_graph_session(
            state,
            manifest,
            session_budget_seconds=budget,
            report_interval_seconds=interval,
            lifecycle_event="engagement_continued",
        )
        return _report_tuple(result)
    finally:
        set_terminal_log_file(None)


async def regenerate_engagement_report(
    directory: Path,
) -> tuple[str, str, str, str]:
    """Run only the reporting node against one existing engagement folder."""
    from src.engagement import (
        load_reportable_engagement,
        update_manifest,
        write_resume_state,
    )
    from src.observability.writers import (
        install_jsonl_log_handler,
        set_terminal_log_file,
        terminal_log_path,
    )

    existing = load_reportable_engagement(directory)
    set_terminal_log_file(
        terminal_log_path(existing.run_id), run_id=existing.run_id
    )
    install_jsonl_log_handler()
    try:
        state = await _generate_report(existing.state, event="report_regenerated")
        write_resume_state(existing.run_id, state)
        update_manifest(
            existing.run_id,
            existing.manifest,
            status=str(existing.manifest.get("status") or "paused"),
            target_url=str(state.get("target_url") or ""),
            target_scope=str(state.get("target_scope") or ""),
            last_report_at=datetime.now().astimezone().isoformat(),
            last_report_active_seconds=float(
                existing.manifest.get("active_seconds_total") or 0.0
            ),
            last_error=str(state.get("report_pdf_error") or ""),
        )
        return _report_tuple(state)
    finally:
        set_terminal_log_file(None)


def _format_duration(seconds: int | float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    if minutes:
        return f"{minutes}m {secs}s" if secs else f"{minutes}m"
    return f"{secs}s"


async def _generate_report(state: dict, *, event: str) -> dict:
    """Generate artifacts without routing through reconnaissance/planning."""
    # Import graph first to preserve the package's established import order.
    import src.graph  # noqa: F401
    from src.nodes import report_node
    from src.observability.writers import append_event

    update = await report_node.execute(state)
    merged = dict(state)
    for key in _REPORT_STATE_FIELDS:
        if key in update:
            merged[key] = update[key]
    append_event(
        str(state.get("run_id") or ""),
        event,
        findings=len(state.get("canonical_findings") or state.get("findings") or []),
        markdown_path=merged.get("report_markdown_path") or "",
        pdf_path=merged.get("report_pdf_path") or "",
        pdf_error=merged.get("report_pdf_error") or "",
    )
    return merged


async def _run_graph_session(
    initial_state: dict,
    manifest: dict,
    *,
    session_budget_seconds: int,
    report_interval_seconds: int,
    lifecycle_event: str,
) -> dict:
    """Run one active session with barrier snapshots and graceful pausing."""
    from src.engagement import update_manifest, write_resume_state
    from src.graph import GRAPH_RECURSION_LIMIT, graph
    from src.observability.writers import append_event, set_terminal_log_file
    from src.tools.shell import cleanup_shell
    from src.traffic import REMOTE_SAFE_PROFILE, remote_safe_engagement

    run_id = str(initial_state.get("run_id") or "")
    started_epoch = time.time()
    started_monotonic = time.monotonic()
    active_before = float(manifest.get("active_seconds_total") or 0.0)
    deadline = started_epoch + int(session_budget_seconds)
    state = dict(initial_state)
    state.update({
        "traffic_profile": REMOTE_SAFE_PROFILE,
        "engagement_started_at": started_epoch,
        "engagement_deadline_at": deadline,
        "budget_exhausted": False,
        "next_action": "",
        "pending_dispatch": [],
        "pending_summary_inputs": [],
        "active_agents": [],
    })
    write_resume_state(run_id, state)
    manifest = update_manifest(
        run_id,
        manifest,
        status="running",
        session_started_at=datetime.now().astimezone().isoformat(),
        current_session_budget_seconds=int(session_budget_seconds),
        report_interval_seconds=max(0, int(report_interval_seconds)),
        last_error="",
    )
    append_event(
        run_id,
        lifecycle_event,
        session_budget_seconds=int(session_budget_seconds),
        active_seconds_before=active_before,
    )

    pause_requested = asyncio.Event()
    force = {"requested": False}
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    previous_sigint = signal.getsignal(signal.SIGINT)
    signal_installed = False

    def request_pause() -> None:
        if not pause_requested.is_set():
            pause_requested.set()
            sys.stderr.write(
                "\nPause requested. Finishing the current safe graph barrier, saving "
                "state, and updating the report. Press Ctrl-C again to force exit.\n"
            )
            sys.stderr.flush()
            append_event(run_id, "pause_requested")
            return
        force["requested"] = True
        sys.stderr.write("\nForce exit requested; preserving the last checkpoint.\n")
        sys.stderr.flush()
        if task is not None:
            task.cancel()

    try:
        loop.add_signal_handler(signal.SIGINT, request_pause)
        signal_installed = True
    except (NotImplementedError, RuntimeError, ValueError):
        # Unix/macOS TUI gets graceful signals. Other event loops retain their
        # normal KeyboardInterrupt behavior and still have atomic snapshots.
        signal_installed = False

    live_recursion_limit = max(
        GRAPH_RECURSION_LIMIT,
        (int(session_budget_seconds) // 30) * 4 + 10,
    )
    last_state = state
    report_fields = {
        key: state.get(key)
        for key in _REPORT_STATE_FIELDS
        if state.get(key)
    }
    last_report_active = float(
        manifest.get("last_report_active_seconds") or active_before
    )
    graph_report_seen = False
    stream = None
    frozen_active: float | None = None

    def active_total() -> float:
        if frozen_active is not None:
            return frozen_active
        return active_before + max(0.0, time.monotonic() - started_monotonic)

    async def persist(current: dict, *, status: str = "running") -> None:
        nonlocal manifest
        current.update(report_fields)
        write_resume_state(run_id, current)
        manifest = update_manifest(
            run_id,
            manifest,
            status=status,
            active_seconds_total=active_total(),
            checkpoint_sequence=int(current.get("checkpoint_seq") or 0),
            target_url=str(current.get("target_url") or ""),
            target_scope=str(current.get("target_scope") or ""),
        )

    try:
        with remote_safe_engagement():
            stream = graph.astream(
                state,
                config={"recursion_limit": live_recursion_limit},
                stream_mode="values",
            )
            async for value in stream:
                graph_report_seen = bool(value.get("report_markdown"))
                last_state = dict(value)
                last_state.update(report_fields)
                await persist(last_state)
                safe_barrier = not bool(last_state.get("pending_summary_inputs"))
                if pause_requested.is_set() and safe_barrier:
                    break
                if (
                    safe_barrier
                    and report_interval_seconds > 0
                    and active_total() - last_report_active
                    >= report_interval_seconds
                ):
                    last_state = await _generate_report(
                        last_state, event="periodic_report_updated"
                    )
                    report_fields.update({
                        key: last_state.get(key)
                        for key in _REPORT_STATE_FIELDS
                        if last_state.get(key)
                    })
                    last_report_active = active_total()
                    manifest = update_manifest(
                        run_id,
                        manifest,
                        last_report_active_seconds=last_report_active,
                        last_report_at=datetime.now().astimezone().isoformat(),
                    )
                    await persist(last_state)

        frozen_active = active_total()
        paused = pause_requested.is_set()
        if paused or not graph_report_seen:
            last_state = await _generate_report(
                last_state,
                event="paused_report_generated" if paused else "final_report_generated",
            )
            report_fields.update({
                key: last_state.get(key)
                for key in _REPORT_STATE_FIELDS
                if last_state.get(key)
            })
        final_status = "paused" if paused else "completed"
        await persist(last_state, status=final_status)
        manifest = update_manifest(
            run_id,
            manifest,
            status=final_status,
            session_finished_at=datetime.now().astimezone().isoformat(),
            last_report_at=datetime.now().astimezone().isoformat(),
            last_report_active_seconds=active_total(),
            last_error=str(last_state.get("report_pdf_error") or ""),
        )
        append_event(
            run_id,
            "engagement_paused" if paused else "engagement_completed",
            active_seconds_total=manifest.get("active_seconds_total"),
            markdown_path=last_state.get("report_markdown_path") or "",
            pdf_path=last_state.get("report_pdf_path") or "",
        )
        return last_state
    except asyncio.CancelledError:
        if not force["requested"]:
            raise
        frozen_active = active_total()
        await persist(last_state, status="interrupted")
        update_manifest(
            run_id,
            manifest,
            status="interrupted",
            session_finished_at=datetime.now().astimezone().isoformat(),
            last_error="Forced exit after second Ctrl-C",
        )
        append_event(run_id, "engagement_force_exited")
        raise KeyboardInterrupt from None
    except Exception as exc:
        # Preserve the last completed barrier first. Then make a best-effort
        # report; a process/power loss cannot do this, but the same snapshot is
        # still available to Continue engagement on the next launch.
        frozen_active = active_total()
        await persist(last_state, status="crashed")
        try:
            last_state = await _generate_report(last_state, event="crash_report_generated")
            await persist(last_state, status="crashed")
        except Exception as report_exc:  # noqa: BLE001
            append_event(
                run_id,
                "crash_report_failed",
                error=f"{type(report_exc).__name__}: {report_exc}",
            )
        update_manifest(
            run_id,
            manifest,
            status="crashed",
            session_finished_at=datetime.now().astimezone().isoformat(),
            last_error=f"{type(exc).__name__}: {exc}",
        )
        append_event(
            run_id,
            "engagement_crashed",
            error=f"{type(exc).__name__}: {exc}",
        )
        raise
    finally:
        if stream is not None and hasattr(stream, "aclose"):
            try:
                await stream.aclose()
            except Exception:  # noqa: BLE001
                pass
        if signal_installed:
            loop.remove_signal_handler(signal.SIGINT)
            try:
                signal.signal(signal.SIGINT, previous_sigint)
            except (ValueError, OSError):
                pass
        try:
            await cleanup_shell()
        except Exception:  # noqa: BLE001
            pass
        set_terminal_log_file(None)


def _report_tuple(result: dict) -> tuple[str, str, str, str]:
    messages = result.get("messages", [])
    report = str(result.get("report_markdown") or "").strip()
    if not report:
        # Compatibility fallback for graphs produced before report_markdown
        # became a state field. Ignore BaseNode's internal boundary markers.
        for message in reversed(messages):
            content = str(getattr(message, "content", "") or "").strip()
            if content.startswith("✅ [") or content.startswith("❌ ["):
                continue
            if content:
                report = content
                break
    if not report:
        report = "# SwarmAttacker Report\n\nNo output was produced."
    return (
        report,
        str(result.get("report_markdown_path") or ""),
        str(result.get("report_pdf_path") or ""),
        str(result.get("report_pdf_error") or ""),
    )


async def execute(user_input: str, target_scope: str = "") -> str:
    """Backward-compatible text-only wrapper around the engagement runner."""
    report, _, _, _ = await execute_engagement(user_input, target_scope)
    return report


async def run(user_input: str, target_scope: str = "") -> str:
    """Run a real-target engagement, print its report, and return it."""
    report, markdown_path, pdf_path, pdf_error = await execute_engagement(
        user_input=user_input, target_scope=target_scope
    )
    print(report)
    if markdown_path:
        print(f"\nMarkdown report: {markdown_path}")
    if pdf_path:
        print(f"\nPDF report: {pdf_path}")
    elif pdf_error:
        print(f"\nPDF generation failed: {pdf_error}")
    return report


def save_report(report: str, output_dir: Path | None = None) -> Path:
    """Legacy helper for callers that save standalone Markdown manually.

    Normal live runs no longer call this function: the report node writes
    ``pentest-report.md`` directly into the engagement's unified run folder.
    """
    if output_dir is None:
        from src.live_output import configured_live_output_root

        output_dir = configured_live_output_root()
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S")
    path = output_dir / f"pentest-{timestamp}.md"
    path.write_text(report.rstrip() + "\n", encoding="utf-8")
    return path
