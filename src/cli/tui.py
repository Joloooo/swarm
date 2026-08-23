"""Interactive ``swarm`` menu — questionary main loop + nested config editor.

Invoked by :func:`src.cli.__init__.main` when the user runs ``swarm``
with no positional argument and no benchmark shortcut. The flow:

  1. Print the rich banner (project name + config-file path).
  2. ``config_store.ensure_complete()`` — materialize swarm-config.toml in
     full (src.graph reads the values straight from that file).
  3. Loop forever:
        - present the top-level :func:`questionary.select`
        - dispatch to runner.* or _config_menu()
        - on Ctrl-C / "Quit", exit cleanly.

Docker bootstrap is **lazy**: ``docker_boot.ensure_ready()`` is only
called right before a benchmark run is dispatched (after the user
picks one or more benchmarks in the xbow picker). The menu itself,
config edits, and Quit never trigger Docker Desktop — SwarmAttacker
only needs Docker when running pentest containers. ``--no-docker``
still skips the bootstrap even for benchmark runs (useful on remote
VMs).

Ctrl-C policy: ``questionary.select`` returns ``None`` when the user
hits Ctrl-C. We treat that as "go back one level" rather than
crashing, so the user can always escape a submenu without losing
their session.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import questionary
from prompt_toolkit.application import Application, get_app
from prompt_toolkit.filters import Condition
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style
from questionary import Choice
from rich.console import Console

from src.benchmark_verdict import format_duration
from src.cli import (
    banner,
    bench_discovery,
    bench_results,
    bench_tags,
    config_store,
    docker_boot,
    runner,
)


_console = Console(stderr=True)


def _clear_terminal() -> None:
    """Clear both the visible terminal and its retained scrollback.

    Rich's ``Console.clear()`` emits the normal screen erase (CSI 2J), which
    redraws cleanly but leaves every prior TUI screen available when the user
    scrolls upward. CSI 3J removes those saved lines as well. The sequence is
    intentionally limited to a real terminal so redirected output is untouched.
    """
    if not _console.is_terminal:
        return
    stream = _console.file
    stream.write("\x1b[3J\x1b[2J\x1b[H")
    stream.flush()

# Shared visual language for every questionary screen.  The logo's warm pink
# is the focus colour; amber identifies the selected value/action.
_PROMPT_STYLE = Style.from_dict({
    "qmark": "fg:#ff5f87 bold",
    "question": "bold",
    "answer": "fg:#ffaf5f bold",
    "pointer": "fg:#ff5f87 bold",
    "highlighted": "fg:#ffaf5f bold",
    "selected": "fg:#ff5f87",
    "instruction": "fg:#767676",
    "text": "",
    "disabled": "fg:#5f5f5f italic",
})


# The single-container picker shows every XBEN-*-24 benchmark on disk
# (104 at last count), laid out in a column grid. ``None`` means no cap;
# set an int here only if you ever need to surface just the first N.
_PICKER_LIMIT: int | None = None

# The ✓/✗/~ marks next to each benchmark are *manual triage state* — you
# set them yourself by pressing ``t`` in the picker to cycle the
# highlighted row through ✓ (solved) → ✗ (genuinely failed) → ~ (yellow:
# codex/API or infra crash, no fair attempt) → no-mark. They persist in
# ``benchmarks/bench_results.json`` via :mod:`src.cli.bench_results`.


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

def main_loop(args: argparse.Namespace) -> None:
    """Drive the interactive menu until the user quits or Ctrl-C's.

    Docker is **not** started here — it's bootstrapped lazily, only
    when the user picks a benchmark action (see ``_ensure_docker``).
    """
    # Materialize swarm-config.toml in full (fills a missing/partial file,
    # keeping any existing values) so it always shows every knob. The values
    # themselves are read straight from the file by src.graph at run time.
    config_store.ensure_complete()

    while True:
        # Treat the interactive menu like one screen instead of appending each
        # prompt and submenu to the terminal forever.  Redraw the banner after
        # clearing so returning from usage/config/benchmark views is clean.
        _clear_terminal()
        banner.show(config_store.path())
        action = _top_level()
        if action is None or action == "quit":
            # Leave the user's terminal clean when the TUI closes; otherwise
            # the large banner and final questionary prompt remain visible.
            _clear_terminal()
            return

        # Fetch + show live 5h/weekly Codex usage for the ~/.codex login.
        # Read-only (no quota used). See codex_usage.
        if action == "__codex_usage__":
            _show_codex_usage()
            continue

        if action == "target":
            _run_target()
            continue

        if action == "xbow":
            picked = _pick_bench()
            if not picked:
                continue
            run_list, concurrency = picked
            if not run_list:
                continue
            if not _ensure_docker(args):
                continue
            if concurrency > 1:
                _run_picker_campaign(run_list, concurrency)
            else:
                runner.run_queue(run_list)
        elif action == "config":
            _config_menu()


def _run_picker_campaign(run_list: list[str], concurrency: int) -> None:
    """Fan a picker selection out across ``concurrency`` Terminal windows.

    The >1-concurrency path of the xbow picker: the same machinery as the
    top-level "Run ALL benchmarks concurrently", but over exactly the
    benchmarks selected in the picker instead of the whole set. This
    terminal becomes the live dashboard until every window finishes. Docker
    is assumed ready — ``main_loop`` bootstraps it before dispatching.
    """
    _console.print(
        f"[cyan]Fanning {len(run_list)} benchmark(s) out across {concurrency} "
        f"concurrent Terminal window(s) — this terminal becomes the live "
        f"dashboard.[/cyan]"
    )
    from benchmarks.launch_split import launch_campaign
    try:
        launch_campaign(ids=run_list, jobs=concurrency, wait=True)
    except KeyboardInterrupt:
        _console.print(
            "\n[dim]Stopped watching — the Terminal windows keep running. "
            "Re-attach the dashboard with `campaign_report`.[/dim]"
        )


def _ensure_docker(args: argparse.Namespace) -> bool:
    """Bootstrap Docker Desktop right before a benchmark dispatch.

    Returns True if Docker is ready (or the user passed
    ``--no-docker``), False if the user Ctrl-C'd out of the
    bootstrap — in which case the caller should drop back to the
    menu instead of running the benchmark.
    """
    if args.no_docker:
        return True
    try:
        docker_boot.ensure_ready()
    except KeyboardInterrupt:
        _console.print("\n[dim]Cancelled during Docker bootstrap — back to menu.[/dim]")
        return False
    return True


# ---------------------------------------------------------------------------
# Top-level menu
# ---------------------------------------------------------------------------

def _top_level() -> str | None:
    choices: list[Choice] = [
        Choice("Target engagements  — new, continue, or regenerate report", value="target"),
        Choice("Codex usage (5-hour / weekly) — fetch live", value="__codex_usage__"),
        Choice("xbow benchmark  (run one, a selection, or all — sequential or concurrent)", value="xbow"),
        Choice("Edit config",                                                 value="config"),
        Choice("Quit",                                                        value="quit"),
    ]

    question = questionary.select(
        "Swarm control center",
        choices=choices,
        use_shortcuts=False,
        instruction="(use ↑/↓, enter to confirm, Ctrl-C to quit)",
        style=_PROMPT_STYLE,
    )
    return question.ask()


def _run_target() -> None:
    """Open the runtime-owned real-target engagement lifecycle."""
    action = questionary.select(
        "Target engagements",
        choices=[
            Choice("New engagement", value="new"),
            Choice("Continue engagement — add active testing time", value="continue"),
            Choice("Regenerate report — no reconnaissance or testing", value="report"),
            Choice("← Back", value="back"),
        ],
        instruction="(use ↑/↓, enter to confirm, Ctrl-C to go back)",
        style=_PROMPT_STYLE,
    ).ask()
    if action in {None, "back"}:
        return
    if action == "new":
        _run_new_target()
    elif action == "continue":
        _run_continued_target()
    else:
        _run_report_regeneration()


def _run_new_target() -> None:
    """Collect an instruction, duration, and optional periodic report interval."""
    from rich.panel import Panel

    from src.cli import oneshot

    _console.print(
        Panel(
            "Describe the target, authorization scope, credentials (if any), "
            "and what you want tested. This becomes the supervisor's first "
            "message exactly as written.\n\n"
            "[dim]Example: Test https://staging.example.com for web "
            "vulnerabilities. Stay on this host and do not test denial of "
            "service.[/dim]",
            title="[bold #ff5f87] NEW TARGET ENGAGEMENT [/bold #ff5f87]",
            title_align="left",
            border_style="#ff5f87",
            padding=(1, 2),
            width=min(88, _console.width),
        )
    )
    instruction = _operator_text_prompt(
        placeholder="Describe the target and scope · Command-V or mouse paste works",
        hint="Enter start · Shift/Option-Enter or Ctrl-J newline · Ctrl-C cancel",
        allow_empty=False,
        fallback_question="Your instruction:",
    )
    if instruction is None:
        return

    duration = _pick_duration("How long should active testing run?")
    if duration is None:
        return
    report_interval = _pick_report_interval()
    if report_interval is None:
        return

    _console.print()
    _console.print(
        Panel(
            "[bold]Real-target mode[/bold]\n"
            "Benchmark discovery, expected flags, and benchmark scoring are disabled.\n"
            "Remote-safe traffic is active: target operations are serialized, scans "
            "are rate-limited, and timeout/block signals trigger shared backoff.\n\n"
            f"Active-time budget: [bold]{_duration_label(duration)}[/bold]\n"
            f"Report updates: [bold]{_report_interval_label(report_interval)}[/bold]\n\n"
            "First Ctrl-C pauses at the next safe graph barrier, saves state, and updates "
            "the report. A second Ctrl-C forces exit from the last durable snapshot.\n"
            "Type guidance and press Enter at any time; it is injected as a new user "
            "message and the planner reassesses at the next safe barrier.",
            border_style="#ffaf5f",
            padding=(0, 2),
            width=min(88, _console.width),
        )
    )

    try:
        result = asyncio.run(
            oneshot.execute_engagement(
                instruction.strip(),
                session_budget_seconds=duration,
                report_interval_seconds=report_interval,
            )
        )
    except KeyboardInterrupt:
        _console.print("\n[yellow]Force-exited. The last checkpoint is resumable.[/yellow]")
        _pause_for_menu()
        return
    except Exception as exc:  # noqa: BLE001
        _show_engagement_error(exc)
        return

    _show_engagement_result(result, title="PENETRATION TEST REPORT")


def _run_continued_target() -> None:
    """Select an existing folder and add an active-time budget."""
    from src.cli import oneshot

    directory = _pick_engagement_folder("Continue which engagement?", require_resume=True)
    if directory is None:
        return
    duration = _pick_duration("How much active testing time should be added?")
    if duration is None:
        return
    operator_instruction = _operator_text_prompt(
        placeholder="Optional new instruction · Enter keeps the existing plan",
        hint="Enter continue · Shift/Option-Enter or Ctrl-J newline · Ctrl-C cancel",
        allow_empty=True,
        fallback_question="Additional instruction (optional):",
    )
    if operator_instruction is None:
        return
    _console.print(
        f"[dim]Continuing {directory.name} for {_duration_label(duration)}. "
        "Logs and reports stay in the same folder.[/dim]"
    )
    try:
        result = asyncio.run(
            oneshot.continue_engagement(
                directory,
                duration,
                operator_instruction=operator_instruction.strip(),
            )
        )
    except KeyboardInterrupt:
        _console.print("\n[yellow]Force-exited. The last checkpoint is resumable.[/yellow]")
        _pause_for_menu()
        return
    except Exception as exc:  # noqa: BLE001
        _show_engagement_error(exc)
        return
    _show_engagement_result(result, title="CONTINUED ENGAGEMENT REPORT")


def _operator_text_prompt(
    *,
    placeholder: str,
    hint: str,
    allow_empty: bool,
    fallback_question: str,
) -> str | None:
    """Collect text with the same editor used during a live engagement."""
    from src.cli.operator_input import read_operator_instruction

    try:
        value = asyncio.run(read_operator_instruction(
            placeholder=placeholder,
            hint=hint,
            allow_empty=allow_empty,
        ))
    except KeyboardInterrupt:
        return None
    if value is not None:
        return value

    # Non-Unix/non-TTY fallback: retain the established questionary prompt.
    return questionary.text(
        fallback_question,
        instruction="(Enter to confirm, Ctrl-C to cancel)",
        style=_PROMPT_STYLE,
        validate=(
            None
            if allow_empty
            else lambda text: bool(text.strip()) or "Please enter an instruction."
        ),
    ).ask()


def _run_report_regeneration() -> None:
    """Select an existing folder and run only the mandatory reporting skill."""
    from src.cli import oneshot

    directory = _pick_engagement_folder("Regenerate which report?", require_resume=False)
    if directory is None:
        return
    _console.print(
        f"[dim]Regenerating from preserved findings in {directory}. "
        "No reconnaissance or attack workers will run.[/dim]"
    )
    try:
        result = asyncio.run(oneshot.regenerate_engagement_report(directory))
    except KeyboardInterrupt:
        _console.print("\n[yellow]Report regeneration cancelled.[/yellow]")
        _pause_for_menu()
        return
    except Exception as exc:  # noqa: BLE001
        _show_engagement_error(exc)
        return
    _show_engagement_result(result, title="REPORT REGENERATED")


def _show_engagement_error(exc: BaseException) -> None:
    from rich.panel import Panel

    _console.print(
        Panel(
            f"{type(exc).__name__}: {exc}",
            title="[bold red] ENGAGEMENT FAILED [/bold red]",
            border_style="red",
        )
    )
    _pause_for_menu()


def _show_engagement_result(
    result: tuple[str, str, str, str],
    *,
    title: str,
) -> None:
    from rich.markdown import Markdown
    from rich.panel import Panel

    from src.engagement import load_manifest

    report, markdown_path, pdf_path, pdf_error = result
    directory = Path(markdown_path).parent if markdown_path else None
    manifest = load_manifest(directory) if directory else None
    status = str((manifest or {}).get("status") or "completed")

    _console.print()
    subtitle = "PDF + Markdown saved" if pdf_path else "Markdown saved"
    _console.print(
        Panel(
            Markdown(report),
            title=f"[bold #ff5f87] {title} [/bold #ff5f87]",
            subtitle=f"{subtitle} • {status}",
            border_style="#ff5f87",
            padding=(1, 2),
        )
    )
    if pdf_path:
        _console.print(f"[dim]  PDF      {pdf_path}[/dim]")
    if markdown_path:
        _console.print(f"[dim]  Markdown {markdown_path}[/dim]")
        _console.print(f"[dim]  Run folder {Path(markdown_path).parent}[/dim]")
    if pdf_error:
        _console.print(f"[yellow]PDF generation warning: {pdf_error}[/yellow]")
    _pause_for_menu()


def _pick_duration(prompt: str) -> int | None:
    picked = questionary.select(
        prompt,
        choices=[
            Choice("2 hours", value=2 * 60 * 60),
            Choice("4 hours", value=4 * 60 * 60),
            Choice("1 hour", value=60 * 60),
            Choice("8 hours", value=8 * 60 * 60),
            Choice("Custom minutes…", value="custom"),
        ],
        instruction="(only active runtime counts; paused time does not)",
        style=_PROMPT_STYLE,
    ).ask()
    if picked is None:
        return None
    if picked != "custom":
        return int(picked)
    value = questionary.text(
        "Active testing minutes:",
        validate=_int_validator,
        style=_PROMPT_STYLE,
    ).ask()
    return int(value) * 60 if value is not None else None


def _pick_report_interval() -> int | None:
    picked = questionary.select(
        "While testing continues, how often should the report be refreshed?",
        choices=[
            Choice("Only when paused or finished", value=0),
            Choice("Every 1 hour", value=60 * 60),
            Choice("Every 2 hours", value=2 * 60 * 60),
            Choice("Custom minutes…", value="custom"),
        ],
        instruction="(updates overwrite the same Markdown and PDF atomically)",
        style=_PROMPT_STYLE,
    ).ask()
    if picked is None:
        return None
    if picked != "custom":
        return int(picked)
    value = questionary.text(
        "Report interval minutes:",
        validate=_int_validator,
        style=_PROMPT_STYLE,
    ).ask()
    return int(value) * 60 if value is not None else None


def _duration_label(seconds: int) -> str:
    hours, remainder = divmod(int(seconds), 3600)
    minutes = remainder // 60
    if hours and minutes:
        return f"{hours}h {minutes}m"
    if hours:
        return f"{hours}h"
    return f"{minutes}m"


def _report_interval_label(seconds: int) -> str:
    return "at pause/end only" if not seconds else f"every {_duration_label(seconds)}"


def _pick_engagement_folder(prompt: str, *, require_resume: bool) -> Path | None:
    from src.engagement import discover_engagement_directories, load_manifest
    from src.live_output import configured_live_output_root

    root = configured_live_output_root()
    directories = discover_engagement_directories(root)
    choices: list[Choice] = []
    for directory in directories:
        manifest = load_manifest(directory) or {}
        status = str(manifest.get("status") or "legacy")
        active = _duration_label(int(float(manifest.get("active_seconds_total") or 0)))
        choices.append(Choice(
            f"{directory.name}  [{status}; {active} active]",
            value=str(directory),
        ))
    choices.extend([
        Choice("Browse for another engagement folder…", value="__browse__"),
        Choice("← Back", value="__back__"),
    ])
    picked = questionary.select(
        prompt,
        choices=choices,
        instruction=f"(engagement root: {root})",
        style=_PROMPT_STYLE,
    ).ask()
    if picked in {None, "__back__"}:
        return None
    directory = (
        _browse_existing_directory(root)
        if picked == "__browse__"
        else Path(str(picked)).expanduser().resolve()
    )
    if directory is None:
        return None
    try:
        from src.engagement import load_report_state, load_resume_state

        if require_resume:
            load_resume_state(directory)
        else:
            load_report_state(directory)
    except Exception as exc:  # noqa: BLE001
        label = "not resumable" if require_resume else "missing report evidence"
        _console.print(f"[yellow]That folder is {label}: {exc}[/yellow]")
        _pause_for_menu()
        return None
    return directory


def _browse_existing_directory(start: Path) -> Path | None:
    """Choose an existing engagement folder without changing output config."""
    if sys.platform == "darwin" and shutil.which("osascript"):
        escaped = str(start).replace('"', '\\"')
        script = (
            'set selectedFolder to choose folder with prompt '
            '"Choose an existing SwarmAttacker engagement folder" '
            f'default location (POSIX file "{escaped}")\n'
            'return POSIX path of selectedFolder'
        )
        completed = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            return Path(completed.stdout.strip()).expanduser().resolve()
        if "User canceled" in completed.stderr or "(-128)" in completed.stderr:
            return None
    selected = _terminal_directory_browser(
        start=start,
        allow_create=False,
        title="Existing engagement folder",
    )
    return Path(selected).resolve() if selected else None


def _pause_for_menu() -> None:
    _console.print("[dim]  Press Enter to return to the control center[/dim]", end=" ")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


def _show_codex_usage() -> None:
    """Fetch and print live 5-hour + weekly Codex usage for the ~/.codex login.

    Read-only — hits the wham/usage status endpoint (no model quota
    consumed). Lazy-imports :mod:`src.cli.codex_usage` so the TUI's normal
    startup stays light.
    """
    from rich import box
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from src.cli import codex_usage

    _console.print("[#767676]  Contacting Codex usage service…[/#767676]")

    table = Table(
        show_header=True,
        header_style="bold #ffaf5f",
        box=box.SIMPLE_HEAD,
        expand=True,
        padding=(0, 1),
    )
    table.add_column("Window", style="bold white")
    table.add_column("Remaining", justify="right")
    table.add_column("Used", justify="right")
    table.add_column("Resets in", justify="right", style="dim")

    def _used_pct(window) -> str:  # noqa: ANN001
        if window is None:
            return "—"
        p = window.used_percent
        colour = "red" if p >= 80 else "yellow" if p >= 50 else "green"
        return f"[{colour}]{p:g}%[/{colour}]"

    def _remaining_pct(window) -> str:  # noqa: ANN001
        if window is None:
            return "—"
        p = max(0.0, min(100.0, 100.0 - window.used_percent))
        colour = "red" if p <= 20 else "yellow" if p <= 50 else "green"
        return f"[{colour}]{p:g}%[/{colour}]"

    try:
        u = codex_usage.fetch()
        account = Text.assemble(
            (u.email or "~/.codex", "bold white"),
            ("   •   ", "#767676"),
            ((u.plan_type or "unknown").upper(), "bold #ffaf5f"),
            (" plan", "dim"),
        )
        table.add_row(
            "5-hour",
            _remaining_pct(u.primary),
            _used_pct(u.primary),
            u.primary.reset_human if u.primary else "—",
        )
        table.add_row(
            "Weekly",
            _remaining_pct(u.secondary),
            _used_pct(u.secondary),
            u.secondary.reset_human if u.secondary else "—",
        )
        credits = (
            f"Credits: {u.credits_balance}"
            if u.has_credits else "No additional credits"
        )
    except codex_usage.CodexAccountAuthError:
        account = Text("Codex login expired", style="bold red")
        table.add_row("Status", "—", "—", "[red]Run: codex login[/red]")
        credits = "Authentication required"
    except Exception as e:  # noqa: BLE001
        account = Text("Could not load Codex usage", style="bold red")
        table.add_row("Status", "—", "—", f"[red]{type(e).__name__}[/red]")
        credits = "Try again in a moment"

    card = Group(
        account,
        Text("Read-only status check • no model quota used", style="dim"),
        Text(),
        table,
        Text(credits, style="dim"),
    )
    _console.print(
        Panel(
            card,
            title="[bold #ff5f87] CODEX USAGE [/bold #ff5f87]",
            title_align="left",
            border_style="#ff5f87",
            padding=(1, 2),
            width=min(72, _console.width),
        )
    )
    _console.print("[dim]  Press Enter to return[/dim]", end=" ")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


# ---------------------------------------------------------------------------
# Single-benchmark picker
# ---------------------------------------------------------------------------

# Column-grid geometry. The picker lays every benchmark out in a grid
# filled column-major (top-to-bottom, then the next column to the right)
# so the sorted ids still read straight down each column. ``_MAX_COLS``
# caps the width; fewer columns are used automatically on a narrow
# terminal. With 104 benchmarks and a wide terminal this is a 26×4 grid
# instead of a 104-row single column.
_MAX_COLS = 4
_GAP = 2             # blank columns between grid cells
# Width kept after each label for its trailing annotation — whichever is
# shown: the " [NNN]" dispatch-order number (selected) or the last-run
# solve time " (Xm Ys)" (unselected). 10 covers " (20m 00s)".
_SUFFIX_RESERVE = 10

# How many selected benchmarks the header lists by name before collapsing to
# a "selected: N of M" count line (listing 100 ids would wrap off-screen).
_QUEUE_PREVIEW = 8

# Colour of the vulnerability tags in each row's label (the part after the
# id). Always shown for an *unselected* benchmark so you can scan vuln classes
# at rest; a selected benchmark takes its slice colour instead (see below).
_TAG_STYLE = "fg:ansibrightblue"

# Colour for a benchmark that is selected to run. The selected set goes into ONE
# shared work-queue that ``concurrency`` worker sessions PULL from — there are no
# fixed per-window lanes any more — so the whole selection is one colour with a
# single 1..N dispatch-order number (``[1]`` is claimed first). Green; red is
# reserved for the ✗ fail mark.
_QUEUE_STYLE = "ansigreen"


# Max width of a grid label. Tag lists run up to ~68 chars for the few
# 3-4-tag benchmarks; without a cap, one such row would force the whole grid
# down to a single 104-row column. So the id (``XBEN-NNN-``) is always kept
# whole and only the *tag list* of the longest few is clipped with a trailing
# … — ~90% of benchmarks still show every tag, and the grid stays 2-3 columns.
_LABEL_CAP = 44


def _capped_tags(base: str, tags_str: str) -> str:
    """Clip ``tags_str`` so ``base + tags_str`` fits within :data:`_LABEL_CAP`.

    Only the tag list is shortened (trailing …); the ``XBEN-NNN-`` id is never
    touched. Returns ``tags_str`` unchanged when it already fits or is empty.
    """
    if not tags_str or len(base) + len(tags_str) <= _LABEL_CAP:
        return tags_str
    keep = max(1, _LABEL_CAP - len(base) - 1)   # 1 col for the …
    return tags_str[:keep] + "…"


def _grid_dims(n: int, width: int, content_w: int) -> tuple[int, int]:
    """Return ``(rows, cols)`` for an ``n``-cell column-major grid.

    ``cols`` is the most that fit in ``width`` (capped at ``_MAX_COLS``),
    then shrunk so the last column is never empty; ``rows`` follows.
    """
    stride = content_w + _GAP
    cols = max(1, min(_MAX_COLS, width // stride))
    cols = min(cols, n)
    rows = -(-n // cols)   # ceil — height needed for that many columns
    cols = -(-n // rows)   # drop any now-empty trailing column
    return rows, cols


def _cell_segments(
    base: str,
    tags_str: str,
    result: str | None,
    order: int | None,
    duration_s: float | None,
    is_cursor: bool,
    content_w: int,
) -> list[tuple[str, str]]:
    """Formatted-text segments for one grid cell, padded to ``content_w``.

    The ✓/✗/~ result mark is coloured. The label is the id base (``XBEN-004-``)
    plus its vulnerability ``tags_str`` (``xss``). A benchmark that is selected
    for a run carries ``order`` = its 1-based place in the shared dispatch
    queue: the whole label is drawn in the queue colour with a ``[order]``
    suffix (``[1]`` is claimed first). An unselected benchmark keeps a
    default-coloured base with its tags in :data:`_TAG_STYLE`, followed by its
    last run's solve time ``(Xm Ys)`` in dim when ``duration_s`` is known (the
    ``[order]`` number takes that slot while selected). The whole cell is
    reverse-video when it is the pointed-at benchmark, so the cursor reads as a
    highlighted bar.
    """
    if result == bench_results.OK:
        segs = [("fg:ansigreen bold", "✓"), ("", " ")]
    elif result == bench_results.FAIL:
        segs = [("fg:ansired bold", "✗"), ("", " ")]
    elif result == bench_results.API:
        segs = [("fg:ansiyellow bold", "~"), ("", " ")]
    else:
        segs = [("", "  ")]
    if order is not None:
        # Selected → whole label + dispatch-order number, in the queue colour.
        style = f"fg:{_QUEUE_STYLE} bold"
        segs.append((style, base + tags_str))
        segs.append((style, f" [{order}]"))
    else:
        segs.append(("", base))
        if tags_str:
            segs.append((_TAG_STYLE, tags_str))
        # Last-run solve time, dim, so the grid shows how long each took.
        if duration_s is not None:
            segs.append(("fg:ansibrightblack", f" ({format_duration(duration_s)})"))
    used = sum(len(text) for _, text in segs)
    if used < content_w:
        segs.append(("", " " * (content_w - used)))
    if is_cursor:
        segs = [((style + " reverse").strip(), text) for style, text in segs]
    return segs


def _pick_bench() -> tuple[list[str], int] | None:
    """Let the user pick benchmarks to run, and at what concurrency.

    Every XBEN-*-24 benchmark on disk is shown in a column grid (filled
    column-major, navigated with the arrow keys), labelled by its
    vulnerability tags (``XBEN-004-xss``) and annotated with its ✓/✗/~ triage
    mark from ``benchmarks/bench_results.json``. Keys:

      ``t`` — cycle the result mark ✓ → ✗ → ~ → none (persisted
              immediately). ✓ solved, ✗ genuinely failed, ~ (yellow)
              malfunction (codex/API or infra crash) with no fair attempt.
      ``r`` — select / unselect the highlighted benchmark. The selected set
              goes into one shared queue that ``concurrency`` worker sessions
              pull from; each bench is numbered ``[N]`` in dispatch order.
      ``a`` — select all / unselect all (toggle).
      ``f`` — select every ✗-failed benchmark / unselect (toggle) — handy for
              re-running just the failures.
      ``m`` — select every ~ malfunction benchmark / unselect (toggle) — the
              codex/API / infra crashes that never got a fair attempt, for
              re-running just those.
      ``c`` — set the concurrency inline: type digits, ``enter`` to confirm,
              ``esc`` to cancel. Capped at the number selected — you can't
              run more windows than benchmarks. Changing it re-splits the
              selection into that many coloured sequences.

    Returns ``(ids, concurrency)``:

      * ``ids``         — the selected set in selection order, or just the
                          highlighted cell when nothing is selected;
      * ``concurrency`` — 1 runs them one after another in this terminal;
                          >1 fans them out across that many Terminal windows
                          (the campaign path). Always clamped to ``len(ids)``.

    ``None`` is returned if the user backs out (q / Ctrl-C) or the submodule
    is missing.

    Concurrency lives only in memory — it always starts at 1 and is never
    written to swarm-config.toml.

    Unlike the rest of the TUI this is a hand-rolled prompt_toolkit
    ``Application`` rather than a ``questionary.select`` — questionary
    only renders a single vertical column, and we need a true grid with
    left/right navigation so 100+ benchmarks fit on one screen.
    """
    ids = bench_discovery.list_ids(limit=_PICKER_LIMIT)
    if not ids:
        _console.print(
            "[yellow]No XBEN benchmarks found.[/yellow] Initialise the "
            "submodule with [bold]git submodule update --init "
            "xbow-validation[/bold]."
        )
        return None

    results = bench_results.load()
    # Last-run solve time per benchmark, read from the same bench_results.json
    # entry as the ✓/✗/~ mark — verdict and time describe the one run, so they
    # appear and disappear together. Shown dim next to each mark.
    durations = bench_results.load_durations()
    queue: list[str] = []        # ordered run/selection set, built with r / a.
    state = {
        "cursor": 0,             # flat index into ``ids`` of the pointed-at cell.
        "concurrency": 1,        # in-memory only, never saved. 1 = sequential.
        "c_mode": False,         # True while typing a concurrency value inline.
        "c_buffer": "",          # digits typed so far in c-mode.
    }
    n = len(ids)
    # Cells are sized to the tag-expanded label (``XBEN-004-xss``), capped at
    # _LABEL_CAP so a few very long tag lists don't collapse the grid to one
    # column. Rows with long tags still widen the columns, so the grid uses
    # fewer of them — the deliberate trade for showing tags.
    content_w = 2 + min(bench_tags.widest_short_id(ids), _LABEL_CAP) + _SUFFIX_RESERVE

    def _width() -> int:
        try:
            return get_app().output.get_size().columns or 80
        except Exception:  # noqa: BLE001 — size unavailable → safe default
            return 80

    def _dims() -> tuple[int, int]:
        return _grid_dims(n, _width(), content_w)

    def _sel_count() -> int:
        """How many benchmarks ``enter`` would run — the concurrency cap."""
        return len(queue) if queue else 1

    def _clamp_concurrency() -> None:
        """Keep concurrency in 1..selected so it can never exceed the set."""
        state["concurrency"] = max(1, min(state["concurrency"], _sel_count()))

    def _queue_order_map() -> dict[str, int]:
        """``{bench_id: dispatch_position}`` (1-based) for the selection.

        The selected set goes into one shared work-queue (FIFO: the launcher
        seeds ``pending`` in this order and workers pop the front), so the
        number shown is simply each bench's place in line — ``[1]`` is claimed
        first. Empty when nothing is selected; recomputed each render so it
        tracks ``r``/``a`` live.
        """
        return {bid: pos for pos, bid in enumerate(queue, 1)}

    def _move(dr: int, dc: int) -> None:
        rows, cols = _dims()
        i = state["cursor"]
        row, col = i % rows, i // rows
        if dc:
            col = min(max(col + dc, 0), cols - 1)
        if dr:
            row = min(max(row + dr, 0), rows - 1)
        # Clamp into the filled part of the target column (the last column
        # may be short), so left/right never strand the cursor on a blank.
        col_len = min((col + 1) * rows, n) - col * rows
        row = min(row, col_len - 1)
        state["cursor"] = col * rows + row

    def _render() -> list[tuple[str, str]]:
        rows, cols = _dims()
        cur_id = ids[state["cursor"]]
        # Live tally over the shown benchmarks — recomputed each render so
        # it updates the instant a ``t`` toggle changes a mark.
        marks = [results.get(b) for b in ids]
        n_ok = marks.count(bench_results.OK)
        n_fail = marks.count(bench_results.FAIL)
        n_api = marks.count(bench_results.API)
        n_none = n - n_ok - n_fail - n_api
        # The selection's dispatch order (queue position), computed per render.
        qmap = _queue_order_map()
        list_sel = len(queue) <= _QUEUE_PREVIEW   # list ids vs. count in header
        out: list[tuple[str, str]] = [
            ("bold", "Which benchmark(s) do you want to run?"),
            ("fg:ansibrightblack", f"   ({n} benchmarks)\n"),
            ("fg:ansigreen bold", f"   ✓ {n_ok} solved"),
            ("fg:ansibrightblack", "  ·  "),
            ("fg:ansired bold", f"✗ {n_fail} failed"),
            ("fg:ansibrightblack", "  ·  "),
            ("fg:ansiyellow bold", f"~ {n_api} malfunction"),
            ("fg:ansibrightblack", f"  ·  {n_none} unmarked\n"),
        ]
        # Failure breakdown by vulnerability tag, in a less-bright red, so a
        # column of ✗ reads as "which classes are we losing on" at a glance.
        failed_ids = [b for b in ids if results.get(b) == bench_results.FAIL]
        if failed_ids:
            summary = " · ".join(
                f"{cnt} {tag}" for tag, cnt in bench_tags.category_counts(failed_ids)
            )
            out.append(("fg:ansired", f"   ✗ by tag: {summary}\n"))
        out.append((
            "fg:ansibrightblack",
            "↑/↓/←/→ move · r select · a all/none · f failed · m malfunction · "
            "t mark ✓/✗/~ · c concurrency · enter run · q/Ctrl-C back\n",
        ))
        # Selection line: list tag-labels for small sets, else a count.
        if queue:
            if list_sel:
                out.append(("fg:ansibrightgreen bold", f"selected ({len(queue)}): "))
                out.append((
                    "fg:ansibrightgreen",
                    " → ".join(bench_tags.short_id(b) for b in queue) + "\n",
                ))
            else:
                out.append(("fg:ansibrightgreen bold", f"selected: {len(queue)} of {n}"))
                out.append((
                    "fg:ansibrightgreen",
                    f"  → 1 shared queue, pulled by "
                    f"{max(1, min(state['concurrency'], len(queue)))} worker(s)\n",
                ))
        else:
            out.append(("fg:ansibrightblack",
                        f"nothing selected — enter runs {bench_tags.short_id(cur_id)}\n"))
        # Concurrency line, or the inline editor while ``c`` is being typed.
        if state["c_mode"]:
            cap = _sel_count()
            out.append(("fg:ansibrightcyan bold", "set concurrency "))
            out.append(("fg:ansibrightblack", f"[1–{cap}]: "))
            out.append(("fg:ansibrightcyan bold", state["c_buffer"]))
            out.append(("fg:ansibrightcyan", "▌"))
            hint = "   (enter ok · esc cancel"
            if cap == 1 and not queue:
                hint += " — select benchmarks first: a = all"
            out.append(("fg:ansibrightblack", hint + ")\n"))
        else:
            conc = state["concurrency"]
            if conc <= 1:
                out.append(("fg:ansibrightblack",
                            "concurrency: 1  (sequential, in this terminal)\n"))
            else:
                out.append(("fg:ansibrightcyan bold", f"concurrency: {conc}"))
                out.append(("fg:ansibrightblack",
                            f"  (fan out across {conc} Terminal windows)\n"))
        out.append(("", "\n"))
        for r in range(rows):
            for c in range(cols):
                i = c * rows + r
                if i >= n:
                    continue
                bench_id = ids[i]
                base, tags = bench_tags.label_parts(bench_id)
                out.extend(_cell_segments(
                    base, _capped_tags(base, ",".join(tags)),
                    results.get(bench_id),
                    qmap.get(bench_id), durations.get(bench_id),
                    i == state["cursor"], content_w,
                ))
                if c != cols - 1:
                    out.append(("", " " * _GAP))
            out.append(("", "\n"))
        return out

    kb = KeyBindings()
    # Two modes share the keymap: normal navigation, and the inline
    # concurrency editor opened by ``c``. ``filter`` routes each key to the
    # right handler so digits/enter mean "type a number" only while editing.
    nav = Condition(lambda: not state["c_mode"])
    cmode = Condition(lambda: state["c_mode"])

    @kb.add("up", eager=True, filter=nav)
    @kb.add("k", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001 (prompt_toolkit event)
        _move(-1, 0)

    @kb.add("down", eager=True, filter=nav)
    @kb.add("j", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        _move(1, 0)

    @kb.add("left", eager=True, filter=nav)
    @kb.add("h", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        _move(0, -1)

    @kb.add("right", eager=True, filter=nav)
    @kb.add("l", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        _move(0, 1)

    @kb.add("t", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        bench_id = ids[state["cursor"]]
        bench_results.cycle(results, bench_id)
        bench_results.save(results)

    @kb.add("r", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        bench_id = ids[state["cursor"]]
        if bench_id in queue:
            queue.remove(bench_id)
        else:
            queue.append(bench_id)
        _clamp_concurrency()

    @kb.add("a", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        # Toggle: all selected → clear; otherwise select everything (in id
        # order, so a small selection keeps its hand-built order).
        if len(queue) == n:
            queue.clear()
        else:
            queue[:] = list(ids)
        _clamp_concurrency()

    @kb.add("f", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        # Select every ✗-failed benchmark (in id order). Toggle: pressing f
        # again — when the selection is exactly the failed set — clears it.
        # No-op when nothing is marked failed.
        failed = [b for b in ids if results.get(b) == bench_results.FAIL]
        if not failed:
            return
        queue[:] = [] if queue == failed else failed
        _clamp_concurrency()

    @kb.add("m", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        # Select every ~ malfunction benchmark (codex/API or infra crash with
        # no fair attempt — stored as bench_results.API). Toggle: pressing m
        # again — when the selection is exactly the malfunction set — clears it.
        # No-op when nothing is marked malfunction.
        malfunction = [b for b in ids if results.get(b) == bench_results.API]
        if not malfunction:
            return
        queue[:] = [] if queue == malfunction else malfunction
        _clamp_concurrency()

    @kb.add("c", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        state["c_mode"] = True
        state["c_buffer"] = ""

    @kb.add("enter", filter=nav)
    def _(event) -> None:  # noqa: ANN001
        run_list = list(queue) if queue else [ids[state["cursor"]]]
        conc = max(1, min(state["concurrency"], len(run_list)))
        event.app.exit(result=(run_list, conc))

    @kb.add("q", filter=nav)
    @kb.add("c-c", filter=nav)
    def _(event) -> None:  # noqa: ANN001
        event.app.exit(result=None)

    # --- inline concurrency editor (active only while ``c_mode`` is set) ----
    def _add_digit(d: str) -> None:
        @kb.add(d, filter=cmode)
        def _(event) -> None:  # noqa: ANN001
            if len(state["c_buffer"]) < 3:   # cap at 3 digits (max 999)
                state["c_buffer"] += d

    for _d in "0123456789":
        _add_digit(_d)

    @kb.add("backspace", filter=cmode)
    def _(event) -> None:  # noqa: ANN001
        state["c_buffer"] = state["c_buffer"][:-1]

    @kb.add("enter", filter=cmode)
    def _(event) -> None:  # noqa: ANN001
        if state["c_buffer"]:
            state["concurrency"] = max(1, min(int(state["c_buffer"]), _sel_count()))
        state["c_mode"] = False
        state["c_buffer"] = ""

    @kb.add("escape", filter=cmode)
    @kb.add("c-c", filter=cmode)
    def _(event) -> None:  # noqa: ANN001
        state["c_mode"] = False
        state["c_buffer"] = ""

    app = Application(
        layout=Layout(HSplit([
            Window(
                FormattedTextControl(_render, focusable=True, show_cursor=False),
                always_hide_cursor=True,
            ),
        ])),
        key_bindings=kb,
        full_screen=False,
        mouse_support=False,
        erase_when_done=True,
    )
    try:
        return app.run()
    except KeyboardInterrupt:
        return None


# ---------------------------------------------------------------------------
# Config submenu
# ---------------------------------------------------------------------------

# Human labels for the ablation switches, in the thesis ablation-table order.
# Each flag, when ON, DISABLES that capability for the run.
_CAPABILITY_KEYS: list[tuple[str, str]] = [
    ("disable_prompting_techniques", "Prompting techniques (standards + [SYSTEM NOTE] nudges)"),
    ("disable_hypothesis_passing",   "Hypothesis passing (structured beliefs)"),
    ("disable_refusal_handling",     "Refusal handling (recovery ladder)"),
    ("disable_skills",               "Skills (per-class specialists)"),
    ("disable_web_search",           "Web search (external lookup)"),
    ("disable_skill_ranking",        "Skill ranking (planner pros/cons summary — observability, on by default)"),
]


def _config_items() -> list[dict[str, Any]]:
    """Flat config rows for the one-screen, auto-saving editor."""
    items: list[dict[str, Any]] = [
        {"section": "MODEL", "label": "Model", "kind": "choice",
         "table": "model", "key": "slug", "choices": config_store.MODEL_CHOICES},
        {"section": "MODEL", "label": "Reasoning effort", "kind": "choice",
         "table": "model", "key": "reasoning_effort",
         "choices": config_store.REASONING_EFFORT_CHOICES},
        {"section": "MODEL", "label": "Reasoning summary", "kind": "choice",
         "table": "model", "key": "reasoning_summary",
         "choices": config_store.REASONING_SUMMARY_CHOICES},
        {"section": "MODEL", "label": "Search synthesis model", "kind": "choice",
         "table": "model", "key": "web_search_synth_model",
         "choices": config_store.WEB_SYNTH_MODEL_CHOICES},
        {"section": "MODEL", "label": "Search synthesis effort", "kind": "choice",
         "table": "model", "key": "web_search_synth_reasoning_effort",
         "choices": config_store.WEB_SYNTH_EFFORT_CHOICES},
        {"section": "RUNTIME", "label": "Console detail", "kind": "choice",
         "table": "verbosity", "key": "mode",
         "choices": config_store.VERBOSITY_CHOICES},
        {"section": "RUNTIME", "label": "Live output folder", "kind": "directory",
         "table": "output", "key": "directory"},
        {"section": "BUDGETS", "label": "Planner iterations", "kind": "int",
         "table": "budgets", "key": "planner_max_iters"},
        {"section": "BUDGETS", "label": "Worker iterations", "kind": "int",
         "table": "budgets", "key": "worker_max_iterations"},
        {"section": "BUDGETS", "label": "LLM output tokens", "kind": "int",
         "table": "budgets", "key": "llm_max_tokens"},
        {"section": "BUDGETS", "label": "LLM call timeout (sec)", "kind": "int",
         "table": "budgets", "key": "llm_call_timeout_s"},
        {"section": "BUDGETS", "label": "Run timeout (sec)", "kind": "int",
         "table": "budgets", "key": "run_timeout_s"},
    ]
    for key, label in _CAPABILITY_KEYS:
        items.append({
            "section": "CAPABILITIES",
            "label": label.split(" (")[0],
            "kind": "bool",
            "table": "capability",
            "key": key,
        })
    return items


def _config_menu() -> None:
    """Show one clean, auto-saving settings screen.

    There is no working copy and therefore no Save/Discard/Back decision.
    Every confirmed edit is written atomically to ``swarm-config.toml``.
    Escape or Ctrl-C simply closes the screen.
    """
    cfg = config_store.get_current_view()
    items = _config_items()

    while True:
        result = _config_editor(cfg, items)
        if result != "directory":
            return
        selected = _choose_output_directory()
        if selected is not None:
            cfg["output"]["directory"] = selected
            config_store.save(cfg)


def _config_editor(
    cfg: dict[str, dict[str, Any]],
    items: list[dict[str, Any]],
) -> str | None:
    """Run the prompt-toolkit settings editor until close/directory request."""
    state: dict[str, Any] = {
        "cursor": 0,
        "editing": False,
        "buffer": "",
        "status": "All changes save automatically",
        "status_error": False,
    }

    def _current() -> dict[str, Any]:
        return items[state["cursor"]]

    def _save(message: str) -> None:
        try:
            config_store.save(cfg)
            state["status"] = f"Saved  {message}"
            state["status_error"] = False
        except Exception as exc:  # noqa: BLE001
            state["status"] = f"Could not save: {exc}"
            state["status_error"] = True

    def _cycle(delta: int) -> None:
        item = _current()
        if item["kind"] == "choice":
            choices = item["choices"]
            current = cfg[item["table"]][item["key"]]
            index = choices.index(current) if current in choices else 0
            value = choices[(index + delta) % len(choices)]
            cfg[item["table"]][item["key"]] = value
            _save(f"{item['label']} = {value}")
        elif item["kind"] == "bool":
            value = not bool(cfg[item["table"]][item["key"]])
            cfg[item["table"]][item["key"]] = value
            _save(f"{item['label']} = {'OFF' if value else 'ON'}")

    def _render() -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = [
            ("bold fg:#ff5f87", "\n  SETTINGS"),
            ("fg:#767676", "  /  swarm-config.toml\n"),
            ("fg:#767676", "  Changes are written as soon as you confirm them.\n\n"),
        ]

        try:
            terminal_width = get_app().output.get_size().columns or 100
        except Exception:  # noqa: BLE001
            terminal_width = 100
        column_width = max(38, (terminal_width - 7) // 2)

        def _item_row(index: int, item: dict[str, Any]) -> list[tuple[str, str]]:
            selected = index == state["cursor"]
            segments: list[tuple[str, str]] = [
                ("bold fg:#ff5f87" if selected else "", "› " if selected else "  ")
            ]
            label_width = min(25, max(17, column_width - 18))
            label = item["label"]
            if len(label) > label_width:
                label = label[:label_width - 1] + "…"
            segments.append((
                "bold" if selected else "fg:#c8c8c8",
                f"{label:<{label_width}} ",
            ))

            value = cfg[item["table"]][item["key"]]
            if selected and state["editing"] and item["kind"] == "int":
                shown = f"[ {state['buffer']}▌ ]"
                style = "bold fg:#ffaf5f"
            elif item["kind"] == "choice":
                shown = f"‹ {value} ›"
                style = "bold fg:#ffaf5f" if selected else "fg:#dedede"
            elif item["kind"] == "bool":
                disabled = bool(value)
                shown = "● OFF" if disabled else "● ON"
                style = "bold fg:#ff5f87" if disabled else "bold fg:#5fd787"
            elif item["kind"] == "directory":
                shown = str(value)
                style = "fg:#ffaf5f" if selected else "fg:#dedede"
            else:
                shown = str(value)
                style = "fg:#ffaf5f" if selected else "fg:#dedede"

            used = 2 + label_width + 1
            available = max(5, column_width - used)
            if len(shown) > available:
                shown = "…" + shown[-(available - 1):]
            segments.append((style, shown))
            visible = used + len(shown)
            if visible < column_width:
                segments.append(("", " " * (column_width - visible)))
            return segments

        def _column_rows(
            indexed: list[tuple[int, dict[str, Any]]],
        ) -> list[list[tuple[str, str]]]:
            rows: list[list[tuple[str, str]]] = []
            previous_section = ""
            for index, item in indexed:
                if item["section"] != previous_section:
                    if previous_section:
                        rows.append([("", " " * column_width)])
                    heading = f"{item['section']}"
                    rows.append([
                        ("bold fg:#ff5f87", f"{heading:<{column_width}}")
                    ])
                    previous_section = item["section"]
                rows.append(_item_row(index, item))
            return rows

        # Model/runtime on the left; budgets/capabilities on the right. This
        # keeps the complete editor visible in a standard 24-line terminal.
        left_rows = _column_rows(list(enumerate(items[:7])))
        right_rows = _column_rows(list(enumerate(items[7:], start=7)))
        row_count = max(len(left_rows), len(right_rows))
        blank = [("", " " * column_width)]
        for row_index in range(row_count):
            out.extend(left_rows[row_index] if row_index < len(left_rows) else blank)
            out.append(("fg:#3a3a3a", "  │  "))
            out.extend(right_rows[row_index] if row_index < len(right_rows) else blank)
            out.append(("", "\n"))

        status_style = "bold fg:#ff5f87" if state["status_error"] else "fg:#5fd787"
        out.extend([
            ("", "\n"),
            (status_style, f"  {state['status']}\n"),
            ("fg:#767676", "  ↑↓ navigate   ←→ change   Enter edit/toggle   Esc close\n"),
        ])
        return out

    kb = KeyBindings()
    nav = Condition(lambda: not state["editing"])
    edit = Condition(lambda: bool(state["editing"]))

    @kb.add("up", eager=True, filter=nav)
    @kb.add("k", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        state["cursor"] = (state["cursor"] - 1) % len(items)

    @kb.add("down", eager=True, filter=nav)
    @kb.add("j", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        state["cursor"] = (state["cursor"] + 1) % len(items)

    @kb.add("left", eager=True, filter=nav)
    @kb.add("h", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        _cycle(-1)

    @kb.add("right", eager=True, filter=nav)
    @kb.add("l", eager=True, filter=nav)
    def _(event) -> None:  # noqa: ANN001
        _cycle(1)

    @kb.add("enter", filter=nav)
    def _(event) -> None:  # noqa: ANN001
        item = _current()
        if item["kind"] in {"choice", "bool"}:
            _cycle(1)
        elif item["kind"] == "int":
            state["editing"] = True
            state["buffer"] = str(cfg[item["table"]][item["key"]])
        elif item["kind"] == "directory":
            event.app.exit(result="directory")

    @kb.add("escape", filter=nav)
    @kb.add("c-c", filter=nav)
    @kb.add("q", filter=nav)
    def _(event) -> None:  # noqa: ANN001
        event.app.exit(result=None)

    def _add_digit(digit: str) -> None:
        @kb.add(digit, filter=edit)
        def _(event) -> None:  # noqa: ANN001
            if len(state["buffer"]) < 9:
                state["buffer"] += digit

    for _digit in "0123456789":
        _add_digit(_digit)

    @kb.add("backspace", filter=edit)
    def _(event) -> None:  # noqa: ANN001
        state["buffer"] = state["buffer"][:-1]

    @kb.add("enter", filter=edit)
    def _(event) -> None:  # noqa: ANN001
        item = _current()
        validation = _int_validator(state["buffer"])
        if validation is not True:
            state["status"] = str(validation)
            state["status_error"] = True
            return
        value = int(state["buffer"])
        cfg[item["table"]][item["key"]] = value
        state["editing"] = False
        state["buffer"] = ""
        _save(f"{item['label']} = {value}")

    @kb.add("escape", filter=edit)
    @kb.add("c-c", filter=edit)
    def _(event) -> None:  # noqa: ANN001
        state["editing"] = False
        state["buffer"] = ""
        state["status"] = "Edit cancelled"
        state["status_error"] = False

    app = Application(
        layout=Layout(HSplit([
            Window(
                FormattedTextControl(_render, focusable=True, show_cursor=False),
                always_hide_cursor=True,
            ),
        ])),
        key_bindings=kb,
        full_screen=False,
        mouse_support=False,
        erase_when_done=True,
    )
    try:
        return app.run()
    except KeyboardInterrupt:
        return None


def _choose_output_directory() -> str | None:
    """Choose a real-target output root, starting from the user's home.

    macOS gets its native folder chooser, including the standard New Folder
    button and Shift-Command-N shortcut. Other environments use the terminal
    browser below, which supports navigation and folder creation without
    requiring a full path to be typed.
    """
    if sys.platform == "darwin" and shutil.which("osascript"):
        _console.print(
            "[dim]Opening the folder chooser at your home directory. "
            "Create a folder with Shift+Command+N.[/dim]"
        )
        script = (
            'set selectedFolder to choose folder with prompt '
            '"Choose where SwarmAttacker should save real-target runs" '
            'default location (path to home folder)\n'
            'return POSIX path of selectedFolder'
        )
        completed = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            return str(Path(completed.stdout.strip()).expanduser().resolve())
        error = completed.stderr.strip()
        if "User canceled" in error or "(-128)" in error:
            return None
        _console.print(
            "[yellow]Native folder chooser was unavailable; "
            "using the terminal browser.[/yellow]"
        )

    return _terminal_directory_browser()


def _terminal_directory_browser(
    *,
    start: Path | None = None,
    allow_create: bool = True,
    title: str = "Live output folder",
) -> str | None:
    """Browse directories in-terminal, optionally permitting folder creation."""
    home = Path.home().expanduser().resolve()
    initial = Path(start).expanduser().resolve() if start else home
    current = initial if initial.is_dir() else home

    while True:
        try:
            directories = sorted(
                (entry for entry in current.iterdir() if entry.is_dir()),
                key=lambda entry: (entry.name.startswith("."), entry.name.casefold()),
            )
        except OSError as exc:
            _console.print(f"[yellow]Cannot open {current}: {exc}[/yellow]")
            current = home
            directories = []

        choices: list[Choice] = [
            Choice("✓  Use this folder", value="__use__", shortcut_key="u"),
        ]
        if allow_create:
            choices.append(
                Choice("＋  Create a new folder", value="__create__", shortcut_key="n")
            )
        choices.extend([
            Choice("⌂  Go to home", value="__home__", shortcut_key="h"),
            Choice("↑  Go to parent", value="__parent__", shortcut_key="b"),
            Choice("─" * 46, value="__sep__", disabled="—", shortcut_key=False),
        ])
        choices.extend(
            Choice(
                f"📁 {entry.name}",
                value=str(entry),
                shortcut_key=False,
            )
            for entry in directories
        )

        picked = questionary.select(
            f"{title}\n{current}",
            choices=choices,
            instruction=(
                "(Enter opens; U use; "
                + ("N new folder; " if allow_create else "")
                + "H home; B parent; "
                "type to search; Ctrl-C cancels)"
            ),
            style=_PROMPT_STYLE,
            use_shortcuts=True,
            use_jk_keys=False,
            use_search_filter=True,
        ).ask()
        if picked is None:
            return None
        if picked == "__use__":
            return str(current)
        if picked == "__home__":
            current = home
            continue
        if picked == "__parent__":
            current = current.parent
            continue
        if picked == "__sep__":
            continue
        if picked == "__create__":
            def _valid_folder_name(value: str) -> bool | str:
                name = value.strip()
                if not name:
                    return "Folder name must not be empty."
                if name in {".", ".."} or "/" in name or "\x00" in name:
                    return "Use a single folder name, not a path."
                if (current / name).exists():
                    return "A file or folder with that name already exists."
                return True

            name = questionary.text(
                "New folder name:",
                validate=_valid_folder_name,
                instruction="(created inside the folder shown above; Ctrl-C cancels)",
                style=_PROMPT_STYLE,
            ).ask()
            if name is None:
                continue
            new_directory = current / name.strip()
            try:
                new_directory.mkdir()
            except OSError as exc:
                _console.print(
                    f"[yellow]Could not create {new_directory}: {exc}[/yellow]"
                )
                continue
            current = new_directory.resolve()
            continue

        current = Path(str(picked)).expanduser().resolve()


def _int_validator(text: str) -> bool | str:
    """questionary validator — must be a positive int."""
    s = text.strip()
    if not s:
        return "Empty — type a positive integer."
    try:
        n = int(s)
    except ValueError:
        return "Not an integer."
    if n <= 0:
        return "Must be > 0."
    return True
