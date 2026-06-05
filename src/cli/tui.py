"""Interactive ``swarm`` menu — questionary main loop + nested config editor.

Invoked by :func:`src.cli.__init__.main` when the user runs ``swarm``
with no positional argument and no benchmark shortcut. The flow:

  1. Print the rich banner (project name + config-file path).
  2. ``config_store.load_into_env()`` — TOML → ``os.environ``, with
     override warnings shown under the banner.
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
from typing import Any

import questionary
from prompt_toolkit.application import Application, get_app
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from questionary import Choice
from rich.console import Console

from src.cli import (
    banner,
    bench_discovery,
    bench_results,
    config_store,
    docker_boot,
    runner,
)


_console = Console(stderr=True)


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
    banner.show(config_store.path())

    # Apply persistent config to env, surfacing any shell-shadow overrides.
    for msg in config_store.load_into_env(override=True):
        _console.print(f"[yellow]·[/yellow] {msg}")

    while True:
        action = _top_level()
        if action is None or action == "quit":
            _console.print("[dim]👋 bye[/dim]")
            return

        # Fetch + show live 5h/weekly Codex usage for the ~/.codex login.
        # Read-only (no quota used). See codex_usage.
        if action == "__codex_usage__":
            _show_codex_usage()
            continue

        if action == "xbow":
            run_list = _pick_bench()
            if not run_list:
                continue
            if not _ensure_docker(args):
                continue
            runner.run_queue(run_list)
        elif action == "campaign":
            _run_campaign(args)
        elif action == "config":
            _config_menu()


def _run_campaign(args: argparse.Namespace) -> None:
    """Fan the full XBEN set out across N parallel Terminal windows.

    Asks how many concurrent windows, bootstraps Docker, then hands off to
    :func:`benchmarks.launch_split.launch_campaign`, which opens one
    Terminal window per slice and turns THIS terminal into a live dashboard
    until every window finishes. Each window inherits the run config because
    launch_campaign forwards the session's ``SWARM_*`` env (the picker run
    path relies on the same inheritance).

    Imported lazily so the TUI's normal startup stays light and the
    benchmarks package isn't pulled in unless a campaign is actually run.
    """
    answer = questionary.text(
        "How many benchmarks to run at once (concurrent Terminal windows)?",
        default="20",
        validate=_int_validator,
        instruction="(all benchmarks are split across this many windows; Ctrl-C cancels)",
    ).ask()
    if answer is None:
        return
    jobs = int(answer)
    if not _ensure_docker(args):
        return
    _console.print(
        f"[cyan]Launching {jobs} concurrent Terminal window(s) over all "
        f"benchmarks — this terminal becomes the live dashboard.[/cyan]"
    )
    from benchmarks.launch_split import launch_campaign
    try:
        launch_campaign(jobs=jobs, wait=True)
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
        Choice("Codex usage (5-hour / weekly) — fetch live", value="__codex_usage__"),
        Choice("xbow benchmark  (pick one or queue several to run in order)", value="xbow"),
        Choice("Run ALL benchmarks concurrently  (fan out across N Terminal windows)", value="campaign"),
        Choice("Edit config",                                                 value="config"),
        Choice("Quit",                                                        value="quit"),
    ]

    question = questionary.select(
        "What do you want to do?",
        choices=choices,
        use_shortcuts=False,
        instruction="(use ↑/↓, enter to confirm, Ctrl-C to quit)",
    )
    return question.ask()


def _show_codex_usage() -> None:
    """Fetch and print live 5-hour + weekly Codex usage for the ~/.codex login.

    Read-only — hits the wham/usage status endpoint (no model quota
    consumed). Lazy-imports :mod:`src.cli.codex_usage` so the TUI's normal
    startup stays light.
    """
    from rich.table import Table

    from src.cli import codex_usage

    _console.print("[dim]Fetching Codex usage… (read-only; no quota used)[/dim]")

    table = Table(show_header=True, header_style="bold", title="Codex usage")
    table.add_column("Account")
    table.add_column("Plan")
    table.add_column("5-hour", justify="right")
    table.add_column("5h resets")
    table.add_column("Weekly", justify="right")
    table.add_column("Weekly resets")
    table.add_column("Credits")

    def _pct(window) -> str:  # noqa: ANN001
        if window is None:
            return "—"
        p = window.used_percent
        colour = "red" if p >= 80 else "yellow" if p >= 50 else "green"
        return f"[{colour}]{p:g}%[/{colour}]"

    try:
        u = codex_usage.fetch()
        table.add_row(
            (u.email or "~/.codex"),
            (u.plan_type or "?"),
            _pct(u.primary),
            u.primary.reset_human if u.primary else "—",
            _pct(u.secondary),
            u.secondary.reset_human if u.secondary else "—",
            (u.credits_balance if u.has_credits else "—"),
        )
    except codex_usage.CodexAccountAuthError:
        table.add_row("~/.codex", "[red]revoked[/red]", "—", "—", "—", "—",
                      "[red]re-login (codex login)[/red]")
    except Exception as e:  # noqa: BLE001
        table.add_row("~/.codex", "[red]error[/red]", "—", "—", "—", "—",
                      f"[red]{type(e).__name__}[/red]")

    _console.print(table)
    _console.print("[dim][enter] to return to the menu…[/dim]", end=" ")
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
_SUFFIX_RESERVE = 5  # width kept for the green " [N]" run-order suffix


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
    bench_id: str,
    result: str | None,
    queue_pos: int | None,
    selected: bool,
    content_w: int,
) -> list[tuple[str, str]]:
    """Formatted-text segments for one grid cell, padded to ``content_w``.

    The ✓/✗/~ result mark is coloured, the ``[N]`` run-order suffix is
    green, and the whole cell is drawn in reverse video when it is the
    pointed-at benchmark (so the cursor reads as a highlighted bar).
    """
    if result == bench_results.OK:
        segs = [("fg:ansigreen bold", "✓"), ("", " ")]
    elif result == bench_results.FAIL:
        segs = [("fg:ansired bold", "✗"), ("", " ")]
    elif result == bench_results.API:
        segs = [("fg:ansiyellow bold", "~"), ("", " ")]
    else:
        segs = [("", "  ")]
    segs.append(("", bench_id))
    if queue_pos is not None:
        segs.append(("fg:ansibrightgreen bold", f" [{queue_pos}]"))
    used = sum(len(text) for _, text in segs)
    if used < content_w:
        segs.append(("", " " * (content_w - used)))
    if selected:
        segs = [((style + " reverse").strip(), text) for style, text in segs]
    return segs


def _pick_bench() -> list[str] | None:
    """Let the user pick one benchmark — or queue several to run in order.

    Every XBEN-*-24 benchmark on disk is shown in a column grid (filled
    column-major, navigated with the arrow keys), each annotated with its
    manual ✓/✗/~ triage mark from ``benchmarks/bench_results.json``. Two
    keys act on the highlighted cell:

      ``t`` — cycle the result mark ✓ → ✗ → ~ → none (persisted
              immediately). ✓ solved, ✗ genuinely failed, ~ (yellow)
              codex/API or infra crash with no fair attempt.
      ``r`` — add / remove the benchmark from an ordered run queue, shown
              as a green ``[1]`` / ``[2]`` suffix in run order.

    Returns the ordered list of benchmark ids to run:

      * a non-empty queue → that queue, in the order it was built;
      * an empty queue    → just the highlighted cell at ``enter``;
      * ``None``          → the user backed out (q / Ctrl-C) or the
                            submodule is missing.

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
            "Benchmarks/xbow-validation[/bold]."
        )
        return None

    results = bench_results.load()
    queue: list[str] = []        # ordered run queue, built live with ``r``.
    state = {"cursor": 0}        # flat index into ``ids`` of the pointed-at cell.
    n = len(ids)
    content_w = 2 + max(len(b) for b in ids) + _SUFFIX_RESERVE

    def _width() -> int:
        try:
            return get_app().output.get_size().columns or 80
        except Exception:  # noqa: BLE001 — size unavailable → safe default
            return 80

    def _dims() -> tuple[int, int]:
        return _grid_dims(n, _width(), content_w)

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
        out: list[tuple[str, str]] = [
            ("bold", "Which benchmark(s) do you want to run?"),
            ("fg:ansibrightblack", f"   ({n} benchmarks)\n"),
            ("fg:ansigreen bold", f"   ✓ {n_ok} solved"),
            ("fg:ansibrightblack", "  ·  "),
            ("fg:ansired bold", f"✗ {n_fail} failed"),
            ("fg:ansibrightblack", "  ·  "),
            ("fg:ansiyellow bold", f"~ {n_api} crashed"),
            ("fg:ansibrightblack", f"  ·  {n_none} unmarked\n"),
            ("fg:ansibrightblack",
             "↑/↓/←/→ move · r queue/unqueue · t mark ✓/✗/~ · "
             "enter run · q/Ctrl-C back\n"),
        ]
        if queue:
            out.append(("fg:ansibrightgreen bold", f"queue ({len(queue)}): "))
            out.append(("fg:ansibrightgreen", " → ".join(queue) + "\n"))
        else:
            out.append(("fg:ansibrightblack",
                        f"nothing queued — enter runs {cur_id}\n"))
        out.append(("", "\n"))
        for r in range(rows):
            for c in range(cols):
                i = c * rows + r
                if i >= n:
                    continue
                bench_id = ids[i]
                pos = queue.index(bench_id) + 1 if bench_id in queue else None
                out.extend(_cell_segments(
                    bench_id, results.get(bench_id), pos,
                    i == state["cursor"], content_w,
                ))
                if c != cols - 1:
                    out.append(("", " " * _GAP))
            out.append(("", "\n"))
        return out

    kb = KeyBindings()

    @kb.add("up", eager=True)
    @kb.add("k", eager=True)
    def _(event) -> None:  # noqa: ANN001 (prompt_toolkit event)
        _move(-1, 0)

    @kb.add("down", eager=True)
    @kb.add("j", eager=True)
    def _(event) -> None:  # noqa: ANN001
        _move(1, 0)

    @kb.add("left", eager=True)
    @kb.add("h", eager=True)
    def _(event) -> None:  # noqa: ANN001
        _move(0, -1)

    @kb.add("right", eager=True)
    @kb.add("l", eager=True)
    def _(event) -> None:  # noqa: ANN001
        _move(0, 1)

    @kb.add("t", eager=True)
    def _(event) -> None:  # noqa: ANN001
        bench_id = ids[state["cursor"]]
        bench_results.cycle(results, bench_id)
        bench_results.save(results)

    @kb.add("r", eager=True)
    def _(event) -> None:  # noqa: ANN001
        bench_id = ids[state["cursor"]]
        if bench_id in queue:
            queue.remove(bench_id)
        else:
            queue.append(bench_id)

    @kb.add("enter")
    def _(event) -> None:  # noqa: ANN001
        event.app.exit(result=list(queue) if queue else [ids[state["cursor"]]])

    @kb.add("q")
    @kb.add("c-c")
    def _(event) -> None:  # noqa: ANN001
        event.app.exit(result=None)

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

def _config_menu() -> None:
    """Loop the edit-config menu until the user saves or discards.

    Working copy lives in ``cfg`` (a plain dict-of-dicts). Only on
    "Save & back" is it flushed to disk via ``config_store.save`` and
    re-injected into ``os.environ`` so subsequent subprocess runs in
    the same session see the new values immediately.
    """
    cfg = config_store.get_current_view()

    while True:
        action = _config_top(cfg)
        if action is None:
            # Ctrl-C inside the config menu → treat like "Discard" so the
            # user can't accidentally save partial edits.
            _console.print("[dim]Config edits discarded.[/dim]")
            return
        if action == "save":
            config_store.save(cfg)
            # Re-inject so the next benchmark run in this session sees
            # the new values. (Subprocesses inherit env via os.environ.)
            for msg in config_store.load_into_env(override=True):
                _console.print(f"[yellow]·[/yellow] {msg}")
            _console.print(f"[green]Saved → {config_store.path()}[/green]")
            return
        if action == "discard":
            _console.print("[dim]Config edits discarded.[/dim]")
            return
        if action == "budgets":
            _budgets_submenu(cfg)
        elif action == "model_slug":
            _select_into(cfg, "model", "slug",
                         "Model:", config_store.MODEL_CHOICES)
        elif action == "reasoning_effort":
            _select_into(cfg, "model", "reasoning_effort",
                         "Reasoning effort:", config_store.REASONING_EFFORT_CHOICES)
        elif action == "reasoning_summary":
            _select_into(cfg, "model", "reasoning_summary",
                         "Reasoning summary:", config_store.REASONING_SUMMARY_CHOICES)
        elif action == "verbosity":
            _select_into(cfg, "verbosity", "mode",
                         "Verbosity:", config_store.VERBOSITY_CHOICES)


def _config_top(cfg: dict[str, dict[str, Any]]) -> str | None:
    """Print the config menu with current values inlined into each label."""
    b = cfg["budgets"]
    budgets_summary = (
        f"planner={b['planner_max_iters']} "
        f"worker={b['worker_max_iterations']} "
        f"custom-tools={b['custom_attack_max_tool_calls']} "
        f"custom-iter={b['custom_attack_max_iterations']} "
        f"llm-tokens={b['llm_max_tokens']} "
        f"web-chars={b['web_search_max_crawled_chars']} "
        f"escalation={'on' if b.get('escalation_enabled', True) else 'off'}"
        f"@{b.get('escalation_fork_after_iters', 3)}it/"
        f"{b.get('escalation_fork_after_seconds', 600)}s"
    )

    choices = [
        Choice(f"Budgets…     {budgets_summary}",                 value="budgets"),
        Choice(f"Model        {cfg['model']['slug']}",            value="model_slug"),
        Choice(f"Reasoning effort   {cfg['model']['reasoning_effort']}",   value="reasoning_effort"),
        Choice(f"Reasoning summary  {cfg['model']['reasoning_summary']}",  value="reasoning_summary"),
        Choice(f"Verbosity    {cfg['verbosity']['mode']}",        value="verbosity"),
        Choice("─" * 40,                                          value="__sep__", disabled="—"),
        Choice("Save & back",                                     value="save"),
        Choice("Discard & back",                                  value="discard"),
    ]
    return questionary.select(
        "Edit config — current values shown inline",
        choices=choices,
        instruction="(enter to edit / save / discard, Ctrl-C discards)",
    ).ask()


def _budgets_submenu(cfg: dict[str, dict[str, Any]]) -> None:
    """Int prompts + the dual-planner escalation on/off toggle, in a loop."""
    keys: list[tuple[str, str]] = [
        ("planner_max_iters",            "Planner max iterations"),
        ("worker_max_iterations",        "Worker max iterations"),
        ("custom_attack_max_tool_calls", "Custom-skill max tool calls"),
        ("custom_attack_max_iterations", "Custom-skill max iterations"),
        ("llm_max_tokens",               "LLM max output tokens (per call)"),
        ("web_search_max_crawled_chars", "Web-search max chars per source"),
        ("escalation_fork_after_iters",  "Escalation: fork 2nd planner after N planner turns"),
        ("escalation_fork_after_seconds", "Escalation: fork 2nd planner after N seconds (OR trigger)"),
    ]
    while True:
        # The escalation switch is a bool, so it toggles on select instead
        # of prompting for an int. Shown first so it's easy to find.
        enabled = bool(cfg["budgets"].get("escalation_enabled", True))
        labels: list[Choice] = [
            Choice(
                f"{'Escalation (dual planner) on/off':<52s} "
                f"{'on' if enabled else 'off'}",
                value="escalation_enabled",
            )
        ]
        labels += [
            Choice(f"{label:<52s} {cfg['budgets'][key]}", value=key)
            for key, label in keys
        ]
        labels.append(Choice("← Back", value="__back__"))

        which = questionary.select(
            "Budgets — which to edit?",
            choices=labels,
            instruction="(Ctrl-C goes back)",
        ).ask()
        if which is None or which == "__back__":
            return

        # Bool toggle — flip and redraw, no text prompt.
        if which == "escalation_enabled":
            cfg["budgets"]["escalation_enabled"] = not enabled
            continue

        label = next(lbl for k, lbl in keys if k == which)
        new = questionary.text(
            f"{label}:",
            default=str(cfg["budgets"][which]),
            validate=_int_validator,
        ).ask()
        if new is None:
            # Ctrl-C on the input → cancel just this edit, keep menu open.
            continue
        cfg["budgets"][which] = int(new)


def _select_into(
    cfg: dict[str, dict[str, Any]],
    table: str,
    key: str,
    prompt: str,
    choices: tuple[str, ...],
) -> None:
    """Show a `questionary.select` and assign the picked value into cfg."""
    current = cfg[table][key]
    picked = questionary.select(
        prompt,
        choices=list(choices),
        default=current if current in choices else None,
        instruction="(Ctrl-C cancels)",
    ).ask()
    if picked is not None:
        cfg[table][key] = picked


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
