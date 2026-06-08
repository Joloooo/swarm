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
from typing import Any

import questionary
from prompt_toolkit.application import Application, get_app
from prompt_toolkit.filters import Condition
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
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

    # Materialize swarm-config.toml in full (fills a missing/partial file,
    # keeping any existing values) so it always shows every knob. The values
    # themselves are read straight from the file by src.graph at run time.
    config_store.ensure_complete()

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
        Choice("Codex usage (5-hour / weekly) — fetch live", value="__codex_usage__"),
        Choice("xbow benchmark  (run one, a selection, or all — sequential or concurrent)", value="xbow"),
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
# Width kept after each label for its trailing annotation — whichever is
# shown: the " [NNN]" per-slice run-order number (selected) or the last-run
# solve time " (Xm Ys)" (unselected). 10 covers " (20m 00s)".
_SUFFIX_RESERVE = 10

# How many selected benchmarks the header lists by name before collapsing to
# a "selected: N of M" count line (listing 100 ids would wrap off-screen).
_QUEUE_PREVIEW = 8

# Colour of the vulnerability tags in each row's label (the part after the
# id). Always shown for an *unselected* benchmark so you can scan vuln classes
# at rest; a selected benchmark takes its slice colour instead (see below).
_TAG_STYLE = "fg:ansibrightblue"

# Per-slice colours for the run sequence(s). The selected set runs as
# ``concurrency`` contiguous slices (each its own Terminal window, each running
# its benchmarks in sequence), so each slice is drawn in its own colour with
# its own 1..N numbering: concurrency 1 → one green sequence; 2 → green +
# yellow; more → cycle this list. Red is excluded (it's the ✗ fail mark), and
# adjacent slices always differ since slices take consecutive colours.
_SLICE_COLORS = (
    "ansigreen", "ansiyellow", "ansicyan", "ansimagenta", "ansiblue",
    "ansibrightgreen", "ansibrightyellow", "ansibrightcyan",
    "ansibrightmagenta", "ansibrightblue",
)


def _slice_color(slice_idx: int) -> str:
    """The colour name for slice ``slice_idx`` (cycles :data:`_SLICE_COLORS`)."""
    return _SLICE_COLORS[slice_idx % len(_SLICE_COLORS)]


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
    slice_info: tuple[int, int] | None,
    duration_s: float | None,
    is_cursor: bool,
    content_w: int,
) -> list[tuple[str, str]]:
    """Formatted-text segments for one grid cell, padded to ``content_w``.

    The ✓/✗/~ result mark is coloured. The label is the id base (``XBEN-004-``)
    plus its vulnerability ``tags_str`` (``xss``). A benchmark that is selected
    for a run carries ``slice_info`` = ``(slice_index, position_in_slice)``:
    the whole label is drawn in that slice's colour with a ``[position]``
    suffix, so each concurrent slice reads as its own coloured 1..N sequence.
    An unselected benchmark keeps a default-coloured base with its tags in
    :data:`_TAG_STYLE`, followed by its last run's solve time ``(Xm Ys)`` in
    dim when ``duration_s`` is known (the slice ``[position]`` takes that slot
    while selected). The whole cell is reverse-video when it is the pointed-at
    benchmark, so the cursor reads as a highlighted bar.
    """
    if result == bench_results.OK:
        segs = [("fg:ansigreen bold", "✓"), ("", " ")]
    elif result == bench_results.FAIL:
        segs = [("fg:ansired bold", "✗"), ("", " ")]
    elif result == bench_results.API:
        segs = [("fg:ansiyellow bold", "~"), ("", " ")]
    else:
        segs = [("", "  ")]
    if slice_info is not None:
        # Selected → whole label + position in the slice's colour.
        style = f"fg:{_slice_color(slice_info[0])} bold"
        segs.append((style, base + tags_str))
        segs.append((style, f" [{slice_info[1]}]"))
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
              codex/API or infra crash with no fair attempt.
      ``r`` — select / unselect the highlighted benchmark. The selected set
              runs as ``concurrency`` contiguous slices, each drawn in its own
              colour with its own 1..N run-order numbering.
      ``a`` — select all / unselect all (toggle).
      ``f`` — select every ✗-failed benchmark / unselect (toggle) — handy for
              re-running just the failures.
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
            "Benchmarks/xbow-validation[/bold]."
        )
        return None

    results = bench_results.load()
    # Last-run solve time per benchmark, read once from the result logs (old
    # runs included). Shown dim next to each ✓/✗/~ mark.
    durations = bench_results.load_last_durations()
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

    def _slice_map() -> dict[str, tuple[int, int]]:
        """``{bench_id: (slice_index, position_in_slice)}`` for the selection.

        Splits the queue into ``concurrency`` contiguous slices using the SAME
        function the campaign launcher uses (``launch_split.split_contiguous``),
        so the coloured sequences shown here are exactly the windows that will
        run. Position is 1-based within each slice. Empty when nothing is
        selected. Cheap (≤104 items), recomputed each render so it tracks
        ``r``/``a``/``c`` live.
        """
        if not queue:
            return {}
        from benchmarks.launch_split import split_contiguous
        conc = max(1, min(state["concurrency"], len(queue)))
        out: dict[str, tuple[int, int]] = {}
        for slice_idx, sl in enumerate(split_contiguous(queue, conc)):
            for pos, bid in enumerate(sl, 1):
                out[bid] = (slice_idx, pos)
        return out

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
        # The selection split into coloured slices, computed once per render.
        smap = _slice_map()
        list_sel = len(queue) <= _QUEUE_PREVIEW   # list ids vs. count in header
        out: list[tuple[str, str]] = [
            ("bold", "Which benchmark(s) do you want to run?"),
            ("fg:ansibrightblack", f"   ({n} benchmarks)\n"),
            ("fg:ansigreen bold", f"   ✓ {n_ok} solved"),
            ("fg:ansibrightblack", "  ·  "),
            ("fg:ansired bold", f"✗ {n_fail} failed"),
            ("fg:ansibrightblack", "  ·  "),
            ("fg:ansiyellow bold", f"~ {n_api} crashed"),
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
            "↑/↓/←/→ move · r select · a all/none · f failed · t mark ✓/✗/~ · "
            "c concurrency · enter run · q/Ctrl-C back\n",
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
                    f"  → split into {max(1, min(state['concurrency'], len(queue)))} "
                    f"coloured slice(s)\n",
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
                    smap.get(bench_id), durations.get(bench_id),
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
            # The next benchmark run reads swarm-config.toml directly via
            # src.graph (each run is a fresh subprocess), so writing the file
            # is all that's needed — no env re-injection.
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
        elif action == "web_synth_model":
            _select_into(cfg, "model", "web_search_synth_model",
                         "Web-search synthesis model:",
                         config_store.WEB_SYNTH_MODEL_CHOICES)
        elif action == "web_synth_effort":
            _select_into(cfg, "model", "web_search_synth_reasoning_effort",
                         "Web-search synthesis effort:",
                         config_store.WEB_SYNTH_EFFORT_CHOICES)
        elif action == "verbosity":
            _select_into(cfg, "verbosity", "mode",
                         "Verbosity:", config_store.VERBOSITY_CHOICES)


def _config_top(cfg: dict[str, dict[str, Any]]) -> str | None:
    """Print the config menu with current values inlined into each label."""
    b = cfg["budgets"]
    budgets_summary = (
        f"planner={b['planner_max_iters']} "
        f"worker={b['worker_max_iterations']} "
        f"llm-tokens={b['llm_max_tokens']} "
        f"timeout={b.get('run_timeout_s', 1200) // 60}m"
    )

    choices = [
        Choice(f"Budgets…     {budgets_summary}",                 value="budgets"),
        Choice(f"Model        {cfg['model']['slug']}",            value="model_slug"),
        Choice(f"Reasoning effort   {cfg['model']['reasoning_effort']}",   value="reasoning_effort"),
        Choice(f"Reasoning summary  {cfg['model']['reasoning_summary']}",  value="reasoning_summary"),
        Choice(f"Web-search synth model   {cfg['model']['web_search_synth_model']}", value="web_synth_model"),
        Choice(f"Web-search synth effort  {cfg['model']['web_search_synth_reasoning_effort']}", value="web_synth_effort"),
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
    """Int prompts for the budget knobs, in a loop."""
    keys: list[tuple[str, str]] = [
        ("planner_max_iters",            "Planner max iterations"),
        ("worker_max_iterations",        "Worker max iterations"),
        ("llm_max_tokens",               "LLM max output tokens (per call)"),
        ("run_timeout_s",                "Agent timeout/benchmark — sec (1200=20m, 2400=40m)"),
    ]
    while True:
        labels: list[Choice] = [
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
