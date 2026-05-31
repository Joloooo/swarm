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
called right before a benchmark action is dispatched (Pentest 1 /
15 daily / 15 silent / all). The menu itself, config edits, and
Quit never trigger Docker Desktop — SwarmAttacker only needs Docker
when running pentest containers. ``--no-docker`` still skips the
bootstrap even for benchmark actions (useful on remote VMs).

Ctrl-C policy: ``questionary.select`` returns ``None`` when the user
hits Ctrl-C. We treat that as "go back one level" rather than
crashing, so the user can always escape a submenu without losing
their session.
"""

from __future__ import annotations

import argparse
from typing import Any

import questionary
from questionary import Choice
from questionary.prompts.common import InquirerControl
from rich.console import Console

from src.cli import (
    banner,
    bench_discovery,
    bench_results,
    codex_accounts,
    config_store,
    docker_boot,
    runner,
)
from src.cli.bench_discovery import count_all


_console = Console(stderr=True)


# How many benchmarks to surface in the single-container picker (sorted
# by id, capped). Bump this when you start running deeper into the
# XBEN catalogue.
_PICKER_LIMIT = 50

# The ✓/✗ marks next to each benchmark are *manual triage state* — you
# set them yourself by pressing ``t`` in the picker to cycle the
# highlighted row through ✓ → ✗ → no-mark. They persist in
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

        # TEMPORARY emergency affordance: Enter (or Tab) on the Codex-account
        # row cycles the live login. Re-loop so the menu redraws with the new
        # active account. See _bind_account_tab / src.cli.codex_accounts.
        if action == "__codex_switch__":
            new = codex_accounts.cycle()
            if new:
                _console.print(f"[cyan]🔑 Codex account → {new}[/cyan]")
            continue

        if action == "xbow":
            run_list = _pick_bench()
            if not run_list:
                continue
            if not _ensure_docker(args):
                continue
            runner.run_queue(run_list)
        elif action == "first5_patched":
            if not _ensure_docker(args):
                continue
            runner.run_first5_patched()
        elif action == "daily_compact":
            if not _ensure_docker(args):
                continue
            runner.run_daily(silent=False)
        elif action == "daily_silent":
            if not _ensure_docker(args):
                continue
            runner.run_daily(silent=True)
        elif action == "all":
            if not _ensure_docker(args):
                continue
            runner.run_all()
        elif action == "config":
            _config_menu()


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
    n_all = count_all()
    all_label = (
        f"Pentest all {n_all} XBEN benchmarks"
        if n_all
        else "Pentest all XBEN benchmarks  (submodule not initialised)"
    )

    # TEMPORARY emergency Codex-account switcher row. Always shown (the main
    # login always exists); Tab cycles main → extra accounts. Fully additive
    # — remove this row + the helpers below and the menu is unchanged.
    choices: list[Choice] = [
        Choice(_account_label(), value="__codex_switch__"),
        Choice("xbow benchmark  (pick one or queue several to run in order)",    value="xbow"),
        Choice("Pentest first 5 patched (XBEN-001 to 005, bit-rot fixes first)", value="first5_patched"),
        Choice("Pentest 15 containers (daily, compact)",                         value="daily_compact"),
        Choice("Pentest 15 containers (daily, silent)",                          value="daily_silent"),
        Choice(all_label,                                                        value="all", disabled=None if n_all else "submodule missing"),
        Choice("Edit config",                                                    value="config"),
        Choice("Quit",                                                           value="quit"),
    ]

    question = questionary.select(
        "What do you want to do?",
        choices=choices,
        use_shortcuts=False,
        instruction="(use ↑/↓, enter to confirm, Ctrl-C to quit)  ·  Tab: switch Codex account",
    )
    _bind_account_tab(question)
    return question.ask()


# ---------------------------------------------------------------------------
# TEMPORARY emergency Codex-account switcher (Tab on the top-level menu)
# ---------------------------------------------------------------------------

def _account_label() -> list[tuple[str, str]]:
    """Title for the Codex-account row — selected account + the cycle set.

    Rebuilt live on every Tab press (see :func:`_bind_account_tab`) so the
    user always sees which OAuth token the next run will use. The account_id
    tail disambiguates even before the main login is renamed.
    """
    sel = codex_accounts.selected()
    names = codex_accounts.order()
    segs: list[tuple[str, str]] = [("fg:ansiyellow bold", "🔑 Codex account: ")]
    segs.append(("fg:ansibrightcyan bold", codex_accounts.display_name(sel)))
    acc = codex_accounts.account_id(sel)
    if acc:
        segs.append(("fg:ansibrightblack", f"  …{acc[-6:]}"))
    if len(names) >= 2:
        segs.append(("", "   ·  Tab/enter to switch  "))
        segs.append((
            "fg:ansibrightblack",
            "[" + " · ".join(codex_accounts.display_name(n) for n in names) + "]",
        ))
    else:
        segs.append(("fg:ansibrightblack", "   ·  (no extra accounts yet — capture one)"))
    return segs


def _bind_account_tab(question: questionary.Question) -> None:
    """Bind Tab on the top-level menu to cycle the active Codex account.

    Swaps ~/.codex/auth.json between the snapshots in ~/.codex-accounts/
    via :mod:`src.cli.codex_accounts`, then rebuilds the account row's
    label and redraws — so switching happens without leaving the menu.
    Mirrors the reach-into-the-app pattern used by :func:`_bind_keys`.
    """
    app = question.application
    ic = next(
        c
        for c in app.layout.find_all_controls()
        if isinstance(c, InquirerControl)
    )

    @app.key_bindings.add("tab", eager=True)
    def _switch(event) -> None:  # noqa: ANN001 (prompt_toolkit event)
        codex_accounts.cycle()
        for choice in ic.choices:
            if choice.value == "__codex_switch__":
                choice.title = _account_label()
        app.invalidate()


# ---------------------------------------------------------------------------
# Single-benchmark picker
# ---------------------------------------------------------------------------

# Multi-line key legend shown under the question. questionary renders
# the ``instruction`` string as part of the prompt block (above the
# rows) and redraws it every frame, so a bulleted block here stays
# visible and pinned to the question no matter how the list scrolls.
_PICKER_LEGEND = (
    "\n"
    "   • ↑/↓      move\n"
    "   • r        queue / unqueue  →  runs 1st, 2nd, 3rd … in that order\n"
    "   • t        mark result  →  ✓ ok · ✗ fail · none\n"
    "   • enter    run the queue  (or just the highlighted row if nothing is queued)\n"
    "   • Ctrl-C   back"
)


def _pick_bench() -> list[str] | None:
    """Let the user pick one benchmark — or queue several to run in order.

    Lists the first ``_PICKER_LIMIT`` XBEN benchmarks (sorted by id),
    each annotated with its manual ✓/✗ triage mark (from
    ``benchmarks/bench_results.json``). Two keys act on the highlighted
    row (see :func:`_bind_keys`):

      ``t`` — cycle the result mark ✓ → ✗ → none (persisted).
      ``r`` — add / remove the benchmark from an ordered run queue,
              shown as a green ``▸ 1st run`` / ``▸ 2nd run`` suffix.

    Returns the ordered list of benchmark ids to run:

      * a non-empty queue → that queue, in the order it was built;
      * an empty queue    → just the highlighted row at ``enter``;
      * ``None``          → the user backed out (Ctrl-C / "Back") or
                            the submodule is missing.
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
    queue: list[str] = []  # ordered run queue, built live with ``r``.

    choices = [
        Choice(title=_bench_label(bench_id, results.get(bench_id), None), value=bench_id)
        for bench_id in ids
    ]
    choices.append(Choice("← Back", value="__back__"))

    question = questionary.select(
        "Which benchmark(s) do you want to run?",
        choices=choices,
        instruction=_PICKER_LEGEND,
    )
    _bind_keys(question, results, queue)

    picked = question.ask()
    if picked is None or picked == "__back__":
        return None
    return list(queue) if queue else [picked]


def _ordinal(n: int) -> str:
    """1 → ``1st``, 2 → ``2nd``, 3 → ``3rd``, 4 → ``4th``, 11 → ``11th`` …"""
    if 10 <= (n % 100) <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


# prompt_toolkit formatted-text segments. questionary.Choice.title
# accepts a list of (style, text) tuples; we use that to colour the
# ✓ / ✗ result mark and the green run-order suffix while leaving the
# benchmark id in the terminal default.
def _bench_label(
    bench_id: str, result: str | None, queue_pos: int | None
) -> list[tuple[str, str]]:
    if result == bench_results.OK:
        mark = ("fg:ansigreen bold", "✓")
    elif result == bench_results.FAIL:
        mark = ("fg:ansired bold", "✗")
    else:
        mark = ("", " ")
    segments = [mark, ("", f"  {bench_id}")]
    if queue_pos is not None:
        segments.append(("fg:ansibrightgreen bold", f"   ▸ {_ordinal(queue_pos)} run"))
    return segments


def _bind_keys(
    question: questionary.Question,
    results: dict[str, str],
    queue: list[str],
) -> None:
    """Wire ``t`` (cycle result mark) and ``r`` (queue / unqueue) into the picker.

    ``questionary.select`` builds a prompt_toolkit ``Application`` but
    exposes no hook for extra key bindings, so we reach into the
    finished app: locate its ``InquirerControl`` (the control that
    renders the rows), then register the two keys against the
    pointed-at benchmark.

      ``t`` cycles the result mark nothing → ✓ → ✗ and persists it to
            ``bench_results.json``.
      ``r`` appends the benchmark to ``queue`` (or removes it if already
            queued); the queue's order is the run order.

    After either key, every benchmark row's title is rebuilt from
    current state — necessary because removing a queued benchmark
    renumbers all the rows after it. The ``← Back`` row (and any
    non-benchmark value) is ignored.

    ``t`` / ``r`` are free here: the picker uses default
    ``use_jk_keys`` (only ``j``/``k`` are bound for navigation) and no
    search filter, so the bindings can't collide with movement or
    typing.
    """
    app = question.application
    ic = next(
        c
        for c in app.layout.find_all_controls()
        if isinstance(c, InquirerControl)
    )

    def _refresh() -> None:
        for choice in ic.choices:
            bench_id = choice.value
            if bench_id == "__back__":
                continue
            pos = queue.index(bench_id) + 1 if bench_id in queue else None
            choice.title = _bench_label(bench_id, results.get(bench_id), pos)
        app.invalidate()

    @app.key_bindings.add("t", eager=True)
    def _toggle_mark(event) -> None:  # noqa: ANN001 (prompt_toolkit event)
        bench_id = ic.get_pointed_at().value
        if bench_id == "__back__":
            return
        bench_results.cycle(results, bench_id)
        bench_results.save(results)
        _refresh()

    @app.key_bindings.add("r", eager=True)
    def _toggle_queue(event) -> None:  # noqa: ANN001 (prompt_toolkit event)
        bench_id = ic.get_pointed_at().value
        if bench_id == "__back__":
            return
        if bench_id in queue:
            queue.remove(bench_id)
        else:
            queue.append(bench_id)
        _refresh()


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
        f"web-chars={b['web_search_max_crawled_chars']}"
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
    """Six int prompts in a loop, with current values as defaults."""
    keys: list[tuple[str, str]] = [
        ("planner_max_iters",            "Planner max iterations"),
        ("worker_max_iterations",        "Worker max iterations"),
        ("custom_attack_max_tool_calls", "Custom-skill max tool calls"),
        ("custom_attack_max_iterations", "Custom-skill max iterations"),
        ("llm_max_tokens",               "LLM max output tokens (per call)"),
        ("web_search_max_crawled_chars", "Web-search max chars per source"),
    ]
    while True:
        labels = [
            Choice(f"{label:<36s} {cfg['budgets'][key]}", value=key)
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
