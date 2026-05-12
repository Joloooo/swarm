"""Interactive ``swarm`` menu — questionary main loop + nested config editor.

Invoked by :func:`src.cli.__init__.main` when the user runs ``swarm``
with no positional argument and no benchmark shortcut. The flow:

  1. Print the rich banner (project name + config-file path).
  2. ``docker_boot.ensure_ready()`` unless ``--no-docker``.
  3. ``config_store.load_into_env()`` — TOML → ``os.environ``, with
     override warnings shown under the banner.
  4. Loop forever:
        - present the top-level :func:`questionary.select`
        - dispatch to runner.* or _config_menu()
        - on Ctrl-C / "Quit", exit cleanly.

Ctrl-C policy: ``questionary.select`` returns ``None`` when the user
hits Ctrl-C. We treat that as "go back one level" rather than
crashing, so the user can always escape a submenu without losing
their session.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

import questionary
from questionary import Choice
from rich.console import Console

from src.cli import banner, config_store, docker_boot, runner
from src.cli.bench_discovery import count_all


_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

def main_loop(args: argparse.Namespace) -> None:
    """Drive the interactive menu until the user quits or Ctrl-C's."""
    banner.show(config_store.path())

    if not args.no_docker:
        try:
            docker_boot.ensure_ready()
        except KeyboardInterrupt:
            _console.print("\n[dim]Cancelled during Docker bootstrap.[/dim]")
            sys.exit(130)

    # Apply persistent config to env, surfacing any shell-shadow overrides.
    for msg in config_store.load_into_env(override=True):
        _console.print(f"[yellow]·[/yellow] {msg}")

    while True:
        action = _top_level()
        if action is None or action == "quit":
            _console.print("[dim]👋 bye[/dim]")
            return

        if action == "one":
            runner.run_one("XBEN-006-24")
        elif action == "daily_compact":
            runner.run_daily(silent=False)
        elif action == "daily_silent":
            runner.run_daily(silent=True)
        elif action == "all":
            runner.run_all()
        elif action == "config":
            _config_menu()


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

    choices = [
        Choice("Pentest 1 container (XBEN-006-24)",        value="one"),
        Choice("Pentest 15 containers (daily, compact)",   value="daily_compact"),
        Choice("Pentest 15 containers (daily, silent)",    value="daily_silent"),
        Choice(all_label,                                  value="all", disabled=None if n_all else "submodule missing"),
        Choice("Edit config",                              value="config"),
        Choice("Quit",                                     value="quit"),
    ]
    return questionary.select(
        "What do you want to do?",
        choices=choices,
        use_shortcuts=False,
        instruction="(use ↑/↓, enter to confirm, Ctrl-C to quit)",
    ).ask()


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
