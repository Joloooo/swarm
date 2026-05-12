"""Splash banner for the ``swarm`` TUI.

Single responsibility: print a rich-formatted welcome panel that
includes the path to the persistent config file. Keeping this in its
own module lets the dispatcher import it without pulling in
``questionary`` or the heavier TUI logic (faster cold-start for
``swarm --help`` and the benchmark shortcuts).
"""

from __future__ import annotations

from pathlib import Path


def show(config_path: Path) -> None:
    """Print the welcome banner to stderr.

    Stderr (not stdout) because the runner subprocesses inherit our
    stdout and we don't want the banner appearing in piped output.
    """
    # Lazy import — rich is a hot dep (~150ms cold) and the dispatcher
    # imports this module unconditionally.
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    console = Console(stderr=True)

    title = Text("SwarmAttacker", style="bold cyan")
    subtitle = Text(" · started", style="dim")
    line1 = Text.assemble(title, subtitle)

    cfg_line = Text.assemble(
        ("cfg: ", "dim"),
        (str(config_path), "yellow"),
    )

    panel = Panel(
        Text.assemble(line1, "\n", cfg_line),
        border_style="cyan",
        expand=False,
        padding=(0, 2),
    )
    console.print(panel)
