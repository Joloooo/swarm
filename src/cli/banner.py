"""Splash banner for the ``swarm`` TUI.

Single responsibility: print the SWARM ASCII-art logo + tagline + the
path to the persistent config file. Called only from the wizard
entry point (:mod:`src.cli.tui`); the benchmark shortcuts and the
one-shot natural-language flow skip it. Keeping this in its own
module lets the dispatcher avoid pulling in ``questionary`` or the
heavier TUI logic when the banner isn't needed (faster cold-start
for ``swarm --help`` and ``swarm --bench …``).
"""

from __future__ import annotations

from pathlib import Path

# ASCII-art block intentionally kept as a single raw string so the
# box-drawing characters line up perfectly when printed. Each line is
# pre-indented by three spaces to give the logo breathing room
# against the terminal's left edge.
_LOGO = """\
   ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗
   ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║
   ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║
   ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║
   ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║
   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
"""

_NAME    = "               SWARM"
_TAGLINE = "        Autonomous Swarm Pentesting Agent"


def show(config_path: Path) -> None:
    """Print the SWARM splash to stderr.

    Stderr (not stdout) because subprocess runners inherit our stdout
    and we don't want the banner contaminating piped output.
    """
    # Lazy import — rich is a hot dep (~150ms cold) and the dispatcher
    # imports this module unconditionally for ``--help``.
    from rich.console import Console
    from rich.text import Text

    console = Console(stderr=True)

    # Spacer line above for separation from any earlier prompt output.
    console.print()
    # Logo: bold cyan reads well on both light and dark terminals.
    console.print(Text(_LOGO, style="bold cyan"), end="")
    # Project name: bold magenta, makes "SWARM" pop under the art.
    console.print(Text(_NAME, style="bold magenta"))
    # Tagline: dim italic so it sits as a subtitle without competing.
    console.print(Text(_TAGLINE, style="dim italic"))
    console.print()
    # Config path: useful when debugging "why didn't my edit stick?".
    cfg_line = Text.assemble(
        ("   cfg: ", "dim"),
        (str(config_path), "yellow"),
    )
    console.print(cfg_line)
    console.print()
