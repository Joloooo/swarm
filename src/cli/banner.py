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

# ASCII-art block: full "SWARMATTACKER" rendered in the ANSI Shadow
# figlet font, kept as a single raw string so the box-drawing
# characters line up perfectly when printed. Each line is pre-indented
# by three spaces to give the logo breathing room against the
# terminal's left edge.
#
# Width: 114 cols of art + 3-space indent = 117 cols total. Fits any
# modern terminal (typical Apple Terminal / iTerm2 width is ≥ 100
# cols at a default font); will line-wrap on a strict 80-col window
# but the project's CLI doesn't target that. Letters were assembled
# from the canonical ANSI Shadow letterforms via
# ``/tmp/build_banner.py``.
_LOGO = """\
   ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗███████╗██████╗
   ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
   ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║███████║   ██║      ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
   ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
   ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""

_TAGLINE = "FULLY AUTONOMOUS WEB PENETRATION TESTING"


def show(config_path: Path) -> None:
    """Print the SWARM splash to stderr.

    Stderr (not stdout) because subprocess runners inherit our stdout
    and we don't want the banner contaminating piped output.
    """
    # Lazy import — rich is a hot dep (~150ms cold) and the dispatcher
    # imports this module unconditionally for ``--help``.
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.text import Text

    console = Console(stderr=True)

    console.print()
    if console.width >= max(map(len, _LOGO.splitlines())):
        console.print(Text(_LOGO, style="bold #ff5f87"), end="")
    else:
        # The full ANSI-shadow wordmark is 114 columns wide.  Use a crisp
        # single-line mark on narrow terminals instead of wrapping the art.
        console.print(
            Align.center(
                Text("S W A R M A T T A C K E R", style="bold #ff5f87")
            )
        )
        console.print()

    identity = Text.assemble(
        ("◆  ", "bold #ffaf5f"),
        (_TAGLINE, "bold white"),
        ("  ◆", "bold #ffaf5f"),
    )
    cfg_line = Text.assemble(
        ("CONFIG  ", "bold #ff5f87"),
        (str(config_path), "#ffaf5f"),
    )
    info = Group(
        Align.center(identity),
        Text(),
        Align.center(cfg_line),
    )
    console.print(
        Panel(
            info,
            border_style="#ff5f87",
            padding=(0, 2),
            width=min(117, console.width),
        )
    )
    console.print()
