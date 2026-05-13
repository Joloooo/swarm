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

# Tagline: the project name is now in the ASCII art itself, so the
# subtitle below just needs the one-line description. Indented to ~42
# columns so it visually sits centered under the 117-column logo.
_TAGLINE = "                                          Fully autonomous Pentesting agent"


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
    # Logo: bold red — the project name itself is rendered in the ASCII
    # art now, so colour does double duty as branding (matches the
    # red-glow thinking pad below) and as the dominant visual element
    # on the splash screen.
    console.print(Text(_LOGO, style="bold red"), end="")
    # Tagline: plain white so the one-line description reads cleanly
    # under the red logo without competing.
    console.print(Text(_TAGLINE, style="white"))
    console.print()
    # Config path: useful when debugging "why didn't my edit stick?".
    cfg_line = Text.assemble(
        ("   cfg: ", "dim"),
        (str(config_path), "yellow"),
    )
    console.print(cfg_line)
    console.print()
