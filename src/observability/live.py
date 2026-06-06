"""Live terminal renderer — the colored, mode-aware view on stderr.

This is the *only* place stderr formatting happens during a run. Every
other emission site (``BaseNode.__call__``, ``shell._common._verbose_print``,
``benchmarks.xbow_runner``) calls into the ``LIVE`` singleton here.

The single ``config.verbosity.mode`` (``silent``/``compact``/``verbose``)
decides what each call actually prints:

* ``silent``  — only ``LIVE.bench_start`` / ``LIVE.bench_end`` / runner errors.
* ``compact`` — one colored line per planner decision, shell command,
  shell outcome, finding, warning, node lifecycle. Default.
* ``verbose`` — today's behaviour: full multi-line dump of every new
  ``AIMessage``/``ToolMessage`` and every command tail line.

Disk artefacts (``logs/run-<id>/...``) are *unchanged in every mode*. This
module never writes to disk — only to stderr.

``config`` is imported lazily inside each method so this module can be
imported from ``observability/__init__.py`` without triggering the
``graph → nodes → base → observability → graph`` cycle.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import shutil
import sys
import time
from typing import Any
from uuid import UUID


# ─────────────────────────── ANSI helpers ────────────────────────────

_RESET   = "\033[0m"
_BOLD    = "\033[1m"
_DIM     = "\033[2m"
_RED     = "\033[31m"
_GREEN   = "\033[32m"
_YELLOW  = "\033[33m"
_BLUE    = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN    = "\033[36m"
_WHITE   = "\033[37m"
_BR_RED  = "\033[91m"  # bright (light) red — used for refused-prompt dumps


def _color_enabled() -> bool:
    """Read the live config; default to no-color if config not yet loaded."""
    try:
        from src.graph import config
        return bool(config.verbosity.color)
    except Exception:
        return False


def _mode() -> str:
    """Read the live config; default to ``compact`` if not yet loaded."""
    try:
        from src.graph import config
        return str(config.verbosity.mode)
    except Exception:
        return "compact"


def _paint(text: str, *codes: str) -> str:
    """Wrap ``text`` in ANSI codes if color is enabled, else return as-is."""
    if not _color_enabled() or not codes:
        return text
    return "".join(codes) + text + _RESET


def _now() -> str:
    return time.strftime("%H:%M:%S")


def _emit(line: str) -> None:
    """Single stderr write — keeps every line atomic across threads.

    Steps under :data:`_STREAM_LOCK`:

      1. If a reasoning stream is mid-line, terminate it with ``\\n`` so
         the new line lands cleanly on its own row instead of getting
         appended to the streaming paragraph.
      2. Erase any drawn "thinking pad" rows so the new line replaces
         the cursor row they used to anchor to.
      3. Print the line to stderr and tee it (ANSI-stripped) to
         ``displayed_terminal_logs.log`` via :func:`writers.write_terminal_line`.
         The tee is a no-op when no sink is configured (e.g. langgraph
         Studio).
      4. Redraw the thinking pad below the new line so concurrent
         in-flight LLM calls stay visible.

    All four steps run while holding :data:`_STREAM_LOCK`; without
    that, parallel writers in the swarm corrupt each other's lines and
    pad clear/draw can race against the ticker thread.
    """
    try:
        with _STREAM_LOCK:
            # Step 1 — close an in-flight reasoning stream.
            if (
                _STREAM_FOCUS["current_agent"] is not None
                and not _STREAM_FOCUS["at_line_start"]
            ):
                _stream_write("\n")
                _STREAM_FOCUS["at_line_start"] = True
                _STREAM_FOCUS["current_agent"] = None

            # Step 2 — erase pad rows so the new line lands in their spot.
            _pad_clear()

            # Step 3 — atomic stderr write + disk tee.
            print(line, file=sys.stderr, flush=True)
            try:
                from src.observability.writers import write_terminal_line
                write_terminal_line(line)
            except Exception:
                # The screen got the data; never let a missing sink
                # crash a run.
                pass

            # Step 4 — redraw the pad under the new content.
            _pad_draw()
    except Exception:  # noqa: BLE001
        # Defensive: if anything in the lock-held block raises (a
        # ``print`` to a closed pipe, etc.) we still want the rest of
        # the run to continue. The user already saw the line on the
        # first attempt — at worst the pad state ends up stale and
        # corrects itself on the next emit.
        pass


# ─────────────── Helpers for extracting text ──────────────────────────
#
# Display clipping was removed by user request — every live-stream
# helper below now returns the full text instead of capping at N chars
# with a trailing ``…``. The only remaining "compaction" is the
# structural ``+N more lines`` hint in ``_summarize_output``: when a
# command's tail spans multiple lines, the synopsis still shows the
# first line + a count of how many more were captured. That's a hint,
# not a string truncation. If you want full multi-line output dumped
# inline too, switch verbosity to ``verbose`` mode (which already
# prints every tail line).


def _inline_newlines(s: str) -> str:
    """Replace newlines with the ``⏎`` glyph so multi-line strings fit
    on one logical terminal line. No length cap — used wherever we
    used to call ``_clip`` for layout reasons.
    """
    return s.replace("\n", " ⏎ ")


def _first_nonempty(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _last_nonempty(text: str) -> str:
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line:
            return line
    return ""


def _summarize_output(tail: str, exit_code: int | None) -> str:
    """One-line summary of a command tail. Used in ``compact`` mode.

    * empty tail → just the exit-code chip (caller adds it).
    * exit==0 and single-line → the full line (no length cap).
    * exit==0 and multi-line → full first line + ``+N more lines``.
    * exit!=0 → full last non-empty line (the actual error usually
      surfaces last).
    * HTTP responses (first line starts with ``HTTP/``) → status + server.

    Display clipping was removed: long commands and outputs now show
    in full. The multi-line ``+N more lines`` hint stays as structural
    info (it's not truncating any individual line, just signalling
    that more lines exist below the synopsis).
    """
    text = (tail or "").strip()
    if not text:
        return ""

    lines = [ln for ln in text.splitlines() if ln.strip()]
    first = lines[0] if lines else ""
    if first.startswith("HTTP/"):
        # Tight HTTP one-liner: status line + Server header (if present).
        # Total response size is already shown by the parent line as bytes.
        bits = [first]
        for ln in lines[:20]:
            if ln.lower().startswith("server:"):
                bits.append(f"server={ln.split(':', 1)[1].strip()}")
                break
        return ", ".join(bits)

    if (exit_code is not None) and exit_code != 0:
        return _last_nonempty(text)

    if len(lines) <= 1:
        return text

    extra = len(lines) - 1
    suffix = f"  +{extra} more line{'s' if extra != 1 else ''}" if extra > 0 else ""
    return first + suffix


# ───────────────── Planner JSON → one-line decision ──────────────────
#
# Live rendering uses the LAX parser — it'd rather show a partially-
# valid decision than render nothing for a slightly malformed JSON
# emission. The shared parser lives at
# ``src.observability.decision_parser.parse_planner_decision``;
# planner.py uses the same function in strict mode for its own
# decision logic.


def _extract_planner_decision(text: str) -> dict | None:
    """Pull the ``{action, target_url, reasoning, ...}`` dict out of an
    AIMessage emitted by the planner.

    Lax mode: accepts any JSON object containing an ``action`` key,
    cleans up trailing commas before parsing. Returns ``None`` if
    nothing parseable is found.
    """
    from src.observability.decision_parser import parse_planner_decision
    return parse_planner_decision(text, strict=False)


# ─────────────────────────── The renderer ────────────────────────────


# ── Streaming-reasoning focus state ─────────────────────────────────
#
# The "focus-follows-most-recent" stream model: at any moment one
# agent's reasoning has "the open line" on the terminal. When another
# agent emits a delta we close the open line with ``\n``, open a new
# line with that agent's prefix, and start streaming its chunks
# inline. Within an agent's open line, chunks concatenate word-by-word
# as the model emits them.
#
# All access to these globals MUST go through ``_STREAM_LOCK`` —
# parallel fan-out workers stream concurrently and a partial-write
# from one would otherwise interleave at the byte level into another's
# in-progress line.
#
# ``current_agent`` — agent_id that currently owns the open line, or
#                    ``None`` if no line is currently open.
# ``at_line_start`` — True when the next chunk must emit a prefix
#                    first (after a focus switch or a natural \n in
#                    the model's reasoning output).
import threading as _threading  # local alias — top-level threading is used elsewhere
_STREAM_LOCK = _threading.Lock()
_STREAM_FOCUS: dict[str, Any] = {
    "current_agent": None,
    "at_line_start": True,
}


# ── Multi-row "thinking pad" anchored below the live stream ────────────
#
# The pad solves the question "is anything happening?" during the gap
# between an LLM request firing and the response arriving — a window
# that can stretch from a few seconds (low effort, simple prompt) to
# several minutes (xhigh effort, big context, parallel fan-out). Without
# a visible indicator the terminal looks frozen and the operator can't
# tell whether the run is stuck, throttled, or simply thinking.
#
# Mental model: the cursor sits just below the most recent normal-output
# line. The pad lives BELOW the cursor — one row per in-flight Codex
# call. On every state-change (new line emitted, call started, call
# finished) and every 200 ms (background ticker), we:
#
#   1. Move cursor up ``_PAD_LINES_DRAWN`` rows and clear from there to
#      the end of screen — this erases the previous pad rendering.
#   2. Emit normal output (or just stay where we are for the ticker).
#   3. Re-render the pad below the new cursor position.
#
# The result: pad rows visually "stick" to the bottom of the live
# stream, scrolling up only as new normal-output lines push them.
#
# Constraints / non-goals:
#   - Disabled on non-TTY stderr (file redirects, pipes, CI). Falls back
#     to silent — the disk artefact ``displayed_terminal_logs.log``
#     contains every normal-output line so no information is lost.
#   - The pad itself is NEVER teed to disk — it's ephemeral UI, and
#     teeing the 5 Hz redraws would balloon the log without adding
#     anything not already covered by ``thinking_started`` /
#     ``thinking_finished`` lines.
#   - Skipped while a reasoning-summary stream is mid-line — the
#     streaming text is itself a liveness signal, and drawing the pad
#     beneath it would split the paragraph across pad redraws.
#
# All access to ``_PAD`` and ``_PAD_LINES_DRAWN`` is serialised by
# ``_STREAM_LOCK`` — the same lock that already serialises ``_emit`` and
# ``_stream_write``, which means the pad code never deadlocks against
# other live-output paths.

# Verb-cycling typewriter + breathing-glow animation. Adapted verbatim
# from the design preview at ``~/Downloads/preview_styles.py`` so the
# pad's animated label matches the look the operator approved out of
# band:
#
#   1. A pulsing red verb (thinking → attacking → scanning → exploiting
#      → probing → pivoting → analyzing → repeat) types in left-to-right,
#      holds with cycling trailing dots, types back out at the same
#      speed, pauses briefly, then the next verb starts.
#   2. The verb text itself breathes — a sine-squared interpolation
#      between deep red (60,0,0) and bright red (255,50,30) over a
#      1.8 s period, rendered in 24-bit truecolor. The sine-squared
#      shape makes the dim half linger and the bright peak sharp,
#      matching Claude Code's thinking shimmer.
#   3. Refresh runs at 20 Hz so the glow looks smooth (slower rates
#      make it strobe).
#
# Both clocks (verb cycle + glow phase) are shared across all in-flight
# rows so concurrent fan-out workers stay visually in sync — every row
# shows the same verb at the same character of the same animation
# phase. Each row still labels itself with its own agent_id and
# elapsed time so the operator can tell which call is which when 3+
# run in parallel.
_VERBS: tuple[str, ...] = (
    "thinking",
    "attacking",
    "scanning",
    "exploiting",
    "probing",
    "pivoting",
    "analyzing",
)
# Per-character type-in / type-out cadence — verb appears letter by
# letter at this rate, then disappears letter by letter at the SAME rate.
_TYPE_PER_CHAR_S: float = 0.10
# How long the full verb stays on screen (with cycling trailing dots).
_HOLD_S: float = 2.50
# Blank gap between one verb fully typing out and the next typing in.
_PAUSE_S: float = 0.40
# One trailing dot toggles every this many seconds during the hold phase.
_DOT_BEAT_S: float = 0.40

# Breathing-glow palette. Deep red is the dim trough; bright red is the
# pulse peak.
_DEEP_RED: tuple[int, int, int] = (60, 0, 0)
_BRIGHT_RED: tuple[int, int, int] = (255, 50, 30)
# Full breathing cycle period — 1.8 s feels alive without strobing.
_GLOW_PERIOD_S: float = 1.8

# Fixed-width verb column so the rest of the row (agent_id, elapsed,
# model) doesn't jump around as the verb grows / shrinks. Longest verb
# is "exploiting" (10) + 3 trailing dots = 13 chars; 14 leaves one
# trailing space for visual breathing room.
_VERB_FIELD_WIDTH: int = 14

# Pad refresh cadence. 50 ms = 20 Hz, matches the breathing-glow's
# sampling rate so the colour transitions look smooth. Faster wastes
# CPU on terminals that won't repaint past ~60 Hz; slower makes the
# pulse choppy. The frame budget per tick is ~few hundred bytes per
# row, comfortably negligible.
_PAD_TICK_S: float = 0.05

# Active call registry. Key is the LangChain run_id (UUID) so the keys
# match those passed to ``thinking_started`` / ``thinking_finished``.
# Value carries everything we need to render one row.
_PAD: dict[Any, dict[str, Any]] = {}

# How many pad rows are currently drawn below the cursor. Updated under
# ``_STREAM_LOCK`` by ``_pad_clear`` / ``_pad_draw``.
_PAD_LINES_DRAWN: int = 0

# Daemon ticker thread + its stop signal. Spun up lazily on the first
# ``thinking_started`` call so the pad never costs anything in non-LLM
# scripts (importing live.py shouldn't start a thread).
_PAD_TICKER_THREAD: _threading.Thread | None = None
_PAD_TICKER_STOP: _threading.Event = _threading.Event()


def _lerp_rgb(
    a: tuple[int, int, int],
    b: tuple[int, int, int],
    t: float,
) -> tuple[int, int, int]:
    """Linear-interpolate between two RGB triples by ``t`` in [0, 1]."""
    return (
        round(a[0] + (b[0] - a[0]) * t),
        round(a[1] + (b[1] - a[1]) * t),
        round(a[2] + (b[2] - a[2]) * t),
    )


def _fg_truecolor(rgb: tuple[int, int, int]) -> str:
    """Render a 24-bit truecolor foreground SGR escape.

    24-bit ANSI is supported by every macOS terminal that matters
    (Apple Terminal ≥ 2.10, iTerm2, Alacritty, kitty, WezTerm). On
    legacy 256-color terminals the escape is parsed and clamped to the
    nearest palette colour, so the verb still appears — just less
    smoothly graded. We accept that trade-off because the pad's
    explicit gate (``_pad_enabled``) already requires a TTY, and any
    TTY old enough to lack truecolor parsing also can't render this
    UI well in the first place.
    """
    r, g, b = rgb
    return f"\x1b[38;2;{r};{g};{b}m"


def _current_verb(now_wall: float) -> str:
    """Return the verb label at wall-clock time ``now_wall``.

    Implements the symmetric typewriter state machine: each verb types
    in at ``_TYPE_PER_CHAR_S`` per character, holds for ``_HOLD_S``
    with cycling 0-3 trailing dots, types out at the same per-char
    rate, then pauses ``_PAUSE_S`` before the next verb starts. The
    cycle repeats forever; using wall-clock time as input means every
    in-flight pad row sees the same label at the same phase, so 3
    concurrent rows render identical animations side by side instead
    of drifting apart.

    The function is total — for any ``t`` it returns the substring of
    the active verb at that phase, or ``""`` during the inter-verb
    pause. Adapted from ``preview_styles.py::current_label``.
    """
    one_pass = sum(
        len(v) * _TYPE_PER_CHAR_S    # type in
        + _HOLD_S                    # hold + dots
        + len(v) * _TYPE_PER_CHAR_S  # type out (same speed)
        + _PAUSE_S                   # gap
        for v in _VERBS
    )
    t = now_wall % one_pass
    # Sub-tick fudge for floating-point boundary stickiness. Without
    # it, ``4.6 - 4.5 = 0.0999999999999996`` and
    # ``int(0.0999.../0.10) = 0`` — the type-in's first character
    # stays empty for one extra tick at every verb transition
    # because the integer step count rounds down a sliver early.
    # 1 ns is far below any human-perceivable phase shift and
    # firmly inside the safe rounding margin for the 100 ms char
    # step / 400 ms dot beat used here.
    eps = 1e-9
    for verb in _VERBS:
        v_in = len(verb) * _TYPE_PER_CHAR_S
        v_hold = _HOLD_S
        v_out = len(verb) * _TYPE_PER_CHAR_S  # symmetric
        v_total = v_in + v_hold + v_out + _PAUSE_S
        if t < v_in:
            # Typing in, left → right. ``t`` can be NEGATIVE here when
            # the previous verb's slot fell through with a residual
            # pause (see ``t -= v_total`` below) — that's how we model
            # the inter-verb gap. ``int(negative / step)`` returns a
            # negative number, and Python slicing with a negative
            # ``stop`` keeps all chars EXCEPT the last ``|n|``
            # ("attacking"[:-3] == "attack"), so without the
            # ``max(0, …)`` clamp the pause would show the next verb
            # growing backwards from its END for 400 ms — appearing
            # as "attac" → "attack" → "attacki" → "attackin" → flash
            # blank → "a" → "at" → … Real users saw this as the next
            # verb popping in for a split-second between every
            # transition. The clamp turns the pause back into a true
            # blank gap so each verb types in cleanly from scratch.
            n = int(t / _TYPE_PER_CHAR_S + eps)
            return verb[: max(0, n)]
        if t < v_in + v_hold:
            # Holding with pulsing trailing dots.
            dots = int((t - v_in) / _DOT_BEAT_S + eps) % 4
            return verb + "." * dots
        if t < v_in + v_hold + v_out:
            # Typing out, right → left (chars vanish from the tail).
            chars_remaining = (
                len(verb)
                - int((t - v_in - v_hold) / _TYPE_PER_CHAR_S + eps)
            )
            return verb[: max(0, chars_remaining)]
        # Otherwise: blank pause before the next verb. ``t`` goes
        # negative for the next iteration; the clamp above handles
        # that correctly so we don't need to special-case the pause
        # explicitly.
        t -= v_total
    return ""


def _glow_color(now_wall: float) -> tuple[int, int, int]:
    """Breathing-glow colour at wall-clock time ``now_wall``.

    Sine-squared in [0, 1] interpolating between ``_DEEP_RED`` and
    ``_BRIGHT_RED`` over a ``_GLOW_PERIOD_S`` cycle. Squaring the
    sine makes the dim half linger (verb spends more frames near the
    deep colour) and the bright peak sharp (a brief flash at peak
    intensity) — same shape as Claude Code's thinking shimmer.
    """
    s = (math.sin(now_wall * 2 * math.pi / _GLOW_PERIOD_S) + 1) / 2
    s = s * s
    return _lerp_rgb(_DEEP_RED, _BRIGHT_RED, s)


def _pad_enabled() -> bool:
    """Return True iff we should render the pad to this stderr.

    Three conditions: stderr is a real TTY (otherwise cursor-move
    escapes corrupt the file), live mode is not silent, and the
    operator hasn't disabled it via ``SWARM_LIVE_THINKING_PAD=0``.
    """
    if os.environ.get("SWARM_LIVE_THINKING_PAD") == "0":
        return False
    if _mode() == "silent":
        return False
    try:
        return bool(sys.stderr.isatty())
    except Exception:  # noqa: BLE001
        return False


def _pad_clear() -> None:
    """Erase the currently-drawn pad from screen.

    Caller MUST hold :data:`_STREAM_LOCK`. After this returns the cursor
    sits at column 0 of the first row the pad used to occupy, ready for
    normal-output writes that will land cleanly above where the pad
    will redraw.

    The ANSI sequence is ``\\r`` (cursor to col 0) + ``\\033[NA`` (up N
    rows) + ``\\033[J`` (clear from cursor to end of screen). On
    terminals without these escapes nothing visibly bad happens — they
    are no-ops on dumb TTYs — but pad rendering will look broken there
    anyway, which is why ``_pad_enabled`` gates the whole feature.
    """
    global _PAD_LINES_DRAWN
    n = _PAD_LINES_DRAWN
    if n <= 0:
        return
    if _pad_enabled():
        try:
            sys.stderr.write(f"\r\033[{n}A\033[J")
            sys.stderr.flush()
        except Exception:  # noqa: BLE001
            pass
    _PAD_LINES_DRAWN = 0


def _pad_draw() -> None:
    """Render the pad below the current cursor position.

    Caller MUST hold :data:`_STREAM_LOCK`. Skipped when the pad is
    disabled, when the active set is empty, or while a reasoning-summary
    stream is currently mid-line (the stream's own text already serves
    as the liveness indicator and the pad would split it). Sets
    ``_PAD_LINES_DRAWN`` so the next clear knows how many rows to
    erase.
    """
    global _PAD_LINES_DRAWN
    if not _pad_enabled() or not _PAD:
        _PAD_LINES_DRAWN = 0
        return
    # Mid-line streaming reasoning: skip. The streaming text itself
    # proves the call is alive, and the pad would interleave with it.
    if (
        _STREAM_FOCUS["current_agent"] is not None
        and not _STREAM_FOCUS["at_line_start"]
    ):
        _PAD_LINES_DRAWN = 0
        return

    # Both the typewriter cycle and the breathing-glow phase are
    # driven off ``time.time()`` (wall clock) so that 1-N concurrent
    # rows are rendered with the SAME verb at the SAME character of
    # the SAME glow phase. Using ``time.perf_counter()`` would also
    # work, but wall-clock keeps the animation phase predictable
    # across process restarts within the same run — handy when
    # comparing two side-by-side terminals.
    now_wall = time.time()
    verb_text = _current_verb(now_wall)
    verb_padded = verb_text.ljust(_VERB_FIELD_WIDTH)
    if _color_enabled():
        verb_str = f"{_fg_truecolor(_glow_color(now_wall))}{verb_padded}{_RESET}"
    else:
        verb_str = verb_padded

    try:
        cols = shutil.get_terminal_size((100, 24)).columns
    except Exception:  # noqa: BLE001
        cols = 100

    now_perf = time.perf_counter()
    rows: list[str] = []
    # Snapshot the dict — entries may change between this read and the
    # write loop on slow terminals; copy is cheap.
    for entry in list(_PAD.values()):
        elapsed = now_perf - entry.get("started", now_perf)
        ag = _agent_tag(entry.get("agent", "?"))
        model = entry.get("model") or ""
        effort = entry.get("reasoning_effort") or ""
        # Elapsed time gets bold past 30 s so a stuck call stands out
        # without the operator having to read the verb.
        time_part = f"{elapsed:5.1f}s"
        if elapsed > 30:
            time_part = _paint(time_part, _BOLD, _YELLOW)
        else:
            time_part = _paint(time_part, _DIM)
        agent_part = _paint(ag, _DIM, _CYAN)
        # Verb is the focal point — agent tag and elapsed are dim
        # context. The pentest verbs cycling in pulsing red are what the
        # operator's eye lands on, on BOTH an LLM-thinking row and a
        # tool-running row (a ⚙-marked row carrying the command), so the
        # gap between dispatch and output is never silent either.
        if entry.get("kind") == "tool":
            cmd = _inline_newlines(entry.get("cmd") or "")
            if len(cmd) > 48:
                cmd = cmd[:47] + "…"
            gear = _paint("⚙ ", _DIM, _CYAN)
            line = f"  {agent_part}  {gear}{verb_str}  {time_part}"
            if cmd:
                line += f"   {_paint(cmd, _DIM)}"
        else:
            meta_bits = []
            if model:
                meta_bits.append(_paint(model, _DIM))
            if effort:
                meta_bits.append(_paint(f"effort={effort}", _DIM))
            meta = "  ".join(meta_bits)
            line = f"  {agent_part}  {verb_str}  {time_part}"
            if meta:
                line += f"   {meta}"
        # Approximate trim to terminal width by ANSI-stripping for length
        # math — we deliberately keep the colored line unmodified when
        # it fits, since splitting in the middle of an escape sequence
        # would corrupt the terminal's state machine.
        from src.observability.writers import _ANSI_RE
        visible = _ANSI_RE.sub("", line)
        if len(visible) > cols:
            # Hard clip on visible chars by walking forward; keep ANSI
            # codes intact. Simple and good enough — the only place that
            # ever overflows is very-long model names on narrow terminals.
            line = visible[: cols - 1] + "…"
        rows.append(line)

    if not rows:
        _PAD_LINES_DRAWN = 0
        return

    try:
        sys.stderr.write("\n".join(rows) + "\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    _PAD_LINES_DRAWN = len(rows)


def _pad_redraw_locked() -> None:
    """Clear + draw in one atomic operation. Caller MUST hold the lock."""
    _pad_clear()
    _pad_draw()


def _pad_ticker_main() -> None:
    """Daemon thread: redraw the pad every :data:`_PAD_TICK_S` seconds.

    Stops only on process exit (the thread is a daemon) or when the
    stop event is set, which never happens in normal operation —
    SwarmAttacker runs one process per benchmark and lets it die.
    """
    while not _PAD_TICKER_STOP.is_set():
        time.sleep(_PAD_TICK_S)
        if not _PAD:
            continue
        try:
            with _STREAM_LOCK:
                _pad_redraw_locked()
        except Exception:  # noqa: BLE001 — never crash the daemon
            pass


def _ensure_pad_ticker() -> None:
    """Start the ticker thread on first use.

    Lazy-start keeps the pad zero-cost in scripts that import live.py
    but never call ``thinking_started`` (tests, ad-hoc tools).
    """
    global _PAD_TICKER_THREAD
    if _PAD_TICKER_THREAD is not None and _PAD_TICKER_THREAD.is_alive():
        return
    _PAD_TICKER_STOP.clear()
    t = _threading.Thread(
        target=_pad_ticker_main,
        name="swarm-thinking-pad",
        daemon=True,
    )
    _PAD_TICKER_THREAD = t
    t.start()


def _stream_write(text: str) -> None:
    """Write `text` to stderr AND tee it (ANSI-stripped) to the file
    sink in ``displayed_terminal_logs.log``. No newline is added.

    This is the only path that should touch stderr during reasoning
    streaming — going through ``print(... flush=True)`` would
    auto-append ``\n`` and break the mid-line chunk concatenation.
    """
    if not text:
        return
    try:
        sys.stderr.write(text)
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    # Lazy import — avoids ``observability → writers → live → ...``
    # cycle at module load time.
    try:
        from src.observability.writers import write_terminal_chunk
        write_terminal_chunk(text)
    except Exception:  # noqa: BLE001
        pass


def _stream_open_line(agent: str) -> None:
    """Emit the line-opening prefix ``HH:MM:SS  💭 <agent>  `` for a
    new streaming line owned by ``agent``. Caller must hold
    :data:`_STREAM_LOCK`.
    """
    ag = _agent_tag(agent)
    head = _paint("💭 ", _DIM, _CYAN)
    tag = _paint(f"{ag} ", _DIM, _CYAN)
    _stream_write(f"{_now()}  {head}{tag}")


def _stream_close_line() -> None:
    """If there's an open streaming line, terminate it with ``\n`` and
    clear the focus. Caller must hold :data:`_STREAM_LOCK`.
    """
    if _STREAM_FOCUS["current_agent"] is not None and not _STREAM_FOCUS["at_line_start"]:
        _stream_write("\n")
    _STREAM_FOCUS["current_agent"] = None
    _STREAM_FOCUS["at_line_start"] = True


def _stream_split_keep_newlines(text: str) -> list[str]:
    """Split ``text`` so each ``\n`` becomes its own token.

    Example: ``"abc\ndef\n"`` → ``["abc", "\n", "def", "\n"]``. Used
    by :meth:`_Live.thinking_delta` to interleave content writes with
    line-boundary handling — every natural newline in the model's
    reasoning closes the current prefixed line and re-opens a fresh
    prefixed continuation line under the same agent.
    """
    if not text:
        return []
    out: list[str] = []
    buf = ""
    for ch in text:
        if ch == "\n":
            if buf:
                out.append(buf)
                buf = ""
            out.append("\n")
        else:
            buf += ch
    if buf:
        out.append(buf)
    return out


class _Live:
    """Singleton — call methods on the module-level ``LIVE`` instance.

    All public methods are no-ops in ``silent`` mode except those that
    mark benchmark boundaries. They delegate to ``_compact_*`` /
    ``_verbose_*`` based on the live mode.
    """

    def __init__(self) -> None:
        # Per-node dedup of duplicated AIMessage content (planner emits
        # the same JSON twice across retry+repaired-parse path).
        self._seen_msg_hashes: set[int] = set()
        # Per-LLM-call thinking state, keyed by the LangChain run UUID.
        # Each entry just records the start time + agent_id so
        # ``thinking_finished`` can compute duration and verify the
        # ``thinking_delta`` calls have a known matching open call.
        # The old heartbeat machinery was removed — reasoning deltas
        # ARE the liveness signal now.
        #
        # Shape: ``{"started": float, "agent": str, "model": str}``.
        self._think_state: dict[Any, dict[str, Any]] = {}
        # Startup banner runs once per process even if the runner
        # invokes the renderer multiple times (e.g. langgraph dev).
        self._banner_emitted: bool = False

    # -------- benchmark boundaries (always visible) ----------

    def bench_start(
        self,
        bench_id: str,
        target: str | None,
        expected_flag: str | None,
    ) -> None:
        self._seen_msg_hashes.clear()
        # Drop any stale spinner rows held over from the previous bench.
        # An LLM call in-flight when the previous bench hit its 900s
        # timeout never receives on_llm_end / on_llm_error (the
        # asyncio.CancelledError raised by asyncio.wait_for is a
        # BaseException and bypasses LangChain's `except Exception`
        # handlers in callbacks.py), so its _PAD entry would otherwise
        # linger forever across bench boundaries. Same per-bench-reset
        # pattern used by reset_totals() in src/llm/callbacks.py and by
        # _seen_msg_hashes.clear() one line above.
        with _STREAM_LOCK:
            _pad_clear()
            _PAD.clear()
        head = _paint(f"◆ {bench_id}", _BOLD, _CYAN)
        target_part = f"target={target}" if target else "target=?"
        flag_part = f"  expected={expected_flag}" if expected_flag else ""
        _emit(f"{_now()}  {head}  {target_part}{flag_part}")

    def bench_end(
        self,
        bench_id: str,
        *,
        ok: bool,
        duration_s: float,
        findings_n: int,
        summary_path: str | None,
        error: str | None = None,
        expected_flag: str = "",
        last_submission: str = "",
        expected_flag_candidates: tuple[str, ...] = (),
    ) -> None:
        """Render the end-of-bench summary line plus an optional
        expected-vs-captured verification block.

        The verification block exists so a human glancing at the
        terminal can verify the verdict at a glance without trusting
        the LLM's narration: it prints the runner's predicted
        ``expected_flag`` (the primary candidate) and the most recent
        ``last_submission`` from ``state["submission_attempts"]`` side
        by side, with a ✓/✗ marker computed by
        :func:`src.edges.flag_match.flags_match` against the FULL
        candidate set (``expected_flag_candidates``) — not just the
        primary. Pure static rendering — no LLM, no narration trust.

        Only printed in benchmark mode (``expected_flag`` non-empty);
        real-pentest runs skip the block since there's no ground truth
        to compare against.
        """
        # One classifier (src.benchmark_verdict.classify) decides ok / fail /
        # crash for BOTH this verdict line and the picker's ✓/✗/~ mark, so a
        # full-budget ``agent timeout`` (fail) is never shown as a crash and a
        # codex/API error (crash) is never hidden among ordinary failures. A
        # late capture (ok with a timeout error attached) reads as FLAG FOUND,
        # not ERROR. Imported locally to keep live.py leaf-level (see below).
        from src.benchmark_verdict import API, OK, classify, format_duration
        status = classify(ok, error)
        if status == OK:
            head = _paint(f"◆ {bench_id}", _BOLD, _GREEN)
            verdict = _paint("✓ FLAG FOUND", _BOLD, _GREEN)
        elif status == API:
            head = _paint(f"⚠ {bench_id}", _BOLD, _YELLOW)
            verdict = _paint(f"~ CRASH: {error}", _BOLD, _YELLOW)
        else:  # FAIL — ran its budget or gave up; show the reason if any.
            head = _paint(f"◇ {bench_id}", _YELLOW)
            verdict = _paint("✗ no flag" + (f" — {error}" if error else ""), _YELLOW)
        tail = (f"({format_duration(duration_s)}, "
                f"{findings_n} finding{'s' if findings_n != 1 else ''})")
        _emit(f"{_now()}  {head}  {verdict}  {tail}")

        # Verification block — benchmark mode only. Skipped silently
        # for real-pentest runs (where expected_flag is empty).
        if expected_flag:
            # Import locally so this module stays leaf-level in the
            # import graph (live.py is imported by graph + state, both
            # of which are upstream of flag_match's consumers).
            from src.edges.flag_match import flags_match

            _emit(f"           {_paint('expected:', _DIM)}  {expected_flag}")
            # Render secondary candidates if any exist beyond the
            # primary — helps a human spot when the sha256 prediction
            # and .env value disagree at a glance.
            if expected_flag_candidates and len(expected_flag_candidates) > 1:
                rest = [c for c in expected_flag_candidates if c != expected_flag]
                if rest:
                    _emit(
                        f"           {_paint('also accept:', _DIM)}  "
                        f"{', '.join(rest)}"
                    )
            if last_submission:
                # Accept any candidate — not just the primary. The
                # display field above shows the primary for readability;
                # the matcher checks the full set.
                check_against: str | tuple[str, ...]
                check_against = expected_flag_candidates or expected_flag
                match_ok = flags_match(
                    submitted=last_submission,
                    expected=check_against,
                )
                marker = (
                    _paint("✓ match", _BOLD, _GREEN) if match_ok
                    else _paint("✗ no match", _BOLD, _RED)
                )
                _emit(
                    f"           {_paint('captured:', _DIM)}  "
                    f"{last_submission}  {marker}"
                )
            else:
                _emit(
                    f"           {_paint('captured:', _DIM)}  "
                    f"{_paint('(no submission attempted)', _DIM)}"
                )

        if summary_path:
            _emit(f"           {_paint('summary', _DIM)} → {summary_path}")

    # -------- runner-side messages ----------

    def runner_message(self, text: str, *, level: str = "info") -> None:
        if _mode() == "silent" and level == "info":
            return
        if level == "error":
            _emit(_paint(text, _RED))
        elif level == "warn":
            _emit(_paint(text, _YELLOW))
        else:
            _emit(_paint(text, _DIM))

    def docker_phase(
        self,
        bench_id: str,
        phase: str,
        duration_s: float,
    ) -> None:
        if _mode() == "silent":
            return
        _emit(
            f"{_now()}  {_paint('▸ docker  ', _DIM, _BLUE)}"
            f"{bench_id} {phase} ({duration_s:.1f}s)"
        )

    # -------- node lifecycle ----------

    def node_finished(
        self,
        name: str,
        duration_ms: int,
        summary: str,
        new_messages: list[Any] | None,
    ) -> None:
        mode = _mode()
        if mode == "silent":
            return
        if mode == "verbose":
            self._verbose_node(name, duration_ms, summary, new_messages or [])
            return
        # compact
        self._compact_node(name, duration_ms, summary, new_messages or [])

    def _verbose_node(
        self,
        name: str,
        duration_ms: int,
        summary: str,
        new_messages: list[Any],
    ) -> None:
        # Reproduces the original SWARM_VERBOSE block from base.py.
        ts = _now()
        _emit(f"\n─── [{ts}] node `{name}` finished in {duration_ms} ms ───\n"
              f"    {summary}")
        for msg in new_messages:
            content = getattr(msg, "content", None)
            if not content:
                continue
            kw = getattr(msg, "additional_kwargs", None) or {}
            if kw.get("node") and isinstance(content, str) and (
                content.startswith("✅ [") or content.startswith("❌ [")
            ):
                continue
            role = type(msg).__name__
            text = content if isinstance(content, str) else str(content)
            _emit(f"    └── {role}:")
            for line in text.splitlines() or [""]:
                _emit(f"        {line}")

    def _compact_node(
        self,
        name: str,
        duration_ms: int,
        summary: str,
        new_messages: list[Any],
    ) -> None:
        # Planner: parse decisions out of the AIMessages; render one line
        # per unique decision. Other nodes: a single dim "▸ name finished"
        # line — tool calls are surfaced separately by shell_command.
        if name == "planner":
            self._render_planner_messages(new_messages, duration_ms)
            return

        # Worker / lifecycle node — structured summary line first.
        head = _paint(f"▸ {name:<8s}", _DIM, _BLUE)
        body = f"{summary}" if summary else "ok"
        # Append a per-agent token totals chip so the user sees the
        # cost of the worker turn inline. Pulls from the running
        # totals maintained by TokenLoggingCallback. We aggregate
        # across every active_agents entry mentioned in the summary
        # — at worker exit there's typically one, sometimes more
        # for fan-out skills like custom-attack.
        tokens_chip = self._aggregate_token_chip(summary)
        tail = f"  ({_fmt_ms(duration_ms)})"
        if tokens_chip:
            tail = f"  ({_fmt_ms(duration_ms)}, {tokens_chip})"
        _emit(f"{_now()}  {head} {body}{tail}")
        # Then a 💭 line per non-trivial worker AIMessage so the LLM's
        # narrative between tool calls is visible. Without this the user
        # only sees commands, not reasoning between them.
        self._emit_worker_thoughts(new_messages)

    def _aggregate_token_chip(self, summary: str) -> str:
        """Pull running token totals for whichever agent_ids appear in
        ``summary`` (the ``active: foo,bar`` part) and render a chip
        like ``in=187k peak=22k think=8.5k``.

        Empty string when no totals are recorded yet (e.g. a node that
        does no LLM calls). Uses lazy import so live.py doesn't have a
        compile-time dependency on llm/callbacks.py — that module
        imports observability which re-exports this one.
        """
        try:
            from src.llm.callbacks import TOKEN_TOTALS
        except Exception:
            return ""
        # Pull active-agent ids out of the summary string. Format:
        # ``... active: a,b,c ...``. If absent, fall back to all agents.
        m = re.search(r"active:\s*([^\s]+)", summary or "")
        if m:
            agents = [s.strip() for s in m.group(1).split(",") if s.strip()]
        else:
            agents = list(TOKEN_TOTALS.keys())
        if not agents:
            return ""
        in_sum = 0
        out_sum = 0
        think_sum = 0
        peak = 0
        for a in agents:
            t = TOKEN_TOTALS.get(a)
            if not t:
                continue
            in_sum += t.input_tokens
            out_sum += t.output_tokens
            think_sum += t.reasoning_tokens
            if t.peak_input > peak:
                peak = t.peak_input
        if not in_sum and not out_sum:
            return ""
        return (
            f"in={_fmt_tokens(in_sum)} "
            f"out={_fmt_tokens(out_sum)} "
            f"think={_fmt_tokens(think_sum)} "
            f"peak={_fmt_tokens(peak)}"
        )

    def _render_planner_messages(
        self,
        new_messages: list[Any],
        duration_ms: int,
    ) -> None:
        """Walk the planner's new AIMessages, print one ``● planner →...``
        line per *unique* decision. Duplicate JSON copies (the supervisor
        retry path re-emits the same payload) are deduped by content hash.
        """
        rendered_any = False
        for msg in new_messages:
            content = getattr(msg, "content", None)
            if not isinstance(content, str) or not content:
                continue
            kw = getattr(msg, "additional_kwargs", None) or {}
            # Skip the boundary ✅/❌ messages base.py injects.
            if kw.get("node") and (
                content.startswith("✅ [") or content.startswith("❌ [")
            ):
                continue
            decision = _extract_planner_decision(content)
            if decision is None:
                continue
            # Dedup duplicate JSON emissions within a single planner turn.
            key = hash((decision.get("action"),
                        decision.get("target_url"),
                        decision.get("reasoning")))
            if key in self._seen_msg_hashes:
                continue
            self._seen_msg_hashes.add(key)

            action = str(decision.get("action") or "?")
            target = decision.get("target_url") or ""
            reasoning = (decision.get("reasoning") or "").strip()

            head = _paint("● planner ", _MAGENTA)
            arrow = _paint(f"→ {action}", _BOLD, _MAGENTA)
            target_part = f"  {target}" if target else ""
            # Reasoning shown in full — newlines collapsed to ⏎ so the
            # decision line stays single-row even when the planner's
            # rationale spans paragraphs. No length cap.
            reason_part = (
                f'  "{_inline_newlines(reasoning)}"' if reasoning else ""
            )
            _emit(f"{_now()}  {head}{arrow}{target_part}"
                  f"{reason_part}  ({_fmt_ms(duration_ms)})")
            rendered_any = True

        if not rendered_any:
            # Fallback — planner produced no parseable decision (e.g. tool
            # call only). Still mark the lifecycle so the user sees the
            # planner ran.
            head = _paint("▸ planner ", _DIM, _BLUE)
            _emit(f"{_now()}  {head} (no decision yet, {_fmt_ms(duration_ms)})")

    def _emit_multiline(
        self,
        prefix: str,
        text: str,
        *,
        color: str = "",
        indent_cols: int = 12,
    ) -> None:
        """Emit ``text`` under the timestamp column, full-width, no clipping.

        First line gets ``prefix`` (e.g. ``"💭 [agent] "`` or ``"↳ "``);
        subsequent paragraph lines get a hanging indent that aligns with
        the start of the prefixed text so multi-line LLM narratives stay
        visually grouped. Color is applied to the *body text only* — the
        prefix stays neutral so the marker is obvious even on dim
        terminals.

        ``indent_cols`` matches the width of the ``HH:MM:SS  `` column
        so the body sits under the timestamp gutter.
        """
        indent = " " * indent_cols
        # Hanging indent for continuation lines: the prefix is visual
        # (emoji + brackets); approximate its display width with len().
        # Two-space pad keeps the wrapper readable even when the prefix
        # is short ("↳ ").
        hang = " " * max(len(prefix), 2)
        lines = [ln for ln in text.splitlines() if ln.strip()] or [text]
        first, rest = lines[0], lines[1:]
        _emit(f"{indent}{prefix}{_paint(first, color) if color else first}")
        for cont in rest:
            painted = _paint(cont, color) if color else cont
            _emit(f"{indent}{hang}{painted}")

    def _emit_worker_thoughts(self, new_messages: list[Any]) -> None:
        """Render worker AIMessages between tool calls as 💭 lines.

        These are the LLM's narrative reasoning — the analysis it
        emits after seeing a tool result and before deciding the next
        action. Without this stream, compact mode shows commands but
        not why each was chosen or what the LLM made of the result.

        Emits the *full* content of each message (no clipping) in
        bold so the LLM's voice is the most-readable thing on screen
        — bash commands and tool mechanics fade into the dim
        background, the operator's eye lands on what the model said.

        Skips:
          - non-AIMessage entries (ToolMessages — already shown via
            ``LIVE.shell_output``);
          - empty content (tool-call-only AIMessages);
          - boundary ``✅``/``❌`` messages we ourselves inject;
          - finding markdown blocks (already rendered via
            ``LIVE.finding`` from base.py with severity coloring).
        """
        # Lazy import — keeps live.py importable without langchain at
        # module-load time.
        from langchain_core.messages import AIMessage

        for msg in new_messages:
            if not isinstance(msg, AIMessage):
                continue
            content = getattr(msg, "content", None)
            if not isinstance(content, str) or not content.strip():
                continue
            kw = getattr(msg, "additional_kwargs", None) or {}
            if kw.get("node") and (
                content.startswith("✅ [") or content.startswith("❌ [")
            ):
                continue
            stripped = content.strip()
            # Findings get their own ▣ line via base.py — don't re-show.
            if (
                stripped.startswith("**FINDING:**")
                or stripped.startswith("## FINDING")
                or stripped.startswith("## Finding")
            ):
                continue
            agent = kw.get("agent_id") or ""
            agent_part = f"[{agent}] " if agent else ""
            self._emit_multiline(
                f"💭 {agent_part}", stripped, color=_BOLD,
            )

    # -------- shell tool ----------

    def shell_command(
        self,
        agent: str | None,
        backend: str,
        cmd: str,
        reasoning: str,
    ) -> None:
        mode = _mode()
        if mode == "silent":
            return
        if mode == "verbose":
            ts = _now()
            tag = f"[{agent or '?'} @ {ts}]"
            _emit(f"\n{tag} ({backend}) $ {cmd}")
            if reasoning:
                _emit(f"{tag}   reasoning: {reasoning}")
            return
        # compact — bash command (mechanics) is dim; the LLM's reasoning
        # underneath is bold so it stands out, since *why* the LLM ran the
        # command is the higher-signal information for the operator.
        # Command shown in full — newlines collapsed to ⏎ glyph so a
        # multi-line heredoc still fits on one logical row, but no
        # length cap.
        head = _paint("$ ", _DIM, _WHITE)
        ag = _paint(_agent_tag(agent), _CYAN)
        cmd_text = _paint(_inline_newlines(cmd), _DIM)
        _emit(f"{_now()}  {head}{ag} {cmd_text}")
        if reasoning and reasoning.strip():
            # Indent under the timestamp column so the reasoning visually
            # belongs to its parent command. Full text — no clipping —
            # so the operator can read the LLM's complete hypothesis.
            self._emit_multiline(
                "↳ ", reasoning.strip(), color=_BOLD,
            )
        # Register a live "running" pad row so the gap between this
        # dispatch and its output isn't silent: the operator sees the
        # same typewriter verb + ticking elapsed an LLM call gets, marked
        # ⚙ and carrying the command, until shell_output drops it. Keyed
        # by agent — a worker runs one command at a time.
        with _STREAM_LOCK:
            _PAD[("tool", agent)] = {
                "started": time.perf_counter(),
                "agent": agent or "?",
                "kind": "tool",
                "cmd": cmd,
            }
            _pad_redraw_locked()
        _ensure_pad_ticker()

    def shell_output(
        self,
        agent: str | None,
        *,
        exit_code: int | None,
        duration_ms: int | str,
        n_bytes: int | str,
        tail: str,
    ) -> None:
        mode = _mode()
        if mode == "silent":
            return
        # Drop this tool's live "running" pad row — the command is done.
        # The compact output line emitted below redraws the pad without it.
        if mode == "compact":
            with _STREAM_LOCK:
                _PAD.pop(("tool", agent), None)
        if mode == "verbose":
            ts = _now()
            tag = f"[{agent or '?'} @ {ts}]"
            suffix = f", exit={exit_code}" if exit_code is not None else ""
            _emit(f"{tag} ↳ output ({duration_ms} ms, {n_bytes} bytes{suffix}):")
            for line in str(tail).splitlines() or [""]:
                _emit(f"{tag}   {line}")
            return
        # compact
        ok = (exit_code == 0) or (exit_code is None)
        if ok:
            mark = _paint("✓ ", _GREEN)
        else:
            mark = _paint("✗ ", _RED)
        ag = _paint(_agent_tag(agent), _CYAN)
        ec = "" if exit_code is None else f"exit={exit_code}  "
        size = _fmt_bytes(n_bytes)
        dur = _fmt_ms(duration_ms)
        synopsis = _summarize_output(tail, exit_code)
        # Synopsis is tool-output mechanics — dim by default so the
        # operator's eye lands on LLM reasoning instead. Errors stay
        # red because real failures are something the user needs to notice.
        if not synopsis:
            synopsis_part = ""
        elif not ok:
            synopsis_part = "  " + _paint(synopsis, _RED)
        else:
            synopsis_part = "  " + _paint(synopsis, _DIM)
        meta = _paint(f"{ec}{size}  ({dur})", _DIM)
        _emit(f"{_now()}  {mark}{ag} {meta}{synopsis_part}")

    # -------- findings & warnings ----------

    def finding(
        self,
        *,
        severity: str,
        title: str,
        agent: str | None = None,
        url: str | None = None,
        payload: str | None = None,
    ) -> None:
        if _mode() == "silent":
            return
        sev = (severity or "INFO").upper()
        if sev in ("CRITICAL", "HIGH"):
            color = _RED
            decoration = (_BOLD,)
        elif sev == "MEDIUM":
            color = _YELLOW
            decoration = ()
        else:
            color = _WHITE
            decoration = (_DIM,)
        head = _paint(f"▣ [{sev}]", color, *decoration)
        bits = [head, title]
        if agent:
            bits.append(_paint(f"({agent})", _DIM))
        if url:
            bits.append(_paint(url, _DIM))
        if payload:
            # Full payload shown — no length cap; newlines collapsed
            # so the finding line stays single-row.
            bits.append(_paint(
                f'payload="{_inline_newlines(payload)}"', _DIM,
            ))
        _emit(f"{_now()}  " + "  ".join(bits))

    def warning(self, text: str, *, kind: str = "warning") -> None:
        if _mode() == "silent":
            return
        head = _paint("⚠ ", _BOLD, _YELLOW)
        _emit(f"{_now()}  {head}{_paint(text, _YELLOW)}")

    # -------- LLM call observability ----------

    # Context-rot threshold. Codex models advertise a 256k window, but
    # quality on multi-turn tool-use trajectories degrades visibly past
    # ~128k. The threshold is set to 100k so a warning fires *before*
    # we hit the rot zone, giving the user time to abort or trim. Override
    # with SWARM_LIVE_CONTEXT_WARN env var if a future model raises the
    # bar.
    _CONTEXT_WARN_INPUT_TOKENS = 100_000

    def _emit_reasoning_block(self, agent: str, text: str) -> None:
        """Emit reasoning that was buffered (because another agent held the
        live stream) as a clean, per-line ``💭 <agent>`` block — the same
        shape a live stream would have produced, just deferred to this
        call's finish. Routed through :func:`_emit` so it stays atomic,
        pad-aware, and teed to the disk log."""
        ag = _agent_tag(agent)
        head = _paint("💭 ", _DIM, _CYAN)
        tag = _paint(f"{ag} ", _DIM, _CYAN)
        for ln in text.splitlines():
            if ln.strip():
                _emit(f"{_now()}  {head}{tag}{_paint(ln, _DIM, _CYAN)}")

    def thinking_started(
        self,
        *,
        agent: str,
        run_id: Any,
        model: str,
        reasoning_effort: str = "",
    ) -> None:
        """Register an in-flight LLM call so the pad shows a spinner row.

        The pad sits below the cursor and ticks every 200 ms while at
        least one call is active. Each row reads
        ``⠋ <agent> thinking 12.3s   gpt-5.5  effort=medium`` and turns
        bold-yellow on the time once the call has been alive for >30 s
        so stuck calls are visually obvious without scrolling.

        Background: a prior version of this method printed a one-shot
        ``🧠 thinking…`` header line plus a 30 s heartbeat task that
        emitted ``…still thinking`` periodically. That worked but
        cluttered the log: every call added 1-N lines of indicator
        text to ``displayed_terminal_logs.log``. The pad approach
        keeps the indicator ephemeral (TTY-only, never teed to disk)
        and shows ALL concurrent calls at once — which the heartbeat
        couldn't because each heartbeat ran in its own task and they
        had no shared rendering surface.

        Silent mode is a no-op. Non-TTY stderr (file redirects, CI)
        also skips the pad render — the call is still tracked so
        ``thinking_finished`` can compute duration, but no spinner row
        is drawn. ``reasoning_effort`` is rendered as a meta chip in
        the pad row when set.
        """
        if _mode() == "silent":
            return
        now = time.perf_counter()
        self._think_state[run_id] = {
            "started": now,
            "agent":   agent,
            "model":   model,
        }
        # Add to the pad registry under the SAME lock that protects
        # render-state transitions, then redraw so the new row appears
        # immediately (the ticker would catch it within 200 ms anyway,
        # but immediate feedback is nicer when an operator just
        # dispatched a worker).
        with _STREAM_LOCK:
            _PAD[run_id] = {
                "started":          now,
                "agent":            agent,
                "model":            model,
                "reasoning_effort": reasoning_effort,
            }
            _pad_redraw_locked()
        _ensure_pad_ticker()

    def thinking_delta(
        self,
        *,
        agent: str,
        run_id: Any,
        text: str,
    ) -> None:
        """Stream one chunk of the model's chain-of-thought to stderr
        and to ``displayed_terminal_logs.log``.

        Concurrency model — "focus follows most-recent". At any moment
        one agent's reasoning has the open terminal line. When a chunk
        arrives from a different agent we terminate the current open
        line with ``\\n``, open a new prefixed line with the new
        agent's tag, and start streaming the new chunks inline. Within
        an agent's open line, successive chunks concatenate
        word-by-word as the model emits them. Natural ``\\n`` characters
        inside the model's reasoning also close the current line and
        open a continuation line under the same agent — that's how
        Codex separates "thoughts" in the summary.

        The lock + focus dance is required because fan-out runs N
        parallel workers, all of which can call this method
        concurrently. Without serialisation their chunks would
        interleave at the byte level inside ``sys.stderr.write`` and
        the output would be illegible.

        Silent mode is a complete no-op (no state mutation either —
        the previous heartbeat-suppression bookkeeping is gone with
        the heartbeat).
        """
        if not text or _mode() == "silent":
            return
        # Unknown run_id (e.g. late delta after thinking_finished, or
        # uninitialised call sites) → drop silently. Without this
        # guard a stray late delta could open a line that never
        # closes.
        st = self._think_state.get(run_id)
        if st is None:
            return

        with _STREAM_LOCK:
            # Option-A concurrency rule: at most ONE call streams its
            # reasoning live at a time. A call's FIRST delta fixes its mode
            # for life — "live" only if this is the sole in-flight call AND
            # no other agent already holds the open line; otherwise
            # "buffer". Streaming N parallel workers char-by-char makes the
            # single focus thrash between them (a fragmented, unreadable
            # smear) and keeps blanking the verb pad. Buffering the others
            # and dumping each as a clean block when it finishes keeps one
            # smooth stream when solo and a calm multi-row verb pad when
            # parallel — exactly the "dynamic when one, tidy when many" feel.
            mode = st.get("display_mode")
            if mode is None:
                solo = len(_PAD) <= 1
                slot_free = _STREAM_FOCUS["current_agent"] in (None, agent)
                mode = "live" if (solo and slot_free) else "buffer"
                st["display_mode"] = mode

            if mode == "buffer":
                # Defer, don't drop: thinking_finished flushes this as one
                # 💭 block so the parallel worker's reasoning is still seen.
                st.setdefault("buf", []).append(text)
                return

            # ---- live (solo) path: stream char-by-char as before ----
            # Erase the thinking pad so the streaming reasoning paragraph
            # lands where the spinner row used to sit. The streaming text
            # is itself the liveness signal here.
            _pad_clear()
            # On focus (re)claim, close any open line then mark that the
            # next write must emit this agent's line-opening prefix.
            if _STREAM_FOCUS["current_agent"] != agent:
                if (
                    _STREAM_FOCUS["current_agent"] is not None
                    and not _STREAM_FOCUS["at_line_start"]
                ):
                    _stream_write("\n")
                _STREAM_FOCUS["current_agent"] = agent
                _STREAM_FOCUS["at_line_start"] = True

            # Walk the incoming text, emitting prefix on each fresh
            # line and a trailing ``\n`` whenever the text crosses a
            # line boundary. Empty strings between consecutive ``\n``
            # are handled correctly (they emit an empty content
            # segment between two newlines, producing a blank line).
            for token in _stream_split_keep_newlines(text):
                if token == "\n":
                    _stream_write("\n")
                    _STREAM_FOCUS["at_line_start"] = True
                    continue
                if _STREAM_FOCUS["at_line_start"]:
                    _stream_open_line(agent)
                    _STREAM_FOCUS["at_line_start"] = False
                _stream_write(_paint(token, _DIM, _CYAN))

    def thinking_finished(
        self,
        *,
        agent: str,
        run_id: Any,
        duration_ms: int,
        model: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        reasoning_tokens: int = 0,
        cached_tokens: int = 0,
        running_input: int = 0,
        peak_input: int = 0,
        error: str | None = None,
    ) -> None:
        """Close the streaming line (if this agent currently holds
        focus) and emit a one-line done summary with token counts.

        The done summary keeps the previous shape:
        ``HH:MM:SS  ✓ <agent>  done (Xms, in=… out=… think=…)`` —
        useful for grep'ing total cost / call rate per agent in the
        saved log. On error it's painted red; on
        ``peak_input >= _CONTEXT_WARN_INPUT_TOKENS`` it's painted
        yellow with the context-rot warning.
        """
        del model  # banner already shows it; per-call repetition is noise
        state = self._think_state.pop(run_id, None)
        mode = _mode()
        if mode == "silent":
            # Even silent mode must deregister the call from the pad —
            # otherwise a phantom row would linger forever on a future
            # switch back to compact mode (we don't support live mode
            # switches today, but defending against stale state is free).
            _PAD.pop(run_id, None)
            return

        # If this agent was holding the open streaming line, close it
        # so the done-summary doesn't get appended to the running
        # reasoning paragraph. While holding the same lock, drop the
        # call from the pad so the spinner row disappears before the
        # done line is printed — otherwise the operator sees "done…"
        # followed by a flickering row that immediately vanishes.
        buffered = ""
        with _STREAM_LOCK:
            if _STREAM_FOCUS["current_agent"] == agent:
                if not _STREAM_FOCUS["at_line_start"]:
                    _stream_write("\n")
                _STREAM_FOCUS["current_agent"] = None
                _STREAM_FOCUS["at_line_start"] = True
            _PAD.pop(run_id, None)
            if state:
                buffered = "".join(state.get("buf", []))
            _pad_redraw_locked()

        # Flush reasoning that was buffered because OTHER agents held the
        # live stream while this call ran (Option-A concurrency). Emitting it
        # now — pad row already gone, lock released (``_emit`` takes it
        # itself) — surfaces each parallel worker's thinking as one clean
        # block instead of a char-by-char smear, and BEFORE its done-summary.
        if buffered.strip():
            self._emit_reasoning_block(agent, buffered)

        ag = _agent_tag(agent)
        rot = peak_input >= self._CONTEXT_WARN_INPUT_TOKENS

        if error:
            head = _paint("✗ ", _BOLD, _RED)
            body = _paint(
                f"{ag} failed ({_fmt_ms(duration_ms)}, {error})", _RED,
            )
            _emit(f"{_now()}  {head}{body}")
            return

        tokens_part = (
            f"in={_fmt_tokens(input_tokens)} "
            f"out={_fmt_tokens(output_tokens)} "
            f"think={_fmt_tokens(reasoning_tokens)}"
        )
        # Surface cache hits whenever the provider reports them. Suppress
        # when zero so non-Codex providers and cold-prefix calls don't
        # litter every line with ``cached=0``.
        if cached_tokens > 0:
            pct = (cached_tokens / input_tokens * 100) if input_tokens else 0
            tokens_part += f" cached={_fmt_tokens(cached_tokens)}({pct:.0f}%)"
        if mode == "verbose":
            tokens_part += f" running_in={_fmt_tokens(running_input)}"

        if rot:
            head = _paint("✓ ", _BOLD, _YELLOW)
            tail = _paint(
                f"{ag} done ({_fmt_ms(duration_ms)}, {tokens_part})  "
                f"⚠ context-rot at peak={_fmt_tokens(peak_input)}",
                _BOLD, _YELLOW,
            )
            _emit(f"{_now()}  {head}{tail}")
        else:
            head = _paint("✓ ", _DIM, _CYAN)
            body = _paint(
                f"{ag} done ({_fmt_ms(duration_ms)}, {tokens_part})", _DIM,
            )
            _emit(f"{_now()}  {head}{body}")

    # -------- Back-compat shim ----------
    #
    # ``llm_call`` was the old per-call stderr emitter. The
    # ``thinking_*`` pipeline supersedes it but call sites that
    # imported it directly (none currently, but defensive) get a
    # no-op so nothing breaks.

    def llm_call(self, **_kwargs: Any) -> None:
        """Deprecated — see ``thinking_started`` /
        ``thinking_finished``. Kept as a no-op for back-compat."""
        return

    # -------- Refused-prompt dump ----------

    def refused_prompt(
        self,
        *,
        agent: str,
        tier: str,
        request: dict,
    ) -> None:
        """Dump the full Codex request that triggered a policy refusal.

        Rendered in bright (light) red to stderr in ``compact`` and
        ``verbose`` modes so the operator can read exactly what the
        model was given and identify the phrase / message / fragment
        tripping the cyber-policy classifier. Silent mode suppresses.

        ``request`` is the dict produced by
        ``ChatCodex._build_request_kwargs`` and attached to refusal
        exceptions as ``e._swarm_request`` (see ``src/llm/codex.py``
        and ``src/refusals/retry.py``). Keys we display:

          - ``model``, ``reasoning_effort``, ``reasoning_summary``
            (a single context line)
          - ``instructions`` (full system prompt)
          - ``input_items`` (every user / assistant / tool item)
          - ``tools`` (names only; schemas would dominate the dump)

        Caller is responsible for rate-limiting — this method dumps
        unconditionally each time it's called. ``retry.py`` only
        invokes it on the FIRST refusal of each tier so the same
        input is not re-rendered across tier-1 plain retries.
        """
        if _mode() == "silent":
            return

        on = _color_enabled()
        lr = _BR_RED if on else ""
        rs = _RESET if on else ""

        def paint(text: str) -> str:
            return f"{lr}{text}{rs}"

        rule = "─" * 72
        _emit(paint(rule))
        _emit(paint(
            f"REFUSED INPUT — {agent} (tier={tier}) "
            f"— what Codex saw before it refused:"
        ))
        _emit(paint(rule))

        # One context line — model + reasoning controls.
        model = request.get("model", "?")
        effort = request.get("reasoning_effort", "—")
        rsum = request.get("reasoning_summary", "—")
        _emit(paint(
            f"  model={model}   effort={effort}   summary={rsum}"
        ))

        # System prompt — full.
        instr = request.get("instructions") or ""
        _emit(paint(f"─── SYSTEM ({len(instr)} chars) ───"))
        if instr:
            for line in instr.splitlines() or [""]:
                _emit(paint(f"  {line}"))
        else:
            _emit(paint("  (empty)"))

        # Input items — full.
        items = request.get("input_items") or []
        _emit(paint(f"─── INPUT_ITEMS ({len(items)}) ───"))
        for i, item in enumerate(items, 1):
            if not isinstance(item, dict):
                _emit(paint(f"  [{i}] {item!r}"))
                continue
            itype = item.get("type", "?")
            if itype == "message":
                role = item.get("role", "?")
                content = item.get("content") or []
                _emit(paint(f"  [{i}] message  role={role}"))
                for block in content:
                    if isinstance(block, dict):
                        btype = block.get("type", "?")
                        text = (
                            block.get("text")
                            or block.get("output_text")
                            or ""
                        )
                        if text:
                            _emit(paint(f"      ({btype})"))
                            for line in text.splitlines() or [""]:
                                _emit(paint(f"      {line}"))
                        else:
                            _emit(paint(f"      ({btype}) {block!r}"))
                    else:
                        _emit(paint(f"      {block!r}"))
            elif itype == "function_call":
                name = item.get("name", "?")
                args = item.get("arguments", "")
                _emit(paint(f"  [{i}] function_call  name={name}"))
                for line in str(args).splitlines() or [""]:
                    _emit(paint(f"      {line}"))
            elif itype == "function_call_output":
                cid = item.get("call_id", "?")
                output = item.get("output", "")
                _emit(paint(f"  [{i}] function_call_output  call_id={cid}"))
                for line in str(output).splitlines() or [""]:
                    _emit(paint(f"      {line}"))
            else:
                _emit(paint(f"  [{i}] {itype}: {item!r}"))

        # Tool names — schemas are noise.
        tools = request.get("tools") or []
        if tools:
            names: list[str] = []
            for t in tools:
                if isinstance(t, dict):
                    names.append(str(t.get("name") or t.get("type") or "?"))
            _emit(paint(
                f"─── TOOLS ({len(names)}) ───  {', '.join(names)}"
            ))

        _emit(paint(rule))

    # -------- Startup banner ----------

    def startup_banner(
        self,
        *,
        model_info: dict | None,
        log_dir: str | None,
        bench_ids: list[str] | None,
        budgets_text: str | None = None,
    ) -> None:
        """Print the startup banner once per process invocation.

        Shows provider/model/reasoning, all budgets and verbosity
        knobs, the **absolute** log directory, and a legend
        explaining which JSONL files populate live vs. at run end.

        ``silent`` mode falls back to a single one-liner so even
        the most muted runs still announce what they're running.
        """
        if self._banner_emitted:
            return
        self._banner_emitted = True

        mi = model_info or {}
        bench_count = len(bench_ids or [])
        provider = str(mi.get("provider") or "?")
        model = str(mi.get("model") or "?")
        mode = _mode()

        if mode == "silent":
            acct = mi.get("codex_account")
            tail = f"  acct={acct}" if acct else ""
            _emit(
                f"=== SwarmAttacker  {provider}/{model}  {mode}  "
                f"{bench_count} benches{tail} ==="
            )
            return

        # Determine terminal width so the rule line fits cleanly.
        try:
            cols = shutil.get_terminal_size((80, 24)).columns
        except Exception:  # noqa: BLE001
            cols = 80
        cols = max(60, min(cols, 100))

        # Title line: ═════ SwarmAttacker run ═════
        # Center the label within ``cols`` *visible* columns, then
        # apply ANSI colour AFTER the centring so the escape codes
        # don't break the math.
        label = " SwarmAttacker run "
        pad = max(0, cols - len(label))
        left = "═" * (pad // 2)
        right = "═" * (pad - pad // 2)
        title_line = left + label + right
        _emit(_paint(title_line, _BOLD, _CYAN))
        _emit(_paint("═" * cols, _CYAN))

        def kv(key: str, val: str) -> None:
            _emit(f"  {_paint(key, _BOLD)}{val}")

        # LLM block
        reff = mi.get("reasoning_effort") or "—"
        rsum = mi.get("reasoning_summary") or "—"
        kv("Provider:   ", f"{provider}   {_paint('Model:', _BOLD)} {model}")
        kv("Reasoning:  ", f"effort={reff}  summary={rsum}")

        # Budgets / verbosity from describe_config()
        cfg_block = (budgets_text or "").splitlines()
        if cfg_block:
            for ln in cfg_block:
                # describe_config() emits "Budgets:\n  k = v\n..." —
                # rewrap so each line is indented uniformly under the
                # banner column.
                _emit(f"  {ln}" if not ln.startswith(" ") else f"  {ln}")

        # Log dir + file legend
        if log_dir:
            kv("Log root:   ", str(log_dir))
            legend = [
                ("nodes.jsonl",          "1 line per node finish — duration, summary, full state diff (before / after / delta with new msgs)"),
                ("llm_calls.jsonl",      "2 lines per LLM call — phase=start (full prompt) + phase=end (tokens, response). Live."),
                ("terminal_events.jsonl","1 line per shell command — populates live"),
                ("worker_traces.jsonl",  "1 line per worker LangChain message — tagged by agent_id + dispatch_ts for filtering"),
                ("final_state.json",     "final agent_state at run end"),
                ("summary.md",           "human entry point — open this first; per-node detail collapsed"),
            ]
            for i, (name, desc) in enumerate(legend):
                bullet = "└─" if i == len(legend) - 1 else "├─"
                _emit(_paint(
                    f"              {bullet} {name:<22s} ({desc})", _DIM,
                ))

        # Benches
        if bench_ids:
            preview = ", ".join(bench_ids[:8])
            if len(bench_ids) > 8:
                preview += f", … ({len(bench_ids)} total)"
            kv("Benches:    ", preview)

        # Closing rule — match the opening width (``rule`` from the other
        # banner helpers is not in scope here; use the computed ``cols``).
        _emit(_paint("═" * cols, _CYAN))


_AGENT_TAG_WIDTH = 24  # fits owasp-input-validation (22) without truncation


def _agent_tag(agent: str | None) -> str:
    """Render an agent id as a left-padded fixed-width tag.

    Names longer than ``_AGENT_TAG_WIDTH`` are clipped with an ellipsis;
    shorter names are right-padded so the column after stays aligned.
    """
    name = agent or "?"
    if len(name) > _AGENT_TAG_WIDTH:
        return name[: _AGENT_TAG_WIDTH - 1] + "…"
    return f"{name:<{_AGENT_TAG_WIDTH}s}"


def _fmt_ms(ms: int | str) -> str:
    try:
        n = int(ms)
    except (TypeError, ValueError):
        return f"{ms}ms"
    if n < 1000:
        return f"{n}ms"
    if n < 60_000:
        return f"{n / 1000:.1f}s"
    return f"{n // 60_000}m{(n % 60_000) // 1000}s"


def _fmt_bytes(n: int | str) -> str:
    try:
        v = int(n)
    except (TypeError, ValueError):
        return f"{n}B"
    if v < 1024:
        return f"{v}B"
    if v < 1024 * 1024:
        return f"{v / 1024:.1f}KB"
    return f"{v / (1024 * 1024):.1f}MB"


def _fmt_tokens(n: int) -> str:
    """Format a token count as ``Xk`` or ``X.Xk`` past 1000.

    Below 1000 we keep the raw integer because per-call output_tokens is
    often in the low hundreds and the ``k`` suffix would round those
    to ``0k`` and lose the signal.
    """
    try:
        v = int(n)
    except (TypeError, ValueError):
        return str(n)
    if v < 1_000:
        return str(v)
    if v < 10_000:
        return f"{v / 1_000:.1f}k"
    return f"{v // 1_000}k"


# Module-level singleton. Importers do ``from src.observability.live import LIVE``.
LIVE = _Live()


# ─────────────────────── stdlib logging integration ───────────────────────


class HttpxQuietFilter:
    """Drop ``httpx`` INFO records unless ``config.verbosity.show_http``.

    Installed once at runner start-up. The library logs every LLM call at
    INFO level (``HTTP Request: POST chatgpt.com/...``); without this filter
    those lines flood the terminal in compact mode. Disk logs are unaffected
    — we don't write a separate httpx log file.
    """

    def filter(self, record) -> bool:  # noqa: D401 — logging.Filter API
        try:
            from src.graph import config
            show = bool(config.verbosity.show_http)
        except Exception:
            show = False
        if show:
            return True
        # Hide httpx INFO; let WARNING+ through so real errors still surface.
        return record.levelno >= 30  # WARNING and above


class LiveLogHandler(logging.Handler):
    """Stdlib logging handler that reformats records through :data:`LIVE`.

    Installed in compact/silent mode so warnings and errors appear in the
    same colored ``⚠`` / red format as the rest of the live stream
    instead of the raw ``2026-05-03 21:19:11,401 WARNING node.recon: …``
    timestamped lines that ``logging.basicConfig`` produces. Records
    below WARNING are dropped (their content is already surfaced by
    LIVE itself in compact mode); errors are routed through
    ``LIVE.runner_message`` with ``level="error"``.

    Verbose mode does NOT install this — the runner keeps
    ``logging.basicConfig`` so the full timestamped log stream is
    available for deep debugging.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — never let a log call crash a run
            try:
                msg = self.format(record)
            except Exception:
                return
        # Tag the source if it's a recognizable node logger so the user
        # can tell whether a warning came from the planner, a worker,
        # the LLM provider, etc.
        prefix = ""
        if record.name.startswith("node."):
            prefix = f"[{record.name[5:]}] "
        elif record.name.startswith("src."):
            prefix = f"[{record.name[4:]}] "
        text = f"{prefix}{msg}".strip()
        if record.levelno >= logging.ERROR:
            # Errors go through the same ⚠ path as warnings so they get
            # the timestamp + colored prefix; the "error:" prefix keeps
            # them distinguishable in the stream.
            LIVE.warning(f"error: {text}")
        elif record.levelno >= logging.WARNING:
            LIVE.warning(text)
        # INFO/DEBUG: dropped intentionally.
