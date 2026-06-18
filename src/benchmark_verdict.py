"""Single source of truth for a benchmark run's outcome.

A finished XBOW benchmark is one of three things, and two places need to
agree on which:

  * the terminal verdict line — :meth:`src.observability.live.Live.bench_end`
  * the picker's ✓/✗/~ triage marks — :mod:`src.cli.bench_results`

Before this module each had its own inline rule, and they disagreed: the
terminal lumped a full-budget ``agent timeout`` together with a codex/API
crash under one "ERROR", while the picker split them. :func:`classify` is
the one rule both now call, so a 1200s timeout (the agent got its fair
shot → ``fail``) is never confused with a codex/infra crash (no fair shot
→ ``api``).

Kept deliberately dependency-free (stdlib only) so it can sit below both
``observability`` and ``cli`` in the import graph without risking a cycle.
"""

from __future__ import annotations

# Outcome values. The picker stores these verbatim in bench_results.json
# (absence of a key == "no mark yet").
OK = "ok"      # a flag was captured
FAIL = "fail"  # ran its time budget / gave up, but found no flag
API = "api"    # codex/API or infra crash — the run never got a fair attempt

# Error-string markers that mean "the run malfunctioned before it could give a
# fair verdict" rather than "the agent tried and failed". ``str.startswith``
# takes this tuple directly. ``benchmarks.xbow_runner`` records errors as
# ``"{ExceptionType}: {msg}"``; the families that never got a fair attempt:
#   * ``Codex``               — any codex/provider error (subclasses CodexAPIError),
#                               including the usage cap.
#   * ``phase '``             — a hung docker build/up (``phase '…' timeout``).
#   * ``CalledProcessError``  — ``make … run`` exited non-zero, i.e. the target
#                               container never came up (docker infra crash —
#                               XBEN-039/040/043 in full_run_06-17_22h59m).
#   * ``InvalidUpdateError``  — a LangGraph state crash from concurrent writes
#                               (XBEN-098, since fixed by the waf_detected reducers).
_CRASH_MARKERS: tuple[str, ...] = (
    "Codex", "phase '", "CalledProcessError", "InvalidUpdateError",
)


def format_duration(seconds: float | int | None) -> str:
    """Human ``Xm YYs`` / ``Ys`` from a second count (``"?"`` if unknown).

    Used by the terminal verdict line (:meth:`src.observability.live.Live.bench_end`)
    and the campaign summary so a solve time reads as ``3m 12s`` rather than
    ``192.0s``. Lives here, in the shared verdict module, so both render times
    identically and stdlib-only.
    """
    if not isinstance(seconds, (int, float)):
        return "?"
    s = max(0, int(round(seconds)))
    m, sec = divmod(s, 60)
    return f"{m}m {sec:02d}s" if m else f"{sec}s"


def classify(flag_found: bool, error: str | None) -> str:
    """Map a :mod:`benchmarks.xbow_runner` result to an outcome.

    * ``ok``   — a flag was captured. This wins even when a late timeout
                 fired during graph wrap-up (``flag_found`` is still True),
                 because the capture itself is what matters.
    * ``api``  — the run crashed on a codex/provider error or an infra
                 (docker build/up) timeout, so it never got a fair attempt
                 and the result is unknown. See :data:`_CRASH_MARKERS`.
    * ``fail`` — anything else with no flag: the agent ran its full time
                 budget (``agent timeout after …``), looped out, or gave up.
    """
    if flag_found:
        return OK
    err = (error or "").strip()
    if err.startswith("agent timeout after"):
        return FAIL
    if err.startswith(_CRASH_MARKERS):
        return API
    return FAIL
