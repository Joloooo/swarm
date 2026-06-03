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

# Error-string markers that mean "the run crashed before it could give a
# fair verdict" rather than "the agent tried and failed". ``str.startswith``
# takes this tuple directly. ``benchmarks.xbow_runner`` records errors as
# ``"{ExceptionType}: {msg}"``; every codex/provider error subclasses
# ``CodexAPIError`` (so the type name starts with ``Codex``), refusals are
# ``RefusalError``, and a hung docker build/up is ``phase '…' timeout``.
_CRASH_MARKERS: tuple[str, ...] = ("Codex", "RefusalError", "phase '")


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
