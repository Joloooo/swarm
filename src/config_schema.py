"""Single source of truth for ``swarm-config.toml`` — the menu config knobs.

Everything the ``swarm`` "Edit config" menu shows lives in ``swarm-config.toml``.
You edit that one file — by hand, or via the TUI — and the app reads it.

This module owns three things and **nothing else**:

  - ``DEFAULTS`` — the factory values, used ONLY to create the file the first
    time and to fill any key you delete. You should never need to edit these;
    change ``swarm-config.toml`` instead.
  - ``CHOICES`` — the valid values for the enum knobs (model slug, reasoning
    effort/summary, verbosity).
  - ``load()`` / ``resolve()`` — read the file and overlay it on ``DEFAULTS`` to
    produce the effective config.

``src/graph.py`` calls :func:`resolve` to build its runtime ``config`` object,
so the *values* genuinely come from ``swarm-config.toml`` — not from code.
``src/cli/config_store.py`` uses the same ``DEFAULTS`` / ``CHOICES`` to display
and write the file. This module imports **nothing from the project** (stdlib
only), so ``graph.py`` can import it at startup without an import cycle.

Scope is deliberately the user-facing menu knobs only. Advanced/dev knobs
(``provider``, the refusal-recovery ``fallback_*`` tier, ``local_*``, and
``verbosity.color`` / ``show_http``) stay as code-only defaults in
``src/graph.py`` and are not surfaced here.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Factory defaults — the seed for swarm-config.toml. Shape mirrors the toml
# tables exactly (``[budgets]`` / ``[model]`` / ``[verbosity]``). Edit the
# toml to change what runs; these only matter on first run or for a key you
# deleted from the file.
# ---------------------------------------------------------------------------
DEFAULTS: dict[str, dict[str, Any]] = {
    "budgets": {
        "planner_max_iters": 50,
        # Worker budget in REAL tool-using rounds (model decides + a tool runs).
        # Converted to a LangGraph super-step recursion_limit (~3 super-steps
        # per round) in skill_runner, so 20 here == 20 real rounds. The old
        # value 40 was super-steps and gave only ~13 real rounds; 20 rounds lets
        # a multi-step exploit finish inside one dispatch.
        "worker_max_iterations": 20,
        "llm_max_tokens": 4096,
        # Per-LLM-call timeout in SECONDS (httpx read/connect for one Codex
        # streaming call). gpt-5.5 at reasoning_effort=medium produces calls up
        # to ~114s; 120 was too tight (calls hit it -> retryable
        # CodexTransportError). 240 gives headroom. SWARM_LLM_TIMEOUT_S overrides.
        "llm_call_timeout_s": 240,
        # Per-benchmark agent wall-clock budget, in SECONDS (1200 = 20 min,
        # 2400 = 40 min). The leash on one graph run; when it expires the run
        # ends with "agent timeout after Ns". Edit here or via the TUI.
        "run_timeout_s": 1200,
    },
    "model": {
        "slug": "gpt-5.5",
        "reasoning_effort": "low",
        "reasoning_summary": "detailed",
        # Web-search synthesis is a relay/summarize task (reproduce payloads
        # from crawled markdown) — it doesn't need the flagship. A cheaper,
        # faster, more refusal-resistant model (gpt-5.4 @ low) cuts the ~55s
        # synthesis that dominates each web_search call.
        "web_search_synth_model": "gpt-5.4",
        "web_search_synth_reasoning_effort": "low",
    },
    "verbosity": {
        "mode": "compact",
    },
    # Ablation switches — each turns OFF one capability of the agent so its
    # contribution can be measured (see the thesis ablation study). EVERY flag
    # defaults to ``false``: with the whole table at its defaults the full
    # system runs byte-identically, so a normal run is never affected. Flip one
    # to ``true`` (by hand or via the `swarm` -> Capability menu) to run that
    # ablation. The matching gates live next to each subsystem and read
    # ``config.capability.*`` from ``src/graph.py``.
    "capability": {
        # Drop ALL prompting techniques in one ablation: the static system-prompt
        # standards (diversity-over-depth, transformation hypothesis,
        # tested-vs-tested-enough, anti-bias checklist + enumeration) AND the
        # run-state [SYSTEM NOTE] steering nudges delivered to the planner and
        # workers (loop / primitive / hypothesis-lock / diversify / …). The paper
        # treats run-state steering as a prompting technique, so they ablate as
        # one flag. The evidence digest is KEPT, so the planner is deprived of
        # steering, not blinded.
        "disable_prompting_techniques": False,
        # Skip structured-hypothesis synthesis in the summarizer; the planner
        # then steers on raw findings instead of fused, evidence-bearing beliefs.
        "disable_hypothesis_passing": False,
        # Bypass the safety-refusal recovery ladder (preventive vocabulary
        # rewrite + same-model retries + fallback-model swap). A refused call
        # simply fails.
        "disable_refusal_handling": False,
        # Every executor runs as one generic worker (base prompt + all tools)
        # instead of a named, per-class skill. Recon is unaffected.
        "disable_skills": False,
        # The planner can no longer reach the web-search node; the agent relies
        # only on the model's own knowledge and the skills.
        "disable_web_search": False,
    },
}

# Valid values for the enum knobs. ``resolve()`` rejects anything else (a
# typo in the file falls back to the default rather than poisoning the run);
# the TUI offers exactly these.
CHOICES: dict[tuple[str, str], tuple[str, ...]] = {
    ("model", "slug"): (
        "gpt-5.5", "gpt-5.4", "gpt-5.4-mini",
        "gpt-5.3-codex", "gpt-5.2", "codex-auto-review",
    ),
    ("model", "reasoning_effort"): (
        "none", "minimal", "low", "medium", "high", "xhigh",
    ),
    ("model", "reasoning_summary"): (
        "auto", "concise", "detailed", "none",
    ),
    ("model", "web_search_synth_model"): (
        "gpt-5.5", "gpt-5.4", "gpt-5.4-mini",
        "gpt-5.3-codex", "gpt-5.2", "codex-auto-review",
    ),
    ("model", "web_search_synth_reasoning_effort"): (
        "none", "minimal", "low", "medium", "high", "xhigh",
    ),
    ("verbosity", "mode"): (
        "silent", "compact", "verbose",
    ),
}


def toml_path() -> Path:
    """Absolute path to ``SwarmAttacker/swarm-config.toml``.

    Resolved from this file's location (``src/config_schema.py`` →
    ``parents[1]`` is the SwarmAttacker root) so it is stable regardless of
    the process's working directory — every entry point and subprocess reads
    the same file.
    """
    return Path(__file__).resolve().parents[1] / "swarm-config.toml"


def load() -> dict[str, dict[str, Any]]:
    """Read ``swarm-config.toml`` into a nested dict.

    Returns ``{}`` if the file is missing (first run) or fails to parse — a
    corrupt file must not brick the CLI; we warn and fall back to defaults.
    """
    p = toml_path()
    if not p.exists():
        return {}
    try:
        with p.open("rb") as f:
            return tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        print(f"warning: failed to parse {p.name}: {exc}", file=sys.stderr)
        return {}


def _is_valid(default: Any, val: Any) -> bool:
    """Does ``val`` (from the file) have the right type to replace ``default``?

    ``bool`` is checked before ``int`` because ``bool`` is a subclass of
    ``int`` in Python — otherwise a stray ``true`` would pass as an int.
    """
    if isinstance(default, bool):
        return isinstance(val, bool)
    if isinstance(default, int):
        return isinstance(val, int) and not isinstance(val, bool)
    return isinstance(val, str)


def resolve() -> dict[str, dict[str, Any]]:
    """Effective config: factory ``DEFAULTS`` overlaid with ``swarm-config.toml``.

    A value present (and valid) in the file wins; a wrong-typed value or an
    enum value not in ``CHOICES`` is ignored and the default is used, so a
    hand-edit typo can never put garbage into the running config. The result
    is always fully populated — every menu knob present.
    """
    on_disk = load()
    out: dict[str, dict[str, Any]] = {}
    for table, keys in DEFAULTS.items():
        file_tbl = on_disk.get(table)
        if not isinstance(file_tbl, dict):
            file_tbl = {}
        out[table] = {}
        for key, default in keys.items():
            val = file_tbl.get(key, default)
            if not _is_valid(default, val):
                val = default
            choices = CHOICES.get((table, key))
            if choices is not None and val not in choices:
                val = default
            out[table][key] = val
    return out
