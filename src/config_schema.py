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
        "worker_max_iterations": 60,
        "custom_attack_max_tool_calls": 40,
        "custom_attack_max_iterations": 25,
        "llm_max_tokens": 4096,
        "web_search_max_crawled_chars": 8000,
        "escalation_enabled": True,
        "escalation_fork_after_seconds": 600,
    },
    "model": {
        "slug": "gpt-5.5",
        "reasoning_effort": "low",
        "reasoning_summary": "detailed",
    },
    "verbosity": {
        "mode": "compact",
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
