"""Read/write side of ``swarm-config.toml`` — the TUI's persistence layer.

``swarm-config.toml`` is the single source of truth for the user-facing menu
knobs (budgets, model slug + reasoning, verbosity). The factory defaults, the
valid choices, and the file→values resolution all live in
:mod:`src.config_schema`; ``src/graph.py`` reads them from there at startup.

This module is just the write/display side used by the ``swarm`` TUI:

  - :func:`get_current_view` — the fully-populated current config for the menu,
  - :func:`save` — write the WHOLE file (every knob, with comments) atomically,
  - :func:`ensure_complete` — materialize a missing/partial file so it always
    contains every knob (called once at startup),

plus thin re-exports (``path``, ``load``, and the ``*_CHOICES`` tuples) so the
existing call sites keep working unchanged.

There is no env-var bridge any more: ``graph.py`` reads ``swarm-config.toml``
directly, so editing the file — by hand or via the TUI — is all that's needed;
the change is picked up on the next ``swarm`` run.

``color`` and ``show_http`` are intentionally NOT in the file: ``color`` is
auto-detected from the TTY at runtime and ``show_http`` is a rarely-toggled
debug flag — both stay as code-only / shell-env settings in ``src/graph.py``.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import tomlkit

from src.config_schema import (
    CHOICES,
    DEFAULTS,
    load,  # noqa: F401 — re-exported for callers that read the raw file
    resolve,
)
from src.config_schema import toml_path as path  # noqa: F401 — re-export as config_store.path

# Enum choices for the TUI menu. Single definition lives in src.config_schema;
# re-exported here so ``config_store.MODEL_CHOICES`` etc. keep working.
MODEL_CHOICES: tuple[str, ...] = CHOICES[("model", "slug")]
REASONING_EFFORT_CHOICES: tuple[str, ...] = CHOICES[("model", "reasoning_effort")]
REASONING_SUMMARY_CHOICES: tuple[str, ...] = CHOICES[("model", "reasoning_summary")]
WEB_SYNTH_MODEL_CHOICES: tuple[str, ...] = CHOICES[("model", "web_search_synth_model")]
WEB_SYNTH_EFFORT_CHOICES: tuple[str, ...] = CHOICES[("model", "web_search_synth_reasoning_effort")]
VERBOSITY_CHOICES: tuple[str, ...] = CHOICES[("verbosity", "mode")]

_HEADER_COMMENTS = (
    "swarm-config.toml — the complete, authoritative config for the `swarm` CLI.\n"
    "Every menu knob is listed here with its current value. Edit by hand OR via\n"
    "the TUI (`swarm` -> Edit config); changes take effect on the next `swarm` run.\n"
    "Delete this file to reset to factory defaults; it is recreated, complete, on\n"
    "the next run. (Factory defaults + valid values live in src/config_schema.py.)"
)

# A one-line banner written above each table when the file is first created.
_SECTION_COMMENTS = {
    "budgets":   "Planner / worker / LLM budgets.",
    "model":     "Model slug + Codex reasoning controls.",
    "verbosity": "Console verbosity: silent | compact | verbose.",
    "capability": (
        "Ablation switches — turn OFF one agent capability to measure its\n"
        "contribution. ALL default false = full system, byte-identical. Flip\n"
        "one to true for an ablation run (see `swarm` -> Capability)."
    ),
    "dev": (
        "Developer mode (NOT an ablation switch). Off by default. Turning it on\n"
        "re-enables development-only observability that is not part of the\n"
        "measured system (currently the planner's skill_ranking)."
    ),
}


def get_current_view() -> dict[str, dict[str, Any]]:
    """The fully-populated current config (file values overlaid on defaults).

    Delegates to :func:`src.config_schema.resolve`, so the TUI always sees the
    full menu surface — every knob present — even when the file is missing or
    only carries a subset.
    """
    return resolve()


def save(cfg: dict[str, dict[str, Any]]) -> None:
    """Write ``cfg`` to ``swarm-config.toml`` atomically — EVERY knob, always.

    No key is ever stripped: the file is the complete picture, so opening it
    shows every value and a TUI edit is immediately visible on disk. Uses
    ``tomlkit`` so hand-added comments survive a round-trip, then writes to
    ``<path>.tmp`` and ``flush`` + ``fsync`` + atomic ``os.replace`` (the repo
    can live under ``~/My Drive/``, which needs the fsync or the rename can
    race Drive's async sync).
    """
    p = path()
    if p.exists():
        with p.open("r", encoding="utf-8") as f:
            doc = tomlkit.parse(f.read())
    else:
        doc = tomlkit.document()
        for line in _HEADER_COMMENTS.splitlines():
            doc.add(tomlkit.comment(line))
        doc.add(tomlkit.nl())

    for table_name, keys in DEFAULTS.items():
        if table_name not in doc:
            tbl = tomlkit.table()
            comment = _SECTION_COMMENTS.get(table_name)
            if comment:
                # tomlkit.comment() only prefixes a single line with '#'; a
                # multi-line section banner must be split or the 2nd+ lines land
                # in the file without '#' and corrupt the TOML.
                for line in comment.splitlines():
                    tbl.add(tomlkit.comment(line))
            doc[table_name] = tbl
        for key, default in keys.items():
            doc[table_name][key] = cfg.get(table_name, {}).get(key, default)

    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(tomlkit.dumps(doc))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


def ensure_complete() -> None:
    """Make ``swarm-config.toml`` contain EVERY menu knob.

    - Missing / first run  -> write the full file at factory defaults.
    - Partial (e.g. a legacy file with only ``reasoning_effort``) -> fill the
      absent keys while KEEPING the values already in the file.
    - Already complete      -> nothing to do (just a parse, no write).

    Called once at CLI/TUI startup so a hand-edited or upgraded file is always
    materialized in full. Best-effort: never raises — a write failure must not
    block startup (the run still uses :func:`resolve` values in memory).
    """
    on_disk = load()
    complete = all(
        isinstance(on_disk.get(table), dict) and key in on_disk[table]
        for table, keys in DEFAULTS.items()
        for key in keys
    )
    if complete:
        return
    try:
        save(get_current_view())
    except Exception as exc:  # noqa: BLE001 — never brick startup over the config file
        print(f"warning: could not materialize {path().name}: {exc}", file=sys.stderr)
