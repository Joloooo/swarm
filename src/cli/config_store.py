"""Persistent config for the ``swarm`` CLI.

This module owns:

  - the location of ``swarm-config.toml`` (repo-root, gitignored),
  - the mapping between TOML keys and ``SWARM_*`` environment
    variables consumed by :mod:`src.graph`,
  - reading (with stdlib ``tomllib``) and writing (with ``tomlkit``
    so comments and hand-edits survive round-trips),
  - and injecting saved values into ``os.environ`` BEFORE any
    subprocess that imports :mod:`src.graph` is spawned.

The TOML schema is intentionally shaped like the menu, not like the
legacy ``config.budgets.*`` grouping in ``src/graph.py`` — ``model.*``
is hoisted out of ``budgets`` into its own table because model knobs
are not budgets:

.. code-block:: toml

    [budgets]
    planner_max_iters            = 50
    worker_max_iterations        = 60
    custom_attack_max_tool_calls = 40
    custom_attack_max_iterations = 25
    llm_max_tokens               = 4096
    web_search_max_crawled_chars = 8000

    [model]
    slug              = "gpt-5.5"
    reasoning_effort  = "medium"
    reasoning_summary = "detailed"

    [verbosity]
    mode = "compact"

``color`` and ``show_http`` are deliberately omitted — ``color`` is
auto-detected from TTY at runtime (a persisted value would override
piped output) and ``show_http`` is a rarely-toggled debug flag that
stays as a shell-env override.

Precedence rule: persistent config WINS over stale shell env vars.
The TUI is now the user's primary control surface, so a fresh edit
from the menu must beat a three-week-old ``export SWARM_X=…`` line
that the user forgot about. ``load_into_env`` returns a list of
override messages so the banner can surface what it did.
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Any

import tomlkit


# ---------------------------------------------------------------------------
# Schema mirrors — these MUST track ``src/graph.py:134-188``.
#
# If anyone adds a new SWARM_* env var to graph.py, they update this dict
# AND the matching ``_CHOICES`` tuple below. The default values here are
# the fallbacks used when neither TOML nor shell env provides a value.
# ---------------------------------------------------------------------------

# Maps (toml_table, toml_key) → (SWARM_ENV_NAME, default_value, kind).
# kind ∈ {"int", "str"}; bool values are not exposed in the TOML.
KEY_TO_ENV: dict[tuple[str, str], tuple[str, Any, str]] = {
    ("budgets", "planner_max_iters"):            ("SWARM_PLANNER_MAX_ITERS",        50,     "int"),
    ("budgets", "worker_max_iterations"):        ("SWARM_WORKER_MAX_ITERATIONS",    60,     "int"),
    ("budgets", "custom_attack_max_tool_calls"): ("SWARM_CUSTOM_MAX_TOOL_CALLS",    40,     "int"),
    ("budgets", "custom_attack_max_iterations"): ("SWARM_CUSTOM_MAX_ITERATIONS",    25,     "int"),
    ("budgets", "llm_max_tokens"):               ("SWARM_LLM_MAX_TOKENS",         4096,     "int"),
    ("budgets", "web_search_max_crawled_chars"): ("SWARM_WEB_MAX_CHARS",          8000,     "int"),
    ("model",   "slug"):                         ("SWARM_MODEL",             "gpt-5.5",     "str"),
    ("model",   "reasoning_effort"):             ("SWARM_REASONING_EFFORT",  "medium",      "str"),
    ("model",   "reasoning_summary"):            ("SWARM_REASONING_SUMMARY", "detailed",    "str"),
    ("verbosity", "mode"):                       ("SWARM_VERBOSITY",         "compact",     "str"),
}

# These mirror the ``choices=...`` tuples in src/graph.py exactly so
# the menu can never produce an invalid value.
MODEL_CHOICES: tuple[str, ...] = (
    "gpt-5.5", "gpt-5.4", "gpt-5.4-mini",
    "gpt-5.3-codex", "gpt-5.2", "codex-auto-review",
)
REASONING_EFFORT_CHOICES: tuple[str, ...] = (
    "none", "minimal", "low", "medium", "high", "xhigh",
)
REASONING_SUMMARY_CHOICES: tuple[str, ...] = (
    "auto", "concise", "detailed", "none",
)
VERBOSITY_CHOICES: tuple[str, ...] = (
    "silent", "compact", "verbose",
)

_HEADER_COMMENTS = (
    "Edited by the `swarm` CLI. Hand-edits are preserved across saves.\n"
    "Empty / missing keys fall back to defaults baked into src/graph.py.\n"
    "Delete this file to reset everything; the TUI will recreate it."
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def path() -> Path:
    """Return ``SwarmAttacker/swarm-config.toml``.

    Resolved from this file's location so the path is stable
    regardless of the user's working directory.
    """
    # src/cli/config_store.py → parents[2] is the SwarmAttacker root.
    return Path(__file__).resolve().parents[2] / "swarm-config.toml"


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def load() -> dict[str, dict[str, Any]]:
    """Read ``swarm-config.toml`` into a nested dict.

    Returns an empty dict if the file is missing (first-run case) or
    fails to parse (we don't want a corrupt config to brick the
    CLI — we surface the error and fall back to defaults).
    """
    p = path()
    if not p.exists():
        return {}
    try:
        with p.open("rb") as f:
            return tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        print(f"warning: failed to parse {p.name}: {exc}", file=sys.stderr)
        return {}


def get_current_view() -> dict[str, dict[str, Any]]:
    """Return a fully-populated dict — file values overlaid on defaults.

    Used by the TUI to display the current value of every knob next to
    its label (e.g. ``Model (gpt-5.5)``). Even when the file is
    missing or only contains a subset, this returns the full menu
    surface.
    """
    on_disk = load()
    view: dict[str, dict[str, Any]] = {}
    for (table, key), (_env, default, _kind) in KEY_TO_ENV.items():
        view.setdefault(table, {})
        view[table][key] = on_disk.get(table, {}).get(key, default)
    return view


# ---------------------------------------------------------------------------
# Write (atomic, fsync-safe for Google Drive)
# ---------------------------------------------------------------------------

def save(cfg: dict[str, dict[str, Any]]) -> None:
    """Persist ``cfg`` to ``swarm-config.toml`` atomically.

    Strategy:
      1. Read the existing file with ``tomlkit`` (preserves comments
         and ordering) — or create a fresh document with our standard
         header if missing.
      2. Walk every key in ``KEY_TO_ENV``: if the new value differs
         from the default, write it; otherwise REMOVE it from the
         document so the file stays minimal (defaults stay implicit).
      3. Write to ``<path>.tmp``, ``flush + fsync`` (the project lives
         under ``~/My Drive/`` which is eventually consistent without
         an explicit fsync), then ``os.replace`` onto the target.
    """
    p = path()

    if p.exists():
        with p.open("r", encoding="utf-8") as f:
            doc = tomlkit.parse(f.read())
    else:
        doc = tomlkit.document()
        # Seed a comment header on first creation. Each comment() call
        # adds one line; the trailing empty line gives breathing room
        # before the first [table].
        for line in _HEADER_COMMENTS.splitlines():
            doc.add(tomlkit.comment(line))
        doc.add(tomlkit.nl())

    for (table_name, key), (_env, default, _kind) in KEY_TO_ENV.items():
        new_val = cfg.get(table_name, {}).get(key, default)

        if new_val == default:
            # User reset back to default — strip the key so the file
            # only carries genuine overrides. If the table becomes
            # empty as a result, drop it too.
            if table_name in doc and key in doc[table_name]:
                del doc[table_name][key]
                if len(doc[table_name]) == 0:
                    del doc[table_name]
            continue

        if table_name not in doc:
            doc[table_name] = tomlkit.table()
        doc[table_name][key] = new_val

    tmp = p.with_suffix(p.suffix + ".tmp")
    text = tomlkit.dumps(doc)
    with tmp.open("w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        # fsync is critical on Google-Drive-backed paths; without it the
        # rename can race with Drive's async sync and resurrect old
        # content. Costs ~5ms, worth every microsecond.
        os.fsync(f.fileno())
    os.replace(tmp, p)


# ---------------------------------------------------------------------------
# Env injection — the bridge to src.graph
# ---------------------------------------------------------------------------

def load_into_env(*, override: bool = True) -> list[str]:
    """Apply every saved TOML value to ``os.environ``.

    Returns a list of human-readable messages describing each env var
    that was overridden by the TUI. The banner prints these so the
    user can see when a stale shell export was shadowed.

    When ``override=False`` (currently unused; kept for symmetry),
    shell env wins and only un-set vars get the TOML value — the
    legacy semantics. Default is ``override=True`` per the precedence
    rule documented at the top of this module.
    """
    on_disk = load()
    messages: list[str] = []

    for (table, key), (env_name, _default, _kind) in KEY_TO_ENV.items():
        if table not in on_disk or key not in on_disk[table]:
            # Nothing saved → leave the env var alone (shell exports
            # and src/graph.py defaults still apply downstream).
            continue
        new_val = str(on_disk[table][key])
        old_val = os.environ.get(env_name)

        if old_val == new_val:
            os.environ[env_name] = new_val  # idempotent
            continue

        if old_val is None or override:
            os.environ[env_name] = new_val
            if old_val is not None:
                messages.append(
                    f"config override: {env_name} (was={old_val} → new={new_val})"
                )
        else:
            messages.append(
                f"shell env kept: {env_name}={old_val} "
                f"(TOML wanted {new_val}; pass override=True to flip)"
            )

    return messages
