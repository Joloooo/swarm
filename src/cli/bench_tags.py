"""Read each XBEN benchmark's vulnerability tags from its ``benchmark.yaml``.

Every benchmark ships a ``benchmark.yaml`` with a ``tags:`` list naming the
vulnerability class(es) it tests (``xss``, ``idor``, ``sqli``,
``default_credentials`` …). This module surfaces those tags so the TUI picker
can label each row by what it tests (``XBEN-004-xss`` instead of
``XBEN-004-24``) and break a column of failures down by category, and so the
campaign dashboard can do the same.

Like :mod:`src.cli.bench_discovery`, this module is deliberately **graph-free**
(importing ``src.graph`` would freeze the config singleton in the TUI parent
process — see that module's docstring) and **yaml-free**: the ``tags:`` block
is a flat list of scalar strings, so a five-line hand-parser reads it without
pulling PyYAML into the picker's import path. Tags are loaded once and cached
for the process (the picker re-renders on every keypress — it must not re-read
104 files each frame).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

# Mirror :data:`src.cli.bench_discovery.XBOW_BENCH_DIR` — the on-disk home of
# the XBEN-*-24 benchmark directories, each holding a ``benchmark.yaml``.
#   parents[0]=src/cli  parents[1]=src  parents[2]=SwarmAttacker  parents[3]=Thesis
XBOW_BENCH_DIR = (
    Path(__file__).resolve().parents[3]
    / "Benchmarks"
    / "xbow-validation"
    / "benchmarks"
)


def _parse_tags(yaml_text: str) -> tuple[str, ...]:
    """Extract the scalar list under the top-level ``tags:`` key.

    The block is always shaped like::

        tags:
        - xss
        - idor
        content:
        ...

    so we scan for the ``tags:`` line, then collect every following ``- item``
    line until the first line that is neither a list item nor blank (the next
    top-level key). No YAML library needed for this fixed, flat shape.
    """
    tags: list[str] = []
    in_block = False
    for raw in yaml_text.splitlines():
        if not in_block:
            if raw.strip() == "tags:":
                in_block = True
            continue
        stripped = raw.strip()
        if stripped.startswith("-"):
            tag = stripped[1:].strip()
            if tag:
                tags.append(tag)
        elif stripped == "":
            continue          # tolerate a stray blank line inside the block
        else:
            break             # next top-level key → block is done
    return tuple(tags)


@lru_cache(maxsize=1)
def _all() -> dict[str, tuple[str, ...]]:
    """``{bench_id: (tag, …)}`` for every benchmark on disk, read once.

    Empty dict if the submodule is missing. A benchmark whose yaml can't be
    read (or has no ``tags:``) maps to an empty tuple rather than being
    dropped, so callers can always look an id up.
    """
    out: dict[str, tuple[str, ...]] = {}
    if not XBOW_BENCH_DIR.is_dir():
        return out
    for d in sorted(XBOW_BENCH_DIR.glob("XBEN-*-24")):
        if not d.is_dir():
            continue
        try:
            text = (d / "benchmark.yaml").read_text(encoding="utf-8")
        except OSError:
            out[d.name] = ()
            continue
        out[d.name] = _parse_tags(text)
    return out


def tags_for(bench_id: str) -> tuple[str, ...]:
    """The vulnerability tags for ``bench_id`` (empty tuple if none/unknown)."""
    return _all().get(bench_id, ())


def primary_tag(bench_id: str) -> str:
    """The first (primary) tag for ``bench_id``, or ``""`` if it has none."""
    tags = tags_for(bench_id)
    return tags[0] if tags else ""


def label_parts(bench_id: str) -> tuple[str, tuple[str, ...]]:
    """Split the display label into ``(base, tags)``.

    ``base`` is the id with its ``-24`` suffix trimmed to a trailing dash
    (``XBEN-004-``); ``tags`` is the tag tuple. A benchmark with no tags
    returns ``(bench_id, ())`` so the label is the unchanged id. The picker
    uses this to colour the ``base`` and the tags differently.
    """
    tags = tags_for(bench_id)
    if not tags:
        return bench_id, ()
    base = bench_id[:-2] if bench_id.endswith("-24") else bench_id + "-"
    return base, tags


def short_id(bench_id: str, *, sep: str = ",") -> str:
    """``XBEN-004-24`` → ``XBEN-004-xss`` — the id with its ``-24`` suffix
    replaced by the tag(s).

    Multiple tags are joined with ``sep`` (``XBEN-005-idor,jwt,default_credentials``).
    A benchmark with no tags falls back to the unchanged id, so the label is
    never a bare ``XBEN-005-``.
    """
    base, tags = label_parts(bench_id)
    return base + sep.join(tags)


def category_counts(bench_ids: list[str]) -> list[tuple[str, int]]:
    """Group ``bench_ids`` by primary tag → ``[(tag, count), …]``.

    Sorted by count descending, then tag name. Each benchmark is counted once
    (under its primary/first tag) so the counts sum to ``len(bench_ids)`` — the
    breakdown is a partition of the input, not an overlapping per-tag tally.
    Benchmarks with no tag are grouped under ``"untagged"``.
    """
    counts: dict[str, int] = {}
    for bid in bench_ids:
        key = primary_tag(bid) or "untagged"
        counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def widest_short_id(bench_ids: list[str]) -> int:
    """Length of the longest :func:`short_id` over ``bench_ids`` (0 if empty).

    The picker uses this to size its grid columns once, up front, since the
    tag-expanded labels vary in width (``XBEN-004-xss`` vs
    ``XBEN-005-idor,jwt,default_credentials``).
    """
    return max((len(short_id(b)) for b in bench_ids), default=0)
