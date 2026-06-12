"""Skill loader — turns a SKILL.md directory into an AgentConfig.

This module replaces the old ``src/agents/configs/`` registry. Each
attack vector now lives as ``src/skills/<name>/SKILL.md`` in the
agentskills.io format: YAML frontmatter (name, description, metadata)
followed by the Markdown system-prompt body. Optional bulky reference
material lives under ``src/skills/<name>/references/`` and is loaded on
demand via :func:`load_reference`.

The loader caches every parsed skill on first access so the planner and
worker nodes can call :func:`load_skill` repeatedly without re-reading
the disk. Custom skills the planner invents at run-time are registered
through :func:`register_custom_skill`; they live in the same in-memory
cache, so a later ``load_skill(name)`` resolves them just like a
file-backed skill.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from src.nodes.base import AgentConfig
from src.tools.registry import resolve_tools

logger = logging.getLogger(__name__)


# Default skills root (this file lives at src/skills/loader.py, so
# Path(__file__).parent IS the skills directory).
SKILLS_DIR = Path(__file__).parent


# Cache: config_name -> AgentConfig. Populated lazily by `load_skill`,
# then augmented at run-time by `register_custom_skill`.
_CACHE: dict[str, AgentConfig] = {}

# Parallel cache: config_name -> short description (from SKILL.md
# frontmatter). The planner uses these to build its dispatch menu —
# the LLM's "what does this skill do" hint without loading the full
# system prompt.
_DESCRIPTIONS: dict[str, str] = {}

# Skills with no metadata.agent_id are reference-only (e.g. the nmap
# skill — a tool-selection cheatsheet, not an attack vector). They get
# loaded into _CACHE so other skills can pull them, but stay out of the
# planner's dispatch menu.
_DISPATCHABLE: set[str] = set()

# Parallel cache: config_name -> normalized routing-signal specs declared
# in that skill's frontmatter (``metadata.routing_signals``). Fed to the
# hypothesis synthesis pass so each skill owns the observation patterns
# that route TO it, instead of a centralized hardcoded table. See
# :func:`list_skill_signal_specs` and ``src/llm/hypotheses.py``.
_ROUTING_SIGNALS: dict[str, list[dict]] = {}

_FILE_INDEX_BUILT = False


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """basically extracting basics of skill from yaml part and that would be provided in every context
    Split a SKILL.md into (frontmatter dict, body string).

    Accepts the standard ``---\\n<yaml>\\n---\\n<body>`` shape. Returns
    ``({}, text)`` for files without frontmatter so callers don't have
    to special-case it.
    """
    if not text.startswith("---"):
        return {}, text
    # Find the closing fence. The first split on "---\n" eats the leading
    # opener; the remainder splits cleanly into frontmatter + body.
    rest = text[3:].lstrip("\n")
    parts = rest.split("\n---", 1)
    if len(parts) != 2:
        return {}, text
    raw_yaml, body = parts
    try:
        meta = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError as exc:
        logger.warning("skill loader: malformed frontmatter — %s", exc)
        return {}, text
    if not isinstance(meta, dict):
        return {}, text
    return meta, body.lstrip("\n")


def _normalize_routing_signals(skill_name: str, md: dict) -> list[dict]:
    """Parse ``metadata.routing_signals`` into normalized spec dicts.

    Frontmatter shape (each entry declares ONE routing rule):

        routing_signals:
          - any: ["{{", "}}", "{%", "${"]        # one group; any marker hits
            weight: 0.7
          - all:                                   # co-occurrence; each group
              - ["{{", "}}", "{%", "${"]           #   must have a marker present
              - ["reject", "blocked", "filtered"]
            weight: 1.4
          - any: ["jinja", "flask", "twig"]
            vuln_class: ssti                        # defaults to the skill name
            weight: 0.8

    Returns ``[{name, vuln_class, weight, all_groups}, ...]`` where
    ``all_groups`` is a list of marker groups (lower-cased). Malformed
    entries are skipped, never raised — one bad entry must not break load.
    """
    raw = md.get("routing_signals")
    if not isinstance(raw, list):
        return []
    default_class = skill_name.strip().lower()
    out: list[dict] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("all"), list):
            groups_raw = [g for g in entry["all"] if isinstance(g, list)]
        elif isinstance(entry.get("any"), list):
            groups_raw = [entry["any"]]
        else:
            continue
        groups = [
            [str(m).strip().lower() for m in g if str(m).strip()]
            for g in groups_raw
        ]
        groups = [g for g in groups if g]
        if not groups:
            continue
        try:
            weight = float(entry.get("weight", 0.7))
        except (TypeError, ValueError):
            weight = 0.7
        out.append({
            "name": f"{default_class}-sig{i}",
            "vuln_class": str(entry.get("vuln_class") or default_class).strip().lower(),
            "weight": weight,
            "all_groups": groups,
        })
    return out


def _build_config(skill_name: str, meta: dict, body: str) -> tuple[AgentConfig, str, bool]:
    """Construct an AgentConfig from parsed SKILL.md content.

    Returns ``(config, description, dispatchable)``. A skill is
    "dispatchable" when its frontmatter sets ``metadata.dispatchable: true``
    — reference skills (e.g. the nmap notes, vuln-classes) omit it, so they
    are loaded on disk but not offered to the planner as targets. Identity
    (label, dispatch key, report group) all derive from the skill's folder
    name; budgets come from the global config.
    """
    from src.graph import config

    md = meta.get("metadata") or {}
    if not isinstance(md, dict):
        md = {}

    # Tools default to ``[bash]`` — most skills only need a shell so they omit
    # the field; specialised skills (sqli, recon, …) list their extra tools.
    tool_names = md.get("tools") or ["bash"]
    if not isinstance(tool_names, list):
        tool_names = ["bash"]
    tools = resolve_tools([str(n) for n in tool_names])

    description = str(meta.get("description") or "").strip()
    # Offered to the planner only when ``dispatchable: true`` is set. The
    # legacy ``agent_id`` presence is still honoured during the migration.
    dispatchable = bool(md.get("dispatchable")) or bool(md.get("agent_id"))

    # Phase routing — "recon" picks the universal+recon-hint prompt;
    # anything else (default "executor") gets the full executor rule
    # bundle. The field is intentionally permissive so a future
    # "neutral" phase (pure tooling helpers) can be added without a
    # loader change.
    phase = str(md.get("phase") or "executor").strip().lower()
    if phase not in {"executor", "recon"}:
        # Unknown phase strings fall back to executor rather than
        # crash; the worker still gets a sensible prompt.
        phase = "executor"

    cfg = AgentConfig(
        # Identity is the skill's own folder name — the label, the dispatch
        # key, and the report grouping all derive from it (no separate
        # agent_id / config_name / methodology fields in the frontmatter).
        agent_id=skill_name,
        methodology="skill",
        config_name=skill_name,
        system_prompt=body,
        tools=tools,
        max_iterations=config.budgets.worker_max_iterations,
        skip_base_prompt=bool(md.get("skip_base_prompt", False)),
        phase=phase,
    )
    return cfg, description, dispatchable


def _load_from_disk(name: str) -> AgentConfig | None:
    """Read ``src/skills/<name>/SKILL.md`` and build an AgentConfig.

    Returns None if the directory or SKILL.md doesn't exist. Side
    effects: populates ``_DESCRIPTIONS`` and ``_DISPATCHABLE`` so the
    planner-facing helpers reflect this skill on subsequent calls.
    """
    path = SKILLS_DIR / name / "SKILL.md"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    meta, body = _split_frontmatter(text)
    cfg, description, dispatchable = _build_config(name, meta, body)
    if description:
        _DESCRIPTIONS[cfg.config_name] = description
    if dispatchable:
        _DISPATCHABLE.add(cfg.config_name)
    md = meta.get("metadata") or {}
    if not isinstance(md, dict):
        md = {}
    specs = _normalize_routing_signals(name, md)
    if specs:
        _ROUTING_SIGNALS[cfg.config_name] = specs
    return cfg


def _build_file_index() -> None:
    """Eager-load every SKILL.md so list_skills() reflects disk state.

    The first call to list_skills() or load_skill(unknown) walks the
    skills/ directory once. After that, custom skills registered at
    run-time are added to the cache the same way.
    """
    global _FILE_INDEX_BUILT
    if _FILE_INDEX_BUILT:
        return
    _FILE_INDEX_BUILT = True
    if not SKILLS_DIR.exists():
        return
    for child in sorted(SKILLS_DIR.iterdir()):
        if not child.is_dir():
            continue
        if (child / "SKILL.md").exists() and child.name not in _CACHE:
            cfg = _load_from_disk(child.name)
            if cfg is not None:
                _CACHE[cfg.config_name] = cfg


def load_skill(name: str) -> AgentConfig | None:
    """Look up a skill by name. Returns None if not found.

    Resolution order:
        1. In-memory cache (already loaded or registered as custom).
        2. Disk: ``src/skills/<name>/SKILL.md``.
    """
    cached = _CACHE.get(name)
    if cached is not None:
        return cached
    cfg = _load_from_disk(name)
    if cfg is not None:
        _CACHE[cfg.config_name] = cfg
    return cfg


def register_custom_skill(name: str, system_prompt: str) -> AgentConfig:
    """Register an in-memory skill for one of the planner's custom_configs.

    Used by the planner when the LLM invents a tailored config on the
    fly. The custom skill always gets ``bash`` as its sole tool — if the
    planner needs typed tools it should pick a pre-built skill.
    Idempotent on the same name (overwrites).
    """
    from src.graph import config
    from src.tools.shell import bash

    cfg = AgentConfig(
        agent_id=f"custom-{name}",
        methodology="custom",
        config_name=name,
        system_prompt=system_prompt,
        tools=[bash],
        max_iterations=config.budgets.worker_max_iterations,
    )
    _CACHE[name] = cfg
    _DISPATCHABLE.add(name)
    return cfg


# Comprehensive pentester body for the planner's free-form ``tasks`` mode.
# This is the SKILL.md body equivalent — it is the *only* body content here
# because ``_build_system_message`` prepends the authorization preamble,
# narration rules, pentesting rules, and finding format around it. So this
# string only has to cover what's task-specific: role identity, the task
# itself, and execution guidance.
#
# The literature pattern (Happe & Cito, Fu et al.) is that the executor
# carries no methodology of its own — the planner decides what to do, and
# the executor just runs it well. That's what this prompt enforces:
# "do exactly the task, report findings in the standard format, stop."
GENERIC_EXECUTOR_PROMPT = """\
You are a generic penetration-testing executor. The supervisor has
delegated one specific task to you. Your job is to execute it on the
in-scope target, observe what happens, and report any findings.

You are NOT the planner. Do not expand the scope. Do not investigate
unrelated leads. If the task is "probe parameter X for IDOR", you
probe parameter X for IDOR; you do not also try SQLi, XSS, or path
traversal on the way. The supervisor will pick those up on the next
turn if they're warranted.

# Your task

{task}

# How to execute

1. Plan in one or two short sentences how you'll attempt the task —
   which tool, which payload class, what a positive vs. negative
   result will look like.
2. Use the ``bash`` tool to run commands. ``curl`` for HTTP probes,
   short ad-hoc scripts for chained requests, ``apt`` / ``pip`` /
   ``git`` to install missing tools on demand. Prefer focused
   single-purpose commands over kitchen-sink scans.
3. Read each tool result before issuing the next — let evidence guide
   payload escalation. If a payload is filtered, think about how
   before trying the next one.
4. When you have evidence (positive or negative), stop and emit your
   findings in the structured format from your operating rules. A
   "no vulnerability found, here is what I tried" report is a useful
   outcome — do not pad it with off-task probes.

# Stopping conditions

Stop and emit your final report when ANY of these is true:

- You confirmed the vulnerability and have a clean PoC.
- You ruled out the vulnerability with reasonable confidence given
  the task scope.
- You hit a blocker (auth required, target unreachable, WAF) that
  needs supervisor input — say so explicitly so the planner can
  pivot.

The supervisor reads your findings and decides the next move. Keep
your report tight and evidence-first.
"""


def register_generic_task(
    task_id: str,
    description: str,
) -> AgentConfig:
    """Register a one-shot executor for the planner's ``tasks`` mode.

    The supervisor stages a free-form task description (e.g. "probe
    /api/v1/orders for IDOR by mutating the ``id`` parameter"); we
    synthesise an AgentConfig that wraps it in
    :data:`GENERIC_EXECUTOR_PROMPT` and caches it under a fresh
    ``config_name``. The :class:`ExecutorNode` then resolves the config
    by name like any other skill — there is no special path in the node.

    ``task_id`` is taken from the dispatch index (``task-0``, ``task-1``,
    ...) so two simultaneous fan-outs don't share a cache slot.
    Idempotent on the same ``task_id`` (overwrites).
    """
    from src.graph import config as runtime_config
    from src.tools.shell import bash

    config_name = f"task-{task_id}"
    system_prompt = GENERIC_EXECUTOR_PROMPT.format(task=description.strip())

    cfg = AgentConfig(
        agent_id=f"executor-{task_id}",
        methodology="generic",
        config_name=config_name,
        system_prompt=system_prompt,
        tools=[bash],
        max_iterations=runtime_config.budgets.worker_max_iterations,
    )
    _CACHE[config_name] = cfg
    _DISPATCHABLE.add(config_name)
    return cfg


def list_skills() -> list[str]:
    """All skill names known to the loader (file-backed + custom)."""
    _build_file_index()
    return sorted(_CACHE.keys())


def list_dispatchable_skills() -> list[tuple[str, str]]:
    """``[(config_name, description), ...]`` for the planner's menu.

    Reference-only skills (e.g. the nmap cheatsheet) are filtered out —
    only skills whose frontmatter declares them as a real attack vector
    via ``metadata.agent_id`` show up here.
    """
    _build_file_index()
    return sorted(
        (name, _DESCRIPTIONS.get(name, "")) for name in _DISPATCHABLE
    )


def get_skill_description(name: str) -> str:
    """Return the frontmatter description for any known skill."""
    _build_file_index()
    return _DESCRIPTIONS.get(name, "")


def list_skill_signal_specs() -> list[dict]:
    """Flattened ``metadata.routing_signals`` specs across all skills.

    Each item: ``{name, vuln_class, weight, all_groups}``. Consumed by
    ``src.llm.hypotheses.routing_rules_from_specs`` to build skill-owned
    routing rules that supersede the built-in baseline per vuln class, so
    the observation patterns that route TO a skill live with that skill
    rather than in a centralized table.
    """
    _build_file_index()
    out: list[dict] = []
    for name in sorted(_ROUTING_SIGNALS):
        out.extend(_ROUTING_SIGNALS[name])
    return out


def list_skill_descriptions() -> list[tuple[str, str, bool]]:
    """Return ``[(name, description, dispatchable), ...]`` for every skill.

    Unlike :func:`list_dispatchable_skills`, this includes reference-only
    skills. Worker-side cross-skill context uses this as its catalogue.
    """
    _build_file_index()
    return sorted(
        (name, _DESCRIPTIONS.get(name, ""), name in _DISPATCHABLE)
        for name in _CACHE
    )


def load_reference(skill_name: str, reference_file: str) -> str | None:
    """Load a file from ``src/skills/<skill>/references/<file>``.

    Used for progressive-disclosure knowledge — the agent pulls a reference
    only when it actually needs it. Returns None if the file doesn't exist.
    """
    path = SKILLS_DIR / skill_name / "references" / reference_file
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def list_references(skill_name: str) -> list[str]:
    """Markdown reference filenames under ``src/skills/<skill>/references/``.

    Returns the ``*.md`` files (sorted), skipping any ``wordlists/`` data
    subdir and non-markdown artifacts. Empty when the skill has no
    references/ dir — callers use that to decide whether to advertise and
    bind the progressive-disclosure machinery at all.
    """
    rdir = SKILLS_DIR / skill_name / "references"
    if not rdir.is_dir():
        return []
    return sorted(
        p.name for p in rdir.iterdir() if p.is_file() and p.suffix == ".md"
    )


def reference_index(skill_name: str) -> list[tuple[str, str]]:
    """``[(filename, one-line description)]`` for a skill's references.

    The description is each file's first H1 header (the ``# ...`` line),
    which by convention reads ``<what it is> — Open WHEN: <trigger>``. The
    index is therefore a generated *view* of the files themselves — there is
    no separate manifest to drift out of sync. Falls back to the filename
    when a file has no H1.
    """
    out: list[tuple[str, str]] = []
    for fname in list_references(skill_name):
        path = SKILLS_DIR / skill_name / "references" / fname
        desc = fname
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("# "):
                    desc = stripped[2:].strip()
                    break
                if stripped:
                    break  # first real content isn't an H1 — use the filename
        except OSError:
            pass
        out.append((fname, desc))
    return out
