# SwarmAttacker skills

Agentskills.io-compliant `SKILL.md` files for SwarmAttacker's pentest
techniques and reference material. Each top-level folder is one skill; the
folder name MUST match the SKILL.md frontmatter `name`. Folders may also
contain a `references/` subdirectory for material that should only be pulled
in on demand.

## Frontmatter

A SKILL.md carries **only** `name` + `description` — nothing else. There is no
SwarmAttacker-specific `metadata` block; the files are plain, portable
agentskills.io skills.

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Lowercase + hyphens. Must match the folder name — it IS the skill's identity (its dispatch key, worker label, and report group all derive from it). Max 64 chars. |
| `description` | yes | When-to-dispatch routing signal for the planner. Max 1024 chars. |

Everything that used to live in a `metadata` block now lives in code, not the
frontmatter:

| What | Now lives in |
|---|---|
| **dispatchable** — is this skill on the planner's menu? | The dispatching node's `SKILLS` map. A skill is dispatchable iff it appears in `EXECUTOR_SKILLS` (`src/nodes/executor.py`) or `RECON_SKILLS` (`src/nodes/recon.py`). |
| **tools** — tools beyond the default `[bash]` | The same `SKILLS` map: `Skill(tools=(...))`. The node stamps `DEFAULT_TOOLS + tools` onto the config at dispatch. |
| **owned-classes** — which vuln-classes the worker may refute | The same `SKILLS` map: `Skill(owns=...)`. `None` = its own name-class, `frozenset()` = none (discovery/triage), `{...}` = exactly those. |
| **skip_base_prompt** — SKILL.md body is the whole prompt | The same `SKILLS` map: `Skill(skip_base_prompt=True)`. |
| **routing_signals** — observation patterns that raise a class's belief | The baseline `ROUTING_RULES` table in `src/llm/hypotheses.py`. |
| **agent_id / config_name / methodology** | Derived from the folder name. |
| **max_iterations** | The global `budgets.worker_max_iterations` in `swarm-config.toml`. |
| **phase** | Set by the node — `ReconNode` forces the recon framing; the executor is the default. |

## Minimal example

```markdown
---
name: example-vector
description: >-
  Use example-vector when recon shows … (concrete, recon-observable triggers).
---

You are an example-vector specialist. Your job is to ...
```

To make a skill dispatchable, add it to the executor's surface in
`src/nodes/executor.py` (or `RECON_SKILLS` in `src/nodes/recon.py`):

```python
EXECUTOR_SKILLS = {
    ...
    "example-vector": Skill(),                                  # bash-only, owns its own class
    "sqli": Skill(tools=("sqlmap_basic", "sqlmap_enum_dbs")),   # extra tools
    "input-validation": Skill(owns=frozenset({"lfi", "rce"})),  # multi-class specialist
}
```

A reference-only skill (e.g. `vuln-classes`, the framework notes) is simply
absent from every node's `SKILLS` map: it stays loadable on disk — and pullable
via `load_reference` — but never reaches the planner's menu.

## Validation

```sh
python3 ~/.claude/skills/validate-skill/scripts/validate.py src/skills/sqli
```

## Runtime

`src/skills/loader.py` discovers each folder and builds an `AgentConfig` from
the SKILL.md body (the prompt) + `description`. The nodes own the dispatch
surface: `list_dispatchable_skills()` reads the names from `EXECUTOR_SKILLS` /
`RECON_SKILLS`, and `ReconNode` / `ExecutorNode` stamp each skill's tools +
owned-classes onto the config before running it. Reference skills are loaded
but only pulled in on demand via `load_reference`.
