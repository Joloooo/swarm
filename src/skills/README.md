# SwarmAttacker skills

Agentskills.io-compliant `SKILL.md` files for SwarmAttacker's pentest
techniques and reference material. Each top-level folder is one skill; the
folder name MUST match the SKILL.md frontmatter `name`. Folders may also
contain a `references/` subdirectory for material that should only be pulled
in on demand.

## Frontmatter

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Lowercase + hyphens. Must match the folder name — it IS the skill's identity (its dispatch key, worker label, and report group all derive from it). Max 64 chars. |
| `description` | yes | When-to-dispatch routing signal for the planner. Max 1024 chars. |
| `metadata` | no | SwarmAttacker-specific fields nest here (see below). |

### `metadata` block (SwarmAttacker fields)

Keep this minimal — most skills only need `dispatchable`. Everything else is
either derived from the folder name or comes from global config.

| Field | Type | Notes |
|---|---|---|
| `dispatchable` | bool | Set `true` to offer this skill on the planner's menu. **Omit it for reference-only skills** (e.g. `vuln-classes`, the framework notes) — they stay loadable on disk but off the menu. |
| `tools` | list[string] | **Only when the skill needs tools beyond the default `[bash]`** (e.g. `sqli` lists sqlmap, `recon-ports` lists the nmap wrappers). Omit for bash-only skills. |
| `skip_base_prompt` | bool | Optional. When `true`, the SKILL.md body is the entire system prompt (no identity/rules preamble). |

What is **not** in the frontmatter (and why):

- **`agent_id` / `config_name` / `methodology`** — derived from the folder name.
- **`max_iterations` / `max_tool_calls`** — a single global knob,
  `budgets.worker_max_iterations` in `swarm-config.toml`, applies to every
  worker.
- **`phase`** — the recon node sets the recon framing on whatever it runs; the
  executor node is the default. Skills don't declare it.

## Minimal example

```markdown
---
name: example-vector
description: >-
  Use example-vector when recon shows … (concrete, recon-observable triggers).
metadata:
  dispatchable: true
---

You are an example-vector specialist. Your job is to ...
```

A specialised skill adds only its extra tools:

```yaml
metadata:
  dispatchable: true
  tools: [bash, sqlmap_basic, sqlmap_enum_dbs]
```

A reference-only skill omits `dispatchable` entirely (and usually has no
`metadata` at all).

## Validation

```sh
python3 ~/.claude/skills/validate-skill/scripts/validate.py src/skills/sqli
```

## Runtime

These SKILL.md files ARE the runtime source of truth. `src/skills/loader.py`
discovers each folder, builds an `AgentConfig`, and exposes the dispatchable
ones to the planner; `ReconNode` / `ExecutorNode` run them. Reference skills
(no `dispatchable`) are loaded but only pulled in on demand via
`load_reference`.
