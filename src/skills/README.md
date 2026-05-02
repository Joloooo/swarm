# SwarmAttacker skills

Agentskills.io-compliant `SKILL.md` files for SwarmAttacker's pentest
attack vectors and reference techniques. Each top-level folder is one
skill; the folder name MUST match the SKILL.md frontmatter `name`.
Folders may also contain a `references/` subdirectory for material that
should only be pulled in on demand.

## Frontmatter

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Lowercase + hyphens. Must match the folder name. Max 64 chars. |
| `description` | yes | Trigger phrase for progressive disclosure. Max 1024 chars. |
| `metadata` | no | Free-form. SwarmAttacker-specific fields nest here. |

### `metadata` block (SwarmAttacker fields)

| Field | Type | Notes |
|---|---|---|
| `agent_id` | string | e.g. `vulntype-sqli` |
| `methodology` | string | `owasp` \| `vulntype` \| `custom` |
| `config_name` | string | Primary key for planner dispatch (matches `name`) |
| `tools` | list[string] | Tool names — resolved by a future tool registry |
| `skill_names` | list[string] | Optional cross-skill references (legacy) |
| `max_tool_calls` | int | Cap |
| `max_iterations` | int | Cap |

## Minimal example

```markdown
---
name: example-vector
description: Use when testing for example-vector — concrete trigger phrases here.
metadata:
  agent_id: vulntype-example
  methodology: vulntype
  config_name: example-vector
  tools: [bash]
  max_tool_calls: 40
  max_iterations: 25
---

You are an example-vector specialist. Your job is to ...
```

## Validation

```sh
python3 ~/.claude/skills/validate-skill/scripts/validate.py src/skills/sqli
```

## Runtime status

These SKILL.md files are **not yet wired into the runtime**. The Python
configs under `src/agents/configs/` remain the source of truth. A
follow-up PR will add a SKILL.md loader, expose a `load_skill` tool to
LLM nodes, and remove the duplication.
