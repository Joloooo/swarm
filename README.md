# SwarmAttacker

Multi-methodology swarm penetration testing agent built with LangGraph. Part of a master's thesis on autonomous LLM-based penetration testing.

The core idea: instead of running one methodology at a time, SwarmAttacker deploys multiple attack agents in parallel (OWASP categories, vulnerability-specific specialists, custom attack chains) and aggregates results.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (package manager)
- tmux (for agent session isolation)
- An LLM API key (Anthropic, OpenAI, or OpenRouter)

## Setup

```bash
# Install dependencies
uv sync

# Configure API keys
cp .env.example .env
# Edit .env and add your keys
```

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | If using Anthropic | Claude API key |
| `OPENAI_API_KEY` | If using OpenAI | OpenAI API key |
| `OPENROUTER_API_KEY` | If using OpenRouter | OpenRouter API key |
| `LANGSMITH_API_KEY` | Optional | Enables LangSmith tracing in LangGraph Studio |

## Running

### CLI

```bash
# Basic scan (analyze only)
uv run swarmattacker http://target.local

# With scope restriction
uv run swarmattacker http://target.local --scope "*.target.local"

# Full mode (analyze + exploit)
# (requires workflow configs with exploit phase defined)
uv run swarmattacker http://target.local --mode full

# Verbose logging
uv run swarmattacker http://target.local -v

# With ablation experiment overlay
uv run swarmattacker http://target.local --experiment no_rag
```

### LangGraph Studio (visual debugger)

LangGraph Studio provides a visual graph UI where you can see nodes light up as agents execute, inspect per-agent state, and step through runs.

```bash
# Start the dev server (opens Studio in browser)
langgraph dev
```

This reads `langgraph.json` which points to `src/graph.py:graph`. Studio will show the full graph: `initialize → recon → pentest_workflow(s) → check_tier2 → report`.

### LangGraph Platform API (programmatic)

For running benchmarks and evaluation experiments without a UI:

```bash
# Start the API server
langgraph up

# Then invoke via Python or curl
curl -X POST http://localhost:8123/runs \
  -H "Content-Type: application/json" \
  -d '{"input": {"target_url": "http://target.local"}}'
```

### Benchmarks

```bash
# Run against a single target
uv run python -m benchmarks.runner --target dvwa

# Run ablation study (all experiment configs)
uv run python -m benchmarks.ablation --target dvwa

# Multi-model comparison
uv run python -m benchmarks.multimodel --target dvwa
```

Benchmark targets are defined in `benchmarks/targets.yaml`. Results are saved to `benchmarks/results/` as JSON and LaTeX tables.

## Architecture

```
START → initialize → recon → [Tier 1 router fans out] → pentest_workflow(s) → check_tier2 → report → END
```

**Nodes** (`src/nodes/`):
- `initialize` — sets up target info and defaults
- `recon` — runs the reconnaissance agent (port scan, directory discovery, fingerprinting)
- `pentest_workflow` — executes a two-phase attack workflow (analyze → optionally exploit)
- `check_tier2` — activates the dynamic LLM planner if Tier 1 found too few results
- `report` — aggregates all findings into a final report

**Edges** (`src/edges/`):
- `route_after_recon` — Tier 1 router analyzes recon output and dispatches relevant workflows in parallel via `Send()`
- `route_tier2` — routes to report after Tier 2 check

**Key subsystems:**
- `agents/` — config-driven agent pattern. One function, different configs. 14 agents across 3 methodologies (OWASP, vuln-type, custom chains)
- `planning/` — two-tier planning. Tier 1: deterministic regex-based router. Tier 2: LLM-generated dynamic agents
- `knowledge/` — triple-hybrid knowledge delivery. Layer 1: prompt rules. Layer 2: skill docs. Layer 3: RAG vector store
- `stealth/` — WAF/IDS detection (Cloudflare, ModSecurity, AWS WAF) with stealth level propagation
- `loop/` — 4-strategy loop detection (hard cap, exact repeat, same-tool repeat, budget pressure)
- `experience/` — guide storage for learning from past runs (Jaccard similarity matching)
- `llm/` — provider-agnostic interface (Anthropic, OpenAI, OpenRouter)

## Project structure

```
SwarmAttacker/
├── pyproject.toml              # Project config (uv + hatchling)
├── langgraph.json              # LangGraph Studio entry point
├── configs/
│   ├── default.yaml            # Base runtime config with all toggles
│   └── experiments/            # Ablation experiment overlays
├── benchmarks/
│   ├── targets.yaml            # Benchmark target definitions (DVWA, Juice Shop, etc.)
│   ├── runner.py               # Benchmark runner
│   ├── ablation.py             # Ablation experiment runner
│   ├── multimodel.py           # Multi-model comparison
│   └── metrics.py              # Metric computation
├── src/                        # Main Python package
│   ├── graph.py                # LangGraph graph (pure wiring)
│   ├── state.py                # Shared state schema + reducers
│   ├── config.py               # YAML config loader with ablation toggles
│   ├── cli.py                  # CLI entry point
│   ├── nodes/                  # Graph nodes (one file per node)
│   ├── edges/                  # Routing logic
│   ├── agents/                 # Config-driven agent system
│   │   ├── base.py             # AgentConfig, WorkflowConfig, make_agent_node
│   │   └── configs/            # 14 agent configs (owasp/, vulntype/, custom/)
│   ├── planning/               # Tier 1 router + Tier 2 dynamic planner
│   ├── knowledge/              # 3-layer knowledge system
│   ├── tools/                  # tmux-based command execution
│   ├── stealth/                # WAF/IDS detection
│   ├── loop/                   # Loop detection
│   ├── experience/             # Guide storage
│   └── llm/                    # Provider-agnostic LLM interface
└── tests/
```

## Configuration

Runtime behavior is controlled by `configs/default.yaml`. Each setting can be overridden per-experiment via files in `configs/experiments/`.

Key toggles:
- `knowledge.base_rules` / `skill_loading` / `rag` — enable/disable each knowledge layer
- `planning.tier1_router` / `tier2_planner` — enable/disable planning tiers
- `stealth.enabled` — enable/disable WAF/IDS evasion
- `agents.methodologies.owasp` / `vulntype` / `custom` — enable/disable agent groups

## Dependencies

| Package | Purpose |
|---|---|
| `langgraph` | Graph orchestration, state management, checkpointing, Studio |
| `langchain-core` | Base abstractions (messages, tools, chat models) |
| `langchain-anthropic` | Claude model integration |
| `langchain-openai` | OpenAI / OpenRouter model integration |
| `pydantic` | Data validation (used by LangChain internals) |
| `libtmux` | tmux session management for agent command isolation |
| `pyyaml` | YAML config file loading |
