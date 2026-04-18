# SwarmAttacker

Multi-methodology swarm penetration testing agent built with LangGraph. Part of a master's thesis on autonomous LLM-based penetration testing.

The core idea: instead of running one methodology at a time, SwarmAttacker deploys multiple attack agents in parallel (OWASP categories, vulnerability-specific specialists, custom attack chains) and aggregates results.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (package manager)
- tmux (for agent session isolation) — install with `brew install tmux`
- Pentesting tools your agents will call: `nmap`, `gobuster`, `sqlmap`, `curl` — install with `brew install nmap gobuster sqlmap`
- An LLM backend, **one of**:
  - **ChatGPT Plus/Pro subscription** (recommended, free with subscription — see [LLM Provider: Codex](#llm-provider-codex-chatgpt-subscription) below)
  - Anthropic API key
  - OpenAI API key
  - OpenRouter API key

## Setup

```bash
uv sync                  # install Python deps + create .venv
./scripts/setup.sh       # install pentesting tools (tmux, nmap, gobuster, sqlmap)
cp .env.example .env     # create .env (can stay empty if using Codex auth)
codex                    # one-time ChatGPT login (saves tokens to ~/.codex/auth.json)
```

## Quick start (local, vulnerable target)

When debugging the agent, point it at a known-vulnerable container running
locally — not a real public site. Frontier models (especially the Codex
backend) often refuse to attack real-looking domains regardless of what
the prompt says, which makes it hard to tell whether the agent is broken
or the model is just refusing.

```bash
# Start OWASP Juice Shop on port 3000 (or use the helper):
bash benchmarks/run_juice_shop.sh

# Then in LangGraph Studio chat:
#   target_url = http://localhost:3000
# Expected: chat shows initialize → recon → [sqli] tool calls →
#   [sqli] finding(s) → … → final report. No blank period > ~10s.
# Expected: at least one SQLi finding on /rest/user/login
#   (classic ' OR 1=1-- on the email field).
```

If you see `⚠️ [agent-id] model refused the task` in chat, the LLM
endpoint is the problem. Check the `LLM provider initialized: …` line
that `provider.py` logs at startup — if `provider=codex` you're hitting
ChatGPT's policy layer at `chatgpt.com/backend-api/codex/responses`,
which is stricter than direct Anthropic. The authorization preamble in
`src/knowledge/prompts/base_rules.py` reduces but doesn't eliminate
these refusals; switching that agent's `LLMConfig` to Anthropic is the
last-resort workaround.

## Running

```bash
source .venv/bin/activate
langgraph dev --allow-blocking
```

Studio opens automatically in your browser. `--allow-blocking` is needed
because the tmux-based terminal tool uses subprocess calls that
LangGraph's blockbuster detector flags (they're already wrapped in
`asyncio.to_thread` and don't actually block the event loop).

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
- `llm/` — provider-agnostic interface (Anthropic, OpenAI, OpenRouter, Codex)
  - `llm/codex.py` — self-contained LangChain chat model for the ChatGPT subscription / Codex backend. Handles OAuth token loading + refresh, Responses API SSE streaming, tool calls, all without any third-party library

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
