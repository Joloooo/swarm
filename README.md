errors to fix:
planner not displaying thinking or any other one reasoning part.
not possible physically
recon should not even have failures




# SwarmAttacker

Multi-methodology swarm penetration testing agent built with LangGraph. Part of a master's thesis on autonomous LLM-based penetration testing.

The core idea: instead of running one methodology at a time, SwarmAttacker deploys multiple attack agents in parallel (OWASP categories, vulnerability-specific specialists, custom attack chains) and aggregates results.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (package manager)
- tmux (for agent session isolation) — install with `brew install tmux`
- Pentesting tools your agents will call: `nmap`, `gobuster`, `sqlmap`, `nikto`, `curl` — install with `brew install nmap gobuster sqlmap nikto` (or just run `./scripts/setup.sh` below). Technology fingerprinting is done via `curl -sI` + the homepage HTML that `fetch_page` already pulls — `whatweb` is intentionally **not** required (it was dropped from Homebrew and added little over a header probe on our target workload).
- An LLM backend, **one of**:
  - **ChatGPT Plus/Pro subscription** (recommended, free with subscription — see [LLM Provider: Codex](#llm-provider-codex-chatgpt-subscription) below)
  - Anthropic API key
  - OpenAI API key
  - OpenRouter API key

## Setup

```bash
uv sync                  # install Python deps + create .venv
./scripts/setup.sh                  # install pentesting tools (tmux, nmap, gobuster, sqlmap, nikto) + Playwright Chromium
./scripts/setup.sh --with-seclists  # ALSO clone SecLists (~1 GB) to ~/.swarmattacker/seclists for the gobuster "medium"/"big" presets
cp .env.example .env     # create .env (can stay empty if using Codex auth)
codex                    # one-time ChatGPT login (saves tokens to ~/.codex/auth.json)
```

## Debug a single benchmark (recommended while iterating)

Use this when you want to watch the agent think on **one** XBOW challenge
and see every tool call and output live in the terminal — the right
rhythm while the agent itself is still being tuned.

```bash
# Daily 15 (resume-friendly):
uv run python -m benchmarks.xbow_runner --daily --resume --skip-build

# Single bench debug:
uv run python -m benchmarks.xbow_runner --bench XBEN-006-24 --skip-build

# Quiet for an overnight sweep:
uv run python -m benchmarks.xbow_runner --daily --resume --skip-build

# Loud for one-time deep debugging:
uv run python -m benchmarks.xbow_runner --bench XBEN-006-24 --verbose
```

What `--verbose` adds, streamed to stderr in real time:

- Every shell command the agent runs (with the agent's own reasoning).
- Every command's output, in full (no truncation).
- Every node transition with duration and a one-line summary.
- Every new AI message a node added, so the planner's decisions and the
  worker's reasoning land in the same terminal as the tool I/O.

When the run finishes you also get a per-run folder with all artifacts:

```
logs/run-XBEN-006-24-<ts>-<pid>/
  nodes.jsonl              # one JSON line per traced() node call, full result
  terminal_events.jsonl    # one JSON line per tool call/output (machine-readable)
  final_state.json         # graph.ainvoke return value, full state
  summary.md               # human-readable digest: timeline + findings + full
                           # message stream + per-node result dumps
```

`summary.md` is the file to open after the run. Pick a benchmark from
`benchmarks/daily_15.txt` (or any `XBEN-XXX-24`), run with `--verbose`,
read the summary, fix one thing, re-run. That's the loop.

**Tip — second-terminal live-tail:** if you ever need a structured view
while a run is going (without `--verbose`), open another terminal and:

```bash
tail -f "logs/run-XBEN-006-24-"*"/terminal_events.jsonl" | jq
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

The canonical entry point while iterating is the benchmark runner —
see "Debug a single benchmark" above. The graph is invoked in-process
via `graph.ainvoke()`; no LangGraph Studio / dev server involved.

The `langgraph dev` Studio UI is currently disabled for this workflow.
If you need to re-enable it (interactive node-by-node debugging in a
browser), run `langgraph dev --allow-blocking` from the project root.
`--allow-blocking` is required because the tmux-based terminal tool
uses subprocess calls that LangGraph's blockbuster detector flags
(they're already wrapped in `asyncio.to_thread` and don't actually
block the event loop).

## Testing

The suite runs in under a second and can be re-run as often as you like:

```bash
uv run pytest                       # full suite
uv run pytest -v                    # verbose, shows each test name
uv run pytest tests/test_skill_loader.py   # one file
```

Tests live in `tests/` and mirror the `src/` layout. Currently only Tier 1
(unit, no LLM, no network) tests exist:

| File | What it pins down |
|---|---|
| `tests/test_skill_loader.py` | Every `SKILL.md` parses; every tool name in any frontmatter resolves via the registry; the planner's dispatch menu is correct |
| `tests/test_tool_registry.py` | Every registry entry is a real `BaseTool`; `tool.name` matches its registry key (otherwise the model emits unroutable tool calls) |
| `tests/test_finding_parsers.py` | Markdown `**FINDING:**` and JSON `{"findings": [...]}` extraction across the formats and edge cases the agent actually emits |
| `tests/test_planner_decision_parser.py` | Fenced / bare / multiple / malformed JSON decision blocks from the planner |

### Test-on-failure policy

This project does **not** add tests preemptively. A new test only gets
written after a real failure has been observed and the fix is in. Every
encountered failure is logged in [`tests/FAILURES.md`](tests/FAILURES.md)
even when no test is added — that file doubles as a thesis artefact (a
real, dated record of agent failure modes encountered during
development). The full policy lives in the project root `CLAUDE.md` /
`AGENTS.md` under "Testing Policy".

Test tiers, in order of cost (always pick the cheapest one that would
catch the failure):

1. **Unit** — pure functions only (parsers, loaders, registries). What's in `tests/` today.
2. **Node** — inject a `FakeListChatModel` into `BaseNode.run_skill_agent(llm=...)`. No real API call. Tests orchestration: did the node load the right skill, set the right state flags, propagate findings back?
3. **Tool smoke** — runs the actual binary (nmap, gobuster, ...) against a local target. Marked `@pytest.mark.tools`.
4. **Live LLM** — real model, real local target. Marked `@pytest.mark.live`, skipped by default.

## Architecture

```
START → initialize → planner ←──────────────────────────┐
                      │                                  │
         ┌────────────┼────────────┬─────────────┐       │
         ↓            ↓            ↓             ↓       │
       recon       executor     web_search    END *      │
                 (×N parallel,                           │
                 Send() fan-out)                         │
                      │                                  │
                      └── all workers return ────────────┘
```

\* The `report` node is currently bypassed: when the planner picks
`action="report"` the graph routes straight to `END`. Run-folder
artifacts (`summary.md`, `nodes.jsonl`, `final_state.json`,
`terminal_events.jsonl`) are the source of truth instead. To re-enable
`report`, edit `_TERMINATE` in `src/edges/routing.py`.

Supervisor-shaped graph: the `planner` node is the single decision-maker.
Every worker edges back to it, and on each turn the planner emits a JSON
directive picking the next action — `recon`, `attack` (with the exact
list of executor dispatches to fan out), `web_search`, or `report`.

**Nodes** (`src/nodes/`):
- `initialize` — seeds stealth defaults and cleans leftover tmux state
- `planner` — supervisor LLM; decides the next action and, for `attack`,
  the list of executor dispatches (pre-built skills, custom_configs,
  or generic tasks) to run in parallel
- `recon` — reconnaissance agent (port scan, directory discovery,
  fingerprinting)
- `executor` — runs ONE dispatch from the planner. Resolves the
  dispatch's `config_name` to an `AgentConfig` (skill, custom_config,
  or synthesised generic-task) and runs it. The Planner+Executor
  split (Happe & Cito 2025; Fu et al. 2025) — the executor owns no
  decision logic, only execution
- `web_search` — looks up external facts on the planner's request
- `report` — aggregates all findings into a final report

**Edges** (`src/edges/`):
- `route_after_planner` — reads the planner's decision. Returns a node
  name (recon / web_search / report) or a list of `Send()` calls (for
  `attack`) that fan out to parallel `executor` runs

**Key subsystems:**
- `agents/` — config-driven agent pattern. One function, different configs. 13 configs across 3 methodologies (OWASP, vuln-type, custom chains)
- `knowledge/` — prompt rules + skill docs (the RAG layer is shelved, see below)
- `loop/` — 4-strategy loop detection (hard cap, exact repeat, same-tool repeat, budget pressure)
- `llm/` — provider-agnostic interface (Anthropic, OpenAI, OpenRouter, Codex)
  - `llm/codex.py` — self-contained LangChain chat model for the ChatGPT subscription / Codex backend. Handles OAuth token loading + refresh, Responses API SSE streaming, tool calls, all without any third-party library

**Experimental subsystems (off by default):** `src/experimental/` holds research
scaffolds that aren't part of the active agent loop. They are kept as evidence
of design exploration; none are registered in the graph. Currently shelved:
- `experimental/rag/` — knowledge vector store (FAISS)
- `experimental/stealth/` — WAF/IDS detection (no evasion behavior)
- `experimental/experience/` — cross-run guide store

## Project structure

```
SwarmAttacker/
├── pyproject.toml              # Project config (uv + hatchling)
├── langgraph.json              # LangGraph Studio entry point
├── benchmarks/
│   ├── targets.yaml            # Benchmark target definitions (DVWA, Juice Shop, etc.)
│   ├── runner.py               # Benchmark runner
│   ├── ablation.py             # Ablation experiment runner
│   ├── multimodel.py           # Multi-model comparison
│   └── metrics.py              # Metric computation
├── src/                        # Main Python package
│   ├── graph.py                # LangGraph graph (pure wiring) + runtime config
│   ├── state.py                # Shared state schema + reducers
│   ├── cli.py                  # CLI entry point
│   ├── nodes/                  # Graph nodes (one file per node)
│   ├── edges/                  # Routing logic
│   ├── knowledge/              # Prompt rules + skill docs
│   ├── tools/                  # tmux-based command execution
│   ├── loop/                   # Loop detection
│   ├── experimental/           # Shelved scaffolds (rag/, stealth/, experience/)
│   └── llm/                    # Provider-agnostic LLM interface
└── tests/                      # See "Testing" section above
    ├── conftest.py             # Shared fixtures (and import-order warm-up)
    ├── FAILURES.md             # Dated log of every failure encountered
    └── test_*.py               # Tier 1 unit tests
```

## Configuration

Runtime behavior is controlled by the `config` singleton in `src/graph.py`
(budgets, verbosity). All settings are overridable via `SWARM_*` environment
variables — see the `_env_*` helpers and `describe_config()` for the full list.

### Local GGUFs via `llama-server`

`Provider.LOCAL` routes every LLM call through a local `llama.cpp` server
(or Ollama) over its OpenAI-compatible endpoint, so any GGUF in `~/llms/`
can be used without code changes.

```bash
brew install llama.cpp
llama-server -m ~/llms/Hermes-3-Llama-3.1-8B-Q4_K_M.gguf \
  --port 8080 --alias hermes-8b -c 32768
# in another shell:
SWARM_PROVIDER=local SWARM_LOCAL_MODEL=hermes-8b uv run swarm ...
```

Env vars: `SWARM_PROVIDER=local`, `SWARM_LOCAL_MODEL=<--alias>`,
`SWARM_LOCAL_BASE_URL=http://127.0.0.1:8080/v1` (Ollama: `:11434/v1`).
Tool-call quality depends entirely on the GGUF — Hermes-3-8B and the
abliterated gemma variants need a hand-crafted jinja template to call
tools reliably (see `tests/FAILURES.md` 2026-05-17). The wiring works;
swap models freely.

## Dependencies

| Package | Purpose |
|---|---|
| `langgraph` | Graph orchestration, state management, checkpointing, Studio |
| `langchain-core` | Base abstractions (messages, tools, chat models) |
| `langchain-anthropic` | Claude model integration |
| `langchain-openai` | OpenAI / OpenRouter model integration |
| `pydantic` | Data validation (used by LangChain internals) |
| `libtmux` | tmux session management for agent command isolation |
| `pyyaml` | SKILL.md frontmatter + benchmark targets parsing |
