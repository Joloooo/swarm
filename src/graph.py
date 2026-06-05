"""LangGraph StateGraph definition — the SwarmAttacker orchestrator.

Supervisor-shaped graph: one planner node is the only decision-maker,
every worker node edges back to it. The planner emits a JSON directive
picking the next action — recon, attack (with the list of configs to
fan out), web_search, or report — and the graph transitions accordingly.

Every node is a :class:`~src.nodes.base.BaseNode` instance, and
``BaseNode.__call__`` itself owns the cross-cutting instrumentation
(timing, boundary AIMessage, JSONL run logging, crash-to-AIMessage
conversion, live stderr streaming via :data:`src.observability.LIVE`).
The graph just wires instances in directly — no wrapper, no
per-node boilerplate.

Boundary messages are tagged with ``additional_kwargs={"node": name}``
so downstream consumers that scan message history can filter them out
and look at real agent output only.

Adding a new node? Subclass :class:`BaseNode`, expose a singleton
instance from ``src.nodes``, and ``graph.add_node("foo", foo_node)``
here. It inherits all the instrumentation automatically.

Flow::

    START → planner ← ────────────────────────────────────────────────┐
              │                                                        │
            ┌─┼────────────────┬───────────┐                           │
            ↓ ↓                ↓           ↓                           │
          recon       executor        web_search    report             │
            │       (×N parallel, via       │           │              │
            │        Send() fan-out)        │           │              │
            ↓             ↓                 │           │              │
            summarizer ←──┘                 │           │              │
            (synchronization point —        │           │              │
            converts pending traces         │           │              │
            into one report each)           │           │              │
                          ↓                 ↓           │              │
                          └─────────────────┴───────────┴──────────────┘
                                          report → END

There is no preceding ``initialize`` node — per-invocation shell
session lifecycle (tmux + bash) is owned by the singleton
:class:`~src.tools.shell.manager.ShellManager`, which registers
``atexit`` + signal handlers at module import time. See
``src/tools/shell/manager.py`` for the rationale.

The ``summarizer`` is the context-window fix: each worker hands its
full trace via ``state["pending_summary_inputs"]`` (transient, not
mirrored to messages) and the summarizer writes ONE structured
``worker_report`` AIMessage per worker. The planner reads only those
reports — never the raw tool-call traces. See
``src/nodes/summarizer.py`` and ``src/llm/digest.py``.
"""

from __future__ import annotations

import logging
import os
import sys
from types import SimpleNamespace

# Load environment variables from .env BEFORE any module that reads them.
# This is the universal entry point — every CLI command, the benchmark
# runner, and the LangGraph Studio bootstrap all import src.graph, so a
# single dotenv load here covers all entry points. Keys read from .env:
# ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, TAVILY_API_KEY,
# LANGSMITH_API_KEY. Without this, langchain_tavily.TavilySearch fails
# at runtime even when the key IS in .env (only the shell-exported keys
# would otherwise reach the process).
try:
    from dotenv import load_dotenv as _load_dotenv

    _load_dotenv()
except ImportError:
    pass


# ============================================================================
# Centralized runtime config — budgets + verbosity in one nested object.
#
# This block exists HERE (top of graph.py, BEFORE any other imports) so that
# transitive imports — planner.py, tools/*, llm/*, observability/* — can
# turn around and `from src.graph import config` without hitting an import
# cycle. Python hands them whatever's been bound in this module's namespace
# at the time of the partial import; as long as `config` is bound before
# the `from src.nodes import (...)` block below, the partial-import works.
#
# DO NOT MOVE THIS BLOCK BELOW THE NODE/STATE/EDGE IMPORTS.
#
# Everything is overridable via env vars, so debug runs need no code edit:
#     SWARM_PLANNER_MAX_ITERS=200 SWARM_VERBOSITY=verbose uv run ...
#
# Shape mirrors the TS `NODE_CONFIG = { discover: { llms: {}, tools: {} } }`
# pattern — one nested literal, attribute-style access:
#     config.budgets.planner_max_iters
#     config.verbosity.mode
# ============================================================================


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_str(
    name: str,
    default: str,
    *,
    choices: tuple[str, ...] | None = None,
) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    if choices and raw not in choices:
        return default
    return raw


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _stderr_is_tty() -> bool:
    try:
        return sys.stderr.isatty()
    except Exception:
        return False


# The single runtime-config object. One literal, one place. Same shape
# (and ergonomics) as a TS `export const NODE_CONFIG = { ... }`.
config = SimpleNamespace(
    budgets=SimpleNamespace(
        # ── Graph supervisor / planner ──
        planner_max_iters            = _env_int("SWARM_PLANNER_MAX_ITERS",        50),
        # ── Escalation / dual-planner race (src/orchestration/escalation.py) ──
        # When the first planner lane is still stuck after this many
        # planner turns (recon + a couple of attack batches), fork a
        # SECOND, independent planner lane with a divergence persona and
        # race them — first capture wins. Only ever fires for the hard
        # runs that don't win early, so the fast-win path is untouched.
        # Disable with SWARM_ESCALATION=0.
        escalation_enabled           = _env_bool("SWARM_ESCALATION",            True),
        escalation_fork_after_iters  = _env_int("SWARM_ESCALATION_FORK_AFTER",     3),
        # ── Worker agents (per invocation) ──
        worker_max_iterations        = _env_int("SWARM_WORKER_MAX_ITERATIONS",    60),
        # ── Planner-invented "custom" attacks ──
        custom_attack_max_tool_calls = _env_int("SWARM_CUSTOM_MAX_TOOL_CALLS",    40),
        custom_attack_max_iterations = _env_int("SWARM_CUSTOM_MAX_ITERATIONS",    25),
        # ── LLM (per-call output cap) ──
        llm_max_tokens               = _env_int("SWARM_LLM_MAX_TOKENS",         4096),
        # ── Web search node (LLM context budget per source) ──
        # 8000 chars ≈ first ~1300 words of each crawled page. Tuned so
        # PortSwigger / OWASP / exploit-db articles include the actual
        # bypass technique (typically ~5000-8000 chars in), not just the
        # intro/definition. 10 sources × 8000 chars = ~80K tokens which
        # comfortably fits any modern model's context. Lower this with
        # SWARM_WEB_MAX_CHARS if synthesis quality degrades on very
        # small-context fallback models.
        web_search_max_crawled_chars = _env_int("SWARM_WEB_MAX_CHARS",          8000),
        # ── Provider selection ──
        # Which LLM backend ``get_llm()`` returns by default. ``codex``
        # uses your ChatGPT subscription via the bundled ``ChatCodex``;
        # ``local`` points at a local llama-server / Ollama HTTP endpoint
        # (see ``local_base_url`` / ``local_model`` below) and reuses the
        # ``ChatOpenAI`` plumbing under the hood.
        provider                     = _env_str("SWARM_PROVIDER", "codex",
                                                choices=("anthropic", "openai",
                                                         "openrouter", "codex",
                                                         "local")),
        # ── Codex model + reasoning controls (GPT-5.x family) ──
        # Model slug. Override with SWARM_MODEL=<slug>. Only consulted when
        # ``provider`` is one of the hosted backends — for ``provider=local``
        # see ``local_model`` instead.
        model                        = _env_str("SWARM_MODEL", "gpt-5.5",
                                                choices=("gpt-5.5", "gpt-5.4",
                                                         "gpt-5.4-mini",
                                                         "gpt-5.3-codex",
                                                         "gpt-5.2",
                                                         "codex-auto-review")),
        # ── Refusal-recovery fallback tier ──
        # When a worker LLM call refuses (CodexCyberPolicyError) and the
        # preventive vocab-filter + plain retry both fail, retry on
        # this fallback model + reasoning_effort. Empirically gpt-5.4
        # at reasoning_effort=low has a markedly more permissive
        # cyber_policy classifier than gpt-5.5 — see the v5 replay
        # finding documented in tests/FAILURES.md (2026-05-24).
        # Only consulted when the primary provider is Codex; other
        # providers (anthropic / openai / local) bypass the fallback.
        fallback_model               = _env_str("SWARM_FALLBACK_MODEL",
                                                "gpt-5.4",
                                                choices=("gpt-5.5", "gpt-5.4",
                                                         "gpt-5.4-mini",
                                                         "gpt-5.3-codex",
                                                         "gpt-5.2",
                                                         "codex-auto-review")),
        fallback_reasoning_effort    = _env_str("SWARM_FALLBACK_REASONING_EFFORT",
                                                "low",
                                                choices=("none", "minimal", "low",
                                                         "medium", "high", "xhigh")),
        # ── Local llama-server / Ollama controls ──
        # Active when ``provider=local``. ``local_model`` is the model
        # alias the local server advertises (matches the ``--alias`` flag
        # passed to ``llama-server`` or the Modelfile name in Ollama).
        # ``local_base_url`` defaults to the llama-server default port;
        # change to ``http://127.0.0.1:11434/v1`` for Ollama.
        local_model                  = _env_str("SWARM_LOCAL_MODEL",
                                                "hermes-8b"),
        local_base_url               = _env_str("SWARM_LOCAL_BASE_URL",
                                                "http://127.0.0.1:8080/v1"),
        # Effort: how hard the model thinks before responding. See the
        # full enum + valid values in src/llm/provider.py:LLMConfig.
        # Default "low" — empirical benchmark runs (2026-05-26) showed
        # gpt-5.5 at medium spends ~60s per call doing chain-of-thought
        # on routine decisions (curl this URL, dirbust that path), which
        # burns the 15-min per-target budget in ~15 turns. Dropping to
        # "low" trades depth-of-reasoning for more turns within budget;
        # bump back to "medium"/"high"/"xhigh" via SWARM_REASONING_EFFORT
        # when a benchmark needs deeper reasoning per step.
        reasoning_effort             = _env_str("SWARM_REASONING_EFFORT", "low",
                                                choices=("none", "minimal", "low",
                                                         "medium", "high", "xhigh")),
        # Summary: whether human-readable chain-of-thought is returned.
        # "detailed" gives the most debugging power; "none" disables
        # summaries entirely (saves tokens but loses visibility).
        reasoning_summary            = _env_str("SWARM_REASONING_SUMMARY", "detailed",
                                                choices=("auto", "concise",
                                                         "detailed", "none")),
    ),
    verbosity=SimpleNamespace(
        # silent  = only bench boundaries + final verdict on stderr
        # compact = (default) one colored line per planner decision,
        #           shell command, outcome, finding, warning
        # verbose = today's full multi-line dump
        mode      = _env_str("SWARM_VERBOSITY", "compact",
                             choices=("silent", "compact", "verbose")),
        color     = _env_bool("SWARM_COLOR",     _stderr_is_tty()),
        show_http = _env_bool("SWARM_LIVE_HTTP", False),
    ),
)


# Graph-level recursion limit — the number of LangGraph super-steps
# (node executions) allowed before a ``GraphRecursionError``. LangGraph's
# default is 25, but each planner cycle costs ~3-4 super-steps
# (planner → recon/executor fan-out → summarizer → back to planner), so
# the default silently caps a run at ~6-8 planner turns — far below
# ``planner_max_iters`` (default 50). That hidden cap, not the wall clock
# or the iteration budget, would otherwise be the real terminal. Derive
# it from ``planner_max_iters`` (×4 for the worst-case per-cycle cost,
# plus a small constant for the START→planner edge and a trailing
# summarizer) so the intended budgets stay the real terminals. Scales
# automatically when SWARM_PLANNER_MAX_ITERS is overridden.
GRAPH_RECURSION_LIMIT = config.budgets.planner_max_iters * 4 + 10


def describe_config() -> str:
    """Pretty-print the active config — log at startup for run snapshots."""
    return (
        "Budgets:\n"
        + "\n".join(
            f"  {k:<32s} = {v}" for k, v in vars(config.budgets).items()
        )
        + "\n\nVerbosity:\n"
        + "\n".join(
            f"  {k:<10s} = {v}" for k, v in vars(config.verbosity).items()
        )
    )


# ============================================================================
# Imports below this line MUST come AFTER the config block above so the
# transitive `from src.graph import config` resolves correctly.
# ============================================================================

from langgraph.graph import END, START, StateGraph  # noqa: E402

from src.edges.routing import route_after_planner, route_after_summarizer  # noqa: E402
from src.nodes import (  # noqa: E402
    executor_node,
    planner_node,
    recon_node,
    report_node,
    summarizer_node,
    web_search_node,
)
from src.state import SwarmGraphState  # noqa: E402

logger = logging.getLogger(__name__)


def build_graph():
    """Build and compile the SwarmAttacker graph."""
    graph = StateGraph(SwarmGraphState)

    # Every node is a BaseNode instance; BaseNode.__call__ already owns
    # the cross-cutting instrumentation (timing, boundary AIMessage,
    # JSONL run logging, crash-to-AIMessage, SWARM_VERBOSE streaming).
    # Adding a new node? Subclass BaseNode, export a singleton from
    # `src.nodes`, register it here. No wrapper required.
    graph.add_node("planner",    planner_node)
    graph.add_node("recon",      recon_node)
    graph.add_node("executor",   executor_node)
    graph.add_node("summarizer", summarizer_node)
    graph.add_node("web_search", web_search_node)
    graph.add_node("report",     report_node)

    # Edges. START routes straight to the planner — no preceding
    # initialize/setup node. Per-invocation shell session lifecycle
    # (creating tmux sessions, killing them on process exit or Ctrl+C)
    # is owned by the singleton :class:`ShellManager` in
    # ``src/tools/shell/manager.py``, which registers atexit + signal
    # handlers at import time. The cognitive graph stays pure cognition.
    graph.add_edge(START, "planner")

    # Supervisor is the only decision-maker. ``route_after_planner``
    # returns either a node name (``recon`` / ``web_search`` / ``report``)
    # or a list of ``Send()`` calls that fan out to parallel executor
    # runs for ``action="attack"``. It is ALSO the flag verifier — on
    # ``action="submit_flag"`` the edge compares the planner's
    # submitted flag against ``state["expected_flag"]`` via
    # :func:`src.edges.flag_match.flags_match` and routes to ``END`` on a match or
    # back to ``"planner"`` on a miss (so the planner can try a
    # different candidate, seeing its rejected attempt in
    # ``submission_attempts``).
    #
    # ``END`` is a valid destination — see ``_TERMINATE`` in
    # ``src/edges/routing.py`` for the report-bypass note. ``"planner"``
    # is also listed so the rejected-submission re-entry path is
    # statically declared (LangGraph validates conditional-edge targets
    # against this whitelist).
    graph.add_conditional_edges(
        "planner",
        route_after_planner,
        [
            "recon",
            "executor",
            "web_search",
            "report",
            "planner",
            END,
        ],
    )

    # Worker → summarizer → planner.
    #
    # Why a summarizer node instead of letting workers talk to the
    # planner directly? Each worker may run up to 60 tool-call
    # iterations and accumulate ~240 KB of trace. Mirroring that into
    # ``state["messages"]`` made the planner's prompt grow ~50 KB per
    # turn — Codex's 256 K window died within ~3 fan-out cycles. The
    # summarizer reads each worker's full trace from
    # ``state["pending_summary_inputs"]`` (a transient field, not
    # mirrored to messages), produces ONE structured ``worker_report``
    # AIMessage per worker, and writes only those reports into global
    # state. The planner's input prompt is bounded to digests + planner
    # decisions instead of raw tool-call storms.
    #
    # The summarizer is the **synchronization point** after fan-out:
    # when 4 parallel executors finish, the summarizer runs ONCE with
    # the accumulated list (via ``_summary_inputs_reducer`` in
    # ``src/state.py``) and produces 4 reports in parallel via
    # ``asyncio.gather``. See ``src/nodes/summarizer.py``.
    #
    # ``web_search`` skips the summarizer because its output is already
    # a single concentrated synthesis, not a tool-call trace.
    graph.add_edge("recon", "summarizer")
    graph.add_edge("executor", "summarizer")

    # Summariser → planner (conditional on captured_flag).
    #
    # The 2026-05-25 re-introduction of ``route_after_summarizer``
    # auto-terminates the graph WHEN a worker's tool output contained
    # a ``flag{...}`` substring that strict-equals ``expected_flag``.
    # The skill runner (``src/nodes/base/skill_runner.py``) does the
    # scan + equality check on the success path and writes the
    # verified value onto ``state.captured_flag``; this edge just
    # reads that boolean.
    #
    # This is NOT a regression of the 2026-05-24 removal: the old
    # design auto-terminated on ANY ``flag{...}`` regex match, which
    # false-positived on swagger schemas, README excerpts, and the
    # agent's own script literals. The new design's strict-equality
    # gate against ``expected_flag`` makes those false positives
    # structurally impossible — ``flag{example}`` cannot equal
    # ``FLAG{<64-hex>}``.
    #
    # In real-pentest mode (``expected_flag`` empty) the skill runner
    # never sets ``captured_flag``, so ``route_after_summarizer``
    # always falls through to ``"planner"`` — capture remains a
    # planner-driven explicit ``submit_flag`` decision, identical to
    # the pre-2026-05-25 behaviour.
    graph.add_conditional_edges(
        "summarizer",
        route_after_summarizer,
        {
            "planner": "planner",
            END: END,
        },
    )
    graph.add_edge("web_search", "planner")

    graph.add_edge("report", END)

    return graph.compile()


# Compiled graph — imported by langgraph.json for Studio
graph = build_graph()
