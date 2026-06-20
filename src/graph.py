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
# ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, LANGSMITH_API_KEY.
# Without this, those keys only reach the process when shell-exported.
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
# The MENU knobs (budgets, model slug + reasoning, verbosity) are DEFINED in
# ``swarm-config.toml`` — edit that file by hand or via ``swarm`` → Edit config.
# They are resolved once here, at import, by ``src/config_schema.py`` (which
# owns the factory defaults). The ADVANCED/dev knobs further down (provider,
# the refusal-recovery fallback tier, the local-server settings) are code-only
# and still honour their ``SWARM_*`` env vars for one-off debug runs — so a
# ``SWARM_*`` name in a comment below applies ONLY to those advanced knobs; a
# menu knob's old env name is historical, edit the toml instead.
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


# Menu config knobs, resolved from swarm-config.toml (overlaid on the factory
# defaults in src/config_schema.py). Read once here, at import — edit the toml
# (or the `swarm` TUI), not this file, to change what runs.
from src.config_schema import resolve as _resolve_menu_config  # noqa: E402

_cfg = _resolve_menu_config()

# The single runtime-config object. One literal, one place. Same shape
# (and ergonomics) as a TS `export const NODE_CONFIG = { ... }`.
config = SimpleNamespace(
    budgets=SimpleNamespace(
        # ── Graph supervisor / planner ──
        planner_max_iters            = _cfg["budgets"]["planner_max_iters"],
        # ── Worker agents (per invocation) ──
        worker_max_iterations        = _cfg["budgets"]["worker_max_iterations"],
        # ── LLM (per-call output cap) ──
        llm_max_tokens               = _cfg["budgets"]["llm_max_tokens"],
        # ── LLM (per-call timeout, seconds) ──
        # httpx read/connect timeout for one Codex streaming call. gpt-5.5
        # medium calls reach ~114s; 120 was too tight (some timed out).
        # SWARM_LLM_TIMEOUT_S overrides for a one-off CLI run.
        llm_call_timeout_s           = _env_int("SWARM_LLM_TIMEOUT_S",
                                                _cfg["budgets"]["llm_call_timeout_s"]),
        # ── Per-benchmark agent wall-clock (seconds) ──
        # The leash on one graph run: xbow_runner wraps graph.ainvoke in
        # asyncio.wait_for(timeout=run_timeout_s). 1200 = 20 min, 2400 = 40 min.
        # Config/TUI-driven (swarm-config.toml [budgets] run_timeout_s); the
        # SWARM_RUN_TIMEOUT_S env var still overrides for a one-off CLI run.
        run_timeout_s                = _env_int("SWARM_RUN_TIMEOUT_S",
                                                _cfg["budgets"]["run_timeout_s"]),
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
        # Model slug — set it in swarm-config.toml ([model] slug) or via the
        # `swarm` TUI. Only consulted when ``provider`` is a hosted backend;
        # for ``provider=local`` see ``local_model`` instead.
        model                        = _cfg["model"]["slug"],
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
        # bump back to "medium"/"high"/"xhigh" in swarm-config.toml
        # ([model] reasoning_effort) when a run needs deeper reasoning.
        reasoning_effort             = _cfg["model"]["reasoning_effort"],
        # Summary: whether human-readable chain-of-thought is returned.
        # "detailed" gives the most debugging power; "none" disables
        # summaries entirely (saves tokens but loses visibility).
        reasoning_summary            = _cfg["model"]["reasoning_summary"],
        # ── Web-search synthesis model ──
        # The web_search node's synthesis step (relay payloads from crawled
        # markdown) runs on this model/effort instead of the flagship — a
        # cheaper, faster, more refusal-resistant tier. Edit in swarm-config.toml
        # ([model] web_search_synth_model / _reasoning_effort) or the TUI.
        web_search_synth_model       = _cfg["model"]["web_search_synth_model"],
        web_search_synth_reasoning_effort = _cfg["model"]["web_search_synth_reasoning_effort"],
    ),
    verbosity=SimpleNamespace(
        # silent  = only bench boundaries + final verdict on stderr
        # compact = (default) one colored line per planner decision,
        #           shell command, outcome, finding, warning
        # verbose = today's full multi-line dump
        mode      = _cfg["verbosity"]["mode"],
        color     = _env_bool("SWARM_COLOR",     _stderr_is_tty()),
        show_http = _env_bool("SWARM_LIVE_HTTP", False),
    ),
    # ── Ablation switches (see swarm-config.toml [capability]) ──
    # Each turns OFF one capability so its contribution can be measured. ALL
    # default false → the full system runs byte-identically; the gates next to
    # each subsystem read these and no-op when their flag is false. SWARM_DISABLE_*
    # env vars override a single flag for a one-off CLI/VM run without editing
    # the toml.
    capability=SimpleNamespace(
        disable_prompting_techniques = _env_bool(
            "SWARM_DISABLE_PROMPTING_TECHNIQUES",
            _cfg["capability"]["disable_prompting_techniques"]),
        disable_hypothesis_passing   = _env_bool(
            "SWARM_DISABLE_HYPOTHESIS_PASSING",
            _cfg["capability"]["disable_hypothesis_passing"]),
        disable_refusal_handling     = _env_bool(
            "SWARM_DISABLE_REFUSAL_HANDLING",
            _cfg["capability"]["disable_refusal_handling"]),
        disable_skills               = _env_bool(
            "SWARM_DISABLE_SKILLS",
            _cfg["capability"]["disable_skills"]),
        disable_web_search           = _env_bool(
            "SWARM_DISABLE_WEB_SEARCH",
            _cfg["capability"]["disable_web_search"]),
        # Observability toggle (default false = skill_ranking ON), managed in
        # the Capability menu; SWARM_DISABLE_SKILL_RANKING overrides for one run.
        disable_skill_ranking        = _env_bool(
            "SWARM_DISABLE_SKILL_RANKING",
            _cfg["capability"]["disable_skill_ranking"]),
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
        + "\n\nCapability (ablation switches; all-false = full system):\n"
        + "\n".join(
            f"  {k:<32s} = {v}" for k, v in vars(config.capability).items()
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
    graph.add_edge("recon", "summarizer")
    graph.add_edge("executor", "summarizer")

    # Summariser → planner (conditional on captured_flag).
    #
    # The 2026-05-25 re-introduction of ``route_after_summarizer``
    # auto-terminates the graph WHEN a worker's tool output contained
    # a ``flag{...}`` substring that strict-equals ``expected_flag``.
    # The skill runner (``src/nodes/base/worker/skill_runner.py``) does the
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
    # ``web_search`` routes to the summarizer (not straight to the planner)
    # so that when it is fanned out ALONGSIDE executors (planner attached a
    # research_query to an attack), it joins the same fan-in barrier and all
    # branches rejoin the planner together — the executors never trigger the
    # planner while the search is still running, and vice versa. Standalone
    # web_search is unaffected: the summarizer no-ops on empty
    # ``pending_summary_inputs`` and yields straight to the planner, and the
    # web_search AIMessage is already in ``state["messages"]`` either way.
    graph.add_edge("web_search", "summarizer")

    graph.add_edge("report", END)

    return graph.compile()


# Compiled graph — imported by langgraph.json for Studio
graph = build_graph()
