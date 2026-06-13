"""Shared state schema for the SwarmAttacker LangGraph graph."""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from enum import Enum
from typing import Annotated, Any

from langchain_core.messages import AnyMessage
from langgraph.graph import add_messages


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PrimitiveStatus(str, Enum):
    """Conversion lifecycle of a finding/primitive — a SEPARATE axis from
    ``Severity``. Severity says *how serious the bug is*; status says *how
    close to the objective this lead is and how hard it has been driven*.

    The progression is monotonic — a primitive only ever advances:

        suspected → demonstrated → converting → exhausted | converted

    - ``suspected``: a lead/hypothesis (e.g. "input looks injectable"),
      not yet proven.
    - ``demonstrated``: a proven exploit primitive (the historical
      meaning of a finding with ``primitive`` set) — a means to the
      objective, not yet the objective.
    - ``converting``: an executor is actively driving this primitive
      toward the flag.
    - ``exhausted``: the conversion methods tried so far have not worked;
      deprioritise or escalate the *method* rather than repeat it.
    - ``converted``: the primitive reached the objective (terminal).

    Stamped by the consolidation pass (``src/llm/consolidate.py``), never
    by the worker directly — the worker only sets ``primitive``.
    """

    SUSPECTED = "suspected"
    DEMONSTRATED = "demonstrated"
    CONVERTING = "converting"
    EXHAUSTED = "exhausted"
    CONVERTED = "converted"


class AttemptResult(str, Enum):
    """Controlled, neutral vocabulary for the outcome of one conversion
    attempt on a primitive. Kept terse and clinical on purpose — the
    rendered attempt line is concatenated into worker/planner prompts, so
    it must stay clear of the cyber_policy safety classifier (no
    "failed to exploit"-style framing). See ``Finding.attempts``.
    """

    NO_EFFECT = "no-effect"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    ERROR = "error"
    PROGRESSED = "progressed"


class HypothesisState(str, Enum):
    """Belief lifecycle of a :class:`Hypothesis` — a SEPARATE axis from
    :class:`PrimitiveStatus`.

    ``PrimitiveStatus`` tracks *conversion of a proven primitive toward
    the flag*. ``HypothesisState`` tracks *how strongly we believe a
    vulnerability of a given class exists on a given surface*, before
    anything is proven. The two meet at ``confirmed``: a hypothesis is
    confirmed exactly when a worker demonstrates the primitive, at which
    point the conversion axis (``PrimitiveStatus``) takes over.

    The progression is monotonic except that ``supported`` and
    ``committed`` may oscillate as evidence accrues or a probe comes back
    empty:

        nascent → supported → committed → confirmed | refuted

    - ``nascent``: one weak signal — a hunch, not yet worth committing
      budget to.
    - ``supported``: several signals agree, but belief is still below the
      commit threshold.
    - ``committed``: belief crossed the threshold; this hypothesis owns a
      budget reservation and a required next action. The planner may not
      pivot away while its required action is untried (see the
      hypothesis budget-lock directive).
    - ``confirmed``: a worker demonstrated the primitive — control passes
      to the conversion axis (``PrimitiveStatus``).
    - ``refuted``: contradicted by evidence, or its required action was
      tried and came back empty enough to drive belief below floor.

    Stamped by the synthesis pass (``src/llm/hypotheses.py``), never by a
    worker directly — a worker only emits :class:`Signal` atoms.
    """

    NASCENT = "nascent"
    SUPPORTED = "supported"
    COMMITTED = "committed"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


@dataclass
class Finding:
    """A single vulnerability or observation discovered during testing."""

    title: str
    severity: Severity
    category: str  # e.g. "sqli", "xss", "idor", "info-disclosure"
    description: str
    evidence: str  # raw tool output / proof
    agent_id: str  # which agent found it
    url: str = ""
    cwe: str = ""
    reproduced: bool = False
    # A *demonstrated exploit primitive* — a proven capability that is a
    # means to the objective but not yet the objective itself (e.g. "I can
    # run shell commands" / "I can read any file" / "I have a working data-
    # leaking SQL injection" / "I hold a privileged session"). Set by the
    # worker (parsed from a ``Primitive:`` line in its FINDING block) when
    # the finding meets the demonstrated-standard for an exploit-capable
    # class. Empty for ordinary observations. The planner's last-mile
    # directive (``src/nodes/planner.py:_unconverted_primitive_directive``)
    # reads this to keep an executor driving the primitive to the flag
    # before opening any new, lower-probability surface. Free-form short
    # tag; the canonical values are rce / file_read / sqli_read /
    # auth_bypass / ssrf, but a worker may coin another.
    primitive: str = ""
    # --- Derived fields, stamped by the consolidation pass (not by the
    # worker). They live only on entries in ``canonical_findings``; the
    # raw append-only ``findings`` log leaves them at their defaults. ---
    # Conversion lifecycle (see ``PrimitiveStatus``). Empty for an ordinary
    # observation; set to suspected/demonstrated/converting/exhausted/
    # converted for a lead or primitive.
    status: str = ""
    # Conversion-attempt log for a primitive — what has been tried to turn
    # it into the flag, with what outcome. Each entry is a small dict
    # ``{"method": str, "result": str, "note": str}`` where ``result`` is
    # an ``AttemptResult`` value and ``method``/``note`` are short neutral
    # phrases. Capped (last 5) by the consolidation pass. Read by the
    # planner's conversion-aware directive and rendered (tail) into the
    # worker seed so a worker does not repeat a dead method.
    attempts: list[dict] = field(default_factory=list)
    # Derived ranking score 0–100 ("proximity to the objective"), computed
    # by the consolidation pass from a deterministic formula (proven-
    # primitive × proximity × 1/attempts, severity as a minor term) plus a
    # bounded LLM nudge. Directives sort on THIS, not raw severity.
    lead_priority: int = 0


@dataclass
class Signal:
    """One atomic observation, or one routing implication, emitted by any
    producer in the swarm (worker, summarizer, a deterministic detector,
    the consolidation pass, or a skill's frontmatter prior).

    This is the UNIFIED replacement for the historically fragmented
    routing channels — ``suggested_next_moves`` items, ``skill_handoffs``
    items, the summarizer's bespoke detector outputs, and the planner's
    hardcoded keyword tells all spelled the same atom five different ways
    (``signal`` / ``possible_vuln_class`` / ``next_move`` / ``technique`` /
    ``where`` / ``surface`` / ``skill`` / ``suggested_skill`` /
    ``confidence``). A ``Signal`` is that atom, once.

    The crucial difference from the old channels: ``vuln_class`` and
    ``suggested_skill`` are OPTIONAL. A signal can be a bare observation
    ("characters {{ }} . _ [ ] are rejected on /total_loan_payments")
    that names no skill — the synthesis pass (``src/llm/hypotheses.py``)
    decides which :class:`Hypothesis` it supports and with what weight.
    That is the home the old schema lacked: an observation that is
    evidence for a hypothesis without already naming the answer.
    """

    # The fact, in one line (was: ``signal`` / ``evidence_excerpt`` /
    # ``next_move`` text).
    observation: str
    # Endpoint / parameter / surface the observation is about (was:
    # ``url`` / ``where`` / ``surface``). Empty for a target-wide fact.
    surface: str = ""
    # Vulnerability class this signal points at, IF known (was:
    # ``category`` / ``possible_vuln_class``). MAY be empty — the
    # synthesizer infers it from the observation + routing rules.
    vuln_class: str = ""
    # Raw proof excerpt, if any (response snippet, tool output).
    evidence: str = ""
    # Routing implication, IF the producer has one (was: ``skill`` /
    # ``suggested_skill`` and ``technique`` / ``next_move``). Optional.
    suggested_skill: str = ""
    technique: str = ""
    # Signed log-odds contribution this signal makes to the hypothesis it
    # supports: positive = evidence FOR, negative = evidence AGAINST.
    # Producers that only know a coarse "high/medium/low" confidence map
    # it through ``signal_weight()`` rather than setting this directly.
    weight: float = 0.0
    # What role this signal plays:
    #   - "observation": a positive/neutral fact
    #   - "negative":    a tried-and-did-not-work result (evidence AGAINST,
    #                    or "this surface is exhausted for this class")
    #   - "routing":     primarily a next-skill hand-off implication
    #   - "confirm":     a PROBE demonstrated the issue — the executor that
    #                    tested this class on this surface returned a
    #                    confirmed verdict. The only signal kind that lets a
    #                    hypothesis cross the COMMIT threshold (priors alone
    #                    cap below it). See ``src/llm/hypotheses.py``.
    #   - "refute":      a PROBE disproved it — the owning skill's own
    #                    "it is not me" verdict. Strong negative weight that
    #                    can drive a hypothesis to ``refuted``.
    kind: str = "observation"
    # Who emitted it: worker | summarizer | detector | consolidator |
    # skill_prior | planner.
    source: str = ""
    source_agent: str = ""


@dataclass
class Hypothesis:
    """A candidate vulnerability theory — the HUB that scattered signals
    fuse into, and the object the belief/utility scoring attaches to.

    Belief and utility are kept on SEPARATE axes, on purpose:

    - ``logodds`` / ``confidence`` answer *is this true?* — accumulated
      from the signed weights of supporting/contradicting signals
      (a naive-Bayes log-odds sum, squashed by a sigmoid). Orthogonal
      negatives on a different surface do not touch this.
    - ``priority`` answers *should I work on it next?* — an
      expected-value number that CONSUMES confidence but also folds in how
      close the class is to the objective, how informative the untried
      action is, and its cost. Cost may reorder the work queue; it must
      never lower ``confidence``.

    See ``src/llm/hypotheses.py`` for the scoring functions and the
    routing-rule table that turns observations into weighted support.
    """

    # Vulnerability class (e.g. "ssti", "sqli", "idor").
    vuln_class: str
    # Endpoint / parameter the hypothesis is about.
    surface: str = ""
    # Belief lifecycle (see :class:`HypothesisState`). Stamped by the
    # synthesis pass, monotonic except supported↔committed oscillation.
    state: str = HypothesisState.NASCENT.value
    # Stable keys of the signals that support / contradict this
    # hypothesis (``signal_key()`` values), so the score is auditable —
    # "why do we believe this" is answerable from the signal log.
    supporting: list[str] = field(default_factory=list)
    contradicting: list[str] = field(default_factory=list)
    # Belief. ``logodds`` is the raw naive-Bayes sum; ``confidence`` is
    # ``sigmoid(logodds)`` in [0, 1].
    logodds: float = 0.0
    confidence: float = 0.0
    # The REQUIRED next action while this hypothesis is committed — the
    # one probe that would confirm or refute it. The planner may not pivot
    # away from a committed hypothesis while this action is untried.
    required_skill: str = ""
    required_technique: str = ""
    action_tried: bool = False
    # Expected-value scheduling score 0–100 (utility, NOT belief). The
    # planner orders work by this; the commit threshold gates on
    # ``confidence`` instead.
    priority: int = 0
    # Once ``state == confirmed`` this links the hypothesis to the proven
    # primitive class (mirrors ``Finding.primitive``) and carries the
    # conversion-attempt log forward onto the conversion axis.
    primitive: str = ""
    attempts: list[dict] = field(default_factory=list)


@dataclass
class AgentResult:
    """Result returned by a single swarm agent when it finishes."""

    agent_id: str
    methodology: str  # "owasp", "vulntype", "custom"
    config_name: str  # e.g. "sqli", "auth-testing", "chain-ssrf-to-rce"
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    completed: bool = False
    phase: str = "analyze"  # "analyze" or "exploit" — which workflow phase produced this


def _merge_findings(left: list[Finding], right: list[Finding]) -> list[Finding]:
    """Reducer: append new findings (dedup by title+url later)."""
    return left + right


def _merge_results(left: list[AgentResult], right: list[AgentResult]) -> list[AgentResult]:
    """Reducer: append agent results."""
    return left + right


def _canonical_findings_reducer(
    existing: list[Finding] | None, new: list[Finding] | None,
) -> list[Finding]:
    """Last non-empty write wins for ``canonical_findings``.

    Unlike the append-only raw ``findings`` log, the canonical view is the
    deduped / merged / status-stamped / ranked picture that the
    consolidation pass (``src/llm/consolidate.py``) REBUILDS in full once
    per summarizer cycle. So the reducer replaces wholesale on a real
    write and keeps the prior view when a node emits nothing (e.g. a
    summarizer pass with no workers) rather than wiping it — the planner
    and worker seeds should always see the most recent canonical view.
    """
    if new:
        return new
    return existing or []


def _exhausted_ledger_reducer(
    existing: dict | None, new: dict | None,
) -> dict:
    """Merge the exhausted/negative-result ledger.

    Keyed by a ``"<category>|<url>"`` string; each value is a short record
    of what was tried on that surface and confirmed not to advance toward
    the flag (negative results routed OUT of the findings channel by the
    consolidation pass, so they inform "don't re-try" without polluting
    the findings digest). New entries win on a key collision (freshest
    outcome), old keys persist.
    """
    if not new:
        return existing or {}
    merged = dict(existing or {})
    merged.update(new)
    return merged


def _recon_summary_reducer(existing: str | None, new: str | None) -> str:
    """First non-empty write wins for ``recon_summary``.

    The recon summarizer writes this field exactly once — on the first
    summarizer pass that processed a recon worker. Subsequent summarizer
    passes (for executor workers) emit nothing for this field, so the
    reducer never overwrites. Returning ``existing`` on later writes
    also defends against a hypothetical second recon dispatch — the
    application map captured by the first recon run is the canonical
    one for the engagement.
    """
    if existing:
        return existing
    return new or ""


def _relevant_summary_reducer(
    existing: dict | None, new: dict | None,
) -> dict:
    """Last non-empty write wins for ``relevant_summary``.

    The planner rewrites this field every turn as part of its decision
    JSON. When the planner emits nothing (e.g. ``action="report"`` with
    no relevant_summary in the decision), we keep the prior turn's
    value rather than wiping it — workers dispatched later in the run
    should still see the most recent investigation state.
    """
    if new:
        return new
    return existing or {}


def _captured_flag_reducer(
    existing: str | None,
    new: str | None,
) -> str | None:
    """First non-None wins — once captured, stays captured.

    The conditional edge ``route_after_summarizer`` reads this field and
    routes to ``END`` on a truthy value. We use first-wins (rather than
    last-wins) so that:

    1. A second parallel worker that also matches expected_flag can't
       overwrite the first match with the same value (harmless but
       wasteful).
    2. A subsequent ``None`` write from a different node (e.g. a
       follow-up summarizer pass) cannot un-capture the flag.

    Two parallel workers landing flag matches in the same fan-out is
    rare (usually only one worker actually executes the winning probe),
    and if it happens both should match the same ``expected_flag``
    string anyway — so dropping the second is correct.
    """
    return existing or new


def _summary_inputs_reducer(
    left: list[dict] | None, right: list[dict] | None,
) -> list[dict]:
    """Reducer for ``pending_summary_inputs``.

    Plain ``operator.add`` would concatenate forever — and after the
    summarizer node has consumed the list, there is no way to clear it
    because re-emitting ``[]`` reduces to a no-op append. So we use a
    sentinel: when ``right`` is ``None``, the field is **cleared**
    (replaced by ``[]``); otherwise it is appended to the existing list.

    Each parallel worker (executor / recon) returns
    ``{"pending_summary_inputs": [singleton]}``; LangGraph fan-out
    accumulates the writes via this reducer so the synchronization-point
    summarizer node sees one entry per worker. The summarizer then
    returns ``{"pending_summary_inputs": None}`` to clear before
    transitioning to the planner.
    """
    if right is None:
        return []
    return list(left or []) + list(right or [])


def _tool_attempts_reducer(
    left: list[dict] | None, right: list[dict] | None,
) -> list[dict]:
    """Append bounded structured tool/surface outcomes.

    This is intentionally separate from ``findings`` and the exhausted
    ledger. A failed scanner or aborted enumeration means the surface is
    still open, not disproven; preserving the tool outcome lets the planner
    choose a fallback without treating the method as covered.
    """
    merged = list(left or []) + list(right or [])
    return merged[-80:]


# How many raw signal atoms to retain. The synthesis pass folds them into
# hypotheses each cycle, so the raw log only needs enough history to
# re-derive belief; older atoms are already reflected in the hypotheses.
_MAX_SIGNALS = 200


def signal_key(s: Any) -> str:
    """Stable identity for a :class:`Signal`, used to dedup the append-only
    log and to reference a signal from a hypothesis's supporting /
    contradicting lists. A given observation about one surface+class is
    one atom regardless of which worker reworded it.
    """
    def _f(name: str) -> str:
        value = getattr(s, name, None)
        if value is None and isinstance(s, dict):
            value = s.get(name)
        return " ".join(str(value or "").split()).lower()

    return "|".join((_f("vuln_class"), _f("surface"), _f("observation")[:120]))


def _signals_reducer(
    left: list[Signal] | None, right: list[Signal] | None,
) -> list[Signal]:
    """Append-only signal log, deduped by :func:`signal_key`, bounded.

    Parallel workers each emit their observations; fan-out accumulates
    them here. A later emission of the same atom (same surface+class+fact)
    wins so a refreshed weight or evidence excerpt replaces the stale one,
    rather than the log carrying both.
    """
    merged: dict[str, Signal] = {}
    for s in list(left or []) + list(right or []):
        if s is None:
            continue
        merged[signal_key(s)] = s
    return list(merged.values())[-_MAX_SIGNALS:]


def _investigation_threads_reducer(
    existing: dict | None, new: dict | None,
) -> dict:
    """Merge the per-skill investigation threads (the continuity store).

    Keyed by ``config_name``; each value is
    ``{"run_count": int, "log": str}`` — a compacted record of everything
    that skill has done across all its dispatches this run (commands kept
    verbatim, tool outputs shrunk). A re-dispatched worker is seeded with
    its thread so it CONTINUES instead of starting fresh and re-deriving
    what prior runs already established. New value wins per key (the worker
    rebuilds the full compacted log each exit), old keys persist.
    """
    if not new:
        return existing or {}
    merged = dict(existing or {})
    merged.update(new)
    return merged


def _hypotheses_reducer(
    existing: list[Hypothesis] | None, new: list[Hypothesis] | None,
) -> list[Hypothesis]:
    """Last-non-empty-write-wins for ``hypotheses``.

    Like ``canonical_findings``, the hypothesis list is REBUILT in full by
    the synthesis pass (``src/llm/hypotheses.py``) once per summarizer
    cycle from the raw signal log + canonical findings. A node that emits
    nothing (e.g. a summarizer pass with no workers) keeps the prior view
    rather than wiping it, so the planner and worker seeds always see the
    most recent ranked hypotheses.
    """
    if new:
        return new
    return existing or []


_HANDOFF_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _compact_handoff_field(value: Any, *, limit: int = 240) -> str:
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


def _handoff_key(item: dict) -> str:
    skill = _compact_handoff_field(
        item.get("suggested_skill") or item.get("skill")
    ).lower()
    surface = _compact_handoff_field(
        item.get("surface") or item.get("where") or item.get("target")
    ).lower()
    technique = _compact_handoff_field(
        item.get("technique") or item.get("next_move") or item.get("move")
    ).lower()
    return "|".join((skill, surface, technique))


def _normalize_handoff_state_item(raw: Any) -> dict | None:
    """Coerce worker/summarizer handoff records into one state shape."""
    if not isinstance(raw, dict):
        return None
    skill = _compact_handoff_field(
        raw.get("suggested_skill") or raw.get("skill"),
        limit=120,
    )
    surface = _compact_handoff_field(
        raw.get("surface") or raw.get("where") or raw.get("target")
    )
    technique = _compact_handoff_field(
        raw.get("technique") or raw.get("next_move") or raw.get("move")
    )
    if not skill or not (surface or technique):
        return None
    confidence = _compact_handoff_field(raw.get("confidence")).lower()
    if confidence not in _HANDOFF_CONFIDENCE_RANK:
        confidence = "medium"
    item = {
        "suggested_skill": skill,
        "surface": surface,
        "technique": technique,
        "confidence": confidence,
    }
    for field in (
        "signal",
        "reason",
        "evidence_excerpt",
        "reproduction",
        "source_agent",
        "source",
        "possible_vuln_class",
    ):
        value = _compact_handoff_field(raw.get(field))
        if value:
            item[field] = value
    return item


def _skill_handoffs_reducer(
    left: list[dict] | None, right: list[dict] | None,
) -> list[dict]:
    """Merge worker-emitted cross-skill handoffs by skill/surface/technique."""
    merged: dict[str, dict] = {}
    for raw in list(left or []) + list(right or []):
        item = _normalize_handoff_state_item(raw)
        if not item:
            continue
        key = _handoff_key(item)
        prior = merged.get(key)
        if (
            prior is None
            or _HANDOFF_CONFIDENCE_RANK[item["confidence"]]
            > _HANDOFF_CONFIDENCE_RANK[prior["confidence"]]
        ):
            merged[key] = item

    ranked = sorted(
        merged.values(),
        key=lambda item: (
            -_HANDOFF_CONFIDENCE_RANK[item["confidence"]],
            item["suggested_skill"],
            item["surface"],
            item["technique"],
        ),
    )
    return ranked[:80]


def _routed_skill_handoffs_reducer(
    left: list[str] | None, right: list[str] | None,
) -> list[str]:
    """Append unique handoff keys already routed by the planner."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in list(left or []) + list(right or []):
        key = str(raw or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out[-120:]


def _recon_done_reducer(existing: bool | None, new: bool | None) -> bool:
    """Sticky-True OR for ``recon_done``.

    Recon fans out into parallel dimension workers (the ``recon`` web/app
    pass and the ``recon-ports`` network pass — see
    :func:`src.edges.routing.route_after_planner`). Each branch returns
    ``recon_done=True``. A plain ``bool`` field would raise
    ``InvalidUpdateError`` ("can receive only one value per step") on the
    two concurrent writes; this reducer collapses them. Semantics: once
    *any* recon branch finishes, recon is done, and a later ``None`` /
    falsy write from another node can't un-set it.
    """
    return bool(existing or new)


class SwarmState:
    """Root state for the SwarmAttacker LangGraph graph.

    Uses LangGraph's annotated reducer pattern so parallel agent branches
    can all write findings/results and they get merged automatically.
    """

    # -- Target info (set once at the start) --
    target_url: str
    target_scope: str  # e.g. "*.example.com" or single URL

    # -- Orchestrator messages (routing / planning decisions) --
    messages: Annotated[list[AnyMessage], add_messages]

    # -- Aggregated results from all swarm agents --
    findings: Annotated[list[Finding], _merge_findings]
    agent_results: Annotated[list[AgentResult], _merge_results]
    # Deduped / merged / status-stamped / ranked view of ``findings``,
    # rebuilt each summarizer cycle by the consolidation pass.
    canonical_findings: Annotated[list[Finding], _canonical_findings_reducer]
    # Negative / status results routed out of the findings channel.
    exhausted_ledger: Annotated[dict, _exhausted_ledger_reducer]

    # -- Stealth state (shared across all agents) --
    waf_detected: bool
    stealth_level: int  # 0=none, 1=cautious, 2=evasive

    # -- Planning / routing metadata --
    active_agents: Annotated[list[str], operator.add]
    # Raw-trace-derived routing suggestions written by the summarizer.
    suggested_next_moves: list[dict]
    # Worker-emitted cross-skill handoffs, routed only by the planner.
    skill_handoffs: Annotated[list[dict], _skill_handoffs_reducer]
    routed_skill_handoffs: Annotated[list[str], _routed_skill_handoffs_reducer]
    # Structured tool/surface outcomes written by workers.
    tool_attempts: Annotated[list[dict], _tool_attempts_reducer]


# LangGraph needs a TypedDict or dict-like schema.
# We use the class above for documentation, but the actual graph state
# is this TypedDict for LangGraph compatibility.
from typing import TypedDict


class RelevantSummary(TypedDict, total=False):
    """Structured shape for ``state["relevant_summary"]``.

    The planner rewrites this dict each turn as part of its decision
    JSON. Four keys, with size caps enforced by the validator
    in ``src/nodes/planner.py`` to prevent unbounded growth across
    turns:

    - ``current_hypothesis``: one sentence (≤ 500 chars) describing
      the most promising path to the flag right now.
    - ``ruled_out``: list of one-line strings (≤ 20 items, ≤ 200
      chars each) recording things tested and confirmed not to work.
      Captures negative results that don't fit the Finding schema
      (the canonical example: "tried `' OR 1=1` on username,
      returned 200 unchanged" — useful for the next dispatch but
      not a finding).
    - ``open_questions``: list of one-line strings (≤ 20 items, ≤ 200
      chars each) recording gaps in knowledge the next dispatch
      should address.
    - ``untried``: ranked list of concrete next moves the swarm has
      NOT yet attempted (≤ 10 items). Each item is a dict
      ``{"where": str, "technique": str, "suggested_skill": str}`` —
      a *machine-actionable* next move (unlike ``open_questions``,
      which is free-text knowledge gaps). The planner consults this
      when a line of attack stalls so it can spin up a genuinely
      different angle instead of re-running the stuck one. See the
      diversify-when-stuck directive in ``src/nodes/planner.py``.

    The seed builder in ``src/nodes/base/skill_runner.py`` renders
    this dict as markdown under "## Investigation state" for the
    worker.
    """

    current_hypothesis: str
    ruled_out: list[str]
    open_questions: list[str]
    untried: list[dict]



class SwarmGraphState(TypedDict, total=False):
    """The actual LangGraph state — TypedDict for graph compatibility."""

    # Run identity. Set once at graph invocation by the runner (or by
    # the initialize node as a fallback for Studio runs). Read by
    # BaseNode.__call__ to route per-node JSONL events into the correct
    # logs/run-<run_id>/ directory.
    run_id: str

    # Target (populated by the supervisor planner on its first turn,
    # not by the CLI). Before the first planner turn these may be empty.
    target_url: str
    target_scope: str

    # Orchestrator conversation
    messages: Annotated[list[AnyMessage], add_messages]

    # Findings & results (reducers merge from parallel branches)
    findings: Annotated[list[Finding], _merge_findings]
    agent_results: Annotated[list[AgentResult], _merge_results]
    # Canonical (deduped/merged/status-stamped/ranked) view of ``findings``,
    # produced by the consolidation pass (``src/llm/consolidate.py``) at the
    # summarizer gather hook and read by the planner directives + worker
    # seeds. Falls back to ``findings`` when empty (cold start / pre-first
    # consolidation). Last-non-empty-write-wins reducer.
    canonical_findings: Annotated[list[Finding], _canonical_findings_reducer]
    # Ledger of negative / status / exhausted results, keyed by
    # "<category>|<url>", routed out of the findings channel by the
    # consolidation pass so the planner knows what has been tried without
    # the findings digest being diluted by ~90% negatives.
    exhausted_ledger: Annotated[dict, _exhausted_ledger_reducer]

    # Stealth
    waf_detected: bool
    stealth_level: int

    # Workflow mode
    mode: str  # "analyze" or "full" — controls whether exploit phase runs

    # Web-search ("crawler") fire policy for this run. Seeded from the
    # SWARM_CRAWL_MODE env var by the runner; read by the planner. "1"
    # BASELINE (planner's own firing), "2" CHARACTERIZATION, "3" STUCK,
    # "5" STUCK_DIVERGENCE, "6" TOOL_DESC, "9" ALL (everything on). See
    # src/nodes/crawl_policy.py. Empty/absent => "9" (all-on) is the DEFAULT,
    # so the full crawl policy runs from any entry point unless overridden.
    crawl_mode: str

    # Planning
    active_agents: Annotated[list[str], operator.add]

    # Config names (skill identities) that were forced onto the tier-2
    # fallback model (gpt-5.4 low) by a cyber_policy refusal this run.
    # Once a skill's prompt has tripped the primary model's safety
    # classifier, its NEXT dispatch starts directly on the fallback model
    # (skipping the 3 doomed primary retries), since the same prompt would
    # refuse identically. Written by ``run_skill_agent`` when a worker used
    # the fallback tier (rescued or exhausted); read at dispatch time to set
    # ``start_on_fallback`` on the refusal-retry ladder. ``operator.add``
    # accumulates across turns; consumers dedup via ``set(...)``.
    fallback_configs: Annotated[list[str], operator.add]

    # -- Supervisor planner state (src/nodes/planner.py) --
    # The action the planner chose on its most recent turn. Read by
    # route_after_planner to pick the next node.
    next_action: str  # "attack" | "recon" | "web_search" | "report"
    # How many times the supervisor has been invoked this run. Capped
    # to prevent runaway supervision loops.
    planner_iters: int
    # Configs the planner staged for attack fan-out. Populated by
    # planner_node when it picks action="attack"; read by
    # route_after_planner to emit one Send() per item. Overwritten each
    # turn, not reduced.
    pending_dispatch: list[dict]
    # Convenience flag the planner can check to avoid asking for recon
    # again when it has already run at least once. Reduced with a
    # sticky-True OR (``_recon_done_reducer``) because recon fans out
    # into parallel dimension workers that each write this key.
    recon_done: Annotated[bool, _recon_done_reducer]
    # Query string the planner asked the web_search node to run. Set
    # only when next_action == "web_search"; read by web_search_node.
    search_query: str
    # Optional research query the planner attaches to an ``attack`` turn so
    # the web_search node runs CONCURRENTLY with the executor fan-out (one
    # extra parallel branch), instead of stealing a whole serial turn while
    # the executors idle. Read by ``route_after_planner``'s attack branch;
    # overwritten (or cleared to "") on every attack turn so it never goes
    # stale. Empty/absent => no parallel research this turn.
    research_query: str
    # Counter for the planner's `_maybe_force_recovery` safety net —
    # how many times it has overridden a `report` decision with a
    # forced `web_search` this run. Capped at 1 to prevent loops.
    # See `_maybe_force_recovery` in src/nodes/planner.py for the rule.
    forced_recoveries: int

    # Set True ONLY by the planner's iteration-cap path
    # (`PlannerNode.execute` when `planner_iters > MAX_PLANNER_ITERS`).
    # In benchmark mode `route_after_planner` refuses to end the run on a
    # VOLUNTARY `report` — it re-plans instead, so a "we're done"
    # hallucination cannot terminate the run. This flag is the one
    # exception: the budget-exhausted `report` it lets reach `END` (else
    # the cap could never terminate and we'd loop planner→report→planner).
    # Real-pentest runs never set it; there a voluntary `report` ends the
    # run as before.
    budget_exhausted: bool
    # Optional benchmark-mode field. When set (by the xbow_runner or any
    # other benchmark driver), the planner and workers know the run has
    # an explicit success criterion — extracting a string matching this
    # value. Real pentest runs leave this empty, and the benchmark-only
    # behavior (flag-aware planner forcing function) does not fire.
    # Read by:
    #   - src.nodes.planner.PlannerNode.execute (planner prompt addendum
    #     and the `_maybe_force_recovery` safety net)
    #   - src.observability.live for display ("expected: ..." line)
    # NOTE: This field is the **primary / display** candidate only. The
    # set of strings actually accepted by ``flags_match`` is
    # ``expected_flag_candidates`` below — a benchmark may have multiple
    # equally-legitimate flag values depending on which build path
    # produced the image (see the xbow_runner docstring).
    expected_flag: str

    # Full set of candidate strings any of which counts as a captured
    # flag. Populated by the benchmark runner alongside
    # ``expected_flag``; typically contains:
    #
    #   * the sha256-of-bench-id prediction (``common.mk`` formula),
    #   * the value parsed from ``<benchmark>/.env``,
    #   * the value read from ``/flag`` inside the running container.
    #
    # All three sources exist in the XBow corpus and can disagree
    # depending on whether the image was built via ``make build``
    # (Makefile-export FLAG wins) or plain ``docker compose build``
    # (.env autoload wins). Building the candidate set up front and
    # accepting any match closes the entire class of
    # "captured-but-rejected" false negatives.
    #
    # Read by every caller of
    # :func:`src.edges.flag_match.flags_match`:
    #   - :class:`src.nodes.base.flag_watcher.FlagWatcherCallback`
    #     (worker-side eager scan)
    #   - :func:`src.nodes.base.skill_runner._run_skill_agent_impl`
    #     (per-node end-of-turn scan that emits ``flag_auto_verified``)
    #   - :func:`src.edges.routing.route_after_planner`
    #     (planner's ``action="submit_flag"`` verdict)
    #   - :func:`src.observability.live.bench_finish`
    #     (post-run match indicator)
    #   - :func:`benchmarks.xbow_runner.run_one` (final scoring)
    #
    # Empty tuple in non-benchmark / real-pentest mode — every consumer
    # then falls through to ``expected_flag``'s emptiness check and
    # uses real-pentest semantics in :func:`flags_match`.
    expected_flag_candidates: tuple[str, ...]

    # Append-only list of flag strings the planner has explicitly
    # submitted via ``action="submit_flag"``. The routing edge
    # (``src.edges.routing.route_after_planner``) compares the most
    # recent entry against ``expected_flag`` using
    # ``src.edges.flag_match.flags_match`` and routes the graph to ``END`` on a
    # match — otherwise control returns to the planner so it can try a
    # different candidate. The system prompt teaches the planner that
    # re-entering after a submission means the previous attempt was
    # rejected.
    #
    # Two consumers:
    #   * ``route_after_planner`` — reads ``attempts[-1]`` to verify.
    #   * ``benchmarks.xbow_runner.run_one`` — reads the same value
    #     post-run as the authoritative verdict (no more passive regex
    #     scan of free-form messages, no more false-positive on a
    #     ``FLAG{...}`` placeholder in narration).
    #
    # The reducer is plain ``operator.add`` so multiple turns of the
    # planner each appending their own attempt are concatenated rather
    # than overwriting.
    submission_attempts: Annotated[list[str], operator.add]

    # Auto-verified flag capture. Set by ``run_skill_agent`` on the
    # worker success path when ANY ToolMessage in the agent's trace
    # contains a ``flag{...}`` substring that strict-equals
    # ``expected_flag`` via ``src.edges.flag_match.flags_match``. The
    # strict-equality gate is what makes this safe vs. the regex-only
    # auto-terminate that was removed on 2026-05-24: false-positive
    # patterns (swagger schemas, README examples, the agent's own
    # script literals) cannot strict-equal the deterministic
    # ``FLAG{sha256(BENCHMARK_UPPER)}`` value, so they simply don't
    # set this field.
    #
    # Consumed by ``src.edges.routing.route_after_summarizer`` to
    # auto-route the graph to ``END`` without requiring a planner
    # round-trip + ``submit_flag``. The skill runner ALSO pushes the
    # same value onto ``submission_attempts`` so ``xbow_runner``'s
    # existing verdict path (which reads ``submission_attempts``)
    # sees the capture without any new wiring.
    #
    # Only meaningful in benchmark mode (where ``expected_flag`` is
    # set). In real-pentest mode ``expected_flag`` is empty and this
    # field is never written — capture remains a planner-driven
    # explicit ``submit_flag`` decision, since no oracle exists.
    captured_flag: Annotated[str | None, _captured_flag_reducer]

    # ── Curated investigation context (the seed-context fix) ──
    # Two structured fields the seed builder in
    # ``src/nodes/base/skill_runner.py`` reads when assembling a worker's
    # initial HumanMessage. Together with ``state["findings"]`` (already
    # cumulative) and ``state["dispatch_reason"]`` (already per-turn),
    # these give a fresh worker the full picture of what is known about
    # the target — eliminating the "every worker re-does recon" failure
    # mode observed across XBEN-001/003 on 2026-05-26.

    # The reconnaissance summary, written ONCE by the summarizer on its
    # first pass that processes a recon worker. Treated as the
    # application's ground-truth map: routes, parameters, auth flow,
    # framework fingerprint, inferred server-side behaviour. Never
    # decays. Workers see it as "## Application map (from initial
    # recon)" in their seed.
    recon_summary: Annotated[str, _recon_summary_reducer]

    # Curated investigation state, rewritten by the planner on every
    # turn as part of its decision JSON. Three fixed keys:
    #   - ``current_hypothesis``: str — one sentence, the most promising
    #     path to the flag right now.
    #   - ``ruled_out``: list[str] — things tested and confirmed not to
    #     work, one-line each (preserves negative results that don't fit
    #     the Finding schema).
    #   - ``open_questions``: list[str] — gaps in knowledge the next
    #     dispatch should address.
    # See ``RelevantSummary`` for the TypedDict schema and the validator
    # in ``src/nodes/planner.py`` for the size caps.
    relevant_summary: Annotated[dict, _relevant_summary_reducer]

    # Raw-trace-derived next-skill suggestions emitted by per-worker
    # summarizer reports, extracted by ``SummarizerNode`` and consumed by
    # the planner's untried-skill floor. Kept separate from
    # ``relevant_summary`` because the planner owns that field; this list
    # records what the worker traces themselves imply.
    #
    # Item shape:
    #   {
    #     "where":        str,
    #     "next_move":    str,
    #     "skill":        str,      # exact dispatchable skill name
    #     "confidence":   "high" | "medium" | "low",
    #     "source_agent": str,
    #     "signal":       str,      # optional observed fact
    #     "possible_vuln_class": str, # optional mechanism label
    #     "reason":       str,      # optional why this routing follows
    #     "source":       str,      # optional summarizer | detector
    #   }
    suggested_next_moves: list[dict]

    # Worker/summarizer-emitted cross-skill handoffs. These are stronger
    # than ordinary next-move hints: a worker has evidence that a different
    # skill should continue a specific surface/mechanism, but workers do not
    # spawn other agents directly. The planner dedupes and routes them.
    #
    # Item shape:
    #   {
    #     "suggested_skill": str,   # exact dispatchable skill name
    #     "surface":         str,   # endpoint/parameter/surface
    #     "technique":       str,   # concrete next test family
    #     "confidence":      "high" | "medium" | "low",
    #     "signal":          str,
    #     "reason":          str,
    #     "evidence_excerpt": str,
    #     "reproduction":    str,
    #     "source_agent":    str,
    #   }
    skill_handoffs: Annotated[list[dict], _skill_handoffs_reducer]

    # Exact handoff keys the planner already routed, formatted as
    # "skill|surface|technique". This suppresses duplicate dispatch for the
    # same handoff while still allowing the same skill to run on a different
    # surface or technique.
    routed_skill_handoffs: Annotated[list[str], _routed_skill_handoffs_reducer]

    # Structured outcomes from important tools and coverage-style probes.
    # Workers append records here so the planner can distinguish:
    #   - tool failed to run -> surface is NOT covered
    #   - tool succeeded with narrow flags -> surface is PARTIALLY covered
    #   - tool succeeded with exhaustive flags -> surface is covered
    #
    # Item shape:
    #   {
    #     "surface":       str,
    #     "tool":          str,
    #     "command":       str,
    #     "status":        "success" | "failed" | "timeout",
    #     "covered":       bool,
    #     "coverage":      "full" | "partial" | "none",
    #     "error_type":    str,
    #     "fallback_needed": bool,
    #     "source_agent":  str,
    #     "config_name":   str,
    #   }
    tool_attempts: Annotated[list[dict], _tool_attempts_reducer]

    # ── Unified signal / hypothesis channel (the signal-unification fix) ──
    # ``signals`` is the append-only log of :class:`Signal` atoms — the
    # single shape that replaces the historically fragmented
    # ``suggested_next_moves`` / ``skill_handoffs`` / detector-output
    # channels. Any producer (worker, summarizer, detector, consolidator,
    # skill prior) writes atoms here; the reducer dedups by
    # :func:`signal_key` and bounds the log.
    signals: Annotated[list[Signal], _signals_reducer]
    # ``hypotheses`` is the ranked list of :class:`Hypothesis` hubs the raw
    # signals fuse into, rebuilt each summarizer cycle by the synthesis
    # pass (``src/llm/hypotheses.py``) with belief (confidence) and utility
    # (priority) on separate axes. Last-non-empty-write-wins, like
    # ``canonical_findings``.
    hypotheses: Annotated[list[Hypothesis], _hypotheses_reducer]
    # Per-skill continuity store (the re-dispatch-context fix). Keyed by
    # ``config_name`` → ``{"run_count": int, "log": str}``: a compacted
    # record of everything that skill has done across all its dispatches
    # (commands kept, tool outputs shrunk to a bounded budget). Seeded into
    # the next dispatch so a re-run continues instead of re-deriving. See
    # the thread builder/compactor in ``src/nodes/base/skill_runner.py``.
    investigation_threads: Annotated[dict, _investigation_threads_reducer]

    # ── Worker → Summarizer hand-off (the context-window fix) ──
    # Each worker (executor, recon, salvage) writes a SINGLE-ITEM list
    # here describing its run; LangGraph fan-out accumulates writes via
    # the ``_summary_inputs_reducer`` so the summarizer node — the
    # synchronization point — sees one entry per parallel worker. The
    # summarizer produces one ``AIMessage`` per entry (the worker's
    # report to the supervisor) and clears the list with ``None``.
    #
    # The raw worker trace NEVER enters ``state["messages"]`` — it lives
    # only inside this list while it's pending, and on disk in the
    # consolidated ``logs/run-<id>/worker_traces.jsonl`` file (one shared
    # file per run; rows tagged with ``agent_id`` + ``dispatch_ts`` so
    # individual worker invocations stay distinguishable). This bound the
    # planner's input prompt to digests + planner decisions instead of the
    # full mirrored trace storm.
    #
    # Each entry shape (see ``src/nodes/summarizer.py`` for the canonical
    # definition):
    #   {
    #     "agent_id":         str,
    #     "config_name":      str,
    #     "methodology":      str,
    #     "dispatch_reason":  str,                 # planner's "why"
    #     "trace":            list[BaseMessage],   # not mirrored to messages
    #     "trace_path":       str,                 # disk pointer
    #     "completed":        bool,
    #     "error":            str | None,
    #     "refused":          bool,
    #     "findings_count":   int,
    #     "tool_attempts":    list[dict],
    #     "summary_tools":    list[BaseTool],  # same tool schema as worker
    #     "precomputed_report": AIMessage | None,
    #                         # optional worker-exit digest used to avoid
    #                         # post-barrier prompt-cache TTL misses
    #     "skip_digest_reason": str | None,
    #   }
    pending_summary_inputs: Annotated[list[dict], _summary_inputs_reducer]


class AgentState(TypedDict, total=False):
    """Per-agent subgraph state — each swarm agent gets its own context."""

    # Inherited from parent
    target_url: str
    target_scope: str

    # Agent's own conversation (isolated context window)
    messages: Annotated[list[AnyMessage], add_messages]

    # Agent identity
    agent_id: str
    config_name: str
    methodology: str

    # Agent's findings (written back to parent via reducer)
    findings: Annotated[list[Finding], _merge_findings]

    # Stealth awareness (read from parent)
    waf_detected: bool
    stealth_level: int
