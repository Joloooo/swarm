"""Hypothesis synthesis — fuse signal atoms into ranked hypotheses.

This module owns the **synthesis primitive**: it reads the raw
:class:`~src.state.Signal` log (plus the canonical findings) and rebuilds
the ranked :class:`~src.state.Hypothesis` list. Like ``consolidate.py`` and
``digest.py`` it is framework-agnostic — pure functions over plain data,
no LangGraph, no network — so it can be unit-tested in isolation.

Why it exists
=============

Before this, an observation that pointed at a vulnerability had no home
that fused it with the others. The framework fingerprint landed in a
recon finding, the blocked-grammar characters in a tool outcome, the
"value processed before validation" error in yet another finding, and a
failed probe on a *different* sink in a fourth. No single object ever
held all of them, so the planner never converted scattered evidence into
one focused theory — it scanned broadly instead. (The canonical example:
a Flask endpoint that rejects ``{{ }} . _ [ ]`` and reports the value was
processed before the numeric check — five fragments of one server-side
template-injection picture that were never assembled.)

The two axes, kept apart on purpose
====================================

- **Belief** (`confidence`): *is this true?* A naive-Bayes log-odds sum
  of the signed weights of the signals that support / contradict the
  hypothesis, squashed by a sigmoid. We use additive log-odds rather than
  a full Bayesian net because there is no labelled corpus to calibrate
  real likelihood ratios — the weights are hand-set and honest about it,
  the independence assumption is explicit, and every contribution is
  auditable ("+1.4 from the grammar block, +0.8 from the Flask signal").
  Belief is **scoped** to ``(vuln_class, surface)`` so a failed probe on a
  *different* sink cannot drain a live hypothesis.

- **Utility** (`priority`): *should I work on it next?* An expected-value
  number that consumes confidence but also folds in how close the class
  is to the objective, whether the deciding probe is still untried, and a
  decay for repeated dead attempts. Cost / fatigue reorder the work
  queue; they must never lower ``confidence``.

The routing-rule inversion
===========================

The rule table below encodes domain knowledge that a free-running model
tends to lose under budget pressure — most importantly that *a blocklist
whose contents are exactly a grammar's tokens is a fingerprint of that
grammar being interpreted*. ``{{``, ``}}``, ``.``, ``_``, ``[``, ``]``
are not generic "dangerous characters" to route around; they are Jinja
attribute/index syntax, so rejecting them is positive evidence of
server-side template rendering, not a dead end.

Vocabulary policy
=================

Neutral test-task vocabulary throughout (see ``CLAUDE.md``). Domain
technical names (SQL injection, SSRF, template injection) stay intact.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from typing import Any, Iterable

from src.state import (
    Finding,
    Hypothesis,
    HypothesisState,
    PrimitiveStatus,
    Signal,
    signal_key,
)

# ── Belief tunables ───────────────────────────────────────────────────

# Coarse confidence words → signed log-odds contribution. Producers that
# only know "high/medium/low" map through :func:`signal_weight`; producers
# with a real measurement set ``Signal.weight`` directly.
_CONFIDENCE_WEIGHT = {"high": 1.4, "medium": 0.8, "low": 0.4}

# Belief thresholds on ``confidence`` = sigmoid(logodds).
SUPPORTED_CONFIDENCE = 0.40  # ≥ this: several signals agree (supported)
COMMIT_CONFIDENCE = 0.70     # ≥ this: commit budget, lock the planner
# When the deciding probe has been tried and belief sits below this, the
# hypothesis is refuted rather than left dangling.
REFUTE_CONFIDENCE = 0.30

# ── Utility tunables ──────────────────────────────────────────────────

# "Exploit value" — roughly how close a confirmed vuln of this class sits
# to the objective, as a 0–1 multiplier on priority. SSTI ranks high
# because it routinely escalates to code execution.
_EXPLOIT_VALUE = {
    "rce": 1.0, "file_read": 1.0, "lfi": 0.95,
    "ssti": 0.85, "deserialization": 0.85,
    "sqli": 0.8, "sqli_read": 0.8, "auth_bypass": 0.8,
    "ssrf": 0.65, "xxe": 0.7, "idor": 0.6,
    "open-redirect": 0.35, "xss": 0.4, "csrf": 0.35,
    "info-disclosure": 0.3,
}
_EXPLOIT_VALUE_DEFAULT = 0.5

# Confidence enters priority sub-linearly so a strong-but-not-certain lead
# still outranks a weak one without a near-certain lead crowding the board.
_CONFIDENCE_EXPONENT = 0.7

# Deterministic next action per class, used when no supporting signal
# carried an explicit skill/technique. Neutral phrasing.
_DEFAULT_ACTION = {
    "ssti": ("ssti", "switch the template grammar on the same parameter"),
    "sqli": ("sqli", "confirm the injection then move to data return"),
    "ssrf": ("ssrf", "redirect the server fetch at an internal target"),
    "idor": ("idor", "swap the object reference for another principal's"),
    "lfi": ("lfi", "traverse to a known file to confirm the read"),
    "deserialization": ("deserialization",
                        "replace the opaque blob with a crafted object"),
    "xxe": ("xxe", "declare an external entity and observe expansion"),
    "rce": ("rce", "run a single direct read of the objective"),
}


# ── Routing-rule table ────────────────────────────────────────────────


@dataclass(frozen=True)
class RoutingRule:
    """One observation pattern → weighted support for a vuln class.

    A rule fires when EVERY group in ``all_groups`` has at least one of
    its markers present in the signal's observation+evidence text (so a
    rule can require a co-occurrence, e.g. template metacharacters AND a
    rejection word). ``weight`` is the log-odds it adds to the
    ``(vuln_class, surface)`` hypothesis.
    """

    name: str
    vuln_class: str
    weight: float
    all_groups: tuple[tuple[str, ...], ...]


# Template metacharacters — the grammar tokens whose presence (especially
# on a blocklist) fingerprints a server-side template engine.
_TEMPLATE_METACHARS = ("{{", "}}", "{%", "%}", "${", "<%", "#{")
_TEMPLATE_ENGINES = (
    "jinja", "flask", "django", "twig", "blade", "thymeleaf", "freemarker",
    "velocity", "erb", "liquid", "handlebars", "nunjucks", "mako", "smarty",
)
_REJECTION_WORDS = (
    "reject", "blocked", "filtered", "forbidden", "not allowed",
    "stripped", "disallowed", "invalid character",
)
_TRANSFORM_BEFORE_VALIDATE = (
    "before validation", "before the numeric", "rendered before",
    "processed before", "not a number", "coerced", "after rendering",
    "evaluated before",
)

ROUTING_RULES: tuple[RoutingRule, ...] = (
    # The grammar-fingerprint inversion: template tokens that are rejected
    # are a fingerprint of a template engine interpreting them, not a WAF
    # to route around. Strong weight.
    RoutingRule(
        name="ssti-grammar-block", vuln_class="ssti", weight=1.4,
        all_groups=(_TEMPLATE_METACHARS, _REJECTION_WORDS),
    ),
    # Template metacharacters seen at all (even without an explicit
    # rejection word) is moderate evidence.
    RoutingRule(
        name="ssti-grammar-present", vuln_class="ssti", weight=0.7,
        all_groups=(_TEMPLATE_METACHARS,),
    ),
    # A template-engine framework fingerprint.
    RoutingRule(
        name="ssti-framework", vuln_class="ssti", weight=0.8,
        all_groups=(_TEMPLATE_ENGINES,),
    ),
    # Input transformed/rendered before it is validated — the ordering
    # tell that distinguishes template injection from a plain bad parser.
    RoutingRule(
        name="ssti-transform-before-validate", vuln_class="ssti", weight=1.2,
        all_groups=(_TRANSFORM_BEFORE_VALIDATE,),
    ),
    RoutingRule(
        name="sqli-error", vuln_class="sqli", weight=1.2,
        all_groups=(("sql syntax", "you have an error in your sql",
                     "unclosed quotation", "odbc", "sqlstate",
                     "union select", "information_schema"),),
    ),
    RoutingRule(
        name="ssrf-fetch-param", vuln_class="ssrf", weight=0.7,
        all_groups=(("url=", "uri=", "callback", "webhook", "image_url",
                     "fetch", "outbound request", "server-side request"),),
    ),
    RoutingRule(
        name="idor-sequential-ref", vuln_class="idor", weight=0.7,
        all_groups=(("sequential id", "incrementing id", "object reference",
                     "another user", "other user's", "guessable id"),),
    ),
    RoutingRule(
        name="lfi-traversal", vuln_class="lfi", weight=0.9,
        all_groups=(("../", "path traversal", "/etc/passwd", "file=",
                     "include(", "directory traversal"),),
    ),
)


def routing_rules_from_specs(specs: Iterable[dict]) -> list[RoutingRule]:
    """Build :class:`RoutingRule` objects from the loader's normalized
    signal specs (see ``src.skills.loader.list_skill_signal_specs``).

    Each spec is ``{"name", "vuln_class", "weight", "all_groups"}`` where
    ``all_groups`` is a list of marker groups — the signal fires only when
    every group has at least one marker present, so a spec can require a
    co-occurrence (template tokens AND a rejection word). Malformed specs
    are skipped rather than raised, so one bad frontmatter entry cannot
    take the synthesis pass offline.
    """
    out: list[RoutingRule] = []
    for spec in specs or []:
        if not isinstance(spec, dict):
            continue
        vuln_class = str(spec.get("vuln_class") or "").strip().lower()
        if not vuln_class:
            continue
        groups_raw = spec.get("all_groups") or []
        groups: list[tuple[str, ...]] = []
        for g in groups_raw:
            markers = tuple(
                str(m).strip().lower() for m in (g or []) if str(m).strip()
            )
            if markers:
                groups.append(markers)
        if not groups:
            continue
        try:
            weight = float(spec.get("weight", 0.7))
        except (TypeError, ValueError):
            weight = 0.7
        out.append(RoutingRule(
            name=str(spec.get("name") or f"{vuln_class}-signal"),
            vuln_class=vuln_class,
            weight=weight,
            all_groups=tuple(groups),
        ))
    return out


def combine_routing_rules(
    skill_rules: Iterable[RoutingRule] | None,
) -> tuple[RoutingRule, ...]:
    """Merge the built-in baseline with skill-declared rules.

    Skill-declared rules **supersede the baseline per vuln class**: if a
    skill declares any routing signals for ``ssti``, the baseline ``ssti``
    rules step aside and the skill owns that class entirely (so a class is
    never scored twice). Classes no skill has declared keep the baseline.
    The baseline therefore acts as a resilient fallback — routing still
    works if a SKILL.md is missing or its frontmatter fails to parse.
    """
    skill_rules = list(skill_rules or [])
    owned = {r.vuln_class for r in skill_rules}
    baseline = [r for r in ROUTING_RULES if r.vuln_class not in owned]
    return tuple(baseline + skill_rules)


def _blob(s: Signal) -> str:
    return f"{getattr(s, 'observation', '')} {getattr(s, 'evidence', '')}".lower()


def _group_hit(blob: str, group: tuple[str, ...]) -> bool:
    return any(marker in blob for marker in group)


def _rule_fires(rule: RoutingRule, blob: str) -> bool:
    return all(_group_hit(blob, group) for group in rule.all_groups)


# ── Belief / utility math ─────────────────────────────────────────────


def signal_weight(confidence: str, *, negative: bool = False) -> float:
    """Map a coarse ``high/medium/low`` confidence to a signed log-odds
    weight. ``negative`` flips the sign (evidence against)."""
    w = _CONFIDENCE_WEIGHT.get(str(confidence or "").strip().lower(), 0.4)
    return -w if negative else w


def signal_from_routing_dict(item: dict, *, default_source: str = "") -> Signal | None:
    """Build a :class:`Signal` from a legacy ``suggested_next_moves`` or
    ``skill_handoffs`` dict.

    Bridges the old fragmented channels onto the unified atom during
    migration: ``where``/``surface`` → ``surface``, ``signal``/``reason``/
    ``next_move`` → ``observation``, ``skill``/``suggested_skill`` →
    ``suggested_skill``, ``possible_vuln_class`` → ``vuln_class``, and the
    coarse ``confidence`` → a log-odds ``weight``. Returns ``None`` when
    the item carries no usable observation or surface.
    """
    if not isinstance(item, dict):
        return None
    surface = str(item.get("surface") or item.get("where") or "").strip()
    observation = str(
        item.get("signal") or item.get("reason")
        or item.get("next_move") or item.get("technique") or ""
    ).strip()
    if not observation and not surface:
        return None
    return Signal(
        observation=observation or "(routing hint)",
        surface=surface,
        vuln_class=str(item.get("possible_vuln_class") or "").strip().lower(),
        evidence=str(item.get("evidence_excerpt") or "").strip(),
        suggested_skill=str(item.get("suggested_skill") or item.get("skill") or "").strip(),
        technique=str(item.get("technique") or item.get("next_move") or "").strip(),
        weight=signal_weight(item.get("confidence") or "medium"),
        kind="routing",
        source=str(item.get("source") or default_source).strip(),
        source_agent=str(item.get("source_agent") or "").strip(),
    )


def confidence_from_logodds(logodds: float) -> float:
    """Sigmoid squash of accumulated log-odds into a [0, 1] belief."""
    # Clamp the exponent to avoid overflow on pathological sums.
    x = max(-30.0, min(30.0, float(logodds)))
    return 1.0 / (1.0 + math.exp(-x))


def hypothesis_priority(
    *, confidence: float, vuln_class: str, state: str,
    action_tried: bool, n_attempts: int,
) -> int:
    """Expected-value scheduling score 0–100 (UTILITY, not belief).

    Consumes ``confidence`` but is a separate axis: a near-certain lead
    that is expensive/exhausted can rank below a cheaper one-probe-away
    lead. Cost/fatigue live here (the attempt decay and the untried-action
    bonus); they never touch ``confidence``.
    """
    if state == HypothesisState.REFUTED.value:
        return 0
    ev = _EXPLOIT_VALUE.get((vuln_class or "").strip().lower(),
                            _EXPLOIT_VALUE_DEFAULT)
    # An untried deciding probe is worth more (information gain); a tried
    # one is half as urgent because we have already spent a look at it.
    info = 1.0 if not action_tried else 0.55
    # Each repeated dead attempt decays urgency so persistence does not
    # become head-banging; floored so a real lead never drops to zero.
    decay = max(0.3, 1.0 - 0.15 * min(max(n_attempts, 0), 5))
    score = 100.0 * (max(0.0, confidence) ** _CONFIDENCE_EXPONENT) * ev * info * decay
    return int(max(0, min(100, round(score))))


def advance_hypothesis_state(
    *, prior: str, confidence: float, has_primitive: bool, action_tried: bool,
) -> str:
    """Belief-lifecycle transition. ``confirmed`` / ``refuted`` are sticky;
    ``nascent``/``supported``/``committed`` track confidence and may
    oscillate as evidence accrues or a probe comes back empty.
    """
    prior = (prior or "").strip().lower()
    if prior in (HypothesisState.CONFIRMED.value, HypothesisState.REFUTED.value):
        return prior
    if has_primitive:
        return HypothesisState.CONFIRMED.value
    # A deciding probe was tried and belief did not hold up → refuted.
    if action_tried and confidence < REFUTE_CONFIDENCE:
        return HypothesisState.REFUTED.value
    if confidence >= COMMIT_CONFIDENCE:
        return HypothesisState.COMMITTED.value
    if confidence >= SUPPORTED_CONFIDENCE:
        return HypothesisState.SUPPORTED.value
    return HypothesisState.NASCENT.value


# ── Signal → hypothesis contributions ─────────────────────────────────


def _contributions(
    s: Signal, rules: tuple[RoutingRule, ...] = ROUTING_RULES,
) -> list[tuple[str, float]]:
    """Resolve one signal into ``[(vuln_class, signed_weight), ...]``.

    An explicit ``vuln_class`` + ``weight`` is used as-is. A bare
    observation is run through ``rules`` to infer which class(es) it
    supports and by how much. ``kind`` adjusts the sign:
    ``negative``/``refute`` count AGAINST the class; ``confirm`` and
    ``observation`` count for it. (Whether a ``confirm`` exists is tracked
    separately by the bucket for the COMMIT gate — see
    :func:`synthesize_hypotheses`.)
    """
    kind = (getattr(s, "kind", "") or "").strip().lower()
    negative = kind in ("negative", "refute")
    out: list[tuple[str, float]] = []

    explicit_class = (getattr(s, "vuln_class", "") or "").strip().lower()
    explicit_weight = float(getattr(s, "weight", 0.0) or 0.0)
    if explicit_class:
        w = explicit_weight if explicit_weight else _CONFIDENCE_WEIGHT["medium"]
        if negative and w > 0:
            w = -w
        out.append((explicit_class, w))

    # Verdict signals (confirm/refute) are scoped to the class the worker
    # actually tested — they do NOT fan out through the routing rules,
    # which are for inferring class from a bare observation.
    if kind in ("confirm", "refute"):
        return out

    blob = _blob(s)
    for rule in rules:
        if rule.vuln_class == explicit_class:
            continue  # already counted explicitly
        if _rule_fires(rule, blob):
            w = -rule.weight if negative else rule.weight
            out.append((rule.vuln_class, w))
    return out


def _is_confirm(s: Signal) -> bool:
    """A probe-confirmation verdict — the only signal that lets a
    hypothesis cross the COMMIT threshold (see the gate in
    :func:`synthesize_hypotheses`)."""
    return (getattr(s, "kind", "") or "").strip().lower() == "confirm"


def _surface_of(s: Signal) -> str:
    return " ".join(str(getattr(s, "surface", "") or "").split()).strip().lower()


def _required_action(
    vuln_class: str, supporting: list[Signal],
) -> tuple[str, str]:
    """The deciding probe for a hypothesis: prefer the highest-weight
    supporting signal that carried an explicit skill/technique, else the
    deterministic per-class default."""
    best: tuple[float, str, str] | None = None
    for s in supporting:
        skill = (getattr(s, "suggested_skill", "") or "").strip()
        technique = (getattr(s, "technique", "") or "").strip()
        if skill or technique:
            w = abs(float(getattr(s, "weight", 0.0) or 0.0))
            if best is None or w > best[0]:
                best = (w, skill or vuln_class, technique)
    if best is not None:
        return best[1], best[2]
    return _DEFAULT_ACTION.get(vuln_class, (vuln_class, ""))


def _finding_contributions(
    findings: Iterable[Finding],
) -> dict[tuple[str, str], dict]:
    """Fold canonical findings into the hypothesis buckets. A demonstrated
    primitive confirms its hypothesis; a suspected finding adds belief."""
    buckets: dict[tuple[str, str], dict] = {}
    for f in findings or []:
        cls = (getattr(f, "category", "") or "").strip().lower()
        if not cls:
            continue
        surface = (getattr(f, "url", "") or "").strip().lower()
        status = (getattr(f, "status", "") or "").strip().lower()
        primitive = (getattr(f, "primitive", "") or "").strip().lower()
        demonstrated = (
            bool(primitive)
            or status in (PrimitiveStatus.DEMONSTRATED.value,
                          PrimitiveStatus.CONVERTING.value,
                          PrimitiveStatus.CONVERTED.value)
        )
        b = buckets.setdefault((cls, surface), {
            "logodds": 0.0, "has_primitive": False, "primitive": "",
            "attempts": [],
        })
        if demonstrated:
            b["has_primitive"] = True
            b["primitive"] = primitive or b["primitive"]
            b["attempts"] = list(getattr(f, "attempts", []) or []) or b["attempts"]
            b["logodds"] += 3.0  # a proven primitive ~ near-certain
        else:
            # A suspected lead is moderate positive belief.
            b["logodds"] += _CONFIDENCE_WEIGHT["medium"]
    return buckets


def synthesize_hypotheses(
    *,
    signals: list[Signal] | None,
    canonical_findings: list[Finding] | None = None,
    prior_hypotheses: list[Hypothesis] | None = None,
    extra_rules: Iterable[RoutingRule] | None = None,
) -> list[Hypothesis]:
    """Rebuild the ranked hypothesis list from the raw signal log + the
    canonical findings, carrying prior terminal states forward.

    Deterministic and LLM-free: the belief layer must stay explainable and
    we have no calibration data to fit a model. ``extra_rules`` are
    skill-declared routing rules (from SKILL.md frontmatter) that supersede
    the built-in baseline per vuln class — pass the result of
    ``combine_routing_rules`` or just the skill rules (combined here).
    Returns the hypotheses sorted by ``priority`` (utility) descending.
    """
    sigs = [s for s in (signals or []) if s is not None]
    rules = combine_routing_rules(extra_rules) if extra_rules is not None else ROUTING_RULES

    # bucket → accumulated belief + the signals backing it
    buckets: dict[tuple[str, str], dict] = {}

    for s in sigs:
        surface = _surface_of(s)
        confirm = _is_confirm(s)
        for cls, w in _contributions(s, rules):
            cls = cls.strip().lower()
            if not cls:
                continue
            b = buckets.setdefault((cls, surface), {
                "logodds": 0.0, "support": [], "contra": [],
                "has_primitive": False, "primitive": "", "attempts": [],
                "has_confirm": False,
            })
            b["logodds"] += w
            (b["contra"] if w < 0 else b["support"]).append(s)
            if confirm:
                b["has_confirm"] = True

    # fold canonical findings into the same buckets
    for (cls, surface), fb in _finding_contributions(canonical_findings or []).items():
        b = buckets.setdefault((cls, surface), {
            "logodds": 0.0, "support": [], "contra": [],
            "has_primitive": False, "primitive": "", "attempts": [],
            "has_confirm": False,
        })
        b["logodds"] += fb["logodds"]
        if fb["has_primitive"]:
            b["has_primitive"] = True
            b["primitive"] = fb["primitive"] or b["primitive"]
            b["attempts"] = fb["attempts"] or b["attempts"]

    # Distribute ambient (surface-less) evidence onto concrete surfaces of
    # the same class — a target-wide clue like a framework fingerprint
    # should reinforce the specific-endpoint hypothesis, not split off into
    # a parallel one. The ambient bucket is kept only when its class has no
    # concrete-surface sibling to absorb it.
    classes_with_surface = {
        cls for (cls, surface) in buckets if surface
    }
    for (cls, surface) in [k for k in buckets if not k[1]]:
        if cls not in classes_with_surface:
            continue
        ambient = buckets.pop((cls, surface))
        for (c2, s2), b in buckets.items():
            if c2 == cls and s2:
                b["logodds"] += ambient["logodds"]
                b["support"].extend(ambient["support"])
                b["contra"].extend(ambient["contra"])

    prior_by_key = {
        (h.vuln_class.strip().lower(), (h.surface or "").strip().lower()): h
        for h in (prior_hypotheses or [])
    }

    out: list[Hypothesis] = []
    for (cls, surface), b in buckets.items():
        logodds = float(b["logodds"])
        confidence = confidence_from_logodds(logodds)

        prior = prior_by_key.get((cls, surface))
        prior_state = getattr(prior, "state", "") if prior else ""
        action_tried = bool(getattr(prior, "action_tried", False)) if prior else False

        state = advance_hypothesis_state(
            prior=prior_state, confidence=confidence,
            has_primitive=b["has_primitive"], action_tried=action_tried,
        )

        skill, technique = _required_action(cls, b["support"])
        attempts = list(b["attempts"] or [])
        priority = hypothesis_priority(
            confidence=confidence, vuln_class=cls, state=state,
            action_tried=action_tried, n_attempts=len(attempts),
        )

        out.append(Hypothesis(
            vuln_class=cls,
            surface=surface,
            state=state,
            supporting=[signal_key(s) for s in b["support"]],
            contradicting=[signal_key(s) for s in b["contra"]],
            logodds=round(logodds, 3),
            confidence=round(confidence, 3),
            required_skill=skill,
            required_technique=technique,
            action_tried=action_tried,
            priority=priority,
            primitive=b["primitive"],
            attempts=attempts,
        ))

    # Carry forward any prior terminal hypothesis that has no live signals
    # this cycle, so a confirmed/committed lead does not vanish.
    live_keys = {(h.vuln_class, h.surface) for h in out}
    for (cls, surface), h in prior_by_key.items():
        if (cls, surface) in live_keys:
            continue
        if getattr(h, "state", "") in (
            HypothesisState.CONFIRMED.value, HypothesisState.COMMITTED.value,
        ):
            out.append(replace(h))

    out.sort(key=lambda h: h.priority, reverse=True)
    return out
