# Closing-verdict parsing + the specialist-refutation gate.
# The worker ends each dispatch with a VERDICT block (its self-assessment of
# whether the assigned class is the real issue). This module parses that block
# into signed Signal atoms that update hypothesis belief, and enforces the gate
# that only a class's own specialist may refute it.

from __future__ import annotations

import re

from langchain_core.messages import AIMessage

from src.state import Signal


# Closing-verdict block (VERDICT_SCHEMA). The worker's self-assessment of whether
# its assigned class is the real issue — parsed into a signed Signal that updates
# hypothesis belief (confirm raises over COMMIT; refute drives it down).
VERDICT_PATTERN = re.compile(
    r"(?:\*\*VERDICT:?\*\*|##\s+VERDICT|##\s+Verdict)"
    r"(?:[\s\S]{0,160}?Class:\s*([\w-]+))?"
    r"(?:[\s\S]{0,200}?Surface:\s*(.+?)$)?"
    r"(?:[\s\S]{0,200}?Probe run:\s*(yes|no))?"
    r"[\s\S]{0,200}?Outcome:\s*(confirmed|refuted|inconclusive)"
    r"(?:[\s\S]{0,160}?Confidence:\s*([0-9.]+))?"
    r"(?:[\s\S]{0,200}?Redirect:\s*(.+?)$)?"
    r"(?:[\s\S]{0,200}?Note:\s*(.+?)$)?",
    re.MULTILINE | re.IGNORECASE,
)


# Verdict outcome → (base log-odds magnitude, Signal.kind). The closing verdict
# is the deciding-probe feedback: a confirmed is the only kind that crosses the
# COMMIT threshold; a refuted is the owning skill's "it is not me".
_VERDICT_OUTCOME = {
    "confirmed": (3.0, "confirm"),
    "refuted": (3.0, "refute"),
    "inconclusive": (0.0, "observation"),
}


# ── Specialist-refutation gate ──
# Only a class's own specialist may pronounce it dead. Prevents XBEN-063: a
# non-ssti worker fires {{7*7}}, hits the {{ blacklist, declares "no SSTI", and
# buries the class. A cross-lane refuted is downgraded to a zero-weight
# observation so the class stays a live lead. Confirms are not gated.

# Class-token aliases so ownership checks match regardless of spelling.
_CLASS_ALIASES = {
    "deser": "deserialization",
    "insecure_deserialization": "deserialization",
    "phar": "deserialization",
    "path-traversal": "lfi",
    "path_traversal": "lfi",
    "directory-traversal": "lfi",
    "command-injection": "rce",
    "command_injection": "rce",
    "cmdi": "rce",
    "os-command-injection": "rce",
    "file-upload": "insecure-file-uploads",
    "file_upload": "insecure-file-uploads",
    "arbitrary_file_upload": "insecure-file-uploads",
}


def _norm_class(token: str) -> str:
    # Normalise a class token to its canonical key for ownership checks.
    t = (token or "").strip().lower()
    return _CLASS_ALIASES.get(t, t)


def _worker_owns_class(
    config_name: str, vuln_class: str, owned: frozenset[str] | None
) -> bool:
    # Whether the dispatched skill is the specialist for vuln_class — i.e.
    # allowed to issue a refuting verdict on it. ``owned`` is the skill's
    # owned-class set, stamped onto the config by the dispatching node from its
    # SKILLS map: None = owns only its own name-class; a (possibly empty) set =
    # exactly those classes (discovery/triage workers pass frozenset() = none).
    skill = _norm_class(config_name)
    cls = _norm_class(vuln_class)
    # No class named (→ own skill) or verdict on own class → its call.
    if not cls or cls == skill:
        return True
    if owned is None:
        # Plain specialist: owns only its own class (handled above).
        return False
    return cls in {_norm_class(c) for c in owned}


def _extract_verdicts(
    messages: list, agent_id: str, config_name: str,
    owned_classes: frozenset[str] | None = None,
) -> list[Signal]:
    # Parse the worker's closing VERDICT block into signed Signal atoms. Returns
    # at most one verdict signal (+ optional redirect routing signal); the LAST
    # verdict wins. Weights: confirmed +3·conf (crosses COMMIT), refuted
    # −3·(1−conf), inconclusive (conf−0.5)·1.2.
    last: tuple = ()
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        for m in VERDICT_PATTERN.finditer(content):
            last = m.groups()
    if not last:
        return []

    cls_raw, surface_raw, probe_raw, outcome_raw, conf_raw, redirect_raw, note_raw = last
    outcome = (outcome_raw or "").strip().lower()
    if outcome not in _VERDICT_OUTCOME:
        return []
    # Deciding-probe gate: a confirm/refute is only trustworthy if the worker ran
    # the canonical test on the real surface. "Probe run: no" (or omitted with a
    # strong outcome) → downgrade to inconclusive, so a wrong-surface verdict
    # cannot bury or over-commit a class.
    probe_run = (probe_raw or "").strip().lower() == "yes"
    if outcome in ("confirmed", "refuted") and not probe_run:
        outcome = "inconclusive"
    vuln_class = (cls_raw or config_name or "").strip().lower()
    surface = " ".join((surface_raw or "").split()).strip()
    note = " ".join((note_raw or "").split()).strip()[:200]
    try:
        conf = max(0.0, min(1.0, float(conf_raw))) if conf_raw else 0.5
    except (TypeError, ValueError):
        conf = 0.5

    # Specialist-refutation gate: a cross-lane refuted becomes a zero-weight
    # observation so it can't bury a class this worker doesn't own.
    cross_lane_refute = (
        outcome == "refuted"
        and not _worker_owns_class(config_name, vuln_class, owned_classes)
    )

    base, kind = _VERDICT_OUTCOME[outcome]
    if outcome == "confirmed":
        weight = base * max(conf, 0.5)
    elif outcome == "refuted":
        weight = -base * max(1.0 - conf, 0.5)
    else:  # inconclusive — mild signed nudge around 0.5
        weight = (conf - 0.5) * 1.2

    if cross_lane_refute:
        kind = "observation"
        weight = 0.0
        note = (
            (note + " — " if note else "")
            + f"cross-lane refute downgraded: {config_name} is not the "
            f"{vuln_class} specialist, so this does not rule the class out"
        )[:200]

    out: list[Signal] = [Signal(
        observation=f"{agent_id} verdict on {vuln_class}: {outcome}"
                    + (f" — {note}" if note else ""),
        surface=surface,
        vuln_class=vuln_class,
        suggested_skill=config_name,
        weight=weight,
        kind=kind,
        source="executor_verdict",
        source_agent=agent_id,
    )]

    # A redirect ("looks like X, not Y") lifts the alternative class so it can
    # rise in the ranking.
    redirect = " ".join((redirect_raw or "").split()).strip()
    if redirect:
        redirect_class = _redirect_class(redirect)
        if redirect_class and redirect_class != vuln_class:
            out.append(Signal(
                observation=f"{agent_id} redirect: {redirect}"[:200],
                surface=surface,
                vuln_class=redirect_class,
                suggested_skill=redirect_class,
                technique=redirect[:120],
                weight=1.0,
                kind="routing",
                source="executor_verdict",
                source_agent=agent_id,
            ))
    return out


# Known class tokens a redirect line might name. Loose — synthesis tolerates an
# unknown class (it becomes a new hypothesis bucket), so this just catches common spellings.
_REDIRECT_CLASSES = (
    "deserialization", "ssti", "sqli", "ssrf", "idor", "lfi", "rce", "xss",
    "xxe", "csrf", "auth", "open-redirect", "file-upload", "mass-assignment",
    "prototype-pollution", "request-smuggling", "crlf", "graphql",
)


def _redirect_class(text: str) -> str:
    # Pull a known class token out of a free-text redirect line.
    low = text.lower()
    for c in _REDIRECT_CLASSES:
        if c in low:
            return c
    return ""
