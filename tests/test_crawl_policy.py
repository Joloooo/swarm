"""Tier 1 — crawl_policy trigger-targeting tests.

Pins the two 2026-06-09 fixes (see ``tests/FAILURES.md``), found in the
06-08/06-09 web-crawl trigger study:

  * **info-category gate** — a finding mis-tagged ``category="info"`` (a 405
    banner, a recon fingerprint snippet) is recon noise, not a researchable
    lead, so it must NOT fire a stuck-conversion web search. 14 of 35
    stuck-fires used to leak through here.
  * **drift guard** — the planner's research nudge and this module's
    stuck-conversion trigger must share ONE gate set, so they can never
    drift apart again (they previously did: the planner copy lacked
    ``info-disclosure``, and neither blocked the bare ``info`` slug).
  * **generic-only component strip** — a bare web-server name
    (Apache/nginx) is stripped from a ``{class} in {component}`` query
    ("sqli in Apache"), while an app framework (Flask/PHP) is kept
    ("SSTI in Flask"). 25 of 35 stuck-fires used to carry ``Apache``.

All pure functions — no LLM, no network.
"""

from __future__ import annotations

import src.nodes.crawl_policy as cp
from src.nodes.crawl_policy import (
    _strip_server_component,
    characterization_fire,
    stuck_conversion_fire,
)
from src.state import Finding, Severity


def _finding(
    category: str,
    severity: Severity = Severity.HIGH,
    *,
    description: str = "",
    url: str = "",
    agent_id: str = "vulntype-x",
) -> Finding:
    return Finding(
        title=f"{category} lead",
        severity=severity,
        category=category,
        description=description,
        evidence="",
        agent_id=agent_id,
        url=url,
    )


def _state(findings, *, recon_summary: str = "") -> dict:
    return {
        "findings": findings,
        "messages": [],
        "active_agents": [],
        "recon_summary": recon_summary,
    }


# ── info-category gate ───────────────────────────────────────────────


def test_info_category_does_not_fire_stuck_conversion():
    """category='info' carries a stuck signal here, so only the gate can
    stop the fire — and it must."""
    state = _state([
        _finding("info", Severity.MEDIUM,
                 description="405 Method Not Allowed; the request was blocked"),
    ])
    assert stuck_conversion_fire(state) is None


def test_informational_and_info_disclosure_also_gated():
    for cat in ("informational", "info-disclosure", "information-disclosure"):
        state = _state([_finding(cat, description="blocked by a filter")])
        assert stuck_conversion_fire(state) is None, cat


def test_real_class_still_fires_when_stuck():
    """Positive control: a confirmed sqli with a filter signal DOES fire —
    the gate only removes noise, it must not silence real leads."""
    state = _state([
        _finding("sqli", url="http://t/?id=1",
                 description="the id parameter was blocked by a filter"),
    ])
    decision = stuck_conversion_fire(state)
    assert decision is not None
    assert decision.trigger == "stuck-conversion"
    assert decision.vuln_class == "sqli"


# ── drift guard: one shared gate set ─────────────────────────────────


def test_planner_and_crawl_policy_share_one_gate():
    import src.nodes.planner as planner

    assert (
        planner._NON_RESEARCHABLE_CATEGORIES
        is cp._NON_RESEARCHABLE_CATEGORIES
    )
    assert "info" in cp._NON_RESEARCHABLE_CATEGORIES


# ── generic-only component strip ─────────────────────────────────────


def test_strip_drops_bare_web_servers():
    assert _strip_server_component("Apache", "2.4.59") == ("", "")
    assert _strip_server_component("apache httpd", "2.4.59") == ("", "")
    assert _strip_server_component("nginx", "") == ("", "")
    assert _strip_server_component("lighttpd", "") == ("", "")


def test_strip_keeps_app_frameworks():
    assert _strip_server_component("Flask", "2.0") == ("Flask", "2.0")
    assert _strip_server_component("Express", "") == ("Express", "")
    # php is kept on purpose — phar deserialization / LFI / RCE are
    # PHP-specific, so "deserialization in PHP" is a useful query.
    assert _strip_server_component("PHP", "7.4") == ("PHP", "7.4")


def test_stuck_query_strips_apache_but_keeps_class_and_param():
    """End-to-end: an Apache recon banner is dropped from the sqli query;
    the class and the parameter under test survive."""
    state = _state(
        [_finding("sqli", url="http://t/?id=1",
                  description="the id parameter was blocked by a filter")],
        recon_summary="Server: Apache/2.4.59",
    )
    decision = stuck_conversion_fire(state)
    assert decision is not None
    assert decision.slots.get("component", "") == ""
    assert "Apache" not in decision.query
    assert "documented sqli techniques" in decision.query


def test_characterization_keeps_its_component():
    """Characterization's component IS the search subject — never stripped."""
    state = _state([], recon_summary="Server: Apache/2.4.59")
    decision = characterization_fire(state)
    assert decision is not None
    assert decision.trigger == "characterization"
    assert "Apache HTTP Server" in decision.query
