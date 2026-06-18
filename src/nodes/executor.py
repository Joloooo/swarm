"""Executor node — runs one skill in the parallel fan-out.

This is the swarm's executor in the Planner+Executor sense (Happe & Cito,
Fu et al.): it owns no decision-making, only execution. The planner
stages one or more dispatch items in ``state["pending_dispatch"]`` and
the routing edge fans out one ``ExecutorNode`` invocation per item.

Each invocation runs exactly one named skill (the planner's ``configs``
lane): the node loads a SKILL.md by name via ``src/skills/loader.py`` and
runs it. Skills carry a focused system prompt plus a curated tool list
(sqlmap for sqli, nmap for recon, etc.). When no class specialist fits a
lead, the planner dispatches the ``exploration`` skill, which discovers
surface and raises hypotheses rather than concluding on any class.

The node loads the config and calls ``self.run_skill_agent``; the stealth
check then runs over the findings.
"""

import dataclasses
import logging

from src.experimental.stealth.monitor import StealthMonitor
from src.nodes.base import BaseNode, Skill
from src.tools.registry import resolve_tools

logger = logging.getLogger(__name__)

_stealth_monitor = StealthMonitor()


# ── The executor's dispatch surface ──
# Every skill this node can run, and what each gets on top of DEFAULT_TOOLS.
# Presence in this map is what makes a skill dispatchable on the executor — the
# planner's menu is built from it (src/skills/loader.list_dispatchable_skills).
# ``owns`` is the set of vuln-classes the skill may refute in its closing
# verdict: None = its own name-class, frozenset() = none (discovery / triage
# workers, which may only redirect), {..} = exactly those (a multi-class
# specialist). ``execute`` stamps the resolved tools + owns onto the loaded
# AgentConfig before running it.
DEFAULT_TOOLS = ("bash",)

EXECUTOR_SKILLS: dict[str, Skill] = {
    'auth-testing': Skill(tools=('hydra_http_form', 'sqlmap_basic')),
    'bfla': Skill(),
    'bug-identification': Skill(owns=frozenset()),
    'business-logic': Skill(),
    'chain-ssrf-to-rce': Skill(owns=frozenset()),
    'cors': Skill(),
    'crlf': Skill(),
    'crypto': Skill(tools=('nmap_specific_ports', 'nmap_ssl_enum', 'sslscan_full', 'testssl_full')),
    'csrf': Skill(),
    'deserialization': Skill(),
    'error-handling': Skill(),
    'exploration': Skill(owns=frozenset()),
    'fuzzing': Skill(tools=('get_wordlist', 'gobuster_dir', 'list_wordlists'), owns=frozenset()),
    'graphql': Skill(),
    'idor': Skill(),
    'information-disclosure': Skill(),
    'input-validation': Skill(owns=frozenset({'crlf', 'insecure-file-uploads', 'lfi', 'rce', 'xxe'})),
    'insecure-file-uploads': Skill(),
    'lfi': Skill(),
    'mass-assignment': Skill(),
    'open-redirect': Skill(),
    'parameter-pollution': Skill(),
    'prototype-pollution': Skill(),
    'race-conditions': Skill(),
    'rce': Skill(),
    'request-builder': Skill(owns=frozenset(), skip_base_prompt=True),
    'request-smuggling': Skill(),
    'session-mgmt': Skill(),
    'sqli': Skill(tools=('sqlmap_basic', 'sqlmap_dump_table', 'sqlmap_enum_dbs')),
    'ssrf': Skill(),
    'ssti': Skill(),
    'subdomain-takeover': Skill(),
    'web-cache': Skill(),
    'xss': Skill(),
    'xxe': Skill(),
}


def _stealth_check(result: dict, config_name: str, state: dict) -> None:
    """Check agent output for WAF/IDS signals, update result in-place."""
    for ar in result.get("agent_results", []):
        if ar.findings:
            for finding in ar.findings:
                alert = _stealth_monitor.analyze_output(finding.evidence)
                if alert.detected:
                    logger.warning(
                        f"Stealth alert from {config_name}: "
                        f"{alert.waf_name} ({alert.alert_type})"
                    )
                    result["waf_detected"] = True
                    result["stealth_level"] = max(
                        state.get("stealth_level", 0),
                        alert.recommended_level,
                    )


class ExecutorNode(BaseNode):
    """Execute one named skill and return its findings."""

    async def execute(self, state: dict) -> dict:
        config_name = state.get("config_name", "")

        # Ablation: with skills disabled (default off), every executor runs as
        # one generic worker (base prompt + all tools, no per-class knowledge)
        # regardless of which skill the planner dispatched. Recon is unaffected
        # — it routes through ReconNode, not this gate.
        from src.graph import config as _rt
        if getattr(_rt.capability, "disable_skills", False):
            from src.skills.loader import generic_executor_config
            config = generic_executor_config(config_name)
        else:
            config = self.load_skill(config_name)
            if config is None:
                self.log.warning("Skill not found: %s", config_name)
                return {"agent_results": [], "active_agents": [], "findings": []}
            # Stamp the executor's dispatch surface onto the loaded config: the
            # skill's real tool set (DEFAULT_TOOLS + its extras) and the
            # vuln-classes it may refute. The loader returns a bash-only,
            # owns-nothing default; this knowledge lives in the node, not SKILL.md.
            spec = EXECUTOR_SKILLS.get(config_name, Skill())
            config = dataclasses.replace(
                config,
                tools=resolve_tools([*DEFAULT_TOOLS, *spec.tools]),
                owned_classes=spec.owns,
                skip_base_prompt=spec.skip_base_prompt,
            )

        self.log.info("[%s] Starting executor agent", config_name)
        result = await self.run_skill_agent(config, state)
        _stealth_check(result, config_name, state)

        findings = result.get("findings", [])
        self.log.info(
            "[%s] Executor agent complete: %d findings", config_name, len(findings)
        )
        return result


executor_node = ExecutorNode()
