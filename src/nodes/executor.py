"""Executor node — runs one skill or one generic task in the parallel fan-out.

This is the swarm's executor in the Planner+Executor sense (Happe & Cito,
Fu et al.): it owns no decision-making, only execution. The planner
stages one or more dispatch items in ``state["pending_dispatch"]`` and
the routing edge fans out one ``ExecutorNode`` invocation per item.

Each invocation can run in one of two modes, decided by the planner:

- **Skill mode** (``configs`` / ``custom_configs`` on the planner JSON).
  Loads a SKILL.md by name via ``src/skills/loader.py`` and runs it.
  Skills carry a focused system prompt plus a curated tool list (sqlmap
  for sqli, nmap for recon, etc.).

- **Generic mode** (``tasks`` on the planner JSON). The planner provides
  only a free-form task description; the loader synthesises a one-shot
  skill with a comprehensive pentester prompt and the ``bash`` tool.
  Use this for tasks that don't fit any pre-built skill — chained
  exploits, niche tech, follow-ups on a specific finding.

The node itself is mode-agnostic: both paths land as an ``AgentConfig``
in the cache, and the node just calls ``self.run_skill_agent``. The
stealth check then runs over the findings regardless of mode.
"""

import logging

from src.experimental.stealth.monitor import StealthMonitor
from src.nodes.base import BaseNode

logger = logging.getLogger(__name__)

_stealth_monitor = StealthMonitor()


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
    """Execute one skill or one generic task and return its findings."""

    async def execute(self, state: dict) -> dict:
        config_name = state.get("config_name", "")

        config = self.load_skill(config_name)
        if config is None:
            self.log.warning("Skill not found: %s", config_name)
            return {"agent_results": [], "active_agents": [], "findings": []}

        self.log.info("[%s] Starting executor agent", config_name)
        result = await self.run_skill_agent(config, state)
        _stealth_check(result, config_name, state)

        findings = result.get("findings", [])
        self.log.info(
            "[%s] Executor agent complete: %d findings", config_name, len(findings)
        )
        return result


executor_node = ExecutorNode()
