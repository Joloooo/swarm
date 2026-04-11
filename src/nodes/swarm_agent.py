"""Swarm agent node — generic executor for any agent config.

This is the target of Send() calls from the router. Each parallel
invocation gets a different config_name via the state, loads the
matching AgentConfig, and runs it.
"""

import logging

from src.agents.base import make_agent_node
from src.agents.configs.registry import get_config
from src.stealth.monitor import StealthMonitor

logger = logging.getLogger(__name__)

_stealth_monitor = StealthMonitor()


async def swarm_agent_node(state: dict) -> dict:
    """Load config by config_name, execute the agent, check for WAF signals."""
    config_name = state.get("config_name", "")
    config = get_config(config_name)
    if config is None:
        logger.warning(f"Config not found: {config_name}")
        return {"agent_results": [], "active_agents": [], "findings": []}

    node_fn = make_agent_node(config)
    result = await node_fn(state)

    # Stealth monitoring: check agent output for WAF/IDS signals
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

    return result
