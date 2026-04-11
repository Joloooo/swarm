"""Tier 1 — Deterministic playbook router.

The router is the first tier of the two-tier planning model:
- Tier 1 (this): Dispatches known attack playbooks deterministically
  based on recon results. Fast, predictable, no LLM call needed.
- Tier 2 (planner.py): Dynamic LLM planner that activates when Tier 1
  fails or finds unexpected paths.

The router reads recon output and decides which swarm agents to activate.
For example, if recon finds a login page, it activates auth-testing.
If it finds PHP, it activates PHP-specific vulnerability agents.
"""

from __future__ import annotations

from dataclasses import dataclass

from swarmattacker.agents.base import AgentConfig
from swarmattacker.agents.configs.registry import get_all_configs, get_config


@dataclass
class RoutingDecision:
    """Which agents to activate and why."""
    agent_configs: list[AgentConfig]
    reasoning: list[str]  # why each agent was selected


# Simple keyword-based routing rules
# Format: (keyword_in_recon_output, config_name, reason)
ROUTING_RULES: list[tuple[str, str, str]] = [
    ("login", "auth-testing", "Login page found — testing authentication"),
    ("sign in", "auth-testing", "Sign-in page found — testing authentication"),
    ("sql", "sqli", "SQL-related technology detected — testing for SQLi"),
    ("mysql", "sqli", "MySQL detected — testing for SQLi"),
    ("postgres", "sqli", "PostgreSQL detected — testing for SQLi"),
    ("php", "sqli", "PHP detected — common SQLi target"),
    ("wordpress", "auth-testing", "WordPress detected — testing default creds"),
]

# Always-active agents (run regardless of recon findings)
ALWAYS_ACTIVE = ["sqli"]


def route(recon_output: str) -> RoutingDecision:
    """Decide which agents to activate based on recon output.

    Phase 2 will expand this with more rules and pattern matching.
    Phase 4 will add Tier 2 dynamic planning as fallback.
    """
    recon_lower = recon_output.lower()
    selected: dict[str, str] = {}  # config_name -> reason

    # Apply routing rules
    for keyword, config_name, reason in ROUTING_RULES:
        if keyword in recon_lower and config_name not in selected:
            selected[config_name] = reason

    # Add always-active agents
    for config_name in ALWAYS_ACTIVE:
        if config_name not in selected:
            selected[config_name] = "Always-active agent"

    # Resolve to AgentConfig instances
    configs = []
    reasoning = []
    for config_name, reason in selected.items():
        config = get_config(config_name)
        if config is not None:
            configs.append(config)
            reasoning.append(reason)

    return RoutingDecision(agent_configs=configs, reasoning=reasoning)
