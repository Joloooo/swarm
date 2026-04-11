"""Tier 2 — Dynamic LLM planner.

Activates when Tier 1 (router) fails or finds unexpected paths.
Uses an LLM to analyze recon results and decide what to test next.

Phase 4 implementation. This module provides the interface.
"""

from __future__ import annotations

from swarmattacker.agents.base import AgentConfig


async def dynamic_plan(
    recon_output: str,
    existing_findings: list,
    failed_agents: list[str],
) -> list[AgentConfig]:
    """Use an LLM to generate a dynamic attack plan.

    Called when:
    - Tier 1 router selected zero agents (nothing matched)
    - All Tier 1 agents failed or found nothing
    - Novel attack surface discovered that no config covers

    Returns new AgentConfig instances with dynamically-generated
    system prompts tailored to the specific findings.

    TODO: Implement in Phase 4.
    """
    raise NotImplementedError("Tier 2 dynamic planner not yet implemented")
