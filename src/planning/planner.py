"""Tier 2 — Dynamic LLM planner.

Activates when Tier 1 (router) fails or finds unexpected paths.
Uses an LLM to analyze recon results and decide what to test next.

The planner reads the recon output and any existing findings, then
generates custom AgentConfig instances with dynamically-crafted
system prompts tailored to the specific target.
"""

from __future__ import annotations

import json
import logging

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.base import AgentConfig
from src.llm.provider import LLMConfig, get_llm
from src.tools.terminal import run_command

logger = logging.getLogger(__name__)

PLANNER_SYSTEM_PROMPT = """\
You are a penetration testing planning specialist. Your job is to analyze
reconnaissance results and decide what attack strategies to pursue.

Given:
1. Recon output from the target
2. Any findings already discovered by other agents
3. Names of agents that have already run (or failed)

You must decide which additional attack strategies to try. For each strategy,
provide a JSON object with:
- "agent_id": A unique identifier (e.g., "dynamic-php-rce")
- "config_name": Short name for the strategy
- "system_prompt": Detailed instructions for the attack agent. Be specific
  about what to test, what tools to use, and what payloads to try.

Respond with a JSON array of strategy objects. If no additional strategies
are warranted, respond with an empty array [].

Focus on:
- Attack vectors not covered by standard OWASP/vuln-type agents
- Target-specific opportunities (e.g., specific CMS plugins, API patterns)
- Chained attacks that combine multiple findings
- Uncommon vulnerability classes relevant to the detected technology stack
"""


async def dynamic_plan(
    recon_output: str,
    existing_findings: list | None = None,
    failed_agents: list[str] | None = None,
    llm_config: LLMConfig | None = None,
) -> list[AgentConfig]:
    """Use an LLM to generate a dynamic attack plan.

    Called when:
    - Tier 1 router selected fewer than the minimum threshold
    - All Tier 1 agents failed or found nothing
    - Novel attack surface discovered that no config covers

    Returns new AgentConfig instances with dynamically-generated
    system prompts tailored to the specific target.
    """
    llm = get_llm(llm_config)
    existing_findings = existing_findings or []
    failed_agents = failed_agents or []

    # Build the planning prompt
    findings_text = ""
    if existing_findings:
        findings_text = "\n".join(
            f"- [{f.severity.value}] {f.title} ({f.category})"
            for f in existing_findings
        )

    user_msg = (
        f"## Recon Output\n{recon_output}\n\n"
        f"## Existing Findings\n{findings_text or 'None yet'}\n\n"
        f"## Already-Run Agents\n{', '.join(failed_agents) or 'None'}\n\n"
        f"Generate additional attack strategies as a JSON array."
    )

    response = await llm.ainvoke([
        SystemMessage(content=PLANNER_SYSTEM_PROMPT),
        HumanMessage(content=user_msg),
    ])

    # Parse the response
    content = response.content if isinstance(response.content, str) else str(response.content)

    # Extract JSON from the response (may be wrapped in markdown code blocks)
    json_str = content
    if "```" in content:
        # Extract content between code fences
        parts = content.split("```")
        for part in parts[1::2]:  # odd indices are inside fences
            cleaned = part.strip()
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
            json_str = cleaned
            break

    try:
        strategies = json.loads(json_str)
    except json.JSONDecodeError:
        logger.warning(f"Tier 2 planner returned unparseable response: {content[:200]}")
        return []

    if not isinstance(strategies, list):
        return []

    # Convert to AgentConfig instances
    configs = []
    for i, strategy in enumerate(strategies):
        if not isinstance(strategy, dict):
            continue
        agent_id = strategy.get("agent_id", f"dynamic-{i}")
        config_name = strategy.get("config_name", f"dynamic-{i}")
        system_prompt = strategy.get("system_prompt", "")

        if not system_prompt:
            continue

        configs.append(AgentConfig(
            agent_id=agent_id,
            methodology="dynamic",
            config_name=config_name,
            system_prompt=system_prompt,
            tools=[run_command],
            max_tool_calls=40,
            max_iterations=25,
        ))

    logger.info(f"Tier 2 planner generated {len(configs)} dynamic agents")
    return configs
