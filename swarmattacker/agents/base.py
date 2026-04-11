"""Config-driven agent: one function, different configs.

Each swarm agent is the same LangGraph node function parameterized by
an AgentConfig (system prompt, tools, methodology, budget). This is
the dominant pattern across pentesting implementations (6/9 use it).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, SystemMessage
from langchain_core.tools import BaseTool
from langgraph.prebuilt import create_react_agent

from swarmattacker.llm.provider import LLMConfig, get_llm
from swarmattacker.state import AgentState, Finding, Severity


@dataclass
class AgentConfig:
    """Everything that makes one swarm agent different from another."""

    # Identity
    agent_id: str  # unique name, e.g. "owasp-auth-testing"
    methodology: str  # "owasp" | "vulntype" | "custom"
    config_name: str  # e.g. "auth-testing", "sqli", "chain-ssrf-rce"

    # Prompt
    system_prompt: str = ""
    skill_docs: list[str] = field(default_factory=list)  # paths to skill docs to load

    # Tools (LangChain tool instances)
    tools: list[BaseTool] = field(default_factory=list)

    # Budget / loop detection
    max_tool_calls: int = 50
    max_iterations: int = 30

    # LLM config (can override per-agent for ablation)
    llm_config: LLMConfig | None = None


def _build_system_message(config: AgentConfig, target_url: str) -> str:
    """Assemble the full system prompt from config + skill docs."""
    parts = []

    # Base identity
    parts.append(
        f"You are a penetration testing agent (ID: {config.agent_id}) "
        f"in the SwarmAttacker swarm.\n"
        f"Methodology: {config.methodology}\n"
        f"Focus area: {config.config_name}\n"
        f"Target: {target_url}\n"
    )

    # Config-provided system prompt (attack instructions)
    if config.system_prompt:
        parts.append(config.system_prompt)

    # Skill-loaded documents (full technique docs)
    for skill_path in config.skill_docs:
        path = Path(skill_path)
        if path.exists():
            parts.append(f"\n--- Skill: {path.stem} ---\n{path.read_text()}")

    # Standard rules
    parts.append(
        "\n--- Rules ---\n"
        "- Report findings with severity, evidence, and reproduction steps.\n"
        "- If you detect WAF/IDS blocking, note it and try evasion techniques.\n"
        "- Stay within scope. Only test the target URL and its subpaths.\n"
        "- Stop after exhausting your methodology or hitting the tool call limit.\n"
    )

    return "\n\n".join(parts)


def create_agent_graph(config: AgentConfig, llm: BaseChatModel | None = None):
    """Create a LangGraph ReAct agent from an AgentConfig.

    Returns a compiled LangGraph graph that can be invoked as a subgraph
    node in the orchestrator.
    """
    if llm is None:
        llm = get_llm(config.llm_config)

    return create_react_agent(
        model=llm,
        tools=config.tools,
        prompt=_build_system_message(config, "{target_url}"),
        state_schema=AgentState,
    )


def make_agent_node(config: AgentConfig, llm: BaseChatModel | None = None):
    """Create a node function for the orchestrator graph.

    This wraps create_agent_graph into a function that:
    1. Injects the target_url into the system prompt
    2. Runs the agent subgraph
    3. Extracts findings from the agent's output
    4. Returns updates to the parent SwarmGraphState
    """
    if llm is None:
        llm = get_llm(config.llm_config)

    async def agent_node(state: dict) -> dict:
        """Execute this agent and return findings to the parent state."""
        target_url = state.get("target_url", "")

        # Build the agent's system message with actual target
        system_msg = _build_system_message(config, target_url)

        # Create the react agent
        agent = create_react_agent(
            model=llm,
            tools=config.tools,
            prompt=system_msg,
        )

        # Run it
        result = await agent.ainvoke({
            "messages": [],
        })

        # Extract any findings the agent reported
        # (For now, findings come back as the agent's final message.
        #  Phase 2 will add structured finding extraction.)
        from swarmattacker.state import AgentResult

        agent_result = AgentResult(
            agent_id=config.agent_id,
            methodology=config.methodology,
            config_name=config.config_name,
            completed=True,
        )

        return {
            "agent_results": [agent_result],
            "active_agents": [config.agent_id],
        }

    agent_node.__name__ = config.agent_id.replace("-", "_")
    return agent_node
