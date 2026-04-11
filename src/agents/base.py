"""Config-driven agent: one function, different configs.

Each swarm agent is the same LangGraph node function parameterized by
an AgentConfig (system prompt, tools, methodology, budget). This is
the dominant pattern across pentesting implementations (6/9 use it).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import BaseTool
from langgraph.prebuilt import create_react_agent

from src.llm.provider import LLMConfig, get_llm
from src.state import AgentResult, AgentState, Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    """Everything that makes one swarm agent different from another."""

    # Identity
    agent_id: str  # unique name, e.g. "owasp-auth-testing"
    methodology: str  # "owasp" | "vulntype" | "custom"
    config_name: str  # e.g. "auth-testing", "sqli", "chain-ssrf-rce"

    # Prompt
    system_prompt: str = ""
    skill_names: list[str] = field(default_factory=list)  # skill doc names to load
    skill_docs: list[str] = field(default_factory=list)  # direct paths (legacy)

    # Tools (LangChain tool instances)
    tools: list[BaseTool] = field(default_factory=list)

    # Budget / loop detection
    max_tool_calls: int = 50
    max_iterations: int = 30

    # LLM config (can override per-agent for ablation)
    llm_config: LLMConfig | None = None


@dataclass
class WorkflowConfig:
    """Multi-step workflow definition. Wraps one or two AgentConfigs.

    A workflow has two phases:
    - analyze: always runs — identifies vulnerabilities
    - exploit: only runs if mode="full" AND phase 1 found something

    Single-phase configs are auto-wrapped with exploit=None by the registry.
    """

    config_name: str
    analyze: AgentConfig
    exploit: AgentConfig | None = None


def _build_system_message(
    config: AgentConfig,
    target_url: str,
    runtime_config: dict | None = None,
    phase1_findings: list[Finding] | None = None,
) -> str:
    """Assemble the full system prompt from config + knowledge layers.

    Respects ablation toggles from runtime_config.
    When phase1_findings is provided, injects analysis results into
    the prompt so the exploit phase knows what to target.
    """
    from src.config import is_enabled

    rc = runtime_config or {}
    parts = []

    # Base identity (always present)
    parts.append(
        f"You are a penetration testing agent (ID: {config.agent_id}) "
        f"in the SwarmAttacker swarm.\n"
        f"Methodology: {config.methodology}\n"
        f"Focus area: {config.config_name}\n"
        f"Target: {target_url}\n"
    )

    # Knowledge layer 1: base rules (toggleable)
    if is_enabled(rc, "knowledge", "base_rules") if rc else True:
        from src.knowledge.prompts.base_rules import get_base_prompt
        stealth_level = rc.get("stealth", {}).get("initial_level", 0) if rc else 0
        parts.append(get_base_prompt(stealth_level))

    # Phase 1 findings injection (for exploit phase)
    if phase1_findings:
        findings_text = "\n".join(
            f"- [{f.severity.value.upper()}] {f.title}"
            + (f" at {f.url}" if f.url else "")
            + (f": {f.evidence[:200]}" if f.evidence else "")
            for f in phase1_findings
        )
        parts.append(
            "--- Analysis Phase Results ---\n"
            "The analysis phase found the following vulnerabilities. "
            "Focus your exploitation on these confirmed targets:\n"
            f"{findings_text}\n"
        )

    # Config-provided system prompt (attack instructions)
    if config.system_prompt:
        parts.append(config.system_prompt)

    # Knowledge layer 2: skill loading (toggleable)
    if is_enabled(rc, "knowledge", "skill_loading") if rc else True:
        from src.knowledge.skills.loader import load_skills
        # Load by skill_names first, then fall back to direct paths
        if config.skill_names:
            skill_content = load_skills(config.skill_names)
            if skill_content:
                parts.append(skill_content)
        for skill_path in config.skill_docs:
            path = Path(skill_path)
            if path.exists():
                parts.append(f"\n--- Skill: {path.stem} ---\n{path.read_text()}")

    # Knowledge layer 3: RAG hint (actual retrieval happens at query time)
    if is_enabled(rc, "knowledge", "rag") if rc else True:
        parts.append(
            "\n--- Dynamic Knowledge ---\n"
            "If you need specific CVE details, bypass techniques, or tool syntax "
            "that you're unsure about, describe what you need and the system will "
            "provide relevant knowledge snippets.\n"
        )

    return "\n\n".join(parts)


# -- Finding extraction from agent output --

FINDING_PATTERN = re.compile(
    r"\*\*FINDING:\*\*.*?"
    r"Title:\s*(.+?)$.*?"
    r"Severity:\s*(\w+).*?"
    r"Category:\s*(\w[\w-]*).*?"
    r"(?:URL:\s*(.+?)$)?"
    r"(?:.*?Evidence:\s*(.+?)$)?",
    re.MULTILINE | re.DOTALL,
)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _extract_findings(messages: list, agent_id: str) -> list[Finding]:
    """Parse structured findings from agent messages."""
    findings = []
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        for match in FINDING_PATTERN.finditer(content):
            title = match.group(1).strip()
            severity_str = match.group(2).strip().lower()
            category = match.group(3).strip().lower()
            url = (match.group(4) or "").strip()
            evidence = (match.group(5) or "").strip()

            findings.append(Finding(
                title=title,
                severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
                category=category,
                description=title,
                evidence=evidence[:500],  # Cap evidence length
                agent_id=agent_id,
                url=url,
            ))
    return findings


def make_agent_node(
    config: AgentConfig,
    llm: BaseChatModel | None = None,
    runtime_config: dict | None = None,
):
    """Create a node function for the orchestrator graph.

    This wraps create_react_agent into a function that:
    1. Injects the target_url and knowledge layers into the system prompt
    2. Runs the agent subgraph with loop detection
    3. Extracts structured findings from the agent's output
    4. Handles errors gracefully (no agent crash kills the swarm)
    5. Returns updates to the parent SwarmGraphState
    """
    if llm is None:
        llm = get_llm(config.llm_config)

    async def agent_node(state: dict) -> dict:
        """Execute this agent and return findings to the parent state."""
        target_url = state.get("target_url", "")

        # Build system message with all knowledge layers
        phase1_findings = state.get("phase1_findings")
        system_msg = _build_system_message(
            config, target_url, runtime_config, phase1_findings,
        )

        # Create the react agent with iteration limit
        agent = create_react_agent(
            model=llm,
            tools=config.tools,
            prompt=system_msg,
        )

        try:
            result = await agent.ainvoke(
                {"messages": []},
                config={"recursion_limit": config.max_iterations},
            )

            messages = result.get("messages", [])
            findings = _extract_findings(messages, config.agent_id)

            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                completed=True,
            )
        except Exception as e:
            logger.error(f"Agent {config.agent_id} failed: {e}")
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                error=str(e),
                completed=False,
            )
            findings = []

        return {
            "agent_results": [agent_result],
            "findings": findings,
            "active_agents": [config.agent_id],
        }

    agent_node.__name__ = config.agent_id.replace("-", "_")
    return agent_node
