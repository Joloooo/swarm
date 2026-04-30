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

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool

# NB: ``src.llm.provider`` is imported lazily inside ``make_agent_node``
# to break the circular import chain
# ``skills.loader → agents.base → llm.provider → graph → nodes → agents.base``.
# Importing it at module level wedges the loader at startup.
from src.state import AgentResult, Finding, Severity

logger = logging.getLogger(__name__)


# Phrases that indicate the model refused the task (so we don't silently
# return 0 findings — we surface the refusal in chat instead).
REFUSAL_PATTERNS = (
    "i can't help",
    "i cannot help",
    "i'm sorry, but i can't",
    "i'm sorry, but i cannot",
    "i cannot assist",
    "i'm unable to",
    "i am unable to",
    "i'm not able to",
    "i am not able to",
    "i don't feel comfortable",
    "as an ai, i",
)


def _looks_like_refusal(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    return any(p in lower for p in REFUSAL_PATTERNS)


@dataclass
class AgentConfig:
    """Everything that makes one swarm agent different from another.

    Skill content (system_prompt + tool list + caps) now comes from
    SKILL.md files under ``src/skills/`` parsed by ``src/skills/loader.py``.
    This dataclass is the in-memory carrier the loader produces.
    """

    # Identity
    agent_id: str  # unique name, e.g. "owasp-auth-testing"
    methodology: str  # "owasp" | "vulntype" | "custom" | "skill"
    config_name: str  # primary key for planner dispatch — matches skill folder

    # Prompt body (the SKILL.md body, minus frontmatter)
    system_prompt: str = ""

    # Tools (LangChain tool instances, resolved from SKILL.md tool names)
    tools: list[BaseTool] = field(default_factory=list)

    # Budget / loop detection
    max_tool_calls: int = 50
    max_iterations: int = 30


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

    # Config-provided system prompt (the SKILL.md body — attack instructions)
    if config.system_prompt:
        parts.append(config.system_prompt)

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
#
# Two parsers run on every assistant message:
# 1. The structured **FINDING:** / ## Finding format defined in base_rules.py
# 2. JSON blocks of the form {"findings": [...]} as a forgiving fallback
#
# The structured pattern only requires Title and Severity now (Category, URL,
# Evidence are optional). Bounded `[\s\S]{0,N}?` gaps prevent runaway matches
# across unrelated headings.

FINDING_PATTERN = re.compile(
    r"(?:\*\*FINDING:?\*\*|##\s+FINDING|##\s+Finding)"
    r"[\s\S]{0,40}?"
    r"Title:\s*(.+?)$"
    r"[\s\S]{0,200}?"
    r"Severity:\s*(\w+)"
    r"(?:[\s\S]{0,200}?Category:\s*([\w-]+))?"
    r"(?:[\s\S]{0,400}?URL:\s*(.+?)$)?"
    r"(?:[\s\S]{0,400}?Evidence:\s*(.+?)$)?",
    re.MULTILINE,
)

# Match a JSON object (non-greedy) that contains a "findings" key. Used as a
# fallback when the model emits {"findings": [...]} instead of the markdown.
JSON_FINDINGS_PATTERN = re.compile(
    r'\{[^{}]*?"findings"\s*:\s*\[[\s\S]*?\]\s*\}',
)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _findings_from_markdown(content: str, agent_id: str) -> list[Finding]:
    """Parse the structured **FINDING:** / ## Finding format."""
    out = []
    for match in FINDING_PATTERN.finditer(content):
        title = match.group(1).strip()
        severity_str = (match.group(2) or "info").strip().lower()
        category = (match.group(3) or "unknown").strip().lower()
        url = (match.group(4) or "").strip()
        evidence = (match.group(5) or "").strip()
        out.append(Finding(
            title=title,
            severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
            category=category,
            description=title,
            evidence=evidence[:500],
            agent_id=agent_id,
            url=url,
        ))
    return out


def _findings_from_json(content: str, agent_id: str) -> list[Finding]:
    """Fallback parser for JSON {"findings": [...]} blocks."""
    out = []
    for match in JSON_FINDINGS_PATTERN.finditer(content):
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
        for item in data.get("findings", []) or []:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "Untitled finding").strip()
            severity_str = str(item.get("severity") or "info").strip().lower()
            category = str(item.get("category") or "unknown").strip().lower()
            url = str(item.get("url") or "").strip()
            evidence = str(item.get("evidence") or item.get("payload") or "")[:500]
            out.append(Finding(
                title=title,
                severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
                category=category,
                description=str(item.get("description") or title),
                evidence=evidence,
                agent_id=agent_id,
                url=url,
            ))
    return out


def _extract_findings(messages: list, agent_id: str) -> list[Finding]:
    """Parse structured findings from agent messages.

    Tries the markdown FINDING format first; falls back to JSON
    {"findings": [...]} blocks. Both parsers run on every AIMessage and
    results are concatenated.
    """
    findings = []
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        findings.extend(_findings_from_markdown(content, agent_id))
        findings.extend(_findings_from_json(content, agent_id))
    return findings


def make_agent_node(
    config: AgentConfig,
    llm: BaseChatModel | None = None,
    runtime_config: dict | None = None,
):
    """Create a node function for the orchestrator graph.

    This wraps create_agent into a function that:
    1. Injects the target_url and knowledge layers into the system prompt
    2. Runs the agent subgraph with loop detection
    3. Extracts structured findings from the agent's output
    4. Handles errors gracefully (no agent crash kills the swarm)
    5. Returns updates to the parent SwarmGraphState
    """
    if llm is None:
        from src.llm.provider import get_llm  # lazy — see top-of-file note
        llm = get_llm()

    async def agent_node(state: dict) -> dict:
        """Execute this agent and return findings + chat trace to the parent."""
        target_url = state.get("target_url", "")

        # Build system message with all knowledge layers
        phase1_findings = state.get("phase1_findings")
        system_msg = _build_system_message(
            config, target_url, runtime_config, phase1_findings,
        )

        # Create the agent with iteration limit
        agent = create_agent(
            model=llm,
            tools=config.tools,
            system_prompt=system_msg,
        )

        trace: list = []
        findings: list[Finding] = []
        try:
            result = await agent.ainvoke(
                {"messages": []},
                config={"recursion_limit": config.max_iterations},
            )

            messages = result.get("messages", [])
            findings = _extract_findings(messages, config.agent_id)

            # Mirror the inner agent trace up to the parent so Studio chat
            # shows every tool call (`run_command("curl ...")`) and the
            # corresponding ToolMessage response inline. Without this the
            # entire conversation is hidden inside the create_agent
            # sub-graph and the parent chat looks frozen.
            trace = [m for m in messages if isinstance(m, (AIMessage, ToolMessage))]
            for m in trace:
                # Tag each message with the agent_id so Studio (and
                # downstream consumers) can group / filter by agent.
                try:
                    m.additional_kwargs.setdefault("agent_id", config.agent_id)
                except Exception:
                    pass

            # Refusal detection — if 0 findings AND the last assistant
            # message reads like a safety refusal, surface it explicitly
            # instead of letting it get swallowed as "0 findings".
            last_text = ""
            for m in reversed(messages):
                if isinstance(m, AIMessage):
                    last_text = (
                        m.content if isinstance(m.content, str) else str(m.content)
                    )
                    break

            refused = (not findings) and _looks_like_refusal(last_text)
            if not findings:
                logger.warning(
                    f"[{config.agent_id}] produced 0 findings — "
                    f"last output: {last_text[:500]!r}"
                )
            if refused:
                logger.warning(f"[{config.agent_id}] looks like a model refusal")
                trace.append(AIMessage(
                    content=(
                        f"⚠️ [{config.agent_id}] model refused the task. "
                        f"Last output: {last_text[:300]}"
                    ),
                    additional_kwargs={
                        "agent_id": config.agent_id,
                        "refusal": True,
                    },
                ))

            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                findings=findings,
                completed=not refused,
                error="model refused" if refused else None,
            )
        except Exception as e:
            logger.error(f"Agent {config.agent_id} failed: {e}")
            trace = [AIMessage(
                content=f"❌ [{config.agent_id}] crashed: {e}",
                additional_kwargs={"agent_id": config.agent_id, "error": True},
            )]
            agent_result = AgentResult(
                agent_id=config.agent_id,
                methodology=config.methodology,
                config_name=config.config_name,
                error=str(e),
                completed=False,
            )
            findings = []

        return {
            "messages": trace,
            "agent_results": [agent_result],
            "findings": findings,
            "active_agents": [config.agent_id],
        }

    agent_node.__name__ = config.agent_id.replace("-", "_")
    return agent_node
