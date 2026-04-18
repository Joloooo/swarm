"""Dynamic dispatch node — asks an LLM to generate custom attack agents.

Invoked by the supervisor planner when it picks ``action="dynamic"``.
Calls :func:`dynamic_plan` (``src.planning.dynamic_agents``) which
returns a list of :class:`AgentConfig` tailored to the current target,
registers them in the config registry so the pentest_workflow node can
find them by ``config_name``, and stages them in
``state["pending_dispatch"]`` for the shared fan-out edge.

Prefer this over ``playbook_dispatch`` when recon output is thin or
hostile (the playbook library's regexes will mostly miss on empty
text) or when the target's tech stack is unusual enough that the
pre-defined playbooks are a poor match.
"""

from __future__ import annotations

import logging

from langchain_core.messages import AIMessage

from src.agents.configs.registry import register_config
from src.planning.dynamic_agents import dynamic_plan
from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


def _last_real_agent_text(messages: list) -> str:
    """Find the most recent real *agent* AIMessage in the history.

    Same filtering rules as ``playbook_dispatch._last_real_agent_text``:
    skip ``traced()`` boundary messages (``additional_kwargs["node"]``),
    refusal / error messages, and any AIMessage without an ``agent_id``
    kwarg (which would be the supervisor planner's own output, not a
    real agent's).
    """
    for msg in reversed(messages):
        if not isinstance(msg, AIMessage) or not msg.content:
            continue
        kw = getattr(msg, "additional_kwargs", {}) or {}
        if kw.get("node") or kw.get("refusal") or kw.get("error"):
            continue
        if not kw.get("agent_id"):
            continue
        content = msg.content
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    parts.append(block.get("text") or block.get("content") or "")
                else:
                    parts.append(str(block))
            return "\n".join(parts)
        return str(content)
    return ""


async def dynamic_dispatch_node(state: SwarmGraphState) -> dict:
    """Generate custom agents via LLM and stage them for fan-out."""
    recon_output = _last_real_agent_text(state.get("messages", []))
    findings = state.get("findings", [])
    prior_results = state.get("agent_results", [])
    failed_agents = [r.agent_id for r in prior_results if r.error]

    configs = await dynamic_plan(
        recon_output=recon_output,
        existing_findings=findings,
        failed_agents=failed_agents,
    )

    # Register each dynamically-generated config so pentest_workflow
    # can resolve it via get_workflow(config_name). dynamic_plan
    # produces fresh config_names each call, so re-registration is
    # harmless.
    for cfg in configs:
        register_config(cfg)

    mode = state.get("mode", "analyze")
    pending = [
        {
            "agent_id": cfg.agent_id,
            "config_name": cfg.config_name,
            "methodology": cfg.methodology,
            "mode": mode,
        }
        for cfg in configs
    ]

    logger.info(
        "dynamic_dispatch staged %d custom workflow(s): %s",
        len(pending),
        [p["config_name"] for p in pending],
    )

    # Flag Tier 2 activation so the final report can note it — this
    # keeps backward compatibility with report_node's existing field.
    update: dict = {"pending_dispatch": pending}
    if pending:
        update["tier2_activated"] = True
    return update
