"""Supervisor planner node — the brain of the SwarmAttacker graph.

The planner is the **only** decision-maker in the graph. Every other
node (recon, playbook_dispatch, dynamic_dispatch, pentest_workflow,
report) edges back here, and the planner decides the next hop by
emitting a JSON directive:

    {"action": "recon" | "playbook" | "dynamic" | "report",
     "target_url": "...",
     "target_scope": "...",
     "note": "one-sentence reasoning"}

The planner has two tools it can call mid-turn:

- ``normalize_url`` — turn messy user input into a canonical URL.
- ``validate_website`` — HTTP reachability check. Reports facts;
  the planner judges whether a failure blocks the run.

It does *not* have shell access. That only becomes available once
the planner routes to an attack node.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent

from src.llm.provider import LLMConfig, get_llm
from src.state import SwarmGraphState
from src.tools.url import normalize_url, validate_website

logger = logging.getLogger(__name__)

# Hard cap on how many times the supervisor can run per session.
# Prevents runaway planner → worker → planner loops when the LLM
# keeps asking for more work without making progress.
MAX_PLANNER_ITERS = 12

VALID_ACTIONS = {"recon", "playbook", "dynamic", "report"}

SUPERVISOR_SYSTEM_PROMPT = """\
You are the supervisor of a penetration-testing swarm. You are the
only decision-maker in the graph — every other node runs only because
you chose it. After each worker node completes, the graph returns to
you and you decide the next step.

# Available actions

Each turn you must end your response with a fenced JSON block
declaring your decision. The allowed values for "action" are:

- "recon"    — run the reconnaissance agent against the target.
               Usually the right first step, but optional: if the
               user already described the target in detail, or if
               recon has already run, you can skip ahead.
- "playbook" — dispatch the Shannon-style deterministic playbook
               library. This expands recon output into a set of
               known attack workflows (sqli, xss, auth-testing,
               idor, ssti, ssrf, lfi, input-validation, session-mgmt,
               error-handling, crypto, business-logic, chain-ssrf).
               The three always-on picks (sqli, xss, input-validation)
               fire even if no regex matched. Choose this when recon
               returned substantive content.
- "dynamic"  — ask a dedicated LLM to generate custom attack configs
               tailored to the target. Prefer this over "playbook"
               when recon output is thin, hostile, or describes an
               unusual tech stack that the regex library won't match
               well.
- "report"   — finalize the run. Aggregates every finding into a
               report and ends the graph. Choose this when you have
               enough evidence, when further tries are unlikely to
               pay off, or when the target is clearly unreachable
               and the user's intent can't be satisfied.

# URL handling

The URL is load-bearing but not strictly required to be a public
URL. Targets may be IPv4/IPv6 addresses, RFC1918 internal ranges,
docker-compose hosts, or CTF boxes. Always call ``normalize_url``
on whatever the user provided, even if it already looks clean —
this gives you a structured object (href, host, is_ip, is_private,
scheme, port) you can reason about.

Call ``validate_website`` only when reachability evidence would
actually change your decision. A failed check is NOT authoritative:
private IPs, firewalled hosts, and WAF-protected sites can all fail
it legitimately. If ``is_private`` is true, don't be surprised when
``validate_website`` times out. Read the ``reason`` field — a DNS
failure is a stronger "don't proceed" signal than a timeout.

# Reassessment

After each worker, look at what came back:

- New findings?   Consider continuing with a different tactic or
                  going to report.
- Recon empty?    Don't blindly fall back to "playbook" — its
                  regexes will mostly miss. Prefer "dynamic".
- Stealth level   If waf_detected is true and stealth_level is 2,
  rising?         be more conservative — consider report rather
                  than firing another loud scan.
- Same action     If you keep picking the same action and nothing
  repeating?      is changing, pick "report" instead.

# Output contract

End EVERY turn with a fenced JSON block of this exact shape:

```json
{
  "action": "recon",
  "target_url": "http://example.com",
  "target_scope": "example.com",
  "note": "initial recon on normalized target"
}
```

- "action" must be one of: recon, playbook, dynamic, report.
- "target_url" must be set once you've normalized it; carry it
  forward on every subsequent turn.
- "target_scope" defaults to the hostname unless the user gave a
  broader scope (e.g. "*.example.com").
- "note" is a single sentence for the audit log — not marketing copy.

If you cannot parse the user's intent, choose "report" with a note
explaining what you need. Never omit the JSON block.
"""


# Extracts a fenced ```json { ... } ``` block from the LLM's final
# message. We are lenient: also accept an un-fenced trailing object.
_JSON_BLOCK = re.compile(
    r"```(?:json)?\s*(\{.*?\})\s*```|(\{[^{}]*\"action\"[^{}]*\})",
    re.DOTALL,
)


def _parse_decision(text: str) -> dict | None:
    """Extract the supervisor's JSON decision from its final message.

    Returns None if no well-formed block is found.
    """
    if not text:
        return None
    for match in _JSON_BLOCK.finditer(text):
        raw = match.group(1) or match.group(2)
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("action") in VALID_ACTIONS:
            return parsed
    return None


def _final_text(messages: list) -> str:
    """Return the content of the last AIMessage in the list, as a string."""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage):
            content = msg.content
            if isinstance(content, str):
                return content
            # Some providers return a list of content blocks.
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


def make_planner_node(llm_config: LLMConfig | None = None):
    """Build the supervisor node function.

    Factory so the graph can inject an ablation LLM config in tests
    without mutating module state.
    """
    llm = get_llm(llm_config)
    agent = create_react_agent(
        model=llm,
        tools=[normalize_url, validate_website],
        prompt=SUPERVISOR_SYSTEM_PROMPT,
    )

    async def planner_node(state: SwarmGraphState) -> dict:
        iters = state.get("planner_iters", 0) + 1

        # Hard cap — force report rather than loop forever.
        if iters > MAX_PLANNER_ITERS:
            logger.warning(
                "Supervisor exceeded MAX_PLANNER_ITERS=%d; forcing report.",
                MAX_PLANNER_ITERS,
            )
            return {
                "planner_iters": iters,
                "next_action": "report",
                "messages": [
                    AIMessage(
                        content=(
                            f"Supervisor hit iteration cap ({MAX_PLANNER_ITERS}). "
                            "Forcing report."
                        )
                    )
                ],
            }

        # Feed the supervisor the full conversation so far. Worker nodes
        # will have appended their own AIMessages; the supervisor reads
        # them as the record of what happened.
        prior_messages = list(state.get("messages", []))
        if not prior_messages:
            # First turn with no user input at all — synthesize a stub.
            prior_messages = [
                HumanMessage(
                    content="No target provided. Ask the user for one via report."
                )
            ]

        try:
            result = await agent.ainvoke({"messages": prior_messages})
        except Exception as e:
            logger.exception("Supervisor planner failed: %s", e)
            return {
                "planner_iters": iters,
                "next_action": "report",
                "messages": [
                    AIMessage(content=f"Supervisor error: {e}. Forcing report.")
                ],
            }

        result_messages: list = result.get("messages", [])
        # Only append the NEW messages the agent produced (anything past
        # the prior conversation we fed in).
        new_messages = result_messages[len(prior_messages):]

        final_text = _final_text(result_messages)
        decision = _parse_decision(final_text)

        if decision is None:
            logger.warning(
                "Supervisor produced no parseable JSON decision; forcing report. "
                "Final text starts: %r",
                final_text[:200],
            )
            return {
                "planner_iters": iters,
                "next_action": "report",
                "messages": new_messages + [
                    AIMessage(
                        content=(
                            "Supervisor output did not include a valid JSON "
                            "decision block. Forcing report."
                        )
                    )
                ],
            }

        action = decision["action"]
        target_url = (decision.get("target_url") or state.get("target_url") or "").strip()
        target_scope = (
            decision.get("target_scope")
            or state.get("target_scope")
            or target_url
        ).strip()

        logger.info(
            "Supervisor turn %d → action=%s target=%s note=%s",
            iters,
            action,
            target_url or "<unset>",
            decision.get("note", "")[:80],
        )

        update: dict[str, Any] = {
            "planner_iters": iters,
            "next_action": action,
            "messages": new_messages,
        }
        if target_url:
            update["target_url"] = target_url
        if target_scope:
            update["target_scope"] = target_scope
        return update

    planner_node.__name__ = "planner_node"
    return planner_node


# Module-level singleton so graph.py can import it directly.
planner_node = make_planner_node()
