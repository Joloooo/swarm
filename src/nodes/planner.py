"""Supervisor planner node — the single decision-maker of the graph.

The planner is the only decision layer in SwarmAttacker. Every other
node (recon, pentest_workflow, web_search, report) edges back here,
and the planner decides the next hop by emitting a JSON directive:

    {"action": "attack" | "recon" | "web_search" | "report",
     "configs": [...],
     "custom_configs": [...],
     "mode": "analyze" | "full",
     "target_url": "...",
     "target_scope": "...",
     "search_query": "...",
     "reasoning": "one or two sentences of reasoning"}

When the planner picks ``action="attack"`` it also supplies the exact
set of attack configs to run — either by name (for the 12 pre-registered
configs under ``src/agents/configs/**``) via the ``configs`` field, or by
inventing a tailored one on the fly via ``custom_configs``. The planner
therefore owns what used to be split across ``playbook_dispatch`` and
``dynamic_dispatch``.

The planner has two tools it can call mid-turn:

- ``normalize_url`` — turn messy user input into a canonical URL.
- ``validate_website`` — HTTP reachability check. Reports facts;
  the planner judges whether a failure blocks the run.

It does *not* have shell access. That only becomes available once the
planner routes to an attack node via ``pentest_workflow``.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage

from src.agents.base import AgentConfig
from src.agents.configs.registry import get_workflow, register_config
from src.llm.provider import LLMConfig, get_llm
from src.state import SwarmGraphState
from src.tools.terminal import run_command
from src.tools.url import normalize_url, validate_website

logger = logging.getLogger(__name__)

# Budgets are centralized in src/graph.py (`Budgets` dataclass + `budgets`
# singleton). The locals below are kept as thin re-bindings so existing call
# sites at lines ~301/353/... don't all need to change.
from src.graph import budgets

# Money-runaway safety net, NOT the primary termination signal. Set high
# enough that it almost never fires for legitimate work — the right way for
# a run to end is the planner picking action="report" (routed to END) by
# itself. Override via SWARM_PLANNER_MAX_ITERS.
MAX_PLANNER_ITERS = budgets.planner_max_iters

VALID_ACTIONS = {"attack", "recon", "web_search", "report"}

# Budget defaults for LLM-invented custom attack configs.
_CUSTOM_MAX_TOOL_CALLS = budgets.custom_attack_max_tool_calls
_CUSTOM_MAX_ITERATIONS = budgets.custom_attack_max_iterations

SUPERVISOR_SYSTEM_PROMPT = """\
You are the supervisor of a penetration-testing swarm. You are the
only decision-maker in the graph — every other node runs only because
you chose it. After each worker node completes, the graph returns to
you and you decide the next step.

# Reasoning fields (required everywhere)

Both the tools you can call (``normalize_url``, ``validate_website``)
and your own JSON decision block require a ``reasoning`` field as
the first argument. The operator reads these live in the Studio chat
and in the audit log. Fill them with one or two sentences that state
the evidence you are acting on and the hypothesis or outcome you
expect — not mechanics ("I will normalize the URL") and not filler
("Proceeding with the plan"). State the evidence → decision link.

# Available actions

Each turn you must end your response with a fenced JSON block declaring
your decision. The allowed values for "action" are:

- "recon"      — run the reconnaissance agent against the target.
                 Usually the right first step, but optional: if the
                 user already described the target in detail, or if
                 recon has already run, you can skip ahead.
- "attack"     — run one or more attack workflows in parallel. You
                 must also supply the configs to run, either by name
                 ("configs") or as freshly-invented ones
                 ("custom_configs"), or both.
- "web_search" — look up an external fact (CVE details, bypass
                 technique, tool syntax). Also supply "search_query".
- "report"     — finalize the run. Aggregate every finding into a
                 report and end the graph. Choose this when you have
                 enough evidence, further tries are unlikely to pay
                 off, or the target is clearly unreachable.

# Available attack configs (for action="attack")

Pick any subset by name in "configs". Use the one-line descriptions
below to judge which configs apply to the recon output you have. You
are NOT required to include any particular config — decide based on
the target. If recon shows the target has no inputs, picking xss is
pointless; if it's a pure static site, most of these don't fit.

Pre-registered configs:
- sqli: SQL injection probing of URL params, forms, headers, cookies;
  uses sqlmap for confirmed injection points.
- xss: reflected and stored cross-site scripting against reflected-input
  surfaces (search, comment, name, feedback fields, etc.).
- idor: insecure direct object reference — tampering with IDs in URLs
  and API paths to access other users' resources.
- lfi: local file inclusion via path traversal on file/path/include params.
- ssrf: server-side request forgery on URL-taking inputs (webhook,
  callback, import-from-url, redirect).
- ssti: server-side template injection against Jinja/Twig/Freemarker/etc.
- auth-testing: authentication bypass, default credentials, weak JWT,
  auth-flow tampering.
- session-mgmt: cookie flags, session fixation, token entropy, CSRF.
- error-handling: verbose errors, stack-trace leaks, tech headers exposed.
- crypto: weak TLS configs, bad hashes, predictable tokens, mixed content.
- business-logic: workflow/state tampering on carts, payments, roles,
  admin functions.
- input-validation: generic fuzzing on upload/API surfaces for encoding
  and boundary issues.
- chain-ssrf-to-rce: exploit chain from SSRF to RCE via internal metadata
  services.

# Custom configs

If recon reveals a stack or attack surface that none of the above cover
well (niche CMS plugin, unusual API pattern, chained findings from prior
turns), add an entry to "custom_configs" instead:

- "config_name": unique short identifier (e.g. "graphql-introspection-abuse").
- "system_prompt": detailed instructions telling that agent what to probe,
  which tools to run, and what payloads to try.

Custom configs run with the same shell tool as the pre-registered ones.

# URL handling

The URL is load-bearing but not strictly required to be a public URL.
Targets may be IPv4/IPv6 addresses, RFC1918 internal ranges, docker-compose
hosts, or CTF boxes. Always call ``normalize_url`` on whatever the user
provided, even if it already looks clean — this gives you a structured
object (href, host, is_ip, is_private, scheme, port) you can reason about.

Call ``validate_website`` only when reachability evidence would actually
change your decision. A failed check is NOT authoritative: private IPs,
firewalled hosts, and WAF-protected sites can all fail it legitimately.
If ``is_private`` is true, don't be surprised when ``validate_website``
times out. Read the ``reason`` field — a DNS failure is a stronger
"don't proceed" signal than a timeout.

# Reassessment

After each worker, look at what came back:

- New findings?   Consider continuing with a different tactic or going
                  to report.
- Recon empty?    Don't blindly run every config; pick a minimal set
                  or go straight to custom_configs tailored to whatever
                  tiny signal recon did surface.
- Stealth level   If waf_detected is true and stealth_level is 2, be
  rising?         more conservative — consider report rather than firing
                  another loud scan.
- Same action     If you keep picking the same action and nothing is
  repeating?      changing, pick "report" instead.

# Output contract

End EVERY turn with a fenced JSON block of this exact shape:

```json
{
  "action": "attack",
  "configs": ["sqli", "xss"],
  "custom_configs": [
    {"config_name": "wp-plugin-cve-lookup",
     "system_prompt": "You test WordPress plugins for known CVEs..."}
  ],
  "mode": "analyze",
  "target_url": "http://example.com",
  "target_scope": "example.com",
  "reasoning": "Recon surfaced PHP + MySQL with a login form at /admin. Attacking the obvious injection and reflection surfaces before expanding scope."
}
```

Rules:

- "action" must be one of: attack, recon, web_search, report.
- When action=="attack", at least one of "configs" or "custom_configs"
  must be non-empty. If you have nothing worth running, pick "report".
- "mode" is "analyze" (default) or "full". "full" lets configs that
  define an exploit phase run it after analyze.
- "search_query" is required iff action=="web_search".
- Carry "target_url" / "target_scope" forward on every subsequent turn.
- "reasoning" is REQUIRED on every turn. One to two sentences
  explaining the evidence that led you to this decision and what
  you expect this step to teach you. It appears in the Studio chat
  and in audit logs — this is how the operator follows along in
  real time. Do not omit it. Do not write marketing fluff ("Let's
  proceed with the plan"). State the evidence → decision link.

If you cannot parse the user's intent, choose "report" with a
``reasoning`` field explaining what you need. Never omit the JSON
block.
"""


# Extracts a fenced ```json { ... } ``` block from the LLM's final
# message. We are lenient: also accept an un-fenced trailing object.
_JSON_BLOCK = re.compile(
    r"```(?:json)?\s*(\{.*?\})\s*```|(\{[^{}]*\"action\"[^{}]*\})",
    re.DOTALL,
)


def _parse_decision(text: str) -> dict | None:
    """Extract the supervisor's JSON decision from its final message.

    Returns None if no well-formed block is found. Uses a forgiving
    two-pass regex — fenced block first, bare object as fallback.
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


def _stage_attack(decision: dict, state: SwarmGraphState) -> list[dict]:
    """Register any custom configs and build the pending_dispatch list.

    Skips unknown named configs and malformed ``custom_configs`` entries
    with a warning. Returns the list of dispatch items (possibly empty —
    the caller is responsible for falling back to "report" in that case).
    """
    mode = decision.get("mode") or state.get("mode") or "analyze"

    # Step 1: register custom configs so get_workflow() can resolve them.
    custom_names: list[str] = []
    raw_custom = decision.get("custom_configs") or []
    if not isinstance(raw_custom, list):
        raw_custom = []
    seen_custom: set[str] = set()
    for entry in raw_custom:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("config_name") or "").strip()
        prompt = str(entry.get("system_prompt") or "").strip()
        if not name or not prompt:
            logger.warning(
                "planner: dropping malformed custom_config %r (missing name or prompt)",
                entry,
            )
            continue
        if name in seen_custom:
            logger.warning(
                "planner: dropping duplicate custom_config name %r", name
            )
            continue
        seen_custom.add(name)
        cfg = AgentConfig(
            agent_id=f"custom-{name}",
            methodology="custom",
            config_name=name,
            system_prompt=prompt,
            tools=[run_command],
            max_tool_calls=_CUSTOM_MAX_TOOL_CALLS,
            max_iterations=_CUSTOM_MAX_ITERATIONS,
        )
        register_config(cfg)
        custom_names.append(name)

    # Step 2: union the named configs with the freshly-registered customs,
    # resolve each against the registry, and stage them for fan-out.
    raw_named = decision.get("configs") or []
    if not isinstance(raw_named, list):
        raw_named = []
    named = [str(n).strip() for n in raw_named if str(n).strip()]

    pending: list[dict] = []
    seen: set[str] = set()
    for i, name in enumerate(named + custom_names):
        if name in seen:
            continue
        seen.add(name)
        wf = get_workflow(name)
        if wf is None:
            logger.warning(
                "planner: unknown config %r (not in registry after custom "
                "registration) — skipping",
                name,
            )
            continue
        pending.append({
            "agent_id": f"{name}-{i}",
            "config_name": name,
            "methodology": wf.analyze.methodology,
            "mode": mode,
        })
    return pending


def make_planner_node(llm_config: LLMConfig | None = None):
    """Build the supervisor node function.

    Factory so the graph can inject an ablation LLM config in tests
    without mutating module state.
    """
    llm = get_llm(llm_config)
    agent = create_agent(
        model=llm,
        tools=[normalize_url, validate_website],
        system_prompt=SUPERVISOR_SYSTEM_PROMPT,
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
        seeded_target = (state.get("target_url") or "").strip()
        if seeded_target:
            prior_messages.insert(
                0,
                HumanMessage(
                    content=(
                        "The graph invocation already includes this authorized "
                        f"benchmark target_url: {seeded_target}. Treat it as "
                        "the user-supplied target. Do not ask for a target."
                    )
                ),
            )
        if not prior_messages:
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

        update: dict[str, Any] = {
            "planner_iters": iters,
            "next_action": action,
            "messages": new_messages,
        }
        if target_url:
            update["target_url"] = target_url
        if target_scope:
            update["target_scope"] = target_scope

        if action == "attack":
            pending = _stage_attack(decision, state)
            if not pending:
                logger.warning(
                    "planner: action=attack but no runnable configs after "
                    "validation — forcing report."
                )
                update["next_action"] = "report"
            else:
                mode = decision.get("mode") or state.get("mode") or "analyze"
                update["mode"] = mode
                update["pending_dispatch"] = pending
        elif action == "web_search":
            query = (decision.get("search_query") or "").strip()
            if query:
                update["search_query"] = query
        # recon / report need no extra fields.

        logger.info(
            "Supervisor turn %d → action=%s target=%s reasoning=%s",
            iters,
            update["next_action"],
            target_url or "<unset>",
            # Prefer "reasoning" (current contract); fall back to legacy
            # "note" so older checkpoints deserialize without log noise.
            (decision.get("reasoning") or decision.get("note") or "")[:120],
        )
        return update

    planner_node.__name__ = "planner_node"
    return planner_node


# Module-level singleton so graph.py can import it directly.
planner_node = make_planner_node()
