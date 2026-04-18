"""Deterministic playbook library — a Shannon-style static attack bundle.

This module is a **library**, not a decision layer. The supervisor
planner (``src/nodes/planner.py``) is the only thing that decides when
pentest work happens. When the planner chooses the ``playbook`` action,
the ``playbook_dispatch`` node calls :func:`route` here to expand recon
output into a concrete list of known attack configs, which are then
fanned out to ``pentest_workflow`` in parallel.

``route()`` matches ~25 regexes against the recon text to pick from 12
pre-defined playbooks (sqli, xss, auth-testing, idor, ssti, ssrf, lfi,
input-validation, session-mgmt, error-handling, crypto, business-logic,
plus the chain-ssrf-to-rce composite). Three of those (sqli, xss,
input-validation) are always included — they are the cheapest,
broadest-coverage checks and worth running even when the regex didn't
light up. This mirrors Shannon's static "try everything of this class"
behavior.

Previously this file lived at ``src/planning/router.py`` and was wired
as the first tier of a two-tier planner. It is no longer a router; the
supervisor has taken over that role.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.agents.base import AgentConfig
from src.agents.configs.registry import get_all_configs, get_config


@dataclass
class RoutingDecision:
    """Which agents to activate and why.

    The supervisor planner is responsible for deciding whether this
    decision is "enough" — if it isn't, the planner picks ``dynamic``
    on the next turn. This dataclass therefore no longer carries any
    confidence/tier signal; it's a pure data container.
    """

    agent_configs: list[AgentConfig] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    mode: str = "analyze"  # "analyze" or "full" — passed through to pentest_workflow


# Routing rules: (regex_pattern, config_name, reason)
# Using regex for more precise matching than simple keyword contains.
ROUTING_RULES: list[tuple[str, str, str]] = [
    # --- Authentication ---
    (r"login|sign.?in|log.?in|auth|/admin", "auth-testing",
     "Login/auth endpoint found"),
    (r"wordpress|wp-login|wp-admin", "auth-testing",
     "WordPress detected — testing default credentials"),
    (r"register|sign.?up|create.?account", "auth-testing",
     "Registration found — testing auth workflows"),

    # --- Session management ---
    (r"set-cookie|session|jsessionid|phpsessid|csrf.?token", "session-mgmt",
     "Session mechanism detected"),
    (r"jwt|bearer|authorization", "session-mgmt",
     "Token-based auth detected — testing session handling"),

    # --- SQL Injection ---
    (r"mysql|mariadb|postgres|mssql|sqlite|oracle|sql", "sqli",
     "Database technology detected"),
    (r"php|asp\.net|jsp|\.do\b", "sqli",
     "Server-side technology with common SQLi surface"),
    (r"id=\d|page=\d|cat=\d|product=\d", "sqli",
     "Numeric parameters found — potential SQLi targets"),

    # --- XSS ---
    (r"search|query|q=|comment|message|feedback|name=", "xss",
     "User-reflected input parameters found"),
    (r"<form|<input|<textarea", "xss",
     "HTML forms detected — testing for reflected/stored XSS"),

    # --- SSTI ---
    (r"jinja|flask|django|twig|freemarker|thymeleaf|mako|template", "ssti",
     "Template engine technology detected"),
    (r"render|template|view", "ssti",
     "Template rendering indicators found"),

    # --- IDOR ---
    (r"/user/\d|/profile/\d|/account/\d|/api/.*/\d", "idor",
     "Object ID references in URLs"),
    (r"user_id|account_id|order_id|profile", "idor",
     "Object reference parameters found"),

    # --- SSRF ---
    (r"url=|redirect=|next=|callback=|webhook=|fetch=|proxy=", "ssrf",
     "URL parameters found — potential SSRF targets"),
    (r"import|upload.?url|from.?url", "ssrf",
     "URL import functionality detected"),

    # --- LFI ---
    (r"file=|path=|page=|include=|template=|lang=|doc=", "lfi",
     "File reference parameters found"),
    (r"\.php\?|\.asp\?|\.jsp\?", "lfi",
     "Server-side script with query params — testing file inclusion"),

    # --- Input validation ---
    (r"upload|file.?upload|multipart", "input-validation",
     "File upload functionality detected"),
    (r"<form.*method|api/|/v\d/", "input-validation",
     "Input surfaces found — testing validation"),

    # --- Error handling ---
    (r"error|exception|stack.?trace|debug|traceback", "error-handling",
     "Error information leaking"),
    (r"x-powered-by|server:|x-aspnet", "error-handling",
     "Technology headers exposed — testing information disclosure"),

    # --- Crypto ---
    (r"https?://[^s]|mixed.?content|http://", "crypto",
     "Potential mixed content or non-HTTPS resources"),
    (r"ssl|tls|certificate|443", "crypto",
     "TLS/SSL service detected — testing configuration"),

    # --- Business logic ---
    (r"checkout|cart|payment|order|transfer|admin", "business-logic",
     "Business-critical functionality detected"),
    (r"role|permission|admin|privilege", "business-logic",
     "Role/permission indicators found"),

    # --- Custom chains ---
    (r"url=.*redirect|callback=|webhook=", "chain-ssrf-to-rce",
     "URL parameter with redirect — potential SSRF chain opportunity"),
]

# Always-active agents — these run regardless of recon output.
# Core vulnerability classes that should always be tested.
ALWAYS_ACTIVE = ["sqli", "xss", "input-validation"]

# Minimum recommended number of agents per dispatch — kept as an
# informational constant so callers (tests, the planner's system prompt,
# etc.) can reason about playbook coverage without hard-coding a number.
MIN_AGENTS_THRESHOLD = 3


def route(recon_output: str) -> RoutingDecision:
    """Expand recon output into a concrete list of playbook agents.

    Returns a RoutingDecision with the selected agents and reasoning.
    ``recon_output`` may be empty — in that case only the ALWAYS_ACTIVE
    set fires. The supervisor planner is responsible for deciding
    whether the returned set is worth dispatching; this function is a
    pure expansion and never raises.
    """
    recon_lower = (recon_output or "").lower()
    selected: dict[str, str] = {}  # config_name -> reason

    # Apply routing rules
    for pattern, config_name, reason in ROUTING_RULES:
        if config_name in selected:
            continue
        if re.search(pattern, recon_lower):
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
            reasoning.append(f"[{config_name}] {reason}")

    return RoutingDecision(
        agent_configs=configs,
        reasoning=reasoning,
    )
