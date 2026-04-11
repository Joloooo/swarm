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

import re
from dataclasses import dataclass, field

from src.agents.base import AgentConfig
from src.agents.configs.registry import get_all_configs, get_config


@dataclass
class RoutingDecision:
    """Which agents to activate and why."""

    agent_configs: list[AgentConfig] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    tier2_needed: bool = False  # True if routing confidence is low


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

# Minimum number of agents that should be selected.
# If fewer than this, mark tier2_needed so the dynamic planner can help.
MIN_AGENTS_THRESHOLD = 3


def route(recon_output: str) -> RoutingDecision:
    """Decide which agents to activate based on recon output.

    Returns a RoutingDecision with the selected agents and reasoning.
    If fewer than MIN_AGENTS_THRESHOLD are selected by rules, sets
    tier2_needed=True so the orchestrator can invoke the dynamic planner.
    """
    recon_lower = recon_output.lower()
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

    # Determine if Tier 2 should be activated
    tier2_needed = len(configs) < MIN_AGENTS_THRESHOLD

    return RoutingDecision(
        agent_configs=configs,
        reasoning=reasoning,
        tier2_needed=tier2_needed,
    )
