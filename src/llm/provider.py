"""Provider-agnostic LLM interface.

Thin wrapper that returns a LangChain BaseChatModel based on config.
Avoids heavy dependencies like LiteLLM — just dispatches to the right
langchain-* provider package.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from langchain_core.language_models import BaseChatModel

from src.graph import config

logger = logging.getLogger(__name__)


class Provider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENROUTER = "openrouter"
    CODEX = "codex"


@dataclass
class LLMConfig:
    """Configuration for an LLM instance.

    The ``reasoning_*`` fields are Codex-specific (consumed by
    ``src.llm.codex.ChatCodex``) and silently ignored by other providers.
    Defaults are sourced from ``config.budgets.reasoning_*`` (see
    ``src/graph.py``) so a run can dial reasoning depth via env var
    without code edits — e.g. ``SWARM_REASONING_EFFORT=high`` for a
    cheaper run during development.
    """

    provider: Provider = Provider.CODEX
    # Model slug. Default sourced from ``config.budgets.model`` (see
    # ``src/graph.py``) which itself reads ``SWARM_MODEL`` — so a run
    # can switch model with no code edit:
    #     SWARM_MODEL=gpt-5.5 uv run python -m benchmarks.xbow_runner ...
    #
    # Why gpt-5.4-mini is the *default*: gpt-5.5's policy classifier
    # refuses roughly 60% of pentest-shaped worker prompts
    # (CodexCyberPolicyError), collapsing benchmark runs into 15-minute
    # timeouts. The mini model's filter is markedly more permissive
    # for the in-scope offensive-security work this swarm exists to do.
    # Override per-instance via ``LLMConfig(model=...)`` (or the env
    # var) when a fresh trial of a larger model is warranted — useful
    # for thesis ablation studies that compare model capability vs.
    # refusal rate side-by-side.
    #
    # Other valid Codex slugs: "gpt-5.5", "gpt-5.4", "gpt-5.3-codex",
    # "gpt-5.2", "codex-auto-review".
    model: str = field(
        default_factory=lambda: getattr(config.budgets, "model", "gpt-5.4-mini")
    )
    temperature: float = 0.0
    max_tokens: int = field(default_factory=lambda: config.budgets.llm_max_tokens)
    # ── Codex-only reasoning controls ─────────────────────────────────
    # Effort: how hard the model thinks before responding. Higher levels
    # produce longer (and more expensive) internal chain-of-thought.
    #
    # Valid values (lowercase, exact strings — anything else is rejected
    # by the upstream API):
    #     "none"     — disable reasoning entirely (not all models accept this)
    #     "minimal"  — internal-only level, rarely useful in practice
    #     "low"      — fast, cheap, light reasoning
    #     "medium"   — balanced (gpt-5.5 default upstream)
    #     "high"     — deeper reasoning, more tokens, slower
    #     "xhigh"    — "extra-high" / maximum reasoning depth (the
    #                  highest level the API exposes; what this codebase
    #                  defaults to so benchmark debugging gets the
    #                  fullest chain-of-thought visible in nodes.jsonl)
    #
    # Source of truth: ReasoningEffort enum in
    # codex-rs/protocol/src/openai_models.rs.
    reasoning_effort: str | None = field(
        default_factory=lambda: getattr(config.budgets, "reasoning_effort", "xhigh")
    )
    # Summary: whether human-readable chain-of-thought is streamed back.
    #
    # Valid values (lowercase, exact strings):
    #     "auto"     — server-chosen length (default in upstream Codex)
    #     "concise"  — short summary per reasoning block
    #     "detailed" — fuller summary, more tokens, more debug power
    #     "none"     — do NOT return summaries (omits the field on the wire)
    #
    # Source of truth: ReasoningSummary enum in
    # codex-rs/protocol/src/config_types.rs.
    reasoning_summary: str | None = field(
        default_factory=lambda: getattr(config.budgets, "reasoning_summary", "detailed")
    )
    # Provider-specific kwargs (e.g. base_url for OpenRouter)
    extra: dict[str, Any] | None = None


def _log_provider_diagnostic(config: LLMConfig, base_url: str | None) -> None:
    """Log which provider/base_url is actually being used.

    Why: some setups (env vars, custom proxies) silently redirect LLM calls
    to endpoints with stricter safety policies. This log line makes the
    actual endpoint visible at startup so the routing is easy to spot in
    `langgraph dev` output.

    For ``provider=codex`` the call goes to ``chatgpt.com/backend-api/codex``
    via the bundled ``ChatCodex`` model (using your ChatGPT subscription
    OAuth tokens). That endpoint has stricter pentest refusals than direct
    Anthropic — if you see ``⚠️ [agent-id] model refused the task`` in
    chat, the authorization preamble in ``base_rules.py`` should help, but
    you may also want to switch to a different provider for the affected
    agents.
    """
    env_overrides = {
        k: os.environ[k]
        for k in (
            "OPENAI_BASE_URL", "OPENAI_API_BASE",
            "ANTHROPIC_BASE_URL",
            "OPENROUTER_BASE_URL",
        )
        if k in os.environ
    }
    logger.info(
        "LLM provider initialized: provider=%s model=%s base_url=%s "
        "env_overrides=%s",
        config.provider.value,
        config.model,
        base_url or "<provider default>",
        env_overrides or "<none>",
    )
    # Loud warning if the OpenAI base URL has been redirected to anything
    # that smells like a ChatGPT/Codex browser-session proxy via env var
    # (separate from the explicit Provider.CODEX path which is intentional).
    openai_url = (
        env_overrides.get("OPENAI_BASE_URL")
        or env_overrides.get("OPENAI_API_BASE", "")
    )
    if (
        config.provider == Provider.OPENAI
        and openai_url
        and ("chatgpt.com" in openai_url or "codex" in openai_url.lower())
    ):
        logger.warning(
            "OPENAI_BASE_URL points at a ChatGPT/Codex proxy (%s) while "
            "provider=openai. Use Provider.CODEX explicitly or unset the "
            "env var.",
            openai_url,
        )


def current_default_config() -> dict[str, Any]:
    """Return a small display dict describing the active LLM defaults.

    Used by the startup banner in ``src/observability/live.py:LIVE.startup_banner``
    so the user sees provider / model / reasoning settings up front
    without having to grep ``logs/`` after the fact. Reads the
    ``LLMConfig()`` defaults — which are themselves driven by
    ``config.budgets`` env-var overrides — so this naturally
    reflects whatever the next ``get_llm()`` call would pick.

    Returns the empty dict on any error so the banner stays
    rendering-safe.
    """
    try:
        cfg = LLMConfig()
        return {
            "provider":          cfg.provider.value,
            "model":             cfg.model,
            "temperature":       cfg.temperature,
            "max_tokens":        cfg.max_tokens,
            "reasoning_effort":  cfg.reasoning_effort,
            "reasoning_summary": cfg.reasoning_summary,
        }
    except Exception:  # noqa: BLE001
        return {}


def get_llm(config: LLMConfig | None = None) -> BaseChatModel:
    """Return a LangChain chat model for the given config.

    Picks the right provider package and passes through config.
    API keys are read from environment variables.
    """
    if config is None:
        config = LLMConfig()

    extra = config.extra or {}

    if config.provider == Provider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic

        _log_provider_diagnostic(config, os.environ.get("ANTHROPIC_BASE_URL"))
        return ChatAnthropic(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            **extra,
        )

    if config.provider == Provider.OPENAI:
        from langchain_openai import ChatOpenAI

        _log_provider_diagnostic(
            config,
            extra.get("base_url") or os.environ.get("OPENAI_BASE_URL"),
        )
        return ChatOpenAI(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            **extra,
        )

    if config.provider == Provider.OPENROUTER:
        from langchain_openai import ChatOpenAI

        _log_provider_diagnostic(config, "https://openrouter.ai/api/v1")
        return ChatOpenAI(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ.get("OPENROUTER_API_KEY", ""),
            **extra,
        )

    if config.provider == Provider.CODEX:
        from src.llm.codex import CODEX_API_ENDPOINT, ChatCodex

        _log_provider_diagnostic(config, CODEX_API_ENDPOINT)
        return ChatCodex(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            reasoning_effort=config.reasoning_effort,
            reasoning_summary=config.reasoning_summary,
        )

    raise ValueError(f"Unknown provider: {config.provider}")
