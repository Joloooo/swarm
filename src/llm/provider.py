"""Provider-agnostic LLM interface.

Thin wrapper that returns a LangChain BaseChatModel based on config.
Avoids heavy dependencies like LiteLLM — just dispatches to the right
langchain-* provider package.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)


class Provider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENROUTER = "openrouter"
    CODEX = "codex"


@dataclass
class LLMConfig:
    """Configuration for an LLM instance."""

    provider: Provider = Provider.CODEX
    model: str = "gpt-5.4-mini"
    temperature: float = 0.0
    max_tokens: int = 4096
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
        )

    raise ValueError(f"Unknown provider: {config.provider}")
