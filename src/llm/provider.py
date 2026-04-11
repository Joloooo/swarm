"""Provider-agnostic LLM interface.

Thin wrapper that returns a LangChain BaseChatModel based on config.
Avoids heavy dependencies like LiteLLM — just dispatches to the right
langchain-* provider package.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

from langchain_core.language_models import BaseChatModel


class Provider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENROUTER = "openrouter"


@dataclass
class LLMConfig:
    """Configuration for an LLM instance."""

    provider: Provider = Provider.ANTHROPIC
    model: str = "claude-sonnet-4-20250514"
    temperature: float = 0.0
    max_tokens: int = 4096
    # Provider-specific kwargs (e.g. base_url for OpenRouter)
    extra: dict[str, Any] | None = None


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

        return ChatAnthropic(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            **extra,
        )

    if config.provider == Provider.OPENAI:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            **extra,
        )

    if config.provider == Provider.OPENROUTER:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ.get("OPENROUTER_API_KEY", ""),
            **extra,
        )

    raise ValueError(f"Unknown provider: {config.provider}")
