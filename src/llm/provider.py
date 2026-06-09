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
    # Local llama-server / Ollama on a localhost HTTP endpoint. Reuses
    # ``ChatOpenAI`` under the hood — the only differences vs. ``OPENAI``
    # are the baked-in localhost ``base_url`` (configurable via
    # ``SWARM_LOCAL_BASE_URL``) and that no real API key is required.
    LOCAL = "local"


@dataclass
class LLMConfig:
    """Configuration for an LLM instance.

    The ``reasoning_*`` fields are Codex-specific (consumed by
    ``src.llm.codex.ChatCodex``) and silently ignored by other providers.
    Defaults are sourced from ``config.budgets.reasoning_*``, which
    ``src/graph.py`` reads from ``swarm-config.toml`` — so a run dials
    reasoning depth by editing ``[model] reasoning_effort`` in that file
    (or via ``swarm`` -> Edit config), no code edit needed.
    """

    # Provider default sourced from ``config.budgets.provider`` (an advanced
    # code-only knob; ``SWARM_PROVIDER`` still overrides it for a one-off,
    # e.g. ``SWARM_PROVIDER=local uv run swarm ...``).
    provider: Provider = field(
        default_factory=lambda: Provider(config.budgets.provider)
    )
    # Model slug. For Codex / OpenAI / Anthropic this is the configured
    # ``[model] slug`` from swarm-config.toml (default gpt-5.5); for
    # ``provider=local`` it uses ``config.budgets.local_model`` instead, so
    # the local backend can advertise its own alias without colliding with
    # the Codex slug whitelist. Override per-instance via
    # ``LLMConfig(model=...)`` for a one-off — e.g. thesis ablation runs that
    # compare model capability vs. refusal rate side-by-side.
    model: str = field(
        default_factory=lambda: (
            config.budgets.local_model
            if config.budgets.provider == "local"
            else config.budgets.model
        )
    )
    temperature: float = 0.0
    max_tokens: int = field(default_factory=lambda: config.budgets.llm_max_tokens)
    # Per-call httpx timeout (seconds) for Codex streaming calls. Sourced from
    # ``config.budgets.llm_call_timeout_s`` (SWARM_LLM_TIMEOUT_S overrides).
    request_timeout_s: float = field(
        default_factory=lambda: float(config.budgets.llm_call_timeout_s)
    )
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
    #     "xhigh"    — "extra-high" / maximum reasoning depth (the highest
    #                  level the API exposes)
    #
    # Source of truth: ReasoningEffort enum in
    # codex-rs/protocol/src/openai_models.rs. The active default is whatever
    # ``[model] reasoning_effort`` says in swarm-config.toml.
    reasoning_effort: str | None = field(
        default_factory=lambda: config.budgets.reasoning_effort
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
        default_factory=lambda: config.budgets.reasoning_summary
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
        out = {
            "provider":          cfg.provider.value,
            "model":             cfg.model,
            "temperature":       cfg.temperature,
            "max_tokens":        cfg.max_tokens,
            "reasoning_effort":  cfg.reasoning_effort,
            "reasoning_summary": cfg.reasoning_summary,
        }
        if cfg.provider == Provider.LOCAL:
            # Surface the local URL so the startup banner makes the
            # endpoint obvious — otherwise "model=hermes-8b" is
            # ambiguous about which llama-server / Ollama instance.
            out["base_url"] = (
                os.environ.get("SWARM_LOCAL_BASE_URL")
                or "http://127.0.0.1:8080/v1"
            )
        return out
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

    if config.provider == Provider.LOCAL:
        # Talks to a local llama-server (or Ollama, etc.) over its
        # OpenAI-compatible Chat Completions endpoint. Reuses the same
        # ``ChatOpenAI`` machinery that ``Provider.OPENAI`` does — only
        # the ``base_url`` and the dummy API key change.
        #
        # No reasoning_summary plumbing here: none of the GGUFs commonly
        # used with llama-server emit ``<think>`` blocks. If a reasoning
        # GGUF (DeepSeek-R1-Distill, Qwen3-thinking) is later added, the
        # ``additional_kwargs["reasoning_content"]`` deltas that
        # ``ChatOpenAI`` already captures can be forwarded to
        # ``LIVE.thinking_delta`` in ``callbacks.py``.
        from langchain_openai import ChatOpenAI

        # Resolution order: LLMConfig(extra={"base_url": ...}) wins,
        # then ``SWARM_LOCAL_BASE_URL``, then llama-server's default
        # port. The ``config.budgets.local_base_url`` value is sourced
        # from ``SWARM_LOCAL_BASE_URL`` anyway, so the env lookup here
        # covers both code paths without needing to un-shadow the
        # module-level ``config`` import (the ``config`` parameter
        # name shadows it inside this function).
        base_url = (
            (config.extra or {}).get("base_url")
            or os.environ.get("SWARM_LOCAL_BASE_URL")
            or "http://127.0.0.1:8080/v1"
        )
        _log_provider_diagnostic(config, base_url)
        kwargs = {k: v for k, v in extra.items() if k != "base_url"}
        return ChatOpenAI(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            base_url=base_url,
            api_key="no-auth",  # llama-server / Ollama ignore this
            **kwargs,
        )

    if config.provider == Provider.CODEX:
        from src.llm.codex import CODEX_API_ENDPOINT, ChatCodex

        # ChatCodex reads the OAuth token from the default ~/.codex/auth.json
        # and refreshes it on demand (see src/llm/codex.py:_ensure_tokens).
        _log_provider_diagnostic(config, CODEX_API_ENDPOINT)
        return ChatCodex(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            reasoning_effort=config.reasoning_effort,
            reasoning_summary=config.reasoning_summary,
            request_timeout_s=config.request_timeout_s,
        )

    raise ValueError(f"Unknown provider: {config.provider}")
