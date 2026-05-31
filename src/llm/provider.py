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
    Defaults are sourced from ``config.budgets.reasoning_*`` (see
    ``src/graph.py``) so a run can dial reasoning depth via env var
    without code edits — e.g. ``SWARM_REASONING_EFFORT=high`` for a
    cheaper run during development.
    """

    # Provider default sourced from ``config.budgets.provider`` (which
    # reads ``SWARM_PROVIDER``). Lets a run switch backends with no
    # code edit, e.g. ``SWARM_PROVIDER=local uv run swarm ...``.
    provider: Provider = field(
        default_factory=lambda: Provider(
            getattr(config.budgets, "provider", "codex")
        )
    )
    # Model slug. For Codex / OpenAI / Anthropic this reads
    # ``SWARM_MODEL``; for ``provider=local`` it reads
    # ``SWARM_LOCAL_MODEL`` instead. The two are kept separate so a
    # single ``.env`` can set valid slugs for both backends without
    # collision (``SWARM_MODEL`` has a hard ``choices=`` whitelist of
    # Codex-only slugs in ``src/graph.py``).
    #
    # Why gpt-5.4-mini is the *default* for Codex: gpt-5.5's policy
    # classifier refuses roughly 60% of pentest-shaped worker prompts
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
        default_factory=lambda: (
            getattr(config.budgets, "local_model", "hermes-8b")
            if getattr(config.budgets, "provider", "codex") == "local"
            else getattr(config.budgets, "model", "gpt-5.4-mini")
        )
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
    # Codex account selection — TEMPORARY emergency switcher (see
    # ``src/cli/codex_accounts.py``). When ``SWARM_CODEX_HOME`` is set,
    # ``ChatCodex`` loads tokens from ``<that dir>/auth.json`` instead of the
    # default ``~/.codex``. Unset → ``None`` → default ``~/.codex`` (the main
    # / jolocorp login), so behaviour is unchanged unless a switch is active.
    # Codex-only; silently ignored by other providers.
    codex_home: str | None = field(
        default_factory=lambda: os.environ.get("SWARM_CODEX_HOME") or None
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
        if cfg.provider == Provider.CODEX and cfg.codex_home:
            # Emergency account switcher active — make it obvious in the
            # banner which (non-default) Codex login this run will use.
            out["codex_home"] = cfg.codex_home
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

        # Guard against a stale account selection: if SWARM_CODEX_HOME points
        # at a dir with no auth.json (e.g. an extra account that was removed),
        # fall back to the default ~/.codex main login instead of crashing
        # every worker with FileNotFoundError.
        codex_home = config.codex_home
        if codex_home and not os.path.exists(os.path.join(codex_home, "auth.json")):
            logger.warning(
                "SWARM_CODEX_HOME=%s has no auth.json — falling back to ~/.codex. "
                "Stale account selection? Run `unset SWARM_CODEX_HOME`.",
                codex_home,
            )
            codex_home = None

        _log_provider_diagnostic(config, CODEX_API_ENDPOINT)
        return ChatCodex(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            reasoning_effort=config.reasoning_effort,
            reasoning_summary=config.reasoning_summary,
            # None → ChatCodex defaults to ~/.codex (main login). Set only
            # when the TUI/env selected an extra account. See LLMConfig above.
            codex_home=codex_home,
        )

    raise ValueError(f"Unknown provider: {config.provider}")
