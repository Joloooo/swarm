"""Agent config registry — loads and provides AgentConfig instances.

All configs are defined in Python modules under the owasp/, vulntype/,
and custom/ subdirectories. This registry discovers and indexes them.
"""

from __future__ import annotations

from swarmattacker.agents.base import AgentConfig

# -- Config store (populated by register_config calls in config modules) --
_CONFIGS: dict[str, AgentConfig] = {}


def register_config(config: AgentConfig) -> None:
    """Register an agent config in the global registry."""
    _CONFIGS[config.config_name] = config


def get_config(config_name: str) -> AgentConfig | None:
    """Get a config by its config_name."""
    _ensure_loaded()
    return _CONFIGS.get(config_name)


def get_all_configs() -> list[AgentConfig]:
    """Get all registered configs."""
    _ensure_loaded()
    return list(_CONFIGS.values())


def get_configs_by_methodology(methodology: str) -> list[AgentConfig]:
    """Get all configs for a given methodology (owasp/vulntype/custom)."""
    _ensure_loaded()
    return [c for c in _CONFIGS.values() if c.methodology == methodology]


_loaded = False


def _ensure_loaded() -> None:
    """Import all config modules to trigger registration. Called once."""
    global _loaded
    if _loaded:
        return
    _loaded = True

    # Import config modules — each one calls register_config() at module level
    from swarmattacker.agents.configs import owasp, vulntype, custom  # noqa: F401
