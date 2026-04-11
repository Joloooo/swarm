"""Agent config registry — loads and provides WorkflowConfig instances.

All configs are defined in Python modules under the owasp/, vulntype/,
and custom/ subdirectories. This registry discovers and indexes them.

Single-phase configs (AgentConfig) are auto-wrapped into WorkflowConfig
with exploit=None. Two-phase configs use register_workflow() directly.
"""

from __future__ import annotations

from src.agents.base import AgentConfig, WorkflowConfig

# -- Config store (populated by register_config / register_workflow calls) --
_CONFIGS: dict[str, WorkflowConfig] = {}


def register_config(config: AgentConfig) -> None:
    """Register a single-phase agent config. Auto-wraps into WorkflowConfig."""
    _CONFIGS[config.config_name] = WorkflowConfig(
        config_name=config.config_name,
        analyze=config,
        exploit=None,
    )


def register_workflow(workflow: WorkflowConfig) -> None:
    """Register a two-phase workflow config directly."""
    _CONFIGS[workflow.config_name] = workflow


def get_workflow(config_name: str) -> WorkflowConfig | None:
    """Get a workflow by its config_name."""
    _ensure_loaded()
    return _CONFIGS.get(config_name)


def get_config(config_name: str) -> AgentConfig | None:
    """Get the analyze-phase AgentConfig by name. Backward compat."""
    _ensure_loaded()
    wf = _CONFIGS.get(config_name)
    return wf.analyze if wf else None


def get_all_configs() -> list[AgentConfig]:
    """Get all registered analyze-phase configs. Backward compat."""
    _ensure_loaded()
    return [wf.analyze for wf in _CONFIGS.values()]


def get_all_workflows() -> list[WorkflowConfig]:
    """Get all registered workflows."""
    _ensure_loaded()
    return list(_CONFIGS.values())


def get_configs_by_methodology(methodology: str) -> list[AgentConfig]:
    """Get all configs for a given methodology (owasp/vulntype/custom)."""
    _ensure_loaded()
    return [wf.analyze for wf in _CONFIGS.values() if wf.analyze.methodology == methodology]


_loaded = False


def _ensure_loaded() -> None:
    """Import all config modules to trigger registration. Called once."""
    global _loaded
    if _loaded:
        return
    _loaded = True

    # Import config modules — each one calls register_config() at module level
    from src.agents.configs import owasp, vulntype, custom  # noqa: F401
