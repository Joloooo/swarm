"""Runtime configuration loader with ablation toggle support.

Loads a base config (configs/default.yaml) and optionally merges
experiment overrides (configs/experiments/*.yaml) on top.

This enables the ablation study: each experiment config toggles
specific components off, and the evaluation framework runs the same
target with different configs to measure the impact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


CONFIGS_DIR = Path(__file__).parent.parent.parent / "configs"


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override wins on conflicts."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(
    experiment: str | None = None,
    config_dir: Path | None = None,
) -> dict[str, Any]:
    """Load runtime config, optionally with an experiment overlay.

    Args:
        experiment: Name of experiment config to overlay (e.g. "no_rag").
                    Looks for configs/experiments/{experiment}.yaml.
        config_dir: Override the config directory (for testing).

    Returns:
        Merged configuration dictionary.
    """
    base_dir = config_dir or CONFIGS_DIR
    default_path = base_dir / "default.yaml"

    if not default_path.exists():
        raise FileNotFoundError(f"Default config not found: {default_path}")

    with open(default_path) as f:
        config = yaml.safe_load(f) or {}

    if experiment:
        exp_path = base_dir / "experiments" / f"{experiment}.yaml"
        if not exp_path.exists():
            raise FileNotFoundError(f"Experiment config not found: {exp_path}")
        with open(exp_path) as f:
            overlay = yaml.safe_load(f) or {}
        config = _deep_merge(config, overlay)

    return config


def is_enabled(config: dict, *keys: str) -> bool:
    """Check if a nested config key is enabled (truthy).

    Usage: is_enabled(config, "knowledge", "rag")  ->  config["knowledge"]["rag"]
    Returns False if any key in the path doesn't exist.
    """
    current = config
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return False
        current = current[key]
    return bool(current)
