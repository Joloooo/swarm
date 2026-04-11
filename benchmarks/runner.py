"""Benchmark runner — executes SwarmAttacker against targets and collects metrics.

Usage:
    python -m benchmarks.runner --target dvwa
    python -m benchmarks.runner --target dvwa --experiment no_rag
    python -m benchmarks.runner --all-targets --all-experiments
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from pathlib import Path

import yaml

from swarmattacker.config import load_config
from swarmattacker.graph import build_graph
from benchmarks.metrics import compute_metrics, BenchmarkMetrics

logger = logging.getLogger(__name__)

TARGETS_FILE = Path(__file__).parent / "targets.yaml"
RESULTS_DIR = Path(__file__).parent / "results"


def load_targets() -> dict:
    """Load benchmark target definitions."""
    with open(TARGETS_FILE) as f:
        return yaml.safe_load(f).get("targets", {})


async def run_benchmark(
    target_name: str,
    target_url: str,
    expected_vulns: list[str],
    experiment: str | None = None,
) -> BenchmarkMetrics:
    """Run SwarmAttacker against a single target and compute metrics."""
    logger.info(f"Starting benchmark: target={target_name}, experiment={experiment or 'default'}")

    # Build graph (picks up experiment config if set)
    graph = build_graph()

    start_time = time.time()

    result = await graph.ainvoke({
        "target_url": target_url,
        "target_scope": target_url,
        "messages": [],
        "findings": [],
        "agent_results": [],
        "active_agents": [],
    })

    duration = time.time() - start_time

    findings = result.get("findings", [])
    agent_results = result.get("agent_results", [])

    metrics = compute_metrics(
        findings=findings,
        agent_results=agent_results,
        expected_vulns=expected_vulns,
        target_name=target_name,
        experiment=experiment or "default",
        duration_seconds=duration,
    )

    logger.info(
        f"Benchmark complete: {metrics.total_findings} findings, "
        f"{metrics.success_rate:.1%} success rate, "
        f"{duration:.1f}s"
    )

    return metrics


def save_results(metrics_list: list[BenchmarkMetrics]) -> Path:
    """Save benchmark results to JSON."""
    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_path = RESULTS_DIR / f"benchmark_{timestamp}.json"

    data = {
        "timestamp": timestamp,
        "results": [m.to_dict() for m in metrics_list],
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    logger.info(f"Results saved to {output_path}")
    return output_path


async def run_all(
    target_names: list[str] | None = None,
    experiments: list[str] | None = None,
) -> list[BenchmarkMetrics]:
    """Run benchmarks across targets and experiments."""
    targets = load_targets()

    if target_names:
        targets = {k: v for k, v in targets.items() if k in target_names}

    if not experiments:
        experiments = ["default"]

    # Discover experiment configs
    exp_dir = Path(__file__).parent.parent / "configs" / "experiments"
    available_experiments = ["default"]
    if exp_dir.exists():
        available_experiments.extend(p.stem for p in exp_dir.glob("*.yaml"))

    if "all" in experiments:
        experiments = available_experiments

    all_metrics = []

    for target_name, target_info in targets.items():
        url = target_info.get("url", "")
        expected = target_info.get("expected_vulns", [])

        for exp in experiments:
            try:
                metrics = await run_benchmark(
                    target_name=target_name,
                    target_url=url,
                    expected_vulns=expected,
                    experiment=exp if exp != "default" else None,
                )
                all_metrics.append(metrics)
            except Exception as e:
                logger.error(f"Benchmark failed: {target_name}/{exp}: {e}")

    return all_metrics


def main():
    parser = argparse.ArgumentParser(description="SwarmAttacker Benchmark Runner")
    parser.add_argument("--target", help="Single target name (from targets.yaml)")
    parser.add_argument("--all-targets", action="store_true", help="Run all targets")
    parser.add_argument("--experiment", help="Experiment config name (e.g., 'no_rag')")
    parser.add_argument("--all-experiments", action="store_true", help="Run all experiments")
    parser.add_argument("--url", help="Direct URL (skip targets.yaml)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    target_names = None
    experiments = None

    if args.all_targets:
        target_names = None  # run all
    elif args.target:
        target_names = [args.target]

    if args.all_experiments:
        experiments = ["all"]
    elif args.experiment:
        experiments = [args.experiment]

    results = asyncio.run(run_all(target_names, experiments))
    if results:
        save_results(results)


if __name__ == "__main__":
    main()
