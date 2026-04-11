"""Multi-model comparison runner.

Runs the same benchmark target with different LLM providers/models
to compare performance across models. Produces comparison tables
for the thesis results chapter.

Usage:
    python -m benchmarks.multimodel --target dvwa
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from benchmarks.metrics import BenchmarkMetrics
from benchmarks.runner import load_targets, save_results
from swarmattacker.graph import build_graph
from benchmarks.metrics import compute_metrics

logger = logging.getLogger(__name__)

# Models to compare (provider, model_id, display_name)
MODEL_CONFIGS = [
    ("anthropic", "claude-sonnet-4-20250514", "Claude Sonnet 4"),
    ("anthropic", "claude-opus-4-20250514", "Claude Opus 4"),
    ("openai", "gpt-4o", "GPT-4o"),
    ("openai", "o3-mini", "o3-mini"),
    ("openrouter", "google/gemini-2.5-pro-preview", "Gemini 2.5 Pro"),
]

RESULTS_DIR = Path(__file__).parent / "results"


async def run_with_model(
    target_name: str,
    target_url: str,
    expected_vulns: list[str],
    provider: str,
    model: str,
    display_name: str,
) -> BenchmarkMetrics:
    """Run benchmark with a specific model."""
    # Set environment to override model
    os.environ["SWARM_LLM_PROVIDER"] = provider
    os.environ["SWARM_LLM_MODEL"] = model

    logger.info(f"Running with {display_name} ({provider}/{model})")

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

    metrics = compute_metrics(
        findings=result.get("findings", []),
        agent_results=result.get("agent_results", []),
        expected_vulns=expected_vulns,
        target_name=target_name,
        experiment=display_name,
        duration_seconds=duration,
    )

    return metrics


def generate_model_comparison_latex(results: list[BenchmarkMetrics]) -> str:
    """Generate a LaTeX table comparing models."""
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Multi-Model Comparison Results}",
        r"\label{tab:model-comparison}",
        r"\begin{tabular}{lccccc}",
        r"\toprule",
        r"Model & Success & Findings & Quality & Autonomy & Duration \\",
        r" & Rate & Count & Score & Rate & (s) \\",
        r"\midrule",
    ]

    for m in results:
        lines.append(
            f"{m.experiment} & "
            f"{m.success_rate:.1%} & "
            f"{m.total_findings} & "
            f"{m.finding_quality_score:.0f} & "
            f"{m.autonomy_rate:.1%} & "
            f"{m.total_duration_seconds:.0f} \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])

    return "\n".join(lines)


async def run_multimodel(target_name: str) -> list[BenchmarkMetrics]:
    """Run all model comparisons against a single target."""
    targets = load_targets()
    if target_name not in targets:
        raise ValueError(f"Target '{target_name}' not found")

    target = targets[target_name]
    url = target["url"]
    expected = target.get("expected_vulns", [])

    all_metrics = []

    for provider, model, display_name in MODEL_CONFIGS:
        try:
            metrics = await run_with_model(
                target_name=target_name,
                target_url=url,
                expected_vulns=expected,
                provider=provider,
                model=model,
                display_name=display_name,
            )
            all_metrics.append(metrics)
        except Exception as e:
            logger.error(f"Model {display_name} failed: {e}")
            all_metrics.append(BenchmarkMetrics(
                target_name=target_name,
                experiment=display_name,
            ))

    # Save results
    save_results(all_metrics)

    # Generate LaTeX table
    RESULTS_DIR.mkdir(exist_ok=True)
    latex = generate_model_comparison_latex(all_metrics)
    latex_path = RESULTS_DIR / f"multimodel_{target_name}_{time.strftime('%Y%m%d')}.tex"
    latex_path.write_text(latex)
    logger.info(f"LaTeX table saved to {latex_path}")

    # Print summary
    print(f"\n{'Model':<25} {'Success':>8} {'Findings':>9} {'Quality':>8} {'Duration':>9}")
    print("-" * 62)
    for m in all_metrics:
        print(
            f"{m.experiment:<25} {m.success_rate:>7.1%} {m.total_findings:>9} "
            f"{m.finding_quality_score:>8.0f} {m.total_duration_seconds:>8.0f}s"
        )

    return all_metrics


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SwarmAttacker Multi-Model Comparison")
    parser.add_argument("--target", required=True, help="Target name from targets.yaml")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    asyncio.run(run_multimodel(args.target))


if __name__ == "__main__":
    main()
