"""Ablation experiment runner.

Runs SwarmAttacker with different config overlays to measure the impact
of each component. Produces a comparison table for the thesis results chapter.

Usage:
    python -m benchmarks.ablation --target dvwa

This will run:
1. default (full system)
2. no_rag (disable RAG knowledge layer)
3. no_skills (disable skill loading)
4. no_knowledge (disable all knowledge layers)
5. single_agent (disable swarm, use one generalist)
6. no_stealth (disable WAF/IDS evasion)

Results are saved to benchmarks/results/ as JSON and as a LaTeX table.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from benchmarks.metrics import BenchmarkMetrics
from benchmarks.runner import load_targets, run_benchmark, save_results

logger = logging.getLogger(__name__)

# Standard ablation experiments
ABLATION_EXPERIMENTS = [
    "default",
    "no_rag",
    "no_skills",
    "no_knowledge",
    "single_agent",
    "no_stealth",
]

RESULTS_DIR = Path(__file__).parent / "results"


def generate_latex_table(results: list[BenchmarkMetrics]) -> str:
    """Generate a LaTeX table comparing ablation results."""
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Ablation Study Results}",
        r"\label{tab:ablation-results}",
        r"\begin{tabular}{lcccccc}",
        r"\toprule",
        r"Experiment & Success & Autonomy & Findings & Quality & Errors & Duration \\",
        r" & Rate & Rate & Count & Score & Rate & (s) \\",
        r"\midrule",
    ]

    for m in results:
        lines.append(
            f"{m.experiment} & "
            f"{m.success_rate:.1%} & "
            f"{m.autonomy_rate:.1%} & "
            f"{m.total_findings} & "
            f"{m.finding_quality_score:.0f} & "
            f"{m.error_rate:.1%} & "
            f"{m.total_duration_seconds:.0f} \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])

    return "\n".join(lines)


async def run_ablation(target_name: str) -> list[BenchmarkMetrics]:
    """Run all ablation experiments against a single target."""
    targets = load_targets()
    if target_name not in targets:
        raise ValueError(f"Target '{target_name}' not found in targets.yaml")

    target = targets[target_name]
    url = target["url"]
    expected = target.get("expected_vulns", [])

    all_metrics = []

    for exp in ABLATION_EXPERIMENTS:
        logger.info(f"\n{'='*60}")
        logger.info(f"ABLATION: {exp} against {target_name}")
        logger.info(f"{'='*60}")

        try:
            experiment_name = exp if exp != "default" else None
            metrics = await run_benchmark(
                target_name=target_name,
                target_url=url,
                expected_vulns=expected,
                experiment=experiment_name,
            )
            all_metrics.append(metrics)
        except Exception as e:
            logger.error(f"Ablation experiment '{exp}' failed: {e}")
            # Add a placeholder with zero metrics
            all_metrics.append(BenchmarkMetrics(
                target_name=target_name,
                experiment=exp,
            ))

    # Save results
    save_results(all_metrics)

    # Generate LaTeX table
    RESULTS_DIR.mkdir(exist_ok=True)
    latex = generate_latex_table(all_metrics)
    latex_path = RESULTS_DIR / f"ablation_{target_name}_{time.strftime('%Y%m%d')}.tex"
    latex_path.write_text(latex)
    logger.info(f"LaTeX table saved to {latex_path}")

    # Print summary
    print(f"\n{'Experiment':<20} {'Success':>8} {'Findings':>9} {'Quality':>8} {'Errors':>7}")
    print("-" * 55)
    for m in all_metrics:
        print(
            f"{m.experiment:<20} {m.success_rate:>7.1%} {m.total_findings:>9} "
            f"{m.finding_quality_score:>8.0f} {m.error_rate:>6.1%}"
        )

    return all_metrics


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SwarmAttacker Ablation Study")
    parser.add_argument("--target", required=True, help="Target name from targets.yaml")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    asyncio.run(run_ablation(args.target))


if __name__ == "__main__":
    main()
