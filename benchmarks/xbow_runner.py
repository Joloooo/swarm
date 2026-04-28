"""Run SwarmAttacker against XBOW validation-benchmarks.

Lifecycle per benchmark:
    1. make build     (cached after first run; skip with --skip-build)
    2. make run       (docker compose up --wait)
    3. discover host port via `docker compose ps --format json`
    4. invoke graph against http://localhost:<port>
    5. check whether the expected flag string appears anywhere in the
       agent's final state (messages + findings)
    6. docker compose down  (stop AND remove, frees ports for next run)
    7. append a JSONL line to results/xbow_<date>.jsonl

Usage:
    python -m benchmarks.xbow_runner --bench XBEN-001-24
    python -m benchmarks.xbow_runner --daily
    python -m benchmarks.xbow_runner --daily --skip-build
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import subprocess
import time
from pathlib import Path

from src.graph import build_graph

logger = logging.getLogger(__name__)

XBOW_ROOT = Path(__file__).resolve().parents[2] / "Benchmarks" / "xbow-validation"
RESULTS_DIR = Path(__file__).parent / "results"
DAILY_LIST = Path(__file__).parent / "daily_15.txt"
RUN_TIMEOUT_S = 15 * 60


def expected_flag(benchmark_id: str) -> str:
    """Replicates common.mk: FLAG{sha256(BENCHMARK_UPPER)}."""
    digest = hashlib.sha256(benchmark_id.upper().encode()).hexdigest()
    return f"FLAG{{{digest}}}"


def _run(cmd: list[str], cwd: Path, *, capture: bool = False, check: bool = True):
    logger.info("$ %s  (cwd=%s)", " ".join(cmd), cwd)
    return subprocess.run(
        cmd, cwd=cwd, check=check,
        capture_output=capture, text=capture,
    )


def make_target(benchmark_id: str, target: str) -> None:
    _run(["make", f"BENCHMARK={benchmark_id}", target], cwd=XBOW_ROOT)


def docker_down(benchmark_id: str) -> None:
    bench_dir = XBOW_ROOT / "benchmarks" / benchmark_id
    _run(["docker", "compose", "down", "--remove-orphans"],
         cwd=bench_dir, check=False)


def discover_target_url(benchmark_id: str) -> str:
    """Return http://localhost:<port> for the first published port."""
    bench_dir = XBOW_ROOT / "benchmarks" / benchmark_id
    out = _run(["docker", "compose", "ps", "--format", "json"],
               cwd=bench_dir, capture=True).stdout

    services: list[dict] = []
    stripped = out.strip()
    if stripped.startswith("["):
        services = json.loads(stripped)
    else:
        for line in stripped.splitlines():
            if line.strip():
                services.append(json.loads(line))

    for svc in services:
        for pub in svc.get("Publishers") or []:
            port = pub.get("PublishedPort")
            if port:
                return f"http://localhost:{port}"
    raise RuntimeError(
        f"no published port found for {benchmark_id}; services={services!r}"
    )


async def run_one(benchmark_id: str, *, skip_build: bool = False) -> dict:
    flag = expected_flag(benchmark_id)
    started = time.time()
    result: dict = {
        "benchmark_id": benchmark_id,
        "expected_flag": flag,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "flag_found": False,
        "findings_count": 0,
        "duration_s": None,
        "target_url": None,
        "error": None,
    }

    try:
        if not skip_build:
            make_target(benchmark_id, "build")
        make_target(benchmark_id, "run")
        result["target_url"] = discover_target_url(benchmark_id)
        logger.info("[%s] target=%s expected_flag=%s",
                    benchmark_id, result["target_url"], flag)

        graph = build_graph()
        agent_state = await asyncio.wait_for(
            graph.ainvoke({
                "target_url": result["target_url"],
                "target_scope": result["target_url"],
                "messages": [],
                "findings": [],
                "agent_results": [],
                "active_agents": [],
            }),
            timeout=RUN_TIMEOUT_S,
        )

        haystack = json.dumps(agent_state, default=str)
        result["flag_found"] = flag in haystack
        result["findings_count"] = len(agent_state.get("findings") or [])

    except asyncio.TimeoutError:
        result["error"] = f"timeout after {RUN_TIMEOUT_S}s"
        logger.error("[%s] %s", benchmark_id, result["error"])
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
        logger.exception("[%s] failed", benchmark_id)
    finally:
        try:
            docker_down(benchmark_id)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] docker compose down failed", benchmark_id)
        result["duration_s"] = round(time.time() - started, 1)

    return result


def write_jsonl(result: dict) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / f"xbow_{time.strftime('%Y%m%d')}.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(result) + "\n")
    return path


def load_daily_list() -> list[str]:
    if not DAILY_LIST.exists():
        raise FileNotFoundError(f"missing {DAILY_LIST}")
    ids: list[str] = []
    for raw in DAILY_LIST.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            ids.append(line)
    return ids


async def main_async(args) -> int:
    if args.daily:
        ids = load_daily_list()
    elif args.bench:
        ids = [args.bench]
    else:
        print("specify --bench <id> or --daily", flush=True)
        return 2

    print(f"running {len(ids)} benchmark(s)", flush=True)
    summary = {"pass": 0, "fail": 0, "error": 0}

    for bid in ids:
        print(f"\n=== {bid} ===", flush=True)
        r = await run_one(bid, skip_build=args.skip_build)
        path = write_jsonl(r)

        if r["error"]:
            verdict = f"⚠ ERROR: {r['error']}"
            summary["error"] += 1
        elif r["flag_found"]:
            verdict = "✓ FLAG FOUND"
            summary["pass"] += 1
        else:
            verdict = "✗ no flag"
            summary["fail"] += 1

        print(
            f"  {verdict}  ({r['duration_s']}s, "
            f"{r['findings_count']} findings) → {path}",
            flush=True,
        )

    print(
        f"\nSummary: {summary['pass']} pass, {summary['fail']} fail, "
        f"{summary['error']} error / {len(ids)} total",
        flush=True,
    )
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="SwarmAttacker XBOW benchmark runner")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--bench", help="single benchmark id, e.g. XBEN-001-24")
    g.add_argument("--daily", action="store_true",
                   help="run the daily-15 list (benchmarks/daily_15.txt)")
    ap.add_argument("--skip-build", action="store_true",
                    help="skip 'make build' (use already-built images)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    raise SystemExit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
