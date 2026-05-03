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
    python -m benchmarks.xbow_runner --daily --resume
    python -m benchmarks.xbow_runner --list-file benchmarks/daily_15_buildable.txt
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import subprocess
import sys
import time
from pathlib import Path

from langchain_core.messages import HumanMessage

from src.graph import build_graph, config
from src.observability import (
    LIVE,
    HttpxQuietFilter,
    make_run_id,
    run_dir,
    write_final_state,
    write_summary,
)

try:
    from src.tools.terminal import set_log_file as _set_terminal_log_file
except ImportError:
    def _set_terminal_log_file(path: Path) -> Path:
        logger.warning(
            "src.tools.terminal.set_log_file is unavailable; "
            "terminal_events.jsonl will not be written to %s",
            path,
        )
        return path

logger = logging.getLogger(__name__)

XBOW_ROOT = Path(__file__).resolve().parents[2] / "Benchmarks" / "xbow-validation"
RESULTS_DIR = Path(__file__).parent / "results"
DAILY_LIST = Path(__file__).parent / "daily_15.txt"

# Per-phase timeouts. Bound everything so an overnight --daily run can't
# stall on a single rotten benchmark (slow mirror, dead apt repo, hung
# pip resolver). On timeout the subprocess is killed and the finally
# clause still runs `docker compose down`.
#
# These are infrastructure timeouts, not agent budgets — they belong
# here next to the runner code, not in src/graph.py:Budgets.
BUILD_TIMEOUT_S = 1500      # 25 min: image pulls + apt + pip (first build is slow)
UP_TIMEOUT_S = 180          # 3 min: `docker compose up --wait` + healthcheck
DOWN_TIMEOUT_S = 90         # 1.5 min: cleanup
DISCOVER_TIMEOUT_S = 30     # 30 s: `docker compose ps`
RUN_TIMEOUT_S = 15 * 60     # 15 min: per-bench wall-clock leash on graph.ainvoke


def docker_is_available() -> tuple[bool, str]:
    """Return whether Docker is installed and the daemon is reachable."""
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        return False, "docker command not found"
    except subprocess.TimeoutExpired:
        return False, "docker info timed out after 15s"

    if proc.returncode == 0:
        return True, ""
    detail = (proc.stderr or proc.stdout).strip()
    return False, detail or f"docker info failed with rc={proc.returncode}"


def expected_flag(benchmark_id: str) -> str:
    """Replicates common.mk: FLAG{sha256(BENCHMARK_UPPER)}."""
    digest = hashlib.sha256(benchmark_id.upper().encode()).hexdigest()
    return f"FLAG{{{digest}}}"


def _run(
    cmd: list[str],
    cwd: Path,
    *,
    timeout: float | None,
    capture: bool = False,
    check: bool = True,
):
    """Run a subprocess with a hard timeout. On timeout the child is killed
    and a CalledProcessError-shaped TimeoutExpired propagates so the caller
    can decide whether to retry or move on."""
    if config.verbosity.mode == "verbose":
        logger.info("$ %s  (cwd=%s, timeout=%s)", " ".join(cmd), cwd, timeout)
    return subprocess.run(
        cmd, cwd=cwd, check=check,
        capture_output=capture, text=capture,
        timeout=timeout,
    )


def _docker_phase(
    cmd: list[str],
    cwd: Path,
    *,
    bench_id: str,
    phase: str,
    timeout: float | None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run a docker/make subprocess that produces verbose lifecycle output.

    Always captures stdout+stderr. In ``verbose`` mode the captured stream
    is replayed verbatim to stderr (preserving today's behavior). In
    ``compact``/``silent`` mode the stream is swallowed and a single
    one-line ``▸ docker <bench> <phase> (Xs)`` summary is emitted via
    :data:`LIVE`. Errors always surface regardless of mode.

    Raises :class:`subprocess.CalledProcessError` on non-zero exit when
    ``check`` is True, mirroring ``subprocess.run(check=True)``.
    """
    started = time.time()
    proc = subprocess.run(
        cmd, cwd=cwd, check=False,
        capture_output=True, text=True, timeout=timeout,
    )
    duration = time.time() - started

    if config.verbosity.mode == "verbose":
        if proc.stdout:
            sys.stderr.write(proc.stdout)
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        sys.stderr.flush()

    if proc.returncode != 0:
        last = ""
        for stream in (proc.stderr, proc.stdout):
            if stream and stream.strip():
                last = stream.strip().splitlines()[-1]
                break
        LIVE.runner_message(
            f"{bench_id} {phase} failed (rc={proc.returncode}): {last}",
            level="error",
        )
        if check:
            raise subprocess.CalledProcessError(
                proc.returncode, cmd, proc.stdout, proc.stderr,
            )
        return proc

    LIVE.docker_phase(bench_id, phase, duration)
    return proc


def make_build(benchmark_id: str) -> None:
    _docker_phase(
        ["make", f"BENCHMARK={benchmark_id}", "build"],
        cwd=XBOW_ROOT, bench_id=benchmark_id,
        phase="build", timeout=BUILD_TIMEOUT_S,
    )


def make_run(benchmark_id: str) -> None:
    _docker_phase(
        ["make", f"BENCHMARK={benchmark_id}", "run"],
        cwd=XBOW_ROOT, bench_id=benchmark_id,
        phase="up", timeout=UP_TIMEOUT_S,
    )


def docker_down(benchmark_id: str) -> None:
    bench_dir = XBOW_ROOT / "benchmarks" / benchmark_id
    _docker_phase(
        ["docker", "compose", "down", "--remove-orphans"],
        cwd=bench_dir, bench_id=benchmark_id,
        phase="down", timeout=DOWN_TIMEOUT_S, check=False,
    )


def discover_target_url(benchmark_id: str) -> str:
    """Return http://localhost:<port> for the first published port."""
    bench_dir = XBOW_ROOT / "benchmarks" / benchmark_id
    out = _run(["docker", "compose", "ps", "--format", "json"],
               cwd=bench_dir, timeout=DISCOVER_TIMEOUT_S, capture=True).stdout

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
    # Pin run_id and log dir BEFORE any graph activity so every
    # BaseNode call and every terminal-tool call lands in the same
    # per-run folder.
    run_id = make_run_id(benchmark_id=benchmark_id)
    rdir = run_dir(run_id)
    _set_terminal_log_file(rdir / "terminal_events.jsonl")

    result: dict = {
        "benchmark_id": benchmark_id,
        "run_id": run_id,
        "run_dir": str(rdir),
        "expected_flag": flag,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "flag_found": False,
        "findings_count": 0,
        "duration_s": None,
        "target_url": None,
        "error": None,
    }
    agent_state: dict = {}

    try:
        if not skip_build:
            make_build(benchmark_id)
        make_run(benchmark_id)
        result["target_url"] = discover_target_url(benchmark_id)
        # Show the start-of-run boundary now that target_url is known.
        LIVE.bench_start(benchmark_id, result["target_url"], flag)
        logger.info("[%s] target=%s expected_flag=%s run_dir=%s",
                    benchmark_id, result["target_url"], flag, rdir)

        graph = build_graph()
        agent_state = await asyncio.wait_for(
            graph.ainvoke({
                "run_id": run_id,
                "target_url": result["target_url"],
                "target_scope": result["target_url"],
                "messages": [
                    HumanMessage(
                        content=(
                            "Authorized benchmark run. Test the target at "
                            f"{result['target_url']} and capture the expected "
                            "FLAG value if you can reach it."
                        )
                    )
                ],
                "findings": [],
                "agent_results": [],
                "active_agents": [],
                # Benchmark-mode signal — workers and the planner read this
                # to know the run has an explicit flag-extraction success
                # criterion. Empty string in non-benchmark contexts.
                "expected_flag": flag or "",
            }),
            timeout=RUN_TIMEOUT_S,
        )

        # Search only worker output for the flag — NOT the full state.
        # The graph state now contains an `expected_flag` field (so the
        # planner and workers can read it for benchmark-mode prompts);
        # if we serialized the full state, that field would self-match
        # and report every run as a successful flag capture.
        flag_search_state = {
            k: v for k, v in agent_state.items() if k != "expected_flag"
        }
        haystack = json.dumps(flag_search_state, default=str)
        result["flag_found"] = bool(flag) and flag in haystack
        result["findings_count"] = len(agent_state.get("findings") or [])

    except asyncio.TimeoutError:
        result["error"] = f"agent timeout after {RUN_TIMEOUT_S}s"
        logger.error("[%s] %s", benchmark_id, result["error"])
    except subprocess.TimeoutExpired as e:
        # build / up / down / ps hung past its phase timeout
        phase = "unknown"
        cmd0 = (e.cmd or [None])[0]
        if cmd0 == "make":
            phase = "build" if "build" in (e.cmd or []) else "up"
        elif cmd0 == "docker":
            phase = "down" if "down" in (e.cmd or []) else "ps"
        result["error"] = f"phase '{phase}' timeout after {e.timeout}s"
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

        # Persist run artifacts even on partial failures — final_state may
        # be empty, summary will still be informative about where it died.
        try:
            write_final_state(run_id, agent_state)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] write_final_state failed", benchmark_id)
        try:
            write_summary(
                run_id,
                benchmark_id=benchmark_id,
                target_url=result["target_url"],
                expected_flag=flag,
                flag_found=result["flag_found"] if not result["error"] else None,
                duration_s=result["duration_s"],
                error=result["error"],
                final_state=agent_state,
            )
        except Exception:  # noqa: BLE001
            logger.exception("[%s] write_summary failed", benchmark_id)

    return result


def write_jsonl(result: dict) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / f"xbow_{time.strftime('%Y%m%d')}.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(result) + "\n")
    return path


def load_recorded_ids(*, skip_errors: bool = False) -> set[str]:
    """Return benchmark IDs already present in results JSONL files.

    Used by overnight runs: if the terminal dies or the machine restarts,
    rerun with ``--resume`` and it will continue with the missing IDs.
    By default every recorded row counts as done, including errors, because
    errors are also useful data for day-to-day benchmark tracking.
    """
    ids: set[str] = set()
    if not RESULTS_DIR.exists():
        return ids

    for path in sorted(RESULTS_DIR.glob("xbow_*.jsonl")):
        for raw in path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if skip_errors and row.get("error"):
                continue
            benchmark_id = row.get("benchmark_id")
            if benchmark_id:
                ids.add(benchmark_id)
    return ids


def load_daily_list() -> list[str]:
    return load_list_file(DAILY_LIST)


def load_list_file(path: Path) -> list[str]:
    """Load benchmark IDs from a text file, stripping comments."""
    if not path.exists():
        raise FileNotFoundError(f"missing {path}")
    ids: list[str] = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            ids.append(line)
    return ids


async def main_async(args) -> int:
    ok, docker_error = docker_is_available()
    if not ok:
        LIVE.runner_message(
            "Docker is not available, so XBOW benchmarks cannot start.\n"
            f"{docker_error}\n\n"
            "Start Docker Desktop, wait until `docker info` succeeds, then rerun:\n"
            "  bash benchmarks/run_xbow_daily.sh --resume --retry-errors",
            level="error",
        )
        return 3

    if args.daily:
        ids = load_daily_list()
    elif args.list_file:
        ids = load_list_file(args.list_file)
    elif args.bench:
        ids = [args.bench]
    else:
        LIVE.runner_message("specify --bench <id> or --daily", level="error")
        return 2

    if args.resume:
        done = load_recorded_ids(skip_errors=args.retry_errors)
        original_count = len(ids)
        ids = [bid for bid in ids if bid not in done]
        skipped = original_count - len(ids)
        LIVE.runner_message(
            f"resume enabled: skipping {skipped} recorded benchmark(s), "
            f"{len(ids)} remaining"
        )

    LIVE.runner_message(f"running {len(ids)} benchmark(s)")
    summary = {"pass": 0, "fail": 0, "error": 0}

    for bid in ids:
        r = await run_one(bid, skip_build=args.skip_build)
        path = write_jsonl(r)

        if r["error"]:
            summary["error"] += 1
        elif r["flag_found"]:
            summary["pass"] += 1
        else:
            summary["fail"] += 1

        LIVE.bench_end(
            bid,
            ok=bool(r["flag_found"]),
            duration_s=float(r["duration_s"] or 0.0),
            findings_n=int(r["findings_count"] or 0),
            summary_path=f"{r['run_dir']}/summary.md",
            error=r["error"],
        )
        LIVE.runner_message(f"           jsonl   → {path}")

    LIVE.runner_message(
        f"Summary: {summary['pass']} pass, {summary['fail']} fail, "
        f"{summary['error']} error / {len(ids)} total"
    )
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="SwarmAttacker XBOW benchmark runner")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--bench", help="single benchmark id, e.g. XBEN-001-24")
    g.add_argument("--daily", action="store_true",
                   help="run the daily-15 list (benchmarks/daily_15.txt)")
    g.add_argument("--list-file", type=Path,
                   help="run benchmark IDs from a custom text file")
    ap.add_argument("--skip-build", action="store_true",
                    help="skip 'make build' (use already-built images)")
    ap.add_argument("--resume", action="store_true",
                    help="skip benchmark IDs already present in results/xbow_*.jsonl")
    ap.add_argument("--retry-errors", action="store_true",
                    help="with --resume, retry IDs whose previous row had an error")
    verbosity = ap.add_mutually_exclusive_group()
    verbosity.add_argument(
        "--verbose", "-v", action="store_true",
        help="stream every tool call, output, and node transition "
             "live to stderr (the old SWARM_VERBOSE=1 behavior)",
    )
    verbosity.add_argument(
        "--silent", action="store_true",
        help="only show benchmark boundaries and the final verdict; "
             "useful for overnight sweeps",
    )
    args = ap.parse_args()

    # Mutate the live config singleton based on CLI flags. The renderer
    # reads config.verbosity.mode lazily on every call, so flipping the
    # field here is sufficient — no env-var dance required.
    if args.verbose:
        config.verbosity.mode = "verbose"
    elif args.silent:
        config.verbosity.mode = "silent"

    # In compact/silent mode the LIVE renderer is the primary stream, so
    # raise the global level to WARNING — INFO lines like
    # ``node.planner: Supervisor turn 1 → ...`` and
    # ``src.llm.provider: LLM provider initialized ...`` would just
    # duplicate what LIVE already shows in colored form. WARNING and
    # above (refusals, retries, real errors) still flow through.
    log_level = logging.INFO if config.verbosity.mode == "verbose" else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Silence httpx INFO ("HTTP Request: POST chatgpt.com/...") unless the
    # operator explicitly opted in via SWARM_LIVE_HTTP=1. Disk logs are
    # unaffected; we don't write a separate httpx log file.
    if not config.verbosity.show_http:
        for log_name in ("httpx", "httpcore", "openai", "anthropic"):
            logging.getLogger(log_name).addFilter(HttpxQuietFilter())

    raise SystemExit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
