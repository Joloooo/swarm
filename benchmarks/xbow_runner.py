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
import functools
import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
from contextlib import AsyncExitStack
from pathlib import Path

from langchain_core.messages import HumanMessage

from benchmarks import loopback
from src.cli import bench_results
from src.graph import GRAPH_RECURSION_LIMIT, build_graph, config
from src.nodes.base.flag_watcher import (
    get_captured_flag,
    is_captured,
    reset_captured,
)
from src.llm.hibernation import (
    enable_hibernation,
    paused_seconds,
    reset_hibernation,
)
from src.llm.rate_limit_signal import (
    get_rate_limit_error,
    is_rate_limited,
    reset_rate_limited,
)
from src.observability import (
    LIVE,
    HttpxQuietFilter,
    LOGS_ROOT,
    LiveLogHandler,
    install_jsonl_log_handler,
    make_run_id,
    run_dir,
    set_sweep_log_file,
    set_terminal_log_file,
    terminal_log_path,
)

logger = logging.getLogger(__name__)

# Map the shared run verdict (src.benchmark_verdict) onto the sweep tally
# buckets: flag → pass, genuine failure → fail, codex/infra crash → crash.
_SUMMARY_KEY = {
    bench_results.OK: "pass",
    bench_results.FAIL: "fail",
    bench_results.API: "crash",
}

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
# Per-benchmark agent wall-clock leash. Config/TUI-driven: edit
# swarm-config.toml [budgets] run_timeout_s (or `swarm` -> Edit config);
# 1200 = 20 min, 2400 = 40 min. SWARM_RUN_TIMEOUT_S still overrides for a
# one-off CLI run (the env override is applied in src/graph.py's config).
RUN_TIMEOUT_S = config.budgets.run_timeout_s


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
    """Replicates common.mk: FLAG{sha256(BENCHMARK_UPPER)}.

    This is the PREDICTED flag based on the XBow convention — what the
    image should contain if it was built following ``common.mk``. The
    actual baked value can disagree (manual ``--build-arg FLAG=...``
    overrides, docker-compose ``.env`` autoload winning over the
    Makefile-exported ``FLAG``, older common.mk versions, Docker prune
    re-tagging older images) — in those cases :func:`read_served_flag`
    or :func:`read_env_flag` provide the actual value. See
    :func:`expected_flag_candidates` for the full set of values any of
    which counts as a capture.
    """
    digest = hashlib.sha256(benchmark_id.upper().encode()).hexdigest()
    return f"FLAG{{{digest}}}"


# Paths inside the running container where XBow benchmarks bake the
# flag. We've directly observed both shapes in the corpus:
#   - ``/flag`` — XBEN-001/002/003 ``Dockerfile`` (``RUN echo -n $FLAG > /flag``)
#   - ``/app/flag.txt`` — the path the runner historically tried first
# Tried in order. New benchmarks that bake elsewhere should be added
# here as we encounter them — silent miss here means the runner falls
# back to the sha256 prediction, which is wrong for any benchmark
# whose container holds the .env UUID instead.
_SERVED_FLAG_PATHS: tuple[str, ...] = ("/flag", "/app/flag.txt")


def read_served_flag(benchmark_id: str) -> str:
    """Read the actual baked flag from inside the running container.

    Tries each path in :data:`_SERVED_FLAG_PATHS` until one succeeds.
    Returns the actual baked flag value as a string, or ``""`` if the
    container isn't running, every probed path is missing, the exec
    fails, or times out. Caller is responsible for falling back to
    other sources (:func:`read_env_flag`, :func:`expected_flag`) when
    this returns ``""`` — see :func:`expected_flag_candidates`.

    Why this exists — 2026-05-25 incident: the XBEN-006-24 image was
    built 2 weeks ago with a manual ``--build-arg FLAG=flag{<uuid>}``
    (not the common.mk sha256 formula). A fresh rebuild today produced
    a sha256-baked image, but Docker Desktop's automatic "remove
    unused images" pruned the new image during a brief idle window and
    re-tagged the older UUID-baked image as ``:latest``. The runner's
    sha256 prediction was correct by formula but didn't match the
    actually-served flag, so every valid capture was rejected by the
    strict matcher.

    Why MULTIPLE paths — 2026-05-27 incident: the watcher rejected a
    correct capture on XBEN-002 because this function read
    ``/app/flag.txt`` (returning ``""``) when the Dockerfile actually
    baked to ``/flag``. The matcher then compared the agent's real
    capture against the sha256 prediction and (correctly) said "no
    match", silently dropping a winning run. See
    ``logs/run-05-27_13h11m26s_XBEN-002/full_logs.jsonl`` line 163 —
    the flag is sitting in the bash output, never made it into state.

    Prerequisite: the container must already be running (i.e. called
    AFTER :func:`make_run`). On the first call before the container
    is up this returns ``""``, which is the expected fallback path.
    """
    bench_dir = XBOW_ROOT / "benchmarks" / benchmark_id
    if not bench_dir.is_dir():
        return ""
    for path in _SERVED_FLAG_PATHS:
        try:
            proc = subprocess.run(
                ["docker", "compose", "exec", "-T", "app",
                 "cat", path],
                cwd=bench_dir,
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                FileNotFoundError):
            continue
        value = (proc.stdout or "").strip()
        if value:
            return value
    return ""


# Match a ``FLAG=...`` (or ``FLAG="..."``) assignment in an .env file.
# The value can be unquoted, double-quoted, or single-quoted — match
# all three. Anchored to start-of-line to avoid catching things like
# ``DEFAULT_FLAG=...`` mid-file.
_ENV_FLAG_RE = re.compile(
    r'^\s*FLAG\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s#]+))',
    re.MULTILINE,
)


def read_env_flag(benchmark_id: str) -> str:
    """Read ``FLAG=...`` from ``<benchmark>/.env`` on disk.

    Returns the value docker-compose's ``.env`` autoload would inject
    into the build environment, or ``""`` if the file is missing or
    has no ``FLAG=`` line. Strips surrounding quotes.

    This is the cheapest authoritative source — no docker-exec needed,
    no container lifecycle, just a file read. For benchmarks where
    ``docker compose build`` ran directly (without ``make build``
    exporting the Makefile-computed sha256 first), this is the value
    that ends up baked into ``/flag``. Build with ``make build`` and
    the Makefile-exported ``FLAG`` wins instead — see
    :func:`expected_flag_candidates` for the full picture.
    """
    env_file = XBOW_ROOT / "benchmarks" / benchmark_id / ".env"
    if not env_file.is_file():
        return ""
    try:
        text = env_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = _ENV_FLAG_RE.search(text)
    if not m:
        return ""
    # The regex has three alternation groups; exactly one matches.
    return (m.group(1) or m.group(2) or m.group(3) or "").strip()


def expected_flag_candidates(benchmark_id: str) -> tuple[str, ...]:
    """All flag values any of which counts as a captured flag.

    XBow benchmarks have THREE potential sources of the truth flag,
    and which one ends up baked into a given image depends on the
    build path Docker Compose took:

    1. **sha256 prediction** — what ``common.mk`` computes
       (``FLAG{sha256(BENCHMARK_UPPER)}``) and passes via
       ``--build-arg`` when the build was triggered by ``make build``.
    2. **``.env`` file** — ``FLAG="flag{<uuid>}"`` auto-loaded by
       docker-compose when ``docker compose build`` ran directly
       (without the Makefile's ``FLAG`` export winning first).
    3. **Live container read** — ``cat /flag`` (or ``/app/flag.txt``)
       inside the running container is the ground truth for what
       eventually got baked, regardless of which build path ran.

    Returns a tuple with deduplicated (case-insensitive), non-empty
    candidates. The order is informative only — the matcher accepts
    case-insensitive equality against any candidate. The first
    non-empty entry is by convention the "primary" candidate used for
    display and ``state["expected_flag"]``.

    Empty tuple is impossible in practice for any well-formed XBow
    benchmark — the sha256 prediction is always derivable from the
    benchmark id alone.
    """
    sha256 = expected_flag(benchmark_id)
    env_value = read_env_flag(benchmark_id)
    served = read_served_flag(benchmark_id)

    # Preserve insertion order, dedupe case-insensitively. ``served``
    # wins primacy when available because it's the actual ground
    # truth; otherwise ``env_value`` (likeliest match for the common
    # ``docker compose build`` path); otherwise sha256.
    ordered = [c for c in (served, env_value, sha256) if c]
    seen_lc: set[str] = set()
    out: list[str] = []
    for c in ordered:
        c_lc = c.lower()
        if c_lc in seen_lc:
            continue
        seen_lc.add(c_lc)
        out.append(c)
    return tuple(out)


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


def _ports_leak_onto(ports: str, ip: str) -> bool:
    """True if a ``docker ps`` *Ports* string publishes on a host address
    that covers loopback ``ip`` — i.e. a wildcard bind (``0.0.0.0`` / ``::``,
    which answers on EVERY loopback alias) or ``ip`` itself. Such a binding
    is reachable on the address this run hands the agent."""
    return (
        "0.0.0.0:" in ports
        or ":::" in ports
        or "[::]:" in ports
        or f"{ip}:" in ports
    )


def _purge_contaminating_containers(leased_ip: str) -> None:
    """Remove running benchmark containers that would leak onto ``leased_ip``.

    A container published on a wildcard host IP (``0.0.0.0`` / ``::``) — or
    directly on ``leased_ip`` reused from an earlier run — answers on the
    very address this run hands the agent, so the agent can discover and
    "solve" that straggler instead of the freshly-launched target.
    (Observed: a leftover XBEN-096 container produced a false flag-capture
    while this run's real app sat unprobed on its leased IP.)

    A correctly-isolated run binds a SPECIFIC ``127.0.0.X``, so a
    wildcard / same-IP publish from an ``xben-*`` container is always a
    straggler from a crashed or un-torn-down prior run — safe for the
    harness, which owns these, to force-remove. Non-``xben`` containers
    are never touched, only flagged loudly so the operator knows the
    target IP may be contaminated. Best-effort: any docker error is
    swallowed (a clean-slate check must never abort a run)."""
    try:
        out = _run(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}"],
            cwd=XBOW_ROOT, timeout=DISCOVER_TIMEOUT_S, capture=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        cid, name, ports = parts[0], parts[1], parts[2]
        if not _ports_leak_onto(ports, leased_ip):
            continue
        if "xben" in name.lower():
            try:
                _run(["docker", "rm", "-f", cid], cwd=XBOW_ROOT,
                     timeout=DISCOVER_TIMEOUT_S, check=False)
            except (OSError, subprocess.SubprocessError):
                continue
            LIVE.runner_message(
                f"clean-slate: removed stale benchmark container {name} "
                f"({ports}) that would leak onto the target IP {leased_ip}",
                level="warn",
            )
        else:
            LIVE.runner_message(
                f"clean-slate: container {name} publishes on {ports} and may "
                f"leak onto the target IP {leased_ip} — left running (not an "
                "xben container); results on this IP may be contaminated",
                level="warn",
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


_OVERRIDE_NAME = "docker-compose.override.yml"


def _override_path(benchmark_id: str) -> Path:
    return XBOW_ROOT / "benchmarks" / benchmark_id / _OVERRIDE_NAME


def _published_target_ports(benchmark_id: str) -> dict[str, list[int]]:
    """``{service: [container_port, ...]}`` for every HOST-published port,
    read from the compose config. ``expose``-only (internal) ports such as a
    backing DB are excluded — we only rebind ports the benchmark actually
    publishes to the host."""
    bench_dir = XBOW_ROOT / "benchmarks" / benchmark_id
    out = _run(
        ["docker", "compose", "config", "--format", "json"],
        cwd=bench_dir, timeout=DISCOVER_TIMEOUT_S, capture=True,
    ).stdout
    cfg = json.loads(out)
    svc_ports: dict[str, list[int]] = {}
    for name, svc in (cfg.get("services") or {}).items():
        targets = [int(p["target"]) for p in (svc.get("ports") or []) if p.get("target")]
        if targets:
            svc_ports[name] = targets
    return svc_ports


# Fallback host ports for a benchmark whose REAL port is held by a
# host-wide wildcard service (macOS AirPlay Receiver squats *:5000 and
# *:7000, reserving those ports on EVERY loopback IP). All kept BELOW
# 10000 on purpose: the agent finds its target by scanning, and a normal
# recon sweep covers 1-10000 — a high fallback like 15000 lands outside
# that range and the app becomes undiscoverable (exactly how XBEN-020's
# app, remapped to 10080, was never found). 20 candidates give ample room
# to find a free one even when several are already occupied.
_REMAP_POOL: tuple[int, ...] = tuple(range(9001, 9021))  # 9001..9020


def _bindable(ip: str, port: int) -> bool:
    """True if a TCP socket can bind ``ip:port`` right now (i.e. it's free)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _free_host_port(ip: str, preferred: int, *, taken=frozenset()) -> int:
    """Choose the host port to publish container port ``preferred`` on for
    this VM's IP ``ip``.

    Privileged ports (<1024, e.g. 80 / 22) are returned UNCHANGED. A
    non-root process cannot bind them, so a probe here is meaningless —
    but Docker Desktop's publisher CAN bind them, so we keep the REAL
    port. (Probing them used to fail with ``PermissionError`` and get
    misread as "busy", remapping 80 -> 10080 and hiding the app on a high
    port — that's the bug this avoids.) If a privileged port is genuinely
    occupied, ``docker compose up`` surfaces the bind error.

    Non-privileged ports are probed with a real bind. ``preferred`` is
    kept when free (realistic). When it's held by a wildcard squatter
    (AirPlay on 5000 / 7000) we fall back to the first free port in
    :data:`_REMAP_POOL` — all BELOW 10000 so recon's port scan still
    finds it. ``taken`` excludes host ports already assigned to sibling
    services in the same benchmark so two squatted ports don't collide on
    one fallback."""
    if preferred < 1024:
        return preferred
    if preferred not in taken and _bindable(ip, preferred):
        return preferred
    for cand in _REMAP_POOL:
        if cand not in taken and _bindable(ip, cand):
            return cand
    return preferred  # pool exhausted; let `up` surface the conflict


def _write_port_override(benchmark_id: str, ip: str) -> Path | None:
    """Pin every host-published port of the benchmark to ``ip`` at its real
    number via a generated ``docker-compose.override.yml`` (auto-merged by
    ``docker compose``). The ``!override`` tag REPLACES the benchmark's default
    random/``0.0.0.0`` publish rather than adding to it — otherwise the
    ``0.0.0.0`` bind would leak the port onto every loopback IP and break
    isolation. Returns the override path, or ``None`` if there is nothing to
    bind or two services collide on one container port (caller then falls back
    to the legacy localhost mapping)."""
    # A stale override from a hard-killed prior run would pollute both the
    # config read below and the merge at `up` — clear it first.
    _override_path(benchmark_id).unlink(missing_ok=True)
    svc_ports = _published_target_ports(benchmark_id)
    if not svc_ports:
        return None
    seen: set[int] = set()
    for ports in svc_ports.values():
        for t in ports:
            if t in seen:
                LIVE.runner_message(
                    f"{benchmark_id}: duplicate published port {t} across "
                    "services — using legacy localhost mapping",
                    level="warn",
                )
                return None
            seen.add(t)
    lines = [
        "# generated per-run by xbow_runner — pins this benchmark's ports to",
        f"# this VM's own loopback IP ({ip}) so the agent scans an isolated",
        "# target with the REAL ports. Removed on teardown.",
        "services:",
    ]
    used_host_ports: set[int] = set()
    for name, ports in svc_ports.items():
        lines.append(f"  {name}:")
        lines.append("    ports: !override")
        for t in ports:
            h = _free_host_port(ip, t, taken=used_host_ports)
            used_host_ports.add(h)
            if h != t:
                LIVE.runner_message(
                    f"{benchmark_id}: host port {t} held by a wildcard service "
                    f"(e.g. macOS AirPlay on 5000/7000) — publishing container "
                    f":{t} on {ip}:{h}",
                    level="warn",
                )
            lines.append(f'      - "{ip}:{h}:{t}"')
    path = _override_path(benchmark_id)
    path.write_text("\n".join(lines) + "\n")
    return path


def _override_host_map(benchmark_id: str) -> dict[int, int]:
    """Parse the generated override into ``{container_port: host_port}``.
    Empty when there is no override (legacy localhost mapping)."""
    try:
        txt = _override_path(benchmark_id).read_text()
    except OSError:
        return {}
    return {
        int(c): int(h)
        for _ip, h, c in re.findall(r'"(\d+\.\d+\.\d+\.\d+):(\d+):(\d+)"', txt)
    }


# Container ports that speak HTTP(S), best-first, for choosing the URL we
# hand the agent as the starting point. SSH (22) and other non-web ports
# are excluded as the PRIMARY target; the agent can still discover them by
# scanning the standard range once it knows where it is.
_WEB_PORT_PREFERENCE = (80, 443, 8080, 8000, 8081, 5000, 5003, 3000, 4567, 8002, 8333)


def _primary_target_url(ip: str, host_map: dict[int, int]) -> str:
    """Build the exact URL the agent is handed: the VM IP + the HOST port
    the primary web service is actually published on.

    Telling the agent precisely where the app lives mirrors a real
    engagement (you are given scope, not asked to find the app "at all
    costs") and removes the failure mode where a remapped port hid the app
    from the agent's scan. The port is omitted when it is the scheme
    default (80 / 443). Falls back to bare ``http://ip`` if the map is
    empty."""
    web = {c: h for c, h in host_map.items() if c != 22} or dict(host_map)
    if not web:
        return f"http://{ip}"
    container = next((p for p in _WEB_PORT_PREFERENCE if p in web), min(web))
    host = web[container]
    scheme = "https" if container == 443 else "http"
    if (scheme == "http" and host == 80) or (scheme == "https" and host == 443):
        return f"{scheme}://{ip}"
    return f"{scheme}://{ip}:{host}"


@functools.lru_cache(maxsize=1)
def _bridge_routable() -> bool:
    """True when a container's OWN docker-network IP is reachable from the host.

    When true, the agent is pointed at the container's bridge IP, so it scans
    only that container's network namespace — the host's own ``0.0.0.0``
    services (AirPlay ``rapportd``, Logitech, a local LLM server, …) never
    appear on the target, which a shared-localhost mapping cannot prevent.

    - Always true on Linux (the host shares routes to the docker bridge).
    - On macOS the docker bridge lives inside the Docker Desktop VM and is NOT
      routable by default; a helper such as ``docker-mac-net-connect`` adds a
      route to the docker subnets (172.x) over a ``utun`` interface. We detect
      that route; absent it we fall back to the per-VM loopback-alias mapping.
    - ``SWARM_BRIDGE_ROUTABLE=1|0`` forces the answer (escape hatch if route
      auto-detection is wrong on a given host).

    Cached: the answer cannot change within one run process.
    """
    forced = os.environ.get("SWARM_BRIDGE_ROUTABLE")
    if forced is not None:
        return forced.strip().lower() in ("1", "true", "yes", "on")
    if sys.platform != "darwin":
        return True
    try:
        rg = subprocess.run(
            ["route", "-n", "get", "172.17.0.1"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        if "utun" in rg:
            return True
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        ns = subprocess.run(
            ["netstat", "-rn", "-f", "inet"],
            capture_output=True, text=True, timeout=4,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(re.search(r"^172[\d.]*\S*\s.*utun", ns, re.M))


def _tcp_reachable(ip: str, port: int, timeout: float = 2.0) -> bool:
    """True if a TCP connection to ``ip:port`` succeeds within ``timeout``."""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _container_ip(container: str) -> str | None:
    """The first docker-network IP of ``container`` (its address inside the
    bridge), or None. ``docker inspect`` is the source of truth."""
    try:
        out = _run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
             container],
            cwd=XBOW_ROOT, timeout=DISCOVER_TIMEOUT_S, capture=True, check=False,
        ).stdout
    except Exception:  # noqa: BLE001 — discovery must never break a run
        return None
    for tok in out.split():
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tok.strip()):
            return tok.strip()
    return None


def _web_container_port(benchmark_id: str) -> int | None:
    """The benchmark's primary web port (container-internal), chosen the same
    way :func:`_primary_target_url` picks one — preferring real web ports over
    SSH (22), smallest otherwise."""
    try:
        svc_ports = _published_target_ports(benchmark_id)
    except Exception:  # noqa: BLE001
        return None
    all_ports = [p for ports in svc_ports.values() for p in ports]
    web = [p for p in all_ports if p != 22] or all_ports
    if not web:
        return None
    return next((p for p in _WEB_PORT_PREFERENCE if p in web), min(web))


def _container_bridge_target(benchmark_id: str) -> str | None:
    """``http://<container-bridge-ip>:<web-port>`` when the benchmark's web
    container is reachable on its own docker-network IP, else None (caller then
    falls back to the loopback alias / localhost). Picks the container that
    actually answers on the web port, so a backing DB sidecar is skipped."""
    port = _web_container_port(benchmark_id)
    if not port:
        return None
    bench_dir = XBOW_ROOT / "benchmarks" / benchmark_id
    try:
        out = _run(["docker", "compose", "ps", "--format", "json"],
                   cwd=bench_dir, timeout=DISCOVER_TIMEOUT_S,
                   capture=True, check=False).stdout
    except Exception:  # noqa: BLE001
        return None
    stripped = out.strip()
    try:
        services = (
            json.loads(stripped) if stripped.startswith("[")
            else [json.loads(line) for line in stripped.splitlines() if line.strip()]
        )
    except json.JSONDecodeError:
        return None
    for svc in services:
        name = svc.get("Name") or svc.get("ID")
        if not name:
            continue
        ip = _container_ip(name)
        if ip and _tcp_reachable(ip, port):
            return f"http://{ip}:{port}"
    return None


# Canonical severity order — drives the ordering of the breakdown shown in
# the end-of-bench line and stored in summary.json. Matches Severity in
# src/state.py (critical → info).
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _findings_breakdown(findings: list) -> dict[str, int]:
    """Count findings per severity, ordered critical→info, omitting zeros.

    ``Finding.severity`` is a ``Severity`` str-enum (see src/state.py); we
    read ``.value`` and fall back to the raw value / ``"info"`` so a
    malformed finding can never break the tally. Returns an insertion-
    ordered dict so callers can render ``"1 high, 2 medium"`` directly.
    """
    counts: dict[str, int] = {}
    for f in findings or []:
        sev = getattr(f, "severity", None)
        val = getattr(sev, "value", sev)
        key = str(val or "info").lower()
        counts[key] = counts.get(key, 0) + 1
    ordered = {s: counts[s] for s in _SEVERITY_ORDER if s in counts}
    # Surface any non-canonical severity strings too, after the known ones.
    for s in counts:
        if s not in ordered:
            ordered[s] = counts[s]
    return ordered


def _record_findings(result: dict, agent_state: dict) -> None:
    """Populate ``findings_count`` + ``findings_by_severity`` on ``result``
    from a graph-state snapshot.

    Called on the normal completion path AND in the timeout / crash
    handlers. Because the graph is now streamed (``graph.astream`` below),
    ``agent_state`` holds the latest full-state snapshot even when
    ``ainvoke`` would never have returned — so a timed-out run reports the
    findings it actually accumulated instead of a hollow ``0``.
    """
    findings = list((agent_state or {}).get("findings") or [])
    result["findings_count"] = len(findings)
    result["findings_by_severity"] = _findings_breakdown(findings)


async def _drive_with_pausable_timeout(coro, timeout: float) -> None:
    """Like ``asyncio.wait_for`` but the clock FREEZES during a usage-cap park.

    A plain ``wait_for`` keeps counting while a worker hibernates on the usage
    cap, so a multi-hour park would blow the agent's wall-clock budget. Here the
    effective deadline is ``timeout + paused_seconds()`` and is re-evaluated on a
    short poll: while a park is open, ``paused_seconds()`` grows in real time, so
    the deadline advances in lockstep with elapsed time and never expires
    mid-park. Once the park ends, the budget stops growing and the timer resumes.

    Raises :class:`asyncio.TimeoutError` (same as ``wait_for``) when the agent's
    *active* time exceeds ``timeout``, so ``run_one``'s timeout handler is
    unchanged. With no hibernation, ``paused_seconds()`` stays 0 and this behaves
    exactly like ``wait_for`` (modulo the poll granularity).
    """
    poll = float(os.getenv("SWARM_RUN_TIMEOUT_POLL_S", "10"))
    task = asyncio.ensure_future(coro)
    start = time.monotonic()
    try:
        while True:
            remaining = (timeout + paused_seconds()) - (time.monotonic() - start)
            if remaining <= 0:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
                raise asyncio.TimeoutError
            done, _ = await asyncio.wait({task}, timeout=min(remaining, poll))
            if task in done:
                return task.result()
    finally:
        if not task.done():
            task.cancel()


async def run_one(benchmark_id: str, *, skip_build: bool = False) -> dict:
    flag = expected_flag(benchmark_id)
    started = time.time()
    # Pin run_id and log dir BEFORE any graph activity so every
    # BaseNode call and every terminal-tool call lands in the same
    # per-run folder.
    run_id = make_run_id(benchmark_id=benchmark_id)
    rdir = run_dir(run_id)
    # Point the LIVE renderer's file sink at this run's plain-text log
    # so every ticker line we print to stderr is also captured to
    # ``displayed_terminal_logs.log`` (ANSI-stripped). The structured
    # ``full_logs.jsonl`` is appended to by callers (LLM callbacks +
    # shell tools); no setup needed there.
    set_terminal_log_file(terminal_log_path(run_id))
    # Wipe any per-agent token totals carried over from a previous
    # bench in the same Python process (the daily sweep runs many
    # benches in one invocation). Without this, the running_input
    # column in llm_calls.jsonl would silently accumulate across
    # benches and the LIVE context-rot warnings would fire too early.
    try:
        from src.llm.callbacks import reset_totals
        reset_totals()
    except Exception:  # noqa: BLE001 — observability must not break runs
        pass

    # Reset the cross-worker captured-flag signal. Same rationale as
    # the token-totals reset above: in the daily-sweep loop multiple
    # benches share one Python process, and without this reset bench
    # N+1 would start with bench N's captured flag still set —
    # FlagWatcher's sibling-cancel hook would fire on every worker's
    # first LLM call, no work would be done, and the run would
    # terminate immediately with no findings. See
    # ``src/nodes/base/flag_watcher.py`` for the design.
    reset_captured()
    # Same rationale for the rate-limit signal: clear any rate-limit/quota
    # flag left set by a previous bench in this process, so this bench is only
    # marked crashed if ITS OWN run hits the limit. See src/llm/rate_limit_signal.py.
    reset_rate_limited()
    # Hibernation: in benchmark mode, a usage-cap hit parks the in-flight agent
    # until the cap resets instead of crashing the run (see src/llm/hibernation.py).
    # Enable it for this (benchmark) path — real audits leave it off so they
    # never silently hang — and clear the per-bench park accumulator so this
    # bench's frozen-timer budget starts from zero.
    enable_hibernation(True)
    reset_hibernation()

    result: dict = {
        "benchmark_id": benchmark_id,
        "run_id": run_id,
        "run_dir": str(rdir),
        "expected_flag": flag,
        # Populated after make_run when we can read live container too.
        "expected_flag_candidates": (flag,) if flag else (),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "flag_found": False,
        "findings_count": 0,
        "findings_by_severity": {},
        "duration_s": None,
        "target_url": None,
        "error": None,
    }
    agent_state: dict = {}

    # The benchmark target bring-up (build → loopback lease → port override →
    # bridge/loopback URL → flag candidates) and its guaranteed teardown are
    # owned by ``provision_target`` (benchmarks/provision.py) — the single
    # definition the agentic-testing harness (tests/probe/) also enters, so a
    # replayed node provisions its target identically to production. Lazy
    # import: provision.py imports THIS module at load time, so importing it at
    # module top here would create a cycle. Entered via an ``AsyncExitStack``
    # so the target teardown runs in this function's ``finally`` — AFTER the
    # timeout / late-capture harvest below — preserving the original ordering.
    from benchmarks.provision import provision_target

    stack = AsyncExitStack()
    try:
        tgt = await stack.enter_async_context(
            provision_target(benchmark_id, skip_build=skip_build)
        )
        result["target_url"] = tgt.target_url
        # Adopt the provisioned flag set. Mirrors the original conditional:
        # only override the sha256-prediction defaults when a real candidate
        # set was readable (empty set → keep the init values).
        candidates = tgt.expected_flag_candidates
        if candidates:
            flag = tgt.expected_flag
            result["expected_flag"] = tgt.expected_flag
            result["expected_flag_candidates"] = candidates

        # Show the start-of-run boundary now that target_url is known.
        LIVE.bench_start(benchmark_id, result["target_url"], flag)
        logger.info(
            "[%s] target=%s expected_flag=%s candidates=%s run_dir=%s",
            benchmark_id, result["target_url"], flag, candidates, rdir,
        )

        graph = build_graph()
        initial_state = {
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
            # Web-search fire-policy mode for this run. Default "9" = all-on
            # (characterization + stuck + divergence + the when-to-use
            # description), so the full crawl policy is active by default.
            # Override SWARM_CRAWL_MODE=1 for the crawl-off baseline, or
            # 2/3/5/6 to isolate one policy. See src/nodes/crawl_policy.py.
            "crawl_mode": os.environ.get("SWARM_CRAWL_MODE", "9"),
            # Benchmark-mode signal — workers and the planner read this
            # to know the run has an explicit flag-extraction success
            # criterion. Empty string in non-benchmark contexts.
            "expected_flag": flag or "",
            # Full candidate set the matcher accepts — flag_watcher,
            # skill_runner, routing, and live observability all read
            # this. See state.AgentState for the field docstring.
            "expected_flag_candidates": candidates,
        }
        # Stream (rather than ainvoke) so the latest full-state snapshot —
        # including findings accumulated so far — survives a timeout cancel.
        # ``stream_mode="values"`` yields the complete state after each
        # super-step; the final yield equals what ainvoke would have
        # returned, so the verdict logic below is unchanged on the normal
        # path. On RUN_TIMEOUT_S the inner stream is cancelled but
        # ``agent_state`` already holds the last completed step's state, so
        # the timeout handler can still read its findings instead of
        # reporting a hollow 0 (the bug that made every timed-out bench show
        # "0 findings" even after workers had classified real ones). Mirrors
        # the same partial-snapshot pattern in
        # ``src/nodes/base/skill_runner.py``.
        async def _drive_graph() -> None:
            nonlocal agent_state
            async for snapshot in graph.astream(
                initial_state,
                config={"recursion_limit": GRAPH_RECURSION_LIMIT},
                stream_mode="values",
            ):
                agent_state = snapshot

        await _drive_with_pausable_timeout(_drive_graph(), RUN_TIMEOUT_S)

        # Verdict: did the planner submit a verified flag?
        #
        # New (2026-05) protocol — the planner emits ``action="submit_flag"``
        # with the flag string it believes the worker captured. The
        # routing edge (`src/edges/routing.py:route_after_planner`)
        # compares that submission against ``state["expected_flag"]``
        # via ``src.edges.flag_match.flags_match`` and routes straight
        # to END when it matches. The runner re-uses the same matcher
        # so the verdict is consistent between in-graph routing and
        # post-run reporting.
        #
        # No more passive regex-scan of free-form state: a placeholder
        # like ``FLAG{...}`` in the planner's narration can no longer
        # masquerade as a captured flag.
        from src.edges.flag_match import flags_match

        attempts = list(agent_state.get("submission_attempts") or [])
        result["submission_attempts"] = attempts
        submitted = attempts[-1].strip() if attempts else ""
        # Match against the full candidate set, not just the "primary"
        # display value — see :func:`expected_flag_candidates` for why
        # the corpus has multiple legitimate flag values per benchmark.
        if submitted and flags_match(submitted=submitted, expected=candidates or (flag,)):
            result["flag_found"] = True
            result["captured_flag"] = submitted
        else:
            result["flag_found"] = False
            result["captured_flag"] = ""
        _record_findings(result, agent_state)

    except asyncio.TimeoutError:
        # Harvest findings from the partial snapshot FIRST — the streamed
        # ``agent_state`` holds the last completed super-step's state even
        # though ainvoke never returned, so a timed-out run reports the
        # findings it actually accumulated instead of 0.
        _record_findings(result, agent_state)
        # Late-capture rescue: a worker may have raised FlagCapturedSignal
        # and set the process-global mid-flight, but the summarizer's
        # Codex call (60–90s) didn't finish before RUN_TIMEOUT_S fired,
        # so graph.ainvoke never returned and we never reached the
        # normal verdict block above. Consult the flag-watcher global
        # directly; if it holds a value that matches expected_flag,
        # credit the capture rather than reporting a pure timeout.
        from src.edges.flag_match import flags_match
        if is_captured():
            captured = get_captured_flag()
            # Match against the full candidate set — see
            # :func:`expected_flag_candidates`.
            if captured and flags_match(
                submitted=captured,
                expected=result.get("expected_flag_candidates") or (flag,),
            ):
                result["flag_found"] = True
                result["captured_flag"] = captured
                result["submission_attempts"] = [captured]
                result["partial_timeout"] = True
                result["error"] = (
                    f"agent timeout after {RUN_TIMEOUT_S}s "
                    f"(flag captured pre-timeout, graph wrap-up incomplete)"
                )
                logger.warning("[%s] %s", benchmark_id, result["error"])
            else:
                result["error"] = f"agent timeout after {RUN_TIMEOUT_S}s"
                logger.error("[%s] %s", benchmark_id, result["error"])
        else:
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
        # A crash mid-run may still leave findings on the streamed snapshot.
        _record_findings(result, agent_state)
    finally:
        # Tear down the provisioned target: docker compose down, drop the port
        # override, release the loopback lease — all owned by provision_target.
        # Running it here in the finally keeps teardown AFTER the timeout /
        # late-capture harvest in the except blocks above, exactly as before.
        await stack.aclose()
        # Report ACTIVE agent time: subtract any usage-cap hibernation so a
        # multi-hour park does not masquerade as a multi-hour solve time (and
        # does not skew the campaign timing stats). Matches the frozen-timer
        # budget — paused time is not work. paused_seconds() is the banked total
        # here (all holds released by now).
        result["duration_s"] = round(max(0.0, time.time() - started - paused_seconds()), 1)
        result["hibernated_s"] = round(paused_seconds(), 1)
    # Rate-limit safety net: if any LLM call this bench hit a Codex rate-limit
    # / quota error (process-global signal set in src/llm/codex.py) and we did
    # NOT capture a flag, record it as a crash even if some node swallowed the
    # exception so result["error"] never picked up a Codex string. classify()
    # keys "crash" off an error starting with "Codex", so prefix accordingly.
    # A genuine capture always wins — never overwrite a success.
    if not result["flag_found"] and is_rate_limited():
        err = result.get("error") or ""
        if not err.startswith("Codex"):
            result["error"] = f"CodexRateLimitError: {get_rate_limit_error()}"

    return result


def _campaign_results_dir() -> Path | None:
    """Campaign output dir from ``SWARM_RESULTS_DIR``, or ``None``.

    Set by ``benchmarks/launch_split.py`` when it fans the benchmark set
    out across ~20 parallel sweep processes. In campaign mode each
    benchmark's verdict is written to its own ``<dir>/<benchmark_id>.json``
    file (see :func:`write_jsonl`) instead of being appended to the shared
    ``results/xbow_<date>.jsonl``. Per-benchmark files never collide, so
    the parallel processes write concurrently with no lock and no
    torn-line risk — both of which the shared append has. Unset ⇒ the
    historical shared-jsonl behaviour, unchanged.
    """
    raw = os.environ.get("SWARM_RESULTS_DIR", "").strip()
    return Path(raw).expanduser() if raw else None


def write_jsonl(result: dict) -> Path:
    """Persist one benchmark result; return the file written.

    Default: append a line to the shared ``results/xbow_<date>.jsonl``.
    Campaign mode (``SWARM_RESULTS_DIR`` set): write a standalone, atomic
    ``<dir>/<benchmark_id>.json`` so parallel sweep processes never share
    a file. Falls back to the shared jsonl if the benchmark id is missing.
    """
    campaign = _campaign_results_dir()
    bid = result.get("benchmark_id")
    if campaign is not None and bid:
        campaign.mkdir(parents=True, exist_ok=True)
        path = campaign / f"{bid}.json"
        # tmp + replace so a reader (the campaign report polling this dir)
        # never sees a half-written file — same rationale as the atomic
        # save in src/cli/bench_results.py for Drive-backed paths.
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(result, indent=2) + "\n")
        os.replace(tmp, path)
        return path
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

    Campaign mode (``SWARM_RESULTS_DIR`` set): results live as one
    ``<benchmark_id>.json`` per benchmark under the campaign dir, so resume
    skips what THIS campaign already finished (a re-launch after some
    sweep windows died) rather than unrelated prior daily runs. When
    unset, the function reads the shared ``results/xbow_*.jsonl`` exactly
    as before.
    """
    ids: set[str] = set()

    def _consider(row: dict) -> None:
        if skip_errors and row.get("error"):
            return
        benchmark_id = row.get("benchmark_id")
        if benchmark_id:
            ids.add(benchmark_id)

    campaign = _campaign_results_dir()
    if campaign is not None:
        if campaign.exists():
            for path in sorted(campaign.glob("*.json")):
                try:
                    _consider(json.loads(path.read_text(encoding="utf-8")))
                except (json.JSONDecodeError, OSError):
                    continue
        return ids

    if not RESULTS_DIR.exists():
        return ids
    for path in sorted(RESULTS_DIR.glob("xbow_*.jsonl")):
        for raw in path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                _consider(json.loads(raw))
            except json.JSONDecodeError:
                continue
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


def _setup_usage_guard(args, ids: list[str]):
    """Build the per-benchmark usage-guard callback, or ``None``.

    Active only when ``--usage-guard`` is set AND the sweep has more than one
    benchmark — a single highlighted run never waits (the TUI scope decision).
    Threshold / margin resolve from the CLI flags, then the ``SWARM_USAGE_*``
    env vars, then the :mod:`src.cli.usage_guard` defaults (90% / 5 min).

    The returned zero-arg callable runs one pre-benchmark check: it blocks
    until the selected account's 5-hour usage is under threshold, or raises
    :class:`usage_guard.UsageGuardAbort` after the configured retries — the
    caller turns that into an early sweep stop.
    """
    if not getattr(args, "usage_guard", False) or len(ids) <= 1:
        return None

    import os

    from src.cli import usage_guard

    threshold = (
        args.usage_threshold
        if args.usage_threshold is not None
        else float(os.environ.get("SWARM_USAGE_THRESHOLD",
                                  usage_guard.DEFAULT_THRESHOLD_PCT))
    )
    margin_min = (
        args.usage_margin_min
        if args.usage_margin_min is not None
        else float(os.environ.get("SWARM_USAGE_MARGIN_MIN", 5))
    )
    margin_seconds = int(margin_min * 60)

    # warn-level so it survives a silent sweep (info is suppressed there).
    LIVE.runner_message(
        f"usage guard ON — pacing {len(ids)} benchmarks on the ~/.codex login "
        f"at ≥{threshold:g}% 5h usage "
        f"(wait = reset + {margin_min:g}m); on a failed check retries "
        f"{usage_guard.FETCH_ATTEMPTS}× then aborts the sweep",
        level="warn",
    )

    def _guard() -> None:
        usage_guard.wait_until_clear(
            "~/.codex",
            threshold_percent=threshold,
            margin_seconds=margin_seconds,
            log=lambda m, level="info": LIVE.runner_message(m, level=level),
        )

    return _guard


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
    elif args.queue:
        # Dynamic pull mode: the actual dispatch claims live from the shared
        # queue. ``ids`` here is only a startup-banner snapshot of what is
        # currently pending campaign-wide — this worker will run whatever
        # subset it manages to claim, not this whole list.
        from benchmarks import work_queue
        ids = work_queue.list_pending(args.queue)
    else:
        LIVE.runner_message("specify --bench <id>, --daily, --list-file or --queue", level="error")
        return 2

    if args.resume and not args.queue:
        done = load_recorded_ids(skip_errors=args.retry_errors)
        original_count = len(ids)
        ids = [bid for bid in ids if bid not in done]
        skipped = original_count - len(ids)
        LIVE.runner_message(
            f"resume enabled: skipping {skipped} recorded benchmark(s), "
            f"{len(ids)} remaining"
        )

    # Startup banner — prints model / budgets / verbosity / log root /
    # file legend before the first bench. Idempotent across calls so
    # re-entrant invocations (langgraph dev) only print once.
    try:
        from src.graph import describe_config
        from src.llm.provider import current_default_config
        # Show the log ROOT — every bench writes its own ``run-<id>/``
        # subdir under here. We deliberately do NOT call
        # ``run_dir(make_run_id(...))`` for this: ``run_dir`` creates the
        # directory as a side effect and ``make_run_id`` stamps a fresh
        # timestamp, so building a banner path that way left an orphan
        # empty ``run-…/`` folder one second off from the real one that
        # ``run_one`` creates when the bench actually starts.
        model_info = current_default_config()
        LIVE.startup_banner(
            model_info=model_info,
            log_dir=str(LOGS_ROOT.resolve()),
            bench_ids=list(ids),
            budgets_text=describe_config(),
        )
    except Exception:  # noqa: BLE001 — banner failure must not stop the run
        pass

    # Sweep-level log sink — persists the per-bench verdict blocks
    # ("◆ XBEN-… ✓ FLAG FOUND …") and the final "Summary: N pass …" line,
    # which the per-run sink (displayed_terminal_logs.log, cleared between
    # benches) never captures because they are emitted with no per-run sink
    # attached. Lands in logs/sweep_<ts>.log.
    sweep_log_path = LOGS_ROOT / f"sweep_{time.strftime('%m-%d_%Hh%Mm%Ss')}.log"
    set_sweep_log_file(sweep_log_path)

    LIVE.runner_message(f"running {len(ids)} benchmark(s)")
    LIVE.runner_message(f"sweep log → {sweep_log_path}")

    # Usage guard: pace a multi-benchmark sweep against the selected Codex
    # account's 5-hour limit (None for a single-benchmark run). See
    # src/cli/usage_guard.py.
    guard = _setup_usage_guard(args, ids)

    summary = {"pass": 0, "fail": 0, "crash": 0}
    aborted = False

    # The per-benchmark unit of work, shared by the fixed-list loop and the
    # dynamic queue loop below: run it, write its jsonl, classify once, mirror
    # the verdict into the picker marks, and emit the end-of-bench verdict line.
    async def _run_and_record(bid: str) -> None:
        r = await run_one(bid, skip_build=args.skip_build)
        try:
            path = write_jsonl(r)

            # Classify the run once — flag (ok) / fail / crash (api) — with the
            # shared src.benchmark_verdict rule, and use that single verdict for
            # BOTH the end-of-sweep tally and the picker mark so the terminal,
            # the Summary line, and the ✓/✗/~ grid can never disagree. A
            # full-budget ``agent timeout`` counts as fail, not crash.
            status = bench_results.classify(bool(r["flag_found"]), r.get("error"))
            summary[_SUMMARY_KEY[status]] += 1

            # Mirror the verdict into the picker's ✓/✗/~ triage marks so the TUI
            # grid reflects this run without a manual ``t`` press. The mark always
            # reflects the latest run, so a codex/infra crash shows ~ even on a
            # benchmark that previously passed/failed — that's how you spot runs
            # that need re-running. Best-effort — must never break the sweep.
            try:
                bench_results.record(bid, status)
            except Exception:  # noqa: BLE001 — triage write must not stop the sweep
                logger.exception("[%s] triage mark update failed", bid)

            # Pull the most recent submission attempt for the
            # expected-vs-captured verification block in bench_end. Empty
            # list → empty string → bench_end renders "(no submission
            # attempted)". On success, ``r["captured_flag"]`` is the
            # verified value, and the last submission_attempts entry
            # equals it; we pick the last attempt either way because it's
            # what the planner most recently committed to (and matches
            # what's verified for the verdict — see the run_one block at
            # xbow_runner.py:307-316).
            last_submission = ""
            attempts = r.get("submission_attempts") or []
            if attempts:
                last_submission = str(attempts[-1] or "").strip()

            LIVE.bench_end(
                bid,
                ok=bool(r["flag_found"]),
                duration_s=float(r["duration_s"] or 0.0),
                findings_n=int(r["findings_count"] or 0),
                findings_by_severity=dict(r.get("findings_by_severity") or {}),
                # The summary.md artefact was removed in the 2026-05 log
                # consolidation; we now point the end-of-bench line at the
                # plain-text terminal log instead. The structured log is one
                # directory over: ``logs/run-<run_id>/full_logs.jsonl``.
                summary_path=f"{r['run_dir']}/displayed_terminal_logs.log",
                error=r["error"],
                expected_flag=str(r.get("expected_flag") or ""),
                last_submission=last_submission,
                expected_flag_candidates=tuple(
                    r.get("expected_flag_candidates") or ()
                ),
            )
            LIVE.runner_message(f"           jsonl   → {path}")
        finally:
            # Keep the per-run displayed-terminal sink attached through the
            # human-facing verdict block above, then clear it before the next
            # benchmark or the campaign-level summary writes.
            try:
                set_terminal_log_file(None)
            except Exception:  # noqa: BLE001 — observability must not break the sweep
                pass

    def _paced() -> bool:
        """Run the usage guard before a bench; False (and abort) if it stops us.

        On a usage-check failure the guard retries, then raises UsageGuardAbort —
        we stop rather than run blind into the rate limit.
        """
        nonlocal aborted
        if guard is None:
            return True
        try:
            guard()
            return True
        except Exception as exc:  # noqa: BLE001 — UsageGuardAbort etc. → stop
            LIVE.runner_message(f"usage guard: {exc}", level="error")
            aborted = True
            return False

    if args.queue:
        # Dynamic pull: claim the next pending bench, run it, mark it done,
        # repeat. When the queue drains, reclaim any crashed peer's in-flight
        # bench (requeue_dead keys on a dead PID, never a time threshold, so a
        # legitimately hibernating run is left alone) before exiting — so a dead
        # session's work is retried by a live worker rather than lost.
        import socket
        from benchmarks import work_queue
        pid, host = os.getpid(), socket.gethostname()
        while True:
            if not _paced():
                break
            bid = work_queue.claim_next_pending(args.queue, pid=pid, worker=host)
            if bid is None:
                if work_queue.requeue_dead(args.queue) == 0:
                    break
                continue
            try:
                await _run_and_record(bid)
            finally:
                work_queue.mark_done(args.queue, bid)
    else:
        for bid in ids:
            if not _paced():
                break
            await _run_and_record(bid)

    total = summary["pass"] + summary["fail"] + summary["crash"]
    LIVE.runner_message(
        f"Summary: {summary['pass']} pass, {summary['fail']} fail, "
        f"{summary['crash']} crash / {total} total"
    )
    LIVE.runner_message(f"sweep log saved → {sweep_log_path}")
    set_sweep_log_file(None)
    if aborted:
        LIVE.runner_message(
            "sweep aborted early by the usage guard (remaining benchmarks "
            "not run)",
            level="error",
        )
        return 5
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="SwarmAttacker XBOW benchmark runner")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--bench", help="single benchmark id, e.g. XBEN-001-24")
    g.add_argument("--daily", action="store_true",
                   help="run the daily-15 list (benchmarks/daily_15.txt)")
    g.add_argument("--list-file", type=Path,
                   help="run benchmark IDs from a custom text file")
    g.add_argument("--queue", type=Path, metavar="CAMPAIGN_DIR",
                   help="pull benchmarks dynamically from a shared campaign "
                        "queue (benchmarks/work_queue.py) instead of a fixed "
                        "list — used by launch_split's concurrent fan-out so "
                        "free workers grab the next pending bench")
    ap.add_argument("--skip-build", action="store_true",
                    help="skip 'make build' (use already-built images)")
    ap.add_argument("--resume", action="store_true",
                    help="skip benchmark IDs already present in results/xbow_*.jsonl")
    ap.add_argument("--retry-errors", action="store_true",
                    help="with --resume, retry IDs whose previous row had an error")
    ap.add_argument(
        "--usage-guard", action="store_true",
        help="for a multi-benchmark sweep, wait before each benchmark until "
             "the selected Codex account's 5-hour usage is back under the "
             "threshold (paces the sweep so it doesn't hit the rate limit). "
             "No effect on a single-benchmark run.",
    )
    ap.add_argument(
        "--usage-threshold", type=float, default=None,
        help="usage guard: 5-hour used-percent that triggers a wait "
             "(default 90, or SWARM_USAGE_THRESHOLD).",
    )
    ap.add_argument(
        "--usage-margin-min", type=float, default=None,
        help="usage guard: minutes to wait past the window reset, for safety "
             "(default 5, or SWARM_USAGE_MARGIN_MIN).",
    )
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

    # Logging setup splits by mode:
    # - verbose: full timestamped basicConfig stream (today's behavior)
    # - compact/silent: route WARNING+ records through LIVE so they
    #   render as colored ⚠/error lines aligned with the rest of the
    #   live stream, instead of raw "2026-05-03 21:19:11 WARNING …"
    #   lines that visually clash.
    if config.verbosity.mode == "verbose":
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
    else:
        root = logging.getLogger()
        root.setLevel(logging.WARNING)
        # Wipe any pre-existing handler (e.g. from langchain / dotenv
        # imports) so output isn't duplicated.
        for h in list(root.handlers):
            root.removeHandler(h)
        root.addHandler(LiveLogHandler())
    # Silence httpx INFO ("HTTP Request: POST chatgpt.com/...") unless the
    # operator explicitly opted in via SWARM_LIVE_HTTP=1. Disk logs are
    # unaffected; we don't write a separate httpx log file.
    if not config.verbosity.show_http:
        for log_name in ("httpx", "httpcore", "openai", "anthropic"):
            logging.getLogger(log_name).addFilter(HttpxQuietFilter())

    # Mirror every ``src.*`` / ``node.*`` / ``benchmarks.*`` logger call
    # into ``full_logs.jsonl`` as type=``log`` rows. Decoupled from
    # ``logging.basicConfig`` so compact mode (root=WARNING) still
    # captures INFO records that document load-bearing decisions —
    # e.g. ``[%s] auto-verified flag in tool output`` from skill_runner.
    # Without this, the only place that line existed was stderr, which
    # the compact LIVE renderer suppresses for INFO records. See the
    # 2026-05-25 XBEN-006-24 retro: three workers had captured the flag
    # in their tool output and the static extractor matched it, but no
    # disk artefact recorded the match, so post-mortem diagnosis was
    # blind.
    install_jsonl_log_handler()

    # Every benchmark run is IP-isolated: ensure the loopback alias pool exists
    # before any target comes up (idempotent; sudo-prompts once per boot, only
    # when the pool is missing). Without it the run silently falls back to a
    # shared localhost where the agent cross-probes other targets and host apps.
    loopback.ensure_pool()

    raise SystemExit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
