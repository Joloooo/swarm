"""Bring up an XBOW benchmark target and hand back its address — the one
place the "map each port to an isolated, agent-reachable URL" layer lives.

``run_one`` (the benchmark runner) and the agentic-testing harness
(`tests/probe/`) both need the *same* bring-up: build the image, lease a
private loopback IP so concurrent runs can't collide, pin the container's
real ports to that IP via a generated compose override, prefer the
container's own docker-bridge IP when routable, discover the published
port, read the baked flag — then tear all of it down. Duplicating that in
the harness would let the two drift (a different bring-up maps the port
differently, so the replay isn't faithful). So it is extracted here as a
single async context manager that both callers enter.

The heavy lifting still lives in ``benchmarks.xbow_runner`` (the port
helpers `_write_port_override` / `_primary_target_url` / … are pinned by
``tests/test_xbow_runner.py`` and stay there); this module only imports
them and sequences the bring-up + guaranteed teardown. The dependency
points one way — ``xbow_runner`` imports ``provision_target`` lazily inside
``run_one`` to avoid an import cycle, and the harness imports it from here.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

from benchmarks import loopback
from benchmarks.xbow_runner import (
    _bridge_routable,
    _container_bridge_target,
    _override_host_map,
    _override_path,
    _primary_target_url,
    _purge_contaminating_containers,
    _write_port_override,
    discover_target_url,
    docker_down,
    expected_flag,
    expected_flag_candidates,
    make_build,
    make_run,
)
from src.observability import LIVE

logger = logging.getLogger(__name__)


@dataclass
class ProvisionedTarget:
    """The address + flag set of a freshly brought-up benchmark container.

    ``target_url`` is exactly what production hands the agent (``run_one``
    seeds it into ``state["target_url"]``, which the worker's system prompt
    renders as ``Target: <url>``). ``target_scope`` mirrors it (benchmarks
    scope to the single URL). ``expected_flag`` is the primary candidate;
    ``expected_flag_candidates`` is the full set the matcher accepts (live
    container read / ``.env`` / sha256 prediction). ``leased_ip`` is the
    per-run loopback alias, or ``None`` when the pool was unavailable and
    the legacy localhost mapping was used.
    """

    target_url: str
    target_scope: str
    expected_flag: str
    expected_flag_candidates: tuple[str, ...]
    leased_ip: str | None


@asynccontextmanager
async def provision_target(
    benchmark_id: str, *, skip_build: bool = False
) -> AsyncIterator[ProvisionedTarget]:
    """Build, start, and isolate ``benchmark_id``; yield its address; tear down.

    The body mirrors ``run_one``'s bring-up exactly (so production and the
    harness provision identically): ``make build`` (unless ``skip_build``) →
    lease a loopback IP and pin ports to it via the compose override (drop
    the lease if the override can't be written) → purge stale containers
    that would leak onto the leased IP → ``make run`` → choose the target
    URL (container bridge IP when routable, else the leased-IP override map,
    else plain ``localhost``) → read the flag candidates.

    The ``finally`` guarantees teardown even on a failed bring-up: ``docker
    compose down`` (frees the network, keeps the image), drop the generated
    override file, release the loopback lease. Teardown order matches
    ``run_one`` — ``down`` before the override is unlinked, because a compose
    ``down`` re-reads the merged config.
    """
    leased_ip: str | None = None
    try:
        if not skip_build:
            make_build(benchmark_id)
        # Give this run its own loopback IP so the benchmark's REAL ports are
        # bound to a unique host address the agent scans in isolation. Falls
        # back to the legacy localhost:<random> mapping if the alias pool
        # isn't set up, or if the override can't be written.
        leased_ip = loopback.acquire()
        if leased_ip and _write_port_override(benchmark_id, leased_ip) is None:
            loopback.release(leased_ip)
            leased_ip = None
        if not leased_ip:
            LIVE.runner_message(
                f"{benchmark_id}: no per-VM loopback IP "
                "(run benchmarks/setup_loopback_pool.sh) — using localhost",
                level="warn",
            )
        else:
            # Clean slate: a container left running by a crashed prior run can
            # still answer on this run's leased IP and be "solved" instead of
            # the freshly-launched target. Remove such stragglers before `up`.
            _purge_contaminating_containers(leased_ip)
        make_run(benchmark_id)
        # Hand back the EXACT app URL (IP + the real published port). Prefer
        # the container's OWN bridge IP when routable (so the agent scans only
        # the container's namespace, never the host's 0.0.0.0 services);
        # otherwise the per-VM loopback alias, else plain localhost.
        bridge_url = (
            _container_bridge_target(benchmark_id) if _bridge_routable() else None
        )
        target_url = bridge_url or (
            _primary_target_url(leased_ip, _override_host_map(benchmark_id))
            if leased_ip
            else discover_target_url(benchmark_id)
        )

        # The full candidate set the matcher accepts (sha256 prediction,
        # .env value, live-container read). The "primary" is whichever the
        # runner can confirm first; the sha256 prediction is the baseline we
        # log against so an upgrade to a live-read value is visible.
        candidates = expected_flag_candidates(benchmark_id)
        sha_prediction = expected_flag(benchmark_id)
        primary = candidates[0] if candidates else sha_prediction
        if candidates and primary != sha_prediction:
            logger.info(
                "[%s] primary flag now %s (was sha256 prediction %s); "
                "full candidate set: %s",
                benchmark_id, primary, sha_prediction, candidates,
            )

        yield ProvisionedTarget(
            target_url=target_url,
            target_scope=target_url,
            expected_flag=primary,
            expected_flag_candidates=candidates,
            leased_ip=leased_ip,
        )
    finally:
        try:
            docker_down(benchmark_id)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] docker compose down failed", benchmark_id)
        # Drop the generated port override and free this run's loopback IP so
        # the next run (or a parallel sweep process) can reuse it.
        _override_path(benchmark_id).unlink(missing_ok=True)
        loopback.release(leased_ip)
