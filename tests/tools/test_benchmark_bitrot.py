"""Tier 3 — benchmark bit-rot regression smoke test.

The XBOW benchmarks were authored in 2024 on base images that have since
rotted (EOL Debian apt mirrors, amd64-only images with no arm64 manifest,
Node/PHP runtimes too old for newer transitive deps). `benchmarks/patch_bitrot.sh`
applies *vuln-neutral* infrastructure fixes so each benchmark still builds
and runs on a current Docker Desktop / Apple Silicon host. See
`tests/FAILURES.md` (2026-05-31 first-50 sweep, 2026-06-01 051–104 build-out)
for the per-family diagnosis.

This test pins one representative per distinct fix mechanism so the whole
category can't silently regress — whether from an edit to `patch_bitrot.sh`
itself or from an upstream submodule bump:

  buster-apt (python:3.8-slim-buster)      -> patch_buster_apt_dockerfile        (XBEN-089)
  buster-apt (php:7.1-apache, no "buster")  -> patch_debian_apt_archive_dockerfile (XBEN-067)
  mysql:5.7.15 build-FROM (arm64/signature) -> patch_mysql_dockerfile             (XBEN-063)
  compose `image: mysql:5.7` (no platform)  -> patch_compose_mysql_platform       (XBEN-078)
  phantomjs Dalgona XSS                      -> patch_phantomjs_xss_dockerfile     (XBEN-051)
  multi-service (haproxy buster + mitmproxy amd64-only) -> dedicated case         (XBEN-066)
  node:14-alpine can't parse Node-15+ `||=` -> patch_node14_to_16_dockerfile      (XBEN-084)

For each representative the test: (1) runs `patch_bitrot.sh <id>` (idempotent;
also clears the build guard so `make build` exercises the real build path),
(2) `make build`, (3) `docker compose up -d --wait` and asserts every service
reaches *healthy*, then (4) ALWAYS `docker compose down --remove-orphans`
(frees the network — Docker's bridge pool caps at ~31 — and the ~8 GB VM's RAM;
the image is kept). The assertion is "builds + comes up healthy", NOT
flag-solvability (that needs the exploit and is out of scope here).

Marked `@pytest.mark.tools` (skipped by default). Run serially (one stack at a
time keeps the 8 GB Docker VM happy)::

    uv run pytest -m tools tests/tools/test_benchmark_bitrot.py -v

Run a single family::

    uv run pytest -m tools tests/tools/test_benchmark_bitrot.py -k mysql -v

Skips automatically if the XBOW submodule is absent or the Docker daemon /
`make` are unavailable. The representatives are chosen to use ephemeral
(container-only) host ports, so they do not collide with services on the host
(unlike XBEN-058/096/099 — see FAILURES.md 2026-06-01).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]          # .../SwarmAttacker
PATCHER = REPO_ROOT / "benchmarks" / "patch_bitrot.sh"
XBOW_BENCH = (REPO_ROOT / ".." / "Benchmarks" / "xbow-validation" / "benchmarks").resolve()

UP_TIMEOUT_S = 180

# One representative per bit-rot fix mechanism in patch_bitrot.sh.
REPRESENTATIVES = [
    pytest.param("XBEN-089-24", id="buster-apt-python"),
    pytest.param("XBEN-067-24", id="buster-apt-php-archive"),
    pytest.param("XBEN-063-24", id="mysql-5.7.15-amd64"),
    pytest.param("XBEN-078-24", id="compose-mysql-5.7-platform"),
    pytest.param("XBEN-051-24", id="phantomjs-xss"),
    pytest.param("XBEN-066-24", id="multiservice-haproxy-mitmproxy"),
    pytest.param("XBEN-084-24", id="node-14-to-16"),
]


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _docker_ok() -> bool:
    if not (_have("docker") and _have("make")):
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=20
        ).returncode == 0
    except Exception:
        return False


pytestmark = [
    pytest.mark.tools,
    pytest.mark.skipif(not PATCHER.is_file(), reason="patch_bitrot.sh not found"),
    pytest.mark.skipif(not XBOW_BENCH.is_dir(), reason="XBOW benchmarks submodule not checked out"),
    pytest.mark.skipif(not _docker_ok(), reason="docker daemon and/or make not available"),
]


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


@pytest.mark.parametrize("bench", REPRESENTATIVES)
def test_bitrot_family_builds_and_runs_healthy(bench: str) -> None:
    bench_dir = XBOW_BENCH / bench
    assert bench_dir.is_dir(), f"missing benchmark dir: {bench_dir}"

    # 1. Apply the vuln-neutral bit-rot patch (idempotent). The patcher also
    #    clears the .xben_build_done guard, so step 2 runs the real build.
    patched = _run(["bash", str(PATCHER), bench], timeout=120)
    assert patched.returncode == 0, (
        f"patch_bitrot.sh failed for {bench}\n"
        f"stdout:\n{patched.stdout}\nstderr:\n{patched.stderr}"
    )

    try:
        # 2. Build (cached layers -> seconds; a full build on a fresh checkout).
        built = _run(["make", "build"], cwd=bench_dir, timeout=1800)
        assert built.returncode == 0, (
            f"`make build` failed for {bench}\n"
            f"stdout(tail):\n{built.stdout[-2000:]}\nstderr(tail):\n{built.stderr[-2000:]}"
        )

        # 3. Start and wait for every service's healthcheck.
        up = _run(
            ["docker", "compose", "up", "-d", "--wait", "--wait-timeout", str(UP_TIMEOUT_S)],
            cwd=bench_dir,
            timeout=UP_TIMEOUT_S + 60,
        )
        assert up.returncode == 0, (
            f"`docker compose up --wait` did not reach healthy for {bench}\n"
            f"stdout(tail):\n{up.stdout[-2000:]}\nstderr(tail):\n{up.stderr[-2000:]}"
        )
    finally:
        # 4. Always tear down — frees the network + RAM, keeps the image.
        _run(["docker", "compose", "down", "--remove-orphans"], cwd=bench_dir, timeout=180)
