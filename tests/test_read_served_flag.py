"""Tier 1 — read_served_flag tests.

``benchmarks/xbow_runner.read_served_flag`` reads the actual baked
flag from inside the running benchmark container via
``docker compose exec``, trying each path in
:data:`xbow_runner._SERVED_FLAG_PATHS` until one succeeds. It's the
source of truth for "what flag is the image actually serving" — used
by :func:`xbow_runner.expected_flag_candidates` to feed the
candidate set so the matcher compares against reality rather than
the convention's prediction.

Why this matters — 2026-05-25 incident: the XBEN-006-24 image was
built 2 weeks ago with a manual ``--build-arg FLAG=flag{<uuid>}``
override. A fresh rebuild today produced a sha256-baked image, but
Docker Desktop's prune cleanup re-tagged the older UUID-baked image
as ``:latest`` during a brief idle window. The runner's prediction
(sha256) and the served value (UUID) diverged, the strict matcher
rejected every valid capture, the run scored as ``flag_found=false``
despite the agent doing everything correctly.

Why MULTIPLE paths — 2026-05-27 incident: an XBEN-002 capture was
silently dropped because this function read ``/app/flag.txt`` (which
doesn't exist for that benchmark) and returned ``""``, falling back
to the sha256 prediction. XBEN-002's Dockerfile actually bakes to
``/flag``. The function now tries every known path and uses the
first one that yields a non-empty value.

These tests pin six behaviours:

  1. Happy path — first path (``/flag``) succeeds, return value.
  2. Fallback — first path fails, second path succeeds, return the
     second's value.
  3. Container down — every exec returns non-zero, function returns "".
  4. Timeout — every exec hangs past the 5s cap, function returns "".
  5. docker binary missing — function returns "" (no crash).
  6. Benchmark directory missing — short-circuits before subprocess.

Strategy: monkeypatch ``subprocess.run`` in the xbow_runner module so
no real docker daemon is touched. Pure Tier-1 — no docker, no
container, no LLM.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from benchmarks import xbow_runner


@pytest.fixture
def bench_id_with_dir(tmp_path, monkeypatch):
    """Provide a benchmark ID whose directory exists in a temp XBOW_ROOT.

    By default the production XBOW_ROOT points at the real
    ``Benchmarks/xbow-validation`` checkout; we monkeypatch to a temp
    layout so ``is_dir()`` returns True without touching anything
    real.
    """
    fake_root = tmp_path / "xbow-validation"
    bench_dir = fake_root / "benchmarks" / "XBEN-006-24"
    bench_dir.mkdir(parents=True)
    monkeypatch.setattr(xbow_runner, "XBOW_ROOT", fake_root)
    return "XBEN-006-24"


# ── 1. Happy path ──────────────────────────────────────────────────────


def test_returns_served_value_when_exec_succeeds(bench_id_with_dir, monkeypatch):
    """First-path success — exec works on the default path (``/flag``),
    return the value verbatim (stripped of trailing whitespace). The
    function exits early; the fallback path is not tried.
    """
    served = "FLAG{9c935b35ad7746d14fa2c01708b767f4cb0a9eaa867e77af44c14592439e53eb}"
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=served + "\n", stderr="",
    )

    captured_calls: list[list] = []

    def fake_run(cmd, **kwargs):
        captured_calls.append(cmd)
        return fake_result

    monkeypatch.setattr(xbow_runner.subprocess, "run", fake_run)

    result = xbow_runner.read_served_flag(bench_id_with_dir)
    assert result == served

    # Sanity-check the command shape and that we tried the first
    # known path (which is ``/flag`` per the XBEN-001/002/003
    # Dockerfile convention).
    assert len(captured_calls) == 1
    cmd = captured_calls[0]
    assert cmd[:3] == ["docker", "compose", "exec"]
    assert "-T" in cmd
    assert "app" in cmd
    # First path tried should be the first entry in _SERVED_FLAG_PATHS.
    assert cmd[-1] == xbow_runner._SERVED_FLAG_PATHS[0]


# ── 1b. Multi-path fallback ────────────────────────────────────────────


def test_falls_back_to_second_path_when_first_missing(bench_id_with_dir, monkeypatch):
    """The function must try every path in :data:`_SERVED_FLAG_PATHS`
    in order until one succeeds — not give up on the first 404. This
    is the XBEN-002 regression: ``/flag`` exists, ``/app/flag.txt``
    doesn't (or vice versa for other benchmarks). Both shapes appear
    in the corpus.
    """
    served = "flag{8b9df79e-91eb-4f4e-8449-5e1d207a0d83}"
    fail_path = xbow_runner._SERVED_FLAG_PATHS[0]
    succeed_path = xbow_runner._SERVED_FLAG_PATHS[1]

    captured_calls: list[list] = []

    def fake_run(cmd, **kwargs):
        captured_calls.append(cmd)
        # First call (probing the first path) raises as if cat returned
        # non-zero (file missing inside container).
        if cmd[-1] == fail_path:
            raise subprocess.CalledProcessError(
                returncode=1, cmd=cmd, output="", stderr="cat: no such file",
            )
        # Second call (probing the second path) succeeds.
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=served + "\n", stderr="",
        )

    monkeypatch.setattr(xbow_runner.subprocess, "run", fake_run)

    result = xbow_runner.read_served_flag(bench_id_with_dir)
    assert result == served
    # Both paths should have been tried in order.
    assert len(captured_calls) == 2
    assert captured_calls[0][-1] == fail_path
    assert captured_calls[1][-1] == succeed_path


def test_strips_trailing_whitespace(bench_id_with_dir, monkeypatch):
    """flag.txt sometimes has a trailing newline (sed-baked); we want
    the bare value, not value + \\n, since flags_match compares
    exact strings."""
    served = "FLAG{abc12345}"
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=f"  {served}\n  \n", stderr="",
    )
    monkeypatch.setattr(xbow_runner.subprocess, "run", lambda *a, **kw: fake_result)
    assert xbow_runner.read_served_flag(bench_id_with_dir) == served


# ── 2. Container down — exec returns non-zero ──────────────────────────


def test_returns_empty_when_exec_fails(bench_id_with_dir, monkeypatch):
    """When the container isn't running, ``docker compose exec`` exits
    non-zero with a "no such service" or "no container" error. The
    function must swallow that and return "" so the caller can fall
    back to the sha256 prediction.
    """
    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=cmd,
                                            output="", stderr="no container")
    monkeypatch.setattr(xbow_runner.subprocess, "run", fake_run)
    assert xbow_runner.read_served_flag(bench_id_with_dir) == ""


# ── 3. Timeout — exec hangs past the 5s cap ────────────────────────────


def test_returns_empty_on_timeout(bench_id_with_dir, monkeypatch):
    """A wedged container or an unresponsive docker daemon must NOT
    block run_one. The function caps at 5s and returns "" on
    TimeoutExpired so the run continues with the prediction fallback.
    """
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=5)
    monkeypatch.setattr(xbow_runner.subprocess, "run", fake_run)
    assert xbow_runner.read_served_flag(bench_id_with_dir) == ""


# ── 4. docker binary missing ───────────────────────────────────────────


def test_returns_empty_when_docker_missing(bench_id_with_dir, monkeypatch):
    """If ``docker`` isn't on PATH (e.g. CI without Docker installed),
    subprocess.run raises FileNotFoundError. Must be swallowed."""
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("docker: not found")
    monkeypatch.setattr(xbow_runner.subprocess, "run", fake_run)
    assert xbow_runner.read_served_flag(bench_id_with_dir) == ""


# ── 5. Benchmark directory missing ─────────────────────────────────────


def test_returns_empty_when_bench_dir_missing(tmp_path, monkeypatch):
    """Short-circuits before subprocess if the benchmark directory
    doesn't exist on disk. Defensive — prevents trying to docker-exec
    in a non-bench cwd which would fail confusingly.
    """
    fake_root = tmp_path / "xbow-validation"
    fake_root.mkdir()
    # No benchmarks/XBEN-999-99/ subdir created.
    monkeypatch.setattr(xbow_runner, "XBOW_ROOT", fake_root)

    called: list = []
    monkeypatch.setattr(
        xbow_runner.subprocess, "run",
        lambda *a, **kw: called.append("ran") or  # noqa: B009
                          subprocess.CompletedProcess([], 0, "", ""),
    )

    assert xbow_runner.read_served_flag("XBEN-999-99") == ""
    assert called == [], "subprocess.run must not be called when bench dir is missing"


# ── 6. Empty stdout — treat as "no value", not "valid empty flag" ──────


def test_returns_empty_when_stdout_is_blank(bench_id_with_dir, monkeypatch):
    """flag.txt that's been zeroed out / not yet sed'd by the
    Dockerfile would return empty stdout. The function must treat
    that as failure (return "") rather than passing "" up as a valid
    flag, because flags_match treats empty expected as real-pentest
    mode and would then accept any well-formed flag — masking a
    legitimately broken image as "no ground truth, accept whatever".
    """
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="   \n  ", stderr="",
    )
    monkeypatch.setattr(xbow_runner.subprocess, "run", lambda *a, **kw: fake_result)
    assert xbow_runner.read_served_flag(bench_id_with_dir) == ""
