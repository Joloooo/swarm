"""Tier-3 — verify ShellManager actually creates and tears down sessions.

Marked ``@pytest.mark.tools`` (skipped by default — needs real ``tmux``).
Run explicitly with::

    uv run --with pytest pytest -m tools tests/tools/test_shell_manager.py -v

These tests answer the user's questions from the design discussion:
  1. Are sessions named uniquely per agent? (UUID-suffix scheme)
  2. Do parallel agents collide? (no — they shouldn't)
  3. Does cleanup_agent kill THIS agent's session and ONLY this one?
  4. Does atexit fire on normal subprocess exit?
  5. Does the SIGTERM handler clean up?
  6. Does the SIGINT (Ctrl+C) handler clean up?
  7. Are stale sessions (killed externally) recreated transparently?

Subprocess-based tests spawn a child Python process that imports the
manager, creates a session, and either exits / receives a signal / hangs.
We then check the parent-side ``tmux ls`` to confirm the session is gone.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest


# ── Skip the whole module unless tmux is installed ───────────────────────────
pytestmark = [
    pytest.mark.tools,
    pytest.mark.skipif(shutil.which("tmux") is None, reason="tmux not installed"),
]


# ── Helpers ──────────────────────────────────────────────────────────────────


def _list_swarm_sessions() -> list[str]:
    """Return tmux session names matching ``swarm-*``. Empty list if no server."""
    try:
        result = subprocess.run(
            ["tmux", "list-sessions", "-F", "#{session_name}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    if result.returncode != 0:
        # No server running → no sessions, not a failure
        return []
    return [
        line.strip() for line in result.stdout.splitlines()
        if line.strip().startswith("swarm-")
    ]


def _tmux_has_session(name: str) -> bool:
    """True iff ``tmux`` knows a session by exactly this name."""
    try:
        result = subprocess.run(
            ["tmux", "has-session", "-t", name],
            capture_output=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def _kill_session(name: str) -> None:
    """Best-effort tmux kill — never raises."""
    subprocess.run(
        ["tmux", "kill-session", "-t", name],
        capture_output=True,
        timeout=5,
    )


# A unique-per-test-run prefix keeps parallel CI workers from stepping on
# each other if this suite is ever run concurrently in the same tmux server.
_TEST_RUN_TAG = f"t{uuid.uuid4().hex[:8]}"


def _agent_id(label: str) -> str:
    """Build a per-test agent_id with the run tag baked in."""
    return f"{_TEST_RUN_TAG}-{label}"


@pytest.fixture(autouse=True)
def _kill_residue_at_boundaries():
    """Belt-and-suspenders: clean up anything our test tag created.

    Runs before AND after each test so that test ordering can never
    cause a false positive on a "session is gone" assertion.
    """
    def _sweep():
        for name in _list_swarm_sessions():
            if _TEST_RUN_TAG in name:
                _kill_session(name)
    _sweep()
    yield
    _sweep()


# ── Test 1: UUID-suffixed naming ─────────────────────────────────────────────


def test_session_name_includes_agent_id_and_uuid():
    """Every session is named ``swarm-{agent_id}-{uuid}``.

    The UUID part is what makes parallel SwarmAttacker runs safe — two
    processes calling for the same agent_id get distinct sessions.
    """
    from src.tools.shell.manager import ShellManager

    mgr = ShellManager()
    aid = _agent_id("naming")
    name, pane_id = mgr.get_or_create_tmux_pane(aid)
    try:
        assert name.startswith(f"swarm-{aid}-")
        # UUID4 is 36 chars (32 hex + 4 dashes). Just check the suffix
        # is non-empty and the right shape — full validation is overkill.
        suffix = name[len(f"swarm-{aid}-"):]
        assert len(suffix) >= 32, f"UUID suffix looks too short: {suffix!r}"
        assert "-" in suffix, "expected a UUID4 (with dashes)"
        assert _tmux_has_session(name), f"session {name} not in tmux ls"
        assert pane_id.startswith("%"), f"unexpected pane id format: {pane_id!r}"
    finally:
        asyncio.run(mgr.cleanup_agent(aid))


# ── Test 2: Two agents in one process get distinct sessions ──────────────────


def test_different_agents_get_distinct_sessions():
    """Concurrent workers MUST NOT collide on a session name."""
    from src.tools.shell.manager import ShellManager

    mgr = ShellManager()
    a1 = _agent_id("multi-a")
    a2 = _agent_id("multi-b")
    name1, _ = mgr.get_or_create_tmux_pane(a1)
    name2, _ = mgr.get_or_create_tmux_pane(a2)
    try:
        assert name1 != name2
        assert _tmux_has_session(name1)
        assert _tmux_has_session(name2)
    finally:
        asyncio.run(mgr.cleanup_agent(a1))
        asyncio.run(mgr.cleanup_agent(a2))


# ── Test 3: Same agent_id reuses its session across calls ────────────────────


def test_same_agent_reuses_session():
    """Calling get_or_create_tmux_pane twice for one agent_id returns the
    same session — state (cd, env vars) persists across that worker's
    tool calls. This is the per-call vs per-worker UUID decision."""
    from src.tools.shell.manager import ShellManager

    mgr = ShellManager()
    aid = _agent_id("reuse")
    name1, pane1 = mgr.get_or_create_tmux_pane(aid)
    name2, pane2 = mgr.get_or_create_tmux_pane(aid)
    try:
        assert name1 == name2, "same agent_id must reuse session"
        assert pane1 == pane2, "same agent_id must reuse pane"
    finally:
        asyncio.run(mgr.cleanup_agent(aid))


# ── Test 4: cleanup_agent removes ONLY this agent's session ──────────────────


async def test_cleanup_agent_removes_only_targeted_session():
    """Critical for parallel-runs safety: cleanup_agent for worker A
    must not touch worker B's session."""
    from src.tools.shell.manager import ShellManager

    mgr = ShellManager()
    a1 = _agent_id("cleanup-a")
    a2 = _agent_id("cleanup-b")
    name1, _ = mgr.get_or_create_tmux_pane(a1)
    name2, _ = mgr.get_or_create_tmux_pane(a2)
    assert _tmux_has_session(name1)
    assert _tmux_has_session(name2)

    await mgr.cleanup_agent(a1)

    assert not _tmux_has_session(name1), "agent-A session should be gone"
    assert _tmux_has_session(name2), "agent-B session should be untouched"

    await mgr.cleanup_agent(a2)
    assert not _tmux_has_session(name2)


# ── Test 5: cleanup_all wipes everything THIS process owns ───────────────────


async def test_cleanup_all_wipes_every_session():
    from src.tools.shell.manager import ShellManager

    mgr = ShellManager()
    aids = [_agent_id(f"all-{i}") for i in range(3)]
    names = [mgr.get_or_create_tmux_pane(a)[0] for a in aids]
    for n in names:
        assert _tmux_has_session(n)

    await mgr.cleanup_all()

    for n in names:
        assert not _tmux_has_session(n), f"{n} should have been cleaned up"


# ── Test 6: cleanup_all does NOT touch unrelated tmux sessions ───────────────


async def test_cleanup_all_does_not_touch_outside_sessions():
    """Strix-style scoping: the manager only kills sessions IT created.
    Externally-created tmux sessions (e.g. user's own work) must survive.
    This is what makes the design safe for two parallel SwarmAttacker
    runs on the same machine."""
    from src.tools.shell.manager import ShellManager

    # Simulate "another process's session" — same naming convention
    # (swarm-*) but NOT created via this manager instance.
    outside_name = f"swarm-outside-{_TEST_RUN_TAG}-{uuid.uuid4()}"
    subprocess.run(
        ["tmux", "new-session", "-d", "-s", outside_name],
        check=True, capture_output=True,
    )
    try:
        assert _tmux_has_session(outside_name)

        mgr = ShellManager()
        aid = _agent_id("cleanup-scope")
        mine, _ = mgr.get_or_create_tmux_pane(aid)
        assert _tmux_has_session(mine)

        await mgr.cleanup_all()

        assert not _tmux_has_session(mine), "my session should be gone"
        assert _tmux_has_session(outside_name), (
            "outside session must NOT have been killed — that would break "
            "parallel SwarmAttacker runs (each manager would wipe the "
            "other's live sessions)."
        )
    finally:
        _kill_session(outside_name)


# ── Test 7: Stale session (killed externally) is recreated transparently ────


def test_stale_session_recreates_on_next_call():
    """If someone runs ``tmux kill-server`` mid-run, the next pane
    lookup should silently create a fresh session instead of returning
    a dead pane id."""
    from src.tools.shell.manager import ShellManager

    mgr = ShellManager()
    aid = _agent_id("stale")
    name1, pane1 = mgr.get_or_create_tmux_pane(aid)
    assert _tmux_has_session(name1)

    # Kill the session externally
    _kill_session(name1)
    assert not _tmux_has_session(name1)

    # Next call should detect the stale pane and create a new session
    name2, pane2 = mgr.get_or_create_tmux_pane(aid)
    try:
        # Session name is the strong identity signal: a brand-new UUID
        # means the manager actually recreated, not handed back the
        # cached dead reference.
        assert name2 != name1, "expected a brand new UUID-suffixed session"
        assert _tmux_has_session(name2)
        # Note: we deliberately do NOT compare ``pane2 != pane1``. tmux
        # pane ids (``%0``, ``%1``, …) are reused after a session is
        # destroyed — the next session's first pane is also ``%0`` if
        # no other sessions exist on the server. The session-name
        # check above is sufficient to prove recreation.
    finally:
        asyncio.run(mgr.cleanup_agent(aid))


# ── Subprocess scenario tests ────────────────────────────────────────────────
#
# These spawn a child Python process that imports the manager and exercises
# the lifecycle the way a real SwarmAttacker run would. We then check the
# parent-side ``tmux ls`` to verify cleanup ran (or didn't).


_CHILD_TEMPLATE = """
import sys, time, os
from src.tools.shell.manager import get_shell_manager

mgr = get_shell_manager()
name, _ = mgr.get_or_create_tmux_pane("{agent_id}")
# Print + flush so the parent reads the session name BEFORE we
# do whatever the test wants us to do next.
print(name, flush=True)

{action}
"""


def _spawn_child(agent_id: str, action: str) -> subprocess.Popen:
    """Spawn a child Python process that creates a session then runs ``action``.

    ``action`` is a snippet of Python code (with no leading indent — it
    appears at module level after the session is created). The child
    prints the session name on stdout's first line and flushes.
    """
    code = _CHILD_TEMPLATE.format(agent_id=agent_id, action=action)
    swarm_root = Path(__file__).resolve().parents[2]
    return subprocess.Popen(
        [sys.executable, "-c", code],
        cwd=str(swarm_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )


def _read_session_name(proc: subprocess.Popen, timeout: float = 15.0) -> str:
    """Read the first line of stdout (the session name)."""
    deadline = time.time() + timeout
    name_line = ""
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line:
            name_line = line.strip()
            if name_line.startswith("swarm-"):
                return name_line
        elif proc.poll() is not None:
            # Child died before printing
            stderr = proc.stderr.read()
            raise RuntimeError(
                f"child exited early (rc={proc.returncode}) before printing "
                f"the session name. stderr:\n{stderr}"
            )
        time.sleep(0.1)
    raise TimeoutError(
        f"child never printed a session name in {timeout}s; got: {name_line!r}"
    )


# ── Test 8: atexit fires on normal exit ──────────────────────────────────────


def test_atexit_cleans_up_on_normal_exit():
    """Child process creates a session, exits cleanly via sys.exit(0).
    atexit hook MUST kill the session before the process is gone."""
    aid = _agent_id("atexit-normal")
    proc = _spawn_child(aid, "import sys; sys.exit(0)")
    try:
        name = _read_session_name(proc)
        proc.wait(timeout=10)
        assert proc.returncode == 0, f"child exit code: {proc.returncode}"
        # Give tmux a moment to actually drop the session metadata.
        time.sleep(0.3)
        assert not _tmux_has_session(name), (
            f"atexit should have killed {name} on normal exit"
        )
    finally:
        if proc.poll() is None:
            proc.kill()


# ── Test 9: atexit fires on uncaught exception ───────────────────────────────


def test_atexit_cleans_up_on_uncaught_exception():
    """Same as above but the child dies via an uncaught exception."""
    aid = _agent_id("atexit-exc")
    proc = _spawn_child(aid, "raise RuntimeError('intentional')")
    try:
        name = _read_session_name(proc)
        proc.wait(timeout=10)
        assert proc.returncode != 0, "expected non-zero exit on exception"
        time.sleep(0.3)
        assert not _tmux_has_session(name), (
            f"atexit should still kill {name} when child dies via exception"
        )
    finally:
        if proc.poll() is None:
            proc.kill()


# ── Test 10: SIGTERM handler runs cleanup ────────────────────────────────────


def test_sigterm_handler_cleans_up():
    """Child sleeps; we send SIGTERM; the handler should kill the
    session before sys.exit(143)."""
    aid = _agent_id("sigterm")
    proc = _spawn_child(aid, "import time; time.sleep(60)")
    try:
        name = _read_session_name(proc)
        # Confirm the session exists before signaling
        assert _tmux_has_session(name)

        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        assert proc.returncode == 143, (
            f"expected SIGTERM exit code 143, got {proc.returncode}"
        )
        time.sleep(0.3)
        assert not _tmux_has_session(name), (
            f"SIGTERM handler should have killed {name}"
        )
    finally:
        if proc.poll() is None:
            proc.kill()


# ── Test 11: SIGINT (Ctrl+C) handler runs cleanup ────────────────────────────


def test_sigint_handler_cleans_up():
    """Same as SIGTERM but with SIGINT — simulates the user hitting Ctrl+C
    in the middle of a benchmark run."""
    aid = _agent_id("sigint")
    proc = _spawn_child(aid, "import time; time.sleep(60)")
    try:
        name = _read_session_name(proc)
        assert _tmux_has_session(name)

        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=10)
        assert proc.returncode == 130, (
            f"expected SIGINT exit code 130, got {proc.returncode}"
        )
        time.sleep(0.3)
        assert not _tmux_has_session(name), (
            f"SIGINT handler should have killed {name}"
        )
    finally:
        if proc.poll() is None:
            proc.kill()


# ── Test 12: SIGKILL leaks (documents the known limitation) ──────────────────


def test_sigkill_leaks_session_documented_limitation():
    """SIGKILL bypasses both atexit and the signal handler — by design,
    this leaks a tmux session. This test PINS that behaviour so future
    refactors that try to "fix" it (and add complexity) get a visible
    regression to defend instead.

    If you ever want to plug this hole, add the PID-based orphan reaper
    we discussed (see plan ``concurrent-kindling-pillow.md``).
    """
    aid = _agent_id("sigkill")
    proc = _spawn_child(aid, "import time; time.sleep(60)")
    try:
        name = _read_session_name(proc)
        assert _tmux_has_session(name)

        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)
        time.sleep(0.3)
        assert _tmux_has_session(name), (
            "SIGKILL is expected to leak — if cleanup ran, either the "
            "test is buggy or someone added the orphan reaper. Update "
            "this test or the docs."
        )
    finally:
        # Manual cleanup since the leak is intentional
        _kill_session(name)


# ── Test 13: Two parallel child processes don't collide ──────────────────────


def test_parallel_child_processes_dont_collide():
    """Two independent SwarmAttacker processes (different PIDs) creating
    sessions for the same agent_id must NOT collide. This is the
    parallel-run capability the refactor unlocks — today it's broken
    on main due to the global ``"swarmattacker"`` session name."""
    aid = _agent_id("parallel")
    # Both children create a session for the SAME agent_id — they get
    # different UUIDs and thus different session names. Each holds its
    # session for a few seconds.
    proc1 = _spawn_child(aid, "import time; time.sleep(3)")
    name1 = _read_session_name(proc1)

    proc2 = _spawn_child(aid, "import time; time.sleep(3)")
    name2 = _read_session_name(proc2)

    try:
        # Different UUIDs in the suffix → different session names
        assert name1 != name2, (
            f"parallel processes for same agent_id must have unique "
            f"sessions, got {name1!r} == {name2!r}"
        )
        # Both sessions live concurrently
        assert _tmux_has_session(name1)
        assert _tmux_has_session(name2)

        # Wait for normal exit — atexit fires in each
        proc1.wait(timeout=10)
        proc2.wait(timeout=10)
        time.sleep(0.3)

        assert not _tmux_has_session(name1), "child-1 atexit should fire"
        assert not _tmux_has_session(name2), "child-2 atexit should fire"
    finally:
        for p in (proc1, proc2):
            if p.poll() is None:
                p.kill()


# ── Test 14: bash subprocess lifecycle ───────────────────────────────────────


async def test_bash_session_created_and_cleaned():
    """Verify the bash side of the manager works end-to-end:
    create a BashSession, verify its subprocess is alive, cleanup_agent
    kills it."""
    from src.tools.shell.manager import get_shell_manager

    mgr = get_shell_manager()
    aid = _agent_id("bash-life")
    sess = await mgr.get_or_create_bash(aid)
    try:
        assert sess.proc.returncode is None, "bash subprocess should be alive"
        pid = sess.proc.pid
        # Sanity check the PID actually exists at the OS level
        os.kill(pid, 0)  # raises if dead
    finally:
        await mgr.cleanup_agent(aid)
        # Give wait() a moment to register
        await asyncio.sleep(0.1)
        assert sess.proc.returncode is not None, (
            "bash subprocess should be dead after cleanup_agent"
        )


# ── Test 15: cleanup_agent kills BOTH tmux + bash for the same agent ────────


async def test_cleanup_agent_kills_both_tmux_and_bash():
    """One worker holds both a tmux session AND a bash subprocess.
    cleanup_agent should free both."""
    from src.tools.shell.manager import get_shell_manager

    mgr = get_shell_manager()
    aid = _agent_id("both")
    name, _ = mgr.get_or_create_tmux_pane(aid)
    sess = await mgr.get_or_create_bash(aid)
    pid = sess.proc.pid

    assert _tmux_has_session(name)
    os.kill(pid, 0)  # bash alive

    await mgr.cleanup_agent(aid)
    await asyncio.sleep(0.1)

    assert not _tmux_has_session(name), "tmux session should be gone"
    assert sess.proc.returncode is not None, "bash should be dead"
