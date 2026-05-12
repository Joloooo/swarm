"""Shell session lifecycle owner — singleton registered at module import.

Every tmux session and bash subprocess this process creates flows through
:data:`_MANAGER`. Cleanup is wired at construction time via ``atexit`` +
signal handlers, so it fires on process exit even if no shell tool is ever
called.

Why a singleton at module level
-------------------------------
The atexit hook must be registered BEFORE any shell session exists; if we
deferred registration to first-tool-use, a worker that crashed before its
first tool call could leave sessions dangling (atexit was never armed).
Module-level instantiation guarantees the cleanup chain is in place the
moment any code imports from ``src.tools.shell``.

Pattern mirrors Strix's ``TerminalManager``
(``Implementations/strix/strix/tools/terminal/terminal_manager.py``):

* one session per worker, UUID-suffixed name (collision-free even across
  parallel SwarmAttacker runs on the same machine);
* per-worker ``cleanup_agent(agent_id)`` that the worker finally-block
  calls so sessions don't pile up across one long graph run;
* process-wide ``cleanup_all()`` (async) and ``_sync_cleanup_all()``
  (atexit-safe) that wipe every session this process created;
* ``signal.SIGINT`` / ``SIGTERM`` handlers that fire ``_sync_cleanup_all``
  before exiting so Ctrl+C and ``kill <pid>`` don't leak.

What this does NOT cover (accepted limitation per the plan): SIGKILL,
OOM-kill, power loss. Those bypass atexit and signal handlers entirely.
Manual cleanup if leaks accumulate: ``tmux kill-server`` (also takes out
non-SwarmAttacker sessions, so use deliberately) or
``tmux ls | grep '^swarm-' | cut -d: -f1 | xargs -n1 tmux kill-session -t``.
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import logging
import signal
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from src.tools.shell._common import log_event as _log_event, workspace_for

logger = logging.getLogger(__name__)


# ── Bash session record (moved here from bash.py) ────────────────────────────


@dataclass
class BashSession:
    """One long-running bash subprocess for one agent.

    The lock serialises commands sent to *this* bash; different agents
    have different sessions and run in parallel.

    Lives in manager.py (was bash.py) so the per-agent lifecycle is owned
    by the same module that registers atexit / signal handlers.
    """
    agent_id: str
    proc: asyncio.subprocess.Process
    workspace: Path
    cwd: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


# ── The manager ──────────────────────────────────────────────────────────────


class ShellManager:
    """Owns every shell session this process creates.

    Public surface:
      - :meth:`get_or_create_tmux_pane` — sync, returns ``(session_name, pane_id)``.
      - :meth:`get_or_create_bash` — async, returns a :class:`BashSession`.
      - :meth:`cleanup_agent` — async, kills BOTH this agent's tmux session
        AND its bash subprocess. Called from the worker finally-block.
      - :meth:`cleanup_all` — async, calls cleanup_agent for every tracked id.
      - Class constants centralise default tool config (was scattered across
        bash.py / tmux.py).
    """

    # Centralised tool config. Tmux pane geometry matters because some
    # tools (less, vim, nmap progress lines) reflow based on terminal
    # size; the defaults here match what real terminals report so output
    # stays parseable.
    DEFAULT_TIMEOUT_S = 120     # was _DEFAULT_TIMEOUT_S in bash.py
    DEFAULT_PANE_WIDTH = 200
    DEFAULT_PANE_HEIGHT = 50

    def __init__(self) -> None:
        # tmux: one session per agent, UUID-suffixed name, lazily created
        self._tmux_sessions: dict[str, str] = {}   # agent_id -> session_name
        self._tmux_panes: dict[str, str] = {}      # agent_id -> pane_id
        self._tmux_lock = threading.Lock()

        # bash: one BashSession per agent
        self._bash_sessions: dict[str, BashSession] = {}
        # asyncio.Lock — created lazily so the manager can be instantiated
        # at module import time when no event loop exists yet.
        self._bash_lock: asyncio.Lock | None = None

        self._closed = False
        self._register_cleanup_handlers()

    # ── Tmux side ────────────────────────────────────────────────────────────

    def get_or_create_tmux_pane(self, agent_id: str) -> tuple[str, str]:
        """Return ``(session_name, pane_id)`` for this agent.

        First call for an ``agent_id``: creates a fresh session named
        ``swarm-{agent_id}-{uuid4}`` and CDs the pane into the agent's
        workspace. Subsequent calls reuse the cached pane (verified to
        still exist).

        Concurrency-safe: the per-agent registry is guarded by a thread
        lock. Two parallel ``Send([])`` workers calling for different
        ``agent_id``s hit the same lock briefly but never collide on a
        session name (UUIDs are unique).

        Why per-agent UUID-suffixed sessions (vs. shared session +
        per-agent windows): two parallel SwarmAttacker runs on the same
        machine used to collide on the global ``"swarmattacker"`` session
        name. Now each run's worker gets its own UUID, and cleanup is
        scoped to the sessions THIS process created — never touches
        another process's live sessions.
        """
        with self._tmux_lock:
            cached_pane = self._tmux_panes.get(agent_id)
            if cached_pane is not None:
                # Validate the cached pane still exists; the session may
                # have been killed externally (e.g. by `tmux kill-server`
                # during dev) between calls.
                check = subprocess.run(
                    ["tmux", "list-panes", "-t", cached_pane],
                    capture_output=True,
                )
                if check.returncode == 0:
                    _log_event("pane_reuse", agent=agent_id, pane=cached_pane)
                    return self._tmux_sessions[agent_id], cached_pane
                _log_event("pane_stale", agent=agent_id, pane=cached_pane)
                self._tmux_panes.pop(agent_id, None)
                self._tmux_sessions.pop(agent_id, None)

            session_name = f"swarm-{agent_id}-{uuid.uuid4()}"
            try:
                subprocess.run(
                    [
                        "tmux", "new-session", "-d", "-s", session_name,
                        "-x", str(self.DEFAULT_PANE_WIDTH),
                        "-y", str(self.DEFAULT_PANE_HEIGHT),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                stderr = (e.stderr or "").strip()
                _log_event(
                    "tmux_session_create_failed",
                    agent=agent_id, session=session_name,
                    rc=e.returncode, stderr=stderr,
                )
                # UUID-suffixed name should make collision impossible; if
                # this still fails something is genuinely wrong (e.g.
                # tmux not installed). Surface it.
                raise RuntimeError(
                    f"tmux session creation failed (rc={e.returncode}): "
                    f"{stderr}"
                ) from e

            # The new session has exactly one pane — fetch its id.
            result = subprocess.run(
                ["tmux", "list-panes", "-t", session_name,
                 "-F", "#{pane_id}"],
                capture_output=True,
                text=True,
                check=True,
            )
            pane_id = result.stdout.strip()
            self._tmux_sessions[agent_id] = session_name
            self._tmux_panes[agent_id] = pane_id

            # CD the pane into the agent's workspace so relative paths in
            # output flags (e.g. ``nmap -oX scan.xml``) land somewhere
            # predictable and the bash tool's workspace_for() agrees.
            try:
                ws = workspace_for(agent_id)
                subprocess.run(
                    ["tmux", "send-keys", "-t", pane_id, f"cd {ws}", "Enter"],
                    check=True,
                )
            except Exception as e:  # noqa: BLE001
                _log_event(
                    "pane_workspace_cd_failed",
                    agent=agent_id, pane=pane_id, error=str(e),
                )

            _log_event(
                "tmux_session_create",
                agent=agent_id, session=session_name, pane=pane_id,
            )
            return session_name, pane_id

    # ── Bash side ────────────────────────────────────────────────────────────

    def _ensure_bash_lock(self) -> asyncio.Lock:
        """Lazily create the bash registry lock once an event loop exists.

        We can't create the asyncio.Lock at __init__ because the manager
        is instantiated at module import (no event loop yet).
        """
        if self._bash_lock is None:
            self._bash_lock = asyncio.Lock()
        return self._bash_lock

    async def get_or_create_bash(self, agent_id: str) -> BashSession:
        """Return this agent's bash session, spawning a fresh one if needed.

        Re-spawns transparently if a prior subprocess has died (someone
        killed the bash out from under us, or a previous in-process
        `cleanup_agent` ran).
        """
        async with self._ensure_bash_lock():
            sess = self._bash_sessions.get(agent_id)
            if sess is not None and sess.proc.returncode is None:
                return sess
            if sess is not None:
                _log_event(
                    "bash_session_dead",
                    agent=agent_id, returncode=sess.proc.returncode,
                )
            sess = await self._spawn_bash(agent_id)
            self._bash_sessions[agent_id] = sess
            return sess

    async def _spawn_bash(self, agent_id: str) -> BashSession:
        """Start a fresh bash subprocess for *agent_id* and CD into its workspace.

        ``bash --noprofile --norc`` keeps the shell deterministic across
        operator machines (no user .bashrc affecting agent runs).
        ``start_new_session=True`` puts bash in its own process group so
        we can SIGINT a hanging child command without killing bash itself.
        """
        workspace = workspace_for(agent_id)
        proc = await asyncio.create_subprocess_exec(
            "bash", "--noprofile", "--norc",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(workspace),
            start_new_session=True,
        )
        sess = BashSession(
            agent_id=agent_id,
            proc=proc,
            workspace=workspace,
            cwd=str(workspace),
        )
        _log_event(
            "bash_spawn",
            agent=agent_id, pid=proc.pid, workspace=str(workspace),
        )
        return sess

    # ── Per-agent cleanup ────────────────────────────────────────────────────

    async def cleanup_agent(self, agent_id: str) -> None:
        """Kill this agent's tmux session AND bash subprocess. Idempotent.

        Called from the worker finally-block in
        ``src/nodes/base/skill_runner.py`` so per-worker resources are
        freed the moment the worker finishes (success, exception,
        salvage, or refusal). Without this, sessions accumulate across
        one long graph run that dispatches many workers.
        """
        # tmux side
        with self._tmux_lock:
            session = self._tmux_sessions.pop(agent_id, None)
            self._tmux_panes.pop(agent_id, None)
        if session:
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["tmux", "kill-session", "-t", session],
                    capture_output=True,
                    timeout=5,
                )
            _log_event("tmux_session_kill", agent=agent_id, session=session)

        # bash side — graceful close (send "exit\n", wait, then SIGKILL)
        async with self._ensure_bash_lock():
            sess = self._bash_sessions.pop(agent_id, None)
        if sess is not None:
            await self._kill_bash_graceful(sess)

    async def _kill_bash_graceful(self, sess: BashSession) -> None:
        """Best-effort graceful shutdown of a bash subprocess.

        Send ``exit\\n`` to stdin so bash flushes any pending writes and
        exits cleanly; if it doesn't die within 1 s, SIGKILL it.
        """
        try:
            if sess.proc.stdin and not sess.proc.stdin.is_closing():
                sess.proc.stdin.write(b"exit\n")
                await sess.proc.stdin.drain()
                sess.proc.stdin.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            await asyncio.wait_for(sess.proc.wait(), timeout=1.0)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                sess.proc.kill()
                await sess.proc.wait()
            except (ProcessLookupError, OSError):
                pass
        _log_event(
            "bash_kill",
            agent=sess.agent_id, returncode=sess.proc.returncode,
        )

    # ── Process-wide cleanup ─────────────────────────────────────────────────

    async def cleanup_all(self) -> None:
        """Async cleanup of every tracked session this process owns.

        Called by the CLI / benchmark teardown when an event loop is
        still available. For atexit (no event loop), see
        :meth:`_sync_cleanup_all`.
        """
        # Snapshot the union of agent ids before iterating — cleanup_agent
        # mutates both registries, so we want a stable iteration set.
        agent_ids = set(self._tmux_sessions.keys()) | set(
            self._bash_sessions.keys()
        )
        for aid in agent_ids:
            try:
                await self.cleanup_agent(aid)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "cleanup_all: cleanup_agent(%r) failed: %s", aid, e,
                )

    def _sync_cleanup_all(self) -> None:
        """Sync wrapper for atexit (which can't await).

        Uses ``subprocess`` for tmux (already sync) and ``proc.kill()``
        for bash (no time for graceful drain — the interpreter is
        already shutting down). Idempotent: a second call is a no-op so
        explicit `cleanup_all` followed by atexit doesn't double-clean.
        """
        if self._closed:
            return
        self._closed = True

        # tmux: kill every session we created
        with self._tmux_lock:
            sessions = list(self._tmux_sessions.values())
            self._tmux_sessions.clear()
            self._tmux_panes.clear()
        for session in sessions:
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["tmux", "kill-session", "-t", session],
                    capture_output=True,
                    timeout=2,
                )

        # bash: kill subprocess directly. No event loop, no graceful exit.
        bash_sessions = list(self._bash_sessions.values())
        self._bash_sessions.clear()
        for sess in bash_sessions:
            with contextlib.suppress(Exception):
                sess.proc.kill()

    # ── Signal / atexit registration ─────────────────────────────────────────

    def _signal_handler(self, signum: int, frame) -> None:
        """SIGINT / SIGTERM handler — clean up then exit.

        Exit codes follow shell convention: 130 for SIGINT (128 + 2),
        143 for SIGTERM (128 + 15). atexit hooks fire on sys.exit() so
        any other registered cleanup also runs.
        """
        self._sync_cleanup_all()
        sys.exit(130 if signum == signal.SIGINT else 143)

    def _register_cleanup_handlers(self) -> None:
        """Wire up atexit + signal handlers ONCE at construction.

        Signal handlers can only be set in the main thread; we silently
        skip if we're being imported from a worker thread (langgraph
        dev's hot-reload path can do this). atexit always succeeds.
        """
        atexit.register(self._sync_cleanup_all)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                # Not in main thread, or already overridden — accept.
                pass


# ── Module-level singleton ───────────────────────────────────────────────────
#
# Instantiated at import time so atexit + signal handlers are armed the
# moment ANY code touches src.tools.shell, regardless of whether a tool
# function ever fires.
_MANAGER = ShellManager()


def get_shell_manager() -> ShellManager:
    """Public accessor for the per-process :class:`ShellManager` singleton."""
    return _MANAGER


__all__ = ["BashSession", "ShellManager", "get_shell_manager"]
