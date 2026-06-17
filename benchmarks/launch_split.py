"""One-command fan-out: run the XBEN benchmark set across N terminals.

This automates the manual workflow of "open ~20 terminal windows, paste a
slice of the benchmark list into each, hit Enter". By default it puts the whole
benchmark list into ONE shared work-queue and launches N terminal sessions that
each PULL the next pending benchmark when they're free — so a session that draws
easy benches keeps working instead of idling while a slow lane grinds for hours
(dynamic load-balancing). ``--static`` restores the legacy fixed-slice split.

Everything from one run is collected under a single **campaign directory**,
``logs/<campaign>/``, so a parallel sweep is as tidy as the manual
``logs/1_full_run`` folder used to be:

    logs/<campaign>/
        queue.json              shared pending/running/done work-queue (default)
        workers                 number of worker sessions launched
        slices/slice_NN.txt     legacy: ids per session (only with --static)
        run-*/                  every per-run log dir (via SWARM_LOGS_ROOT)
        results/<id>.json       one verdict per benchmark (via SWARM_RESULTS_DIR)
        .done/worker_NN         marker each session touches when it exits
        summary.json/.txt       written by benchmarks/campaign_report

Each session is a fully independent OS process: its own PID, its own
loopback IP leased from ``benchmarks/.loopback_leases/`` (so targets don't
collide on ports), and — thanks to the two env vars above — its own files
under the campaign dir. After spawning the windows, the launching terminal
becomes a live dashboard (``campaign_report.watch_and_report``) that prints
the combined pass/fail/crash table once every session has finished.

Two launch backends, picked with ``--tmux``:

* **osascript (default)** — opens N real macOS Terminal.app windows. Each is
  a fresh, ``$TMUX``-free shell, so the agent's OWN tmux (it drives tmux
  internally for tool sessions) starts clean with no nesting. This is the
  recommended backend.
* **tmux** — one detached tmux session with one window per slice. NOTE: the
  agent uses tmux on the default socket, so running the sweep inside an
  outer tmux risks nesting; prefer osascript unless you know you want this.

Usage::

    uv run python -m benchmarks.launch_split                 # 20 Terminal windows, then dashboard
    uv run python -m benchmarks.launch_split --jobs 8        # 8 sessions
    uv run python -m benchmarks.launch_split --name nightly  # name the campaign dir
    uv run python -m benchmarks.launch_split --stagger 5     # 5s between docker ups (gentler)
    uv run python -m benchmarks.launch_split --resume        # skip ids already in this campaign
    uv run python -m benchmarks.launch_split --no-wait       # spawn only; don't open the dashboard
    uv run python -m benchmarks.launch_split --dry-run       # print the plan + commands, launch nothing

Re-print a finished (or in-flight) campaign any time::

    uv run python -m benchmarks.campaign_report logs/<campaign>
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # SwarmAttacker/
DEFAULT_LIST = ROOT / "benchmarks" / "all_xben_24.txt"
LOGS_ROOT = ROOT / "logs"                            # campaign dirs live here
LOOPBACK_POOL = 20                                   # matches loopback.POOL size


def read_ids(list_file: Path) -> list[str]:
    """Read benchmark IDs, dropping blank lines and ``#`` comments."""
    if not list_file.exists():
        sys.exit(f"list file not found: {list_file}")
    ids: list[str] = []
    for raw in list_file.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            ids.append(line)
    if not ids:
        sys.exit(f"no benchmark ids in {list_file}")
    return ids


def split_contiguous(ids: list[str], n: int) -> list[list[str]]:
    """Split ``ids`` into ``n`` contiguous, size-balanced slices.

    The first ``len(ids) % n`` slices get one extra id, so 104 ids over 20
    slices yields 4 slices of 6 then 16 of 5 — exactly the "first few get
    six, the rest five" division. ``n`` is clamped to ``len(ids)`` so no
    empty slices are produced.
    """
    n = max(1, min(n, len(ids)))
    base, extra = divmod(len(ids), n)
    slices: list[list[str]] = []
    i = 0
    for k in range(n):
        size = base + (1 if k < extra else 0)
        slices.append(ids[i:i + size])
        i += size
    return slices


def campaign_name(explicit: str | None) -> str:
    """Campaign dir name: ``--name`` if given, else ``full_run_<MM-DD_HHhMMm>``."""
    if explicit:
        # keep it filesystem-safe
        return "".join(c if (c.isalnum() or c in "-_.") else "-" for c in explicit)
    return f"full_run_{time.strftime('%m-%d_%Hh%Mm')}"


def slice_paths_for(campaign: Path, n: int) -> list[Path]:
    """The slice file paths a campaign of ``n`` slices will use (no I/O)."""
    return [campaign / "slices" / f"slice_{k:02d}.txt" for k in range(n)]


def materialize_campaign(campaign: Path, slices: list[list[str]],
                         *, resume: bool = False) -> None:
    """Create logs/<name>/{slices,results,.done} and write the slice files.

    Only called on a real launch — never in ``--dry-run`` — so a preview
    leaves no empty campaign dir behind in ``logs/``.

    Stale slices and done-markers from a same-named prior campaign are
    always cleared. Old ``results/<id>.json`` files are cleared too on a
    FRESH run (``resume=False``) so a re-run under a reused name starts
    clean and its summary isn't polluted by the previous run's verdicts;
    on ``resume=True`` they are kept, because that is exactly the state
    ``--resume`` reads to skip already-finished benchmarks.
    """
    (campaign / "slices").mkdir(parents=True, exist_ok=True)
    (campaign / "results").mkdir(parents=True, exist_ok=True)
    (campaign / ".done").mkdir(parents=True, exist_ok=True)
    for old in (campaign / "slices").glob("slice_*.txt"):
        old.unlink()
    for old in (campaign / ".done").glob("slice_*"):
        old.unlink()
    if not resume:
        for old in (campaign / "results").glob("*.json"):
            old.unlink()
    for p, slice_ids in zip(slice_paths_for(campaign, len(slices)), slices):
        p.write_text("\n".join(slice_ids) + "\n")


# SWARM_* vars the campaign owns per-session — never forwarded from the
# parent env (the launcher sets these itself, fresh, for each window).
_CAMPAIGN_OWNED_ENV = {"SWARM_LOGS_ROOT", "SWARM_RESULTS_DIR"}


def _shquote(s: str) -> str:
    """POSIX single-quote a string so it survives the shell intact.

    Robust to spaces (the repo can live under '.../My Drive/...') and to
    embedded single quotes. Safe inside both the AppleScript double-quoted
    ``do script`` string and a tmux ``send-keys`` argument.
    """
    return "'" + s.replace("'", "'\\''") + "'"


def inherited_swarm_env() -> dict[str, str]:
    """Current ``SWARM_*`` env (minus campaign-owned vars), to forward.

    osascript/tmux open FRESH shells that do NOT inherit this process's
    environment. Menu config (model/budgets/verbosity) is NOT carried this
    way — each session reads swarm-config.toml directly via src.graph. This
    only forwards any genuine shell ``SWARM_*`` overrides the user exported
    (e.g. advanced knobs like ``SWARM_PROVIDER``), so they reach each session.
    Empty when nothing is set, so a bare standalone run is unchanged.
    """
    return {
        k: v for k, v in os.environ.items()
        if k.startswith("SWARM_") and k not in _CAMPAIGN_OWNED_ENV
    }


def runner_cmd(source: str, campaign: Path, marker: str,
               runner_flags: list[str]) -> str:
    """Shell command one session runs.

    ``source`` is the already-shell-quoted runner source flag — either
    ``--queue '<campaign>'`` (dynamic pull, the default) or
    ``--list-file '<slice>'`` (legacy static). Forwards the parent's
    ``SWARM_*`` env (model config + Codex account), sets SWARM_LOGS_ROOT +
    SWARM_RESULTS_DIR so the session's logs and results land under the campaign
    dir, then touches a done-marker AFTER the runner exits (``;`` not ``&&`` so
    the marker is written even if the run errors). Everything is shell-quoted,
    so spaces in paths/values are safe inside the AppleScript / tmux command.
    """
    flags = " ".join(runner_flags)
    forwarded = "".join(
        f"{k}={_shquote(v)} " for k, v in sorted(inherited_swarm_env().items())
    )
    return (
        f"cd {_shquote(str(ROOT))} && "
        f"{forwarded}"
        f"SWARM_LOGS_ROOT={_shquote(str(campaign))} "
        f"SWARM_RESULTS_DIR={_shquote(str(campaign / 'results'))} "
        f"uv run python -m benchmarks.xbow_runner "
        f"{source} {flags} ; "
        f"touch {_shquote(str(campaign / '.done' / marker))}"
    )


def _recorded_ids(campaign: Path) -> set[str]:
    """Benchmark ids this campaign already has a result file for (for --resume)."""
    rd = campaign / "results"
    ids: set[str] = set()
    if rd.is_dir():
        for p in rd.glob("*.json"):
            try:
                row = json.loads(p.read_text(encoding="utf-8"))
                ids.add(row.get("benchmark_id") or p.stem)
            except (OSError, json.JSONDecodeError):
                ids.add(p.stem)
    return ids


def materialize_queue_campaign(
    campaign: Path, ids: list[str], *,
    done_ids: set[str], n_workers: int, resume: bool,
) -> None:
    """Create the campaign dirs and seed the shared work-queue.

    Writes ``queue.json`` (pending = ``ids`` minus already-done), the
    ``workers`` count file the dashboard waits on, and a clean ``.done`` dir.
    On a fresh run old ``results`` are cleared; on ``--resume`` they are kept and
    become the ``done`` set, so anything without a result file (including a
    crashed session's in-flight bench) is re-queued automatically.
    """
    from benchmarks import work_queue
    (campaign / "results").mkdir(parents=True, exist_ok=True)
    (campaign / ".done").mkdir(parents=True, exist_ok=True)
    for old in (campaign / ".done").iterdir():
        if old.is_file():
            old.unlink()
    if not resume:
        for old in (campaign / "results").glob("*.json"):
            old.unlink()
    work_queue.init_queue(campaign, ids, done_ids=list(done_ids))
    (campaign / "workers").write_text(f"{n_workers}\n", encoding="utf-8")


def launch_osascript(cmds: list[str], stagger: float) -> None:
    """Open one Terminal.app window per command via AppleScript ``do script``.

    Each ``do script`` with no target window opens a NEW window, so N calls
    give N windows. ``stagger`` seconds between launches spaces out the
    concurrent ``docker compose up`` calls (gentler on the daemon and the
    docker network address-pool); 0 = launch as fast as possible.
    """
    for i, cmd in enumerate(cmds):
        script = f'tell application "Terminal" to do script "{cmd}"'
        subprocess.run(["osascript", "-e", script], check=True)
        if stagger and i < len(cmds) - 1:
            time.sleep(stagger)
    subprocess.run(
        ["osascript", "-e", 'tell application "Terminal" to activate'],
        check=False,
    )


def launch_tmux(cmds: list[str], stagger: float, session: str = "xben") -> None:
    """Create a detached tmux session with one window per command."""
    if subprocess.run(["tmux", "has-session", "-t", session],
                      capture_output=True).returncode == 0:
        sys.exit(
            f"tmux session '{session}' already exists — attach with "
            f"`tmux attach -t {session}` or kill it with "
            f"`tmux kill-session -t {session}`, then rerun."
        )
    for k, cmd in enumerate(cmds):
        win = f"s{k:02d}"
        if k == 0:
            subprocess.run(
                ["tmux", "new-session", "-d", "-s", session, "-n", win],
                check=True,
            )
        else:
            subprocess.run(
                ["tmux", "new-window", "-t", session, "-n", win], check=True,
            )
        subprocess.run(
            ["tmux", "send-keys", "-t", f"{session}:{win}", cmd, "Enter"],
            check=True,
        )
        if stagger and k < len(cmds) - 1:
            time.sleep(stagger)
    print(f"tmux session '{session}' started with {len(cmds)} windows.")
    print(f"  attach : tmux attach -t {session}")
    print(f"  detach : Ctrl-b d   ·   switch: Ctrl-b <number>")
    print(f"  kill   : tmux kill-session -t {session}")


def launch_campaign(
    *,
    jobs: int = 20,
    list_file: Path = DEFAULT_LIST,
    ids: list[str] | None = None,
    name: str | None = None,
    tmux: bool = False,
    stagger: float = 0.0,
    verbose: bool = False,
    silent: bool = False,
    build: bool = False,
    resume: bool = False,
    static: bool = False,
    wait: bool = True,
    interval: float = 5.0,
    dry_run: bool = False,
) -> Path:
    """Split the benchmark list and launch one terminal session per slice.

    The importable core shared by the ``__main__`` CLI and the ``swarm``
    TUI ("Run all benchmarks concurrently"). Returns the campaign Path.
    Pass ``ids`` to fan out an explicit benchmark list (the xbow picker's
    current selection); otherwise the canonical ``list_file`` is read.
    Forwards the caller's ``SWARM_*`` env into every session (see
    :func:`inherited_swarm_env`) so a TUI-launched campaign honours the
    selected Codex account and config. ``wait`` turns the CALLING terminal
    into the live dashboard once the sessions are spawned.

    Verbosity is inherited from the forwarded ``SWARM_VERBOSITY`` config by
    default (so a TUI campaign streams the same compact output as a normal
    single run); pass ``verbose=True`` or ``silent=True`` to override it.
    """
    # An explicit ``ids`` list (e.g. the TUI picker's current selection)
    # overrides ``list_file``; otherwise read the canonical benchmark list.
    ids = list(ids) if ids is not None else read_ids(list_file)

    if jobs > LOOPBACK_POOL and not tmux:
        print(
            f"note: --jobs {jobs} exceeds the {LOOPBACK_POOL}-IP loopback "
            f"pool; sessions past the {LOOPBACK_POOL}th fall back to shared "
            f"localhost and may see each other's ports.",
            file=sys.stderr,
        )

    name = campaign_name(name)
    campaign = LOGS_ROOT / name

    # Verbosity: by default pass NO flag, so each window's runner derives
    # its mode from the forwarded ``SWARM_VERBOSITY`` env (the swarm-config
    # verbosity setting, default "compact"). ``--verbose``/``--silent`` are
    # explicit overrides for that config — mutually exclusive, verbose wins.
    if verbose:
        runner_flags = ["--verbose"]
    elif silent:
        runner_flags = ["--silent"]
    else:
        runner_flags = []
    if not build:
        runner_flags.append("--skip-build")
    # Pace every window against the selected Codex account's 5-hour limit,
    # same as the sequential picker path (src/cli/runner.py). Each window waits
    # before starting a benchmark if 5-hour usage is ≥ the threshold (default
    # 90%), so a fan-out doesn't keep firing benchmarks straight into the limit.
    runner_flags.append("--usage-guard")

    if static:
        # Legacy fixed contiguous slices: each session owns a disjoint lane and
        # runs it in order. No rebalancing — kept behind --static for parity.
        if resume:
            runner_flags.append("--resume")
        slices = split_contiguous(ids, jobs)
        print(f"campaign: logs/{name}  (static slices)")
        print(f"{len(ids)} benchmarks → {len(slices)} sessions "
              f"({'tmux' if tmux else 'Terminal windows'}):")
        for k, s in enumerate(slices):
            print(f"  slice {k:02d}: {len(s):2d}  {s[0]}..{s[-1]}")
        slice_paths = slice_paths_for(campaign, len(slices))
        cmds = [
            runner_cmd(f"--list-file {_shquote(str(p))}", campaign,
                       f"slice_{k:02d}", runner_flags)
            for k, p in enumerate(slice_paths)
        ]
    else:
        # Default: one shared work-queue, N sessions PULL from it. A session
        # that finishes early grabs the next pending bench instead of idling
        # while a slow lane grinds — dynamic load-balancing. --resume is handled
        # by the queue (pending = ids minus already-recorded), so it is NOT
        # forwarded to the runner.
        done_ids = _recorded_ids(campaign) if resume else set()
        pending = [i for i in ids if i not in done_ids]
        n_workers = max(1, min(jobs, len(pending))) if pending else 0
        print(f"campaign: logs/{name}  (shared queue)")
        print(f"{len(pending)} benchmark(s) → 1 shared queue · {n_workers} "
              f"worker session(s) pulling "
              f"({'tmux' if tmux else 'Terminal windows'})")
        if done_ids:
            print(f"  resume: {len(done_ids)} already recorded, skipped")
        cmds = [
            runner_cmd(f"--queue {_shquote(str(campaign))}", campaign,
                       f"worker_{k:02d}", runner_flags)
            for k in range(n_workers)
        ]

    if not cmds:
        print("nothing to run (all benchmarks already recorded).")
        return campaign

    if dry_run:
        print("\ndry-run — commands that WOULD launch (no files written):")
        for c in cmds:
            print(f"  {c}")
        return campaign

    # Create the loopback isolation pool ONCE here — in this terminal, before
    # spawning the windows — so each window's runner finds it ready and they
    # don't each prompt for sudo. Idempotent: a no-op when the pool is already
    # up. (Each spawned runner also calls ensure_pool() as a backstop.)
    from benchmarks import loopback
    loopback.ensure_pool()

    if static:
        materialize_campaign(campaign, slices, resume=resume)
    else:
        materialize_queue_campaign(
            campaign, ids, done_ids=done_ids,
            n_workers=len(cmds), resume=resume,
        )

    if tmux:
        launch_tmux(cmds, stagger)
    else:
        launch_osascript(cmds, stagger)
        print(f"opened {len(cmds)} Terminal windows.")

    if not wait:
        print(f"\nnot waiting. Report when ready with:\n"
              f"  uv run python -m benchmarks.campaign_report '{campaign}'")
        return campaign

    # This terminal becomes the live dashboard: tick progress until every
    # session drops its .done marker, then print + save the combined summary.
    from benchmarks.campaign_report import watch_and_report
    print("\nwaiting for sessions to finish — live dashboard below "
          "(Ctrl-C to stop waiting and report partial):\n")
    watch_and_report(campaign, wait=True, interval=interval)
    return campaign


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Fan the XBEN benchmark set out across N terminal sessions.")
    ap.add_argument("--jobs", "-j", type=int, default=20,
                    help="number of parallel terminal sessions (default 20)")
    ap.add_argument("--name", default=None,
                    help="campaign dir name under logs/ (default full_run_<ts>)")
    ap.add_argument("--list-file", type=Path, default=DEFAULT_LIST,
                    help=f"benchmark id list to divide (default {DEFAULT_LIST.name})")
    ap.add_argument("--tmux", action="store_true",
                    help="use one tmux session with N windows instead of N "
                         "Terminal.app windows (osascript is recommended — see "
                         "module docstring)")
    ap.add_argument("--stagger", type=float, default=0.0,
                    help="seconds between session launches, to space out "
                         "concurrent 'docker compose up' calls (default 0)")
    ap.add_argument("--verbose", action="store_true",
                    help="override config: pass --verbose to each runner "
                         "(default derives the mode from SWARM_VERBOSITY)")
    ap.add_argument("--silent", action="store_true",
                    help="override config: pass --silent to each runner "
                         "(default derives the mode from SWARM_VERBOSITY)")
    ap.add_argument("--build", action="store_true",
                    help="let each runner build images (default --skip-build)")
    ap.add_argument("--resume", action="store_true",
                    help="skip ids already recorded in this campaign and re-queue "
                         "anything left unfinished (re-launch after windows died)")
    ap.add_argument("--static", action="store_true",
                    help="legacy mode: pre-split into fixed contiguous slices "
                         "instead of the dynamic shared queue (no rebalancing)")
    ap.add_argument("--no-wait", action="store_true",
                    help="spawn the sessions but don't turn this terminal into "
                         "the live dashboard (report later with campaign_report)")
    ap.add_argument("--interval", type=float, default=5.0,
                    help="dashboard refresh interval in seconds (default 5)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the split and the commands, but launch nothing")
    args = ap.parse_args()

    # Make sure swarm-config.toml is complete before fanning out — each
    # spawned session reads the configured model/budgets/verbosity straight
    # from it via src.graph. Best-effort — a config error must never block a run.
    try:
        from src.cli import config_store
        config_store.ensure_complete()
    except Exception:  # noqa: BLE001
        pass

    launch_campaign(
        jobs=args.jobs,
        list_file=args.list_file,
        name=args.name,
        tmux=args.tmux,
        stagger=args.stagger,
        verbose=args.verbose,
        silent=args.silent,
        build=args.build,
        resume=args.resume,
        static=args.static,
        wait=not args.no_wait,
        interval=args.interval,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
