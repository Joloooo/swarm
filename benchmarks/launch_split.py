"""One-command fan-out: divide the XBEN benchmark set across N terminals.

This automates the manual workflow of "open ~20 terminal windows, paste a
slice of the benchmark list into each, hit Enter". It splits
``benchmarks/all_xben_24.txt`` into N contiguous slices and launches one
terminal session per slice, each running::

    uv run python -m benchmarks.xbow_runner --list-file <slice> --skip-build --silent

The N sessions run in parallel with each other; within a session the
benchmarks run one after another (the xbow_runner is sequential). Each
spawned process is fully independent — its own PID, its own per-run log
dir, and its own loopback IP leased from ``benchmarks/.loopback_leases/``
(see ``benchmarks/loopback.py``), so the targets don't collide on ports.

Two launch backends, picked with ``--tmux``:

* **osascript (default)** — opens N real macOS Terminal.app windows, one per
  slice. This is the literal "20 terminals open at once" behaviour.
* **tmux** — creates one detached tmux session named ``xben`` with one
  window per slice. Cleaner for many slices; attach with
  ``tmux attach -t xben``, detach with ``Ctrl-b d``, kill all with
  ``tmux kill-session -t xben``.

Usage::

    uv run python -m benchmarks.launch_split                 # 20 Terminal windows
    uv run python -m benchmarks.launch_split --jobs 8        # 8 windows
    uv run python -m benchmarks.launch_split --tmux          # 20 tmux panes
    uv run python -m benchmarks.launch_split --jobs 6 --tmux --verbose
    uv run python -m benchmarks.launch_split --resume        # skip already-recorded ids
    uv run python -m benchmarks.launch_split --dry-run       # print the plan, launch nothing

Notes:
* ``--jobs`` is capped at 20 by default because the loopback pool has 20
  isolated IPs (``127.0.0.2``..``127.0.0.21``); going higher means some
  parallel runs fall back to the shared ``localhost`` mapping and can see
  each other's ports. Override the cap is your call — pass a bigger number
  if you've widened the pool.
* Slices are written to ``benchmarks/.split/slice_NN.txt`` (regenerated
  each run).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # SwarmAttacker/
DEFAULT_LIST = ROOT / "benchmarks" / "all_xben_24.txt"
SPLIT_DIR = ROOT / "benchmarks" / ".split"
LOOPBACK_POOL = 20                                  # matches loopback.POOL size


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
    six, the rest five" division. Never returns empty slices: ``n`` is
    clamped to ``len(ids)``.
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


def write_slices(slices: list[list[str]]) -> list[Path]:
    """Persist each slice to ``.split/slice_NN.txt`` and return the paths."""
    SPLIT_DIR.mkdir(parents=True, exist_ok=True)
    for old in SPLIT_DIR.glob("slice_*.txt"):
        old.unlink()
    paths: list[Path] = []
    for k, slice_ids in enumerate(slices):
        p = SPLIT_DIR / f"slice_{k:02d}.txt"
        p.write_text("\n".join(slice_ids) + "\n")
        paths.append(p)
    return paths


def runner_cmd(slice_path: Path, runner_flags: list[str]) -> str:
    """Shell command a single terminal runs for one slice.

    Paths are single-quoted so a space in the repo path can't break the
    command; single quotes are safe inside the double-quoted AppleScript
    string and inside a tmux ``send-keys`` argument.
    """
    flags = " ".join(runner_flags)
    return (
        f"cd '{ROOT}' && "
        f"uv run python -m benchmarks.xbow_runner "
        f"--list-file '{slice_path}' {flags}"
    )


def launch_osascript(cmds: list[str]) -> None:
    """Open one Terminal.app window per command via AppleScript ``do script``.

    Each ``do script`` with no target window opens a NEW window, so N calls
    give N windows. Terminal is brought to the front at the end.
    """
    for cmd in cmds:
        script = f'tell application "Terminal" to do script "{cmd}"'
        subprocess.run(["osascript", "-e", script], check=True)
    subprocess.run(
        ["osascript", "-e", 'tell application "Terminal" to activate'],
        check=False,
    )


def launch_tmux(cmds: list[str], session: str = "xben") -> None:
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
    print(f"tmux session '{session}' started with {len(cmds)} windows.")
    print(f"  attach : tmux attach -t {session}")
    print(f"  switch : Ctrl-b <window-number>   detach: Ctrl-b d")
    print(f"  kill   : tmux kill-session -t {session}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Fan the XBEN benchmark set out across N terminal sessions.")
    ap.add_argument("--jobs", "-j", type=int, default=20,
                    help="number of parallel terminal sessions (default 20)")
    ap.add_argument("--list-file", type=Path, default=DEFAULT_LIST,
                    help=f"benchmark id list to divide (default {DEFAULT_LIST.name})")
    ap.add_argument("--tmux", action="store_true",
                    help="use one tmux session with N windows instead of N "
                         "Terminal.app windows")
    ap.add_argument("--verbose", action="store_true",
                    help="pass --verbose to each runner (default is --silent)")
    ap.add_argument("--build", action="store_true",
                    help="let each runner build images (default --skip-build)")
    ap.add_argument("--resume", action="store_true",
                    help="pass --resume so each slice skips already-recorded ids")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the split and the commands, but launch nothing")
    args = ap.parse_args()

    ids = read_ids(args.list_file)

    if args.jobs > LOOPBACK_POOL and not args.tmux:
        print(
            f"note: --jobs {args.jobs} exceeds the {LOOPBACK_POOL}-IP loopback "
            f"pool; runs past the {LOOPBACK_POOL}th fall back to shared "
            f"localhost and may see each other's ports.",
            file=sys.stderr,
        )

    slices = split_contiguous(ids, args.jobs)

    runner_flags = ["--verbose"] if args.verbose else ["--silent"]
    if not args.build:
        runner_flags.append("--skip-build")
    if args.resume:
        runner_flags.append("--resume")

    print(f"{len(ids)} benchmarks → {len(slices)} sessions "
          f"({'tmux' if args.tmux else 'Terminal windows'}):")
    for k, s in enumerate(slices):
        print(f"  slice {k:02d}: {len(s):2d}  {s[0]}..{s[-1]}")

    if args.dry_run:
        slice_paths = write_slices(slices)
        print("\ndry-run — commands that WOULD launch:")
        for p in slice_paths:
            print(f"  {runner_cmd(p, runner_flags)}")
        return

    slice_paths = write_slices(slices)
    cmds = [runner_cmd(p, runner_flags) for p in slice_paths]
    if args.tmux:
        launch_tmux(cmds)
    else:
        launch_osascript(cmds)
        print(f"opened {len(cmds)} Terminal windows.")


if __name__ == "__main__":
    main()
