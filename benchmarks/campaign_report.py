"""Aggregate and display the results of a parallel benchmark campaign.

A "campaign" is one fan-out of the XBEN set across N terminal sessions
launched by ``benchmarks/launch_split.py``. Every session writes its
per-run logs and its per-benchmark verdicts under one campaign directory
(``logs/<campaign>/``) via ``SWARM_LOGS_ROOT`` / ``SWARM_RESULTS_DIR``,
and drops a ``.done/slice_NN`` marker when its slice finishes. This module
is the other half: it waits for all slices to finish, then prints — and
saves — a single combined summary of which benchmarks passed, failed,
crashed, or never reported.

Layout it reads under ``<campaign>/``::

    slices/slice_NN.txt     the benchmark ids assigned to each session (static)
    results/<id>.json       one verdict file per benchmark (write_jsonl) —
                            TRANSIENT: swept once the campaign finishes
    .done/slice_NN          marker touched when a session's slice exits —
                            TRANSIENT: swept once the campaign finishes
    run-*/                  per-run log dirs (kept; the lasting record)

Writes ``<campaign>/summary.txt`` (the rendered table — the kept artifact).
On a confirmed-complete campaign it then removes the transient ``results/``
and ``.done/`` dirs, leaving only the run dirs + ``summary.txt`` behind.
(``summary.json`` is no longer written — nothing consumed it.)

Standalone usage — re-print any past campaign at any time::

    uv run python -m benchmarks.campaign_report logs/full_run_06-05_14h30m
    uv run python -m benchmarks.campaign_report logs/full_run_… --no-wait
    uv run python -m benchmarks.campaign_report logs/full_run_… --interval 10

``launch_split.py`` calls :func:`watch_and_report` in the launching
terminal so that window becomes a live dashboard for the whole sweep.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

from src.benchmark_verdict import API, FAIL, OK, classify, format_duration
from src.cli import bench_tags

# Status → (bucket key, glyph) for display + summary tally.
_BUCKET = {OK: ("pass", "✓"), FAIL: ("fail", "✗"), API: ("crash", "~")}
_MISSING = ("missing", "⋯")


def slices_dir(campaign: Path) -> Path:
    return campaign / "slices"


def results_dir(campaign: Path) -> Path:
    return campaign / "results"


def done_dir(campaign: Path) -> Path:
    return campaign / ".done"


def _queue_ids(campaign: Path) -> list[str]:
    """All ids in the shared work-queue (pending + running + done), if present.

    Queue-mode campaigns (the default fan-out) have no slice files — the work
    list lives in ``queue.json``. Returns [] for a static/legacy campaign.
    """
    from benchmarks.work_queue import queue_path
    qp = queue_path(campaign)
    if not qp.exists():
        return []
    try:
        q = json.loads(qp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[str] = []
    out += list(q.get("pending") or [])
    out += list(q.get("running") or {})   # dict → its keys (the ids)
    out += list(q.get("done") or [])
    return out


def expected_ids(campaign: Path) -> list[str]:
    """All benchmark ids in this campaign. Order preserved, de-duplicated.

    Source priority: the shared ``queue.json`` (dynamic fan-out), then
    ``slices/`` (legacy static fan-out), then whatever ``results/`` exist (an
    ad-hoc results folder).
    """
    ids: list[str] = _queue_ids(campaign)
    sd = slices_dir(campaign)
    if not ids and sd.is_dir():
        for f in sorted(sd.glob("slice_*.txt")):
            for raw in f.read_text().splitlines():
                line = raw.split("#", 1)[0].strip()
                if line:
                    ids.append(line)
    if not ids:  # ad-hoc dir — infer from result files
        ids = [p.stem for p in sorted(results_dir(campaign).glob("*.json"))]
    seen: set[str] = set()
    out: list[str] = []
    for bid in ids:
        if bid not in seen:
            seen.add(bid)
            out.append(bid)
    return out


def worker_count(campaign: Path) -> int:
    """Number of worker sessions this campaign launched.

    Queue mode records it in a ``workers`` file (the pullers aren't tied to
    fixed slices); a legacy static campaign infers it from its slice files.
    """
    wf = campaign / "workers"
    if wf.exists():
        try:
            return int(wf.read_text().strip())
        except (ValueError, OSError):
            pass
    return len(list(slices_dir(campaign).glob("slice_*.txt")))


def done_count(campaign: Path) -> int:
    """Number of worker sessions that have finished (markers touched)."""
    dd = done_dir(campaign)
    return len([p for p in dd.iterdir() if p.is_file()]) if dd.is_dir() else 0


def collect(campaign: Path) -> dict[str, dict]:
    """Map ``benchmark_id -> result dict`` from every ``results/<id>.json``."""
    out: dict[str, dict] = {}
    rd = results_dir(campaign)
    if not rd.is_dir():
        return out
    for p in sorted(rd.glob("*.json")):
        try:
            row = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        bid = row.get("benchmark_id") or p.stem
        out[bid] = row
    return out


def summarize(campaign: Path) -> dict:
    """Build the full campaign summary from slices + result files."""
    ids = expected_ids(campaign)
    results = collect(campaign)

    buckets: dict[str, list[str]] = {"pass": [], "fail": [], "crash": [], "missing": []}
    by_benchmark: dict[str, dict] = {}
    durations: list[float] = []
    starts: list[str] = []
    ends: list[float] = []

    for bid in ids:
        row = results.get(bid)
        if row is None:
            buckets["missing"].append(bid)
            by_benchmark[bid] = {"status": "missing"}
            continue
        status = classify(bool(row.get("flag_found")), row.get("error"))
        key = _BUCKET[status][0]
        buckets[key].append(bid)
        dur = row.get("duration_s")
        if isinstance(dur, (int, float)):
            durations.append(float(dur))
        by_benchmark[bid] = {
            "status": key,
            "flag_found": bool(row.get("flag_found")),
            "duration_s": dur,
            "findings": row.get("findings_count"),
            "findings_by_severity": row.get("findings_by_severity") or {},
            "error": row.get("error"),
            "captured_flag": row.get("captured_flag") or "",
        }

    timing = {
        "agent_time_s": round(sum(durations), 1) if durations else 0.0,
        "median_s": round(sorted(durations)[len(durations) // 2], 1) if durations else 0.0,
        "max_s": round(max(durations), 1) if durations else 0.0,
        "n_with_duration": len(durations),
    }

    return {
        "campaign": campaign.name,
        "campaign_dir": str(campaign),
        "totals": {
            "total": len(ids),
            "pass": len(buckets["pass"]),
            "fail": len(buckets["fail"]),
            "crash": len(buckets["crash"]),
            "missing": len(buckets["missing"]),
            "recorded": len(results),
        },
        "workers": {"total": worker_count(campaign), "done": done_count(campaign)},
        "pass": buckets["pass"],
        "fail": buckets["fail"],
        "crash": buckets["crash"],
        "missing": buckets["missing"],
        "by_benchmark": by_benchmark,
        "timing": timing,
    }


def _fmt_ids(
    ids: list[str],
    *,
    per_line: int = 3,
    indent: str = "   ",
    label=None,
) -> str:
    """Lay ``ids`` out ``per_line`` to a row, each rendered via ``label``.

    ``label`` maps a benchmark id to its display string (default: its
    tag-expanded :func:`src.cli.bench_tags.short_id`, e.g. ``XBEN-004-xss``).
    The pass list passes a label that also appends the solve time.
    """
    if not ids:
        return f"{indent}(none)"
    label = label or bench_tags.short_id
    cells = [label(b) for b in ids]
    rows = [
        indent + "  ".join(cells[i:i + per_line])
        for i in range(0, len(cells), per_line)
    ]
    return "\n".join(rows)


def render(summary: dict) -> str:
    """Pretty multi-line report (also what gets saved to summary.txt)."""
    t = summary["totals"]
    sl = summary["workers"]
    tm = summary["timing"]
    bar = "═" * 70

    # Per-benchmark solve time for the pass list — ✓ XBEN-004-xss (3m 12s).
    by_bench = summary.get("by_benchmark", {})

    def _pass_label(bid: str) -> str:
        dur = (by_bench.get(bid) or {}).get("duration_s")
        return f"{bench_tags.short_id(bid)} ({format_duration(dur)})"
    pass_pct = f"  ({100 * t['pass'] / t['total']:.1f}%)" if t["total"] else ""
    agent_h = tm["agent_time_s"] / 3600
    lines = [
        bar,
        f" Campaign {summary['campaign']}",
        bar,
        f" {t['total']} benchmarks · {sl['total']} workers "
        f"({sl['done']}/{sl['total']} finished)",
        f" agent-time Σ{agent_h:.1f}h · median {tm['median_s'] / 60:.1f}m · "
        f"max {tm['max_s'] / 60:.1f}m",
        "",
        f"   ✓ pass     {t['pass']:>3}{pass_pct}",
        f"   ✗ fail     {t['fail']:>3}",
        f"   ~ malfunction {t['crash']:>3}",
        f"   ⋯ missing  {t['missing']:>3}",
        "",
        f" ✓ PASS ({t['pass']}):",
        _fmt_ids(summary["pass"], per_line=2, label=_pass_label),
        f" ✗ FAIL ({t['fail']}):",
        _fmt_ids(summary["fail"]),
        f" ~ MALFUNCTION ({t['crash']}):",
        _fmt_ids(summary["crash"]),
        f" ⋯ MISSING ({t['missing']}):",
        _fmt_ids(summary["missing"]),
        bar,
    ]
    return "\n".join(lines)


def _dur(s) -> str:
    """``8m 14s`` (right-aligned minutes), or ``   ?   `` when unknown."""
    if s is None:
        return "   ?   "
    s = int(round(s))
    return f"{s // 60:>2d}m {s % 60:02d}s"


def _hms(s) -> str:
    """``30h 54m`` — hours + minutes, for the campaign wall total."""
    s = int(round(s))
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def _big(t: int) -> str:
    """Compact token magnitude: ``2.15M`` ≥1M, ``829k`` ≥1k, else the int."""
    if t >= 1_000_000:
        return f"{t / 1e6:.2f}M"
    if t >= 1_000:
        return f"{t / 1e3:.0f}k"
    return str(t)


def render_token_timing(campaign: Path, summary: dict) -> str:
    """Render the ``TOKENS & TIMING`` + ``PER-BENCHMARK`` sections.

    Reads each per-benchmark ``results/<id>.json`` for its ``duration_s`` and
    ``tokens`` (``{"in","out","total","calls"}``, written by the xbow runner).
    Token total is ``in + out`` only — cached/reasoning tokens are subsets of
    those, so they are never added separately. Layout matches the golden
    ``summary.txt`` byte-for-byte.

    Robust to incomplete data: a result with no ``duration_s`` shows ``?`` and
    is excluded from the average-duration mean; a result with no ``tokens`` is
    treated as 0 and still listed. With zero token data anywhere the token
    lines read 0 rather than erroring.
    """
    results = collect(campaign)
    by_bench = summary.get("by_benchmark", {})

    rows: list[dict] = []
    for bid in sorted(results):
        row = results[bid] or {}
        tok = row.get("tokens") or {}
        total = tok.get("total")
        if total is None:
            tin = tok.get("in") or 0
            tout = tok.get("out") or 0
            total = tin + tout
        else:
            tin = tok.get("in") or 0
            tout = tok.get("out") or 0
        dur = row.get("duration_s")
        if not isinstance(dur, (int, float)):
            dur = None
        # Verdict: ✓ when the flag was captured, else ✗.
        passed = bool(row.get("flag_found"))
        rows.append({
            "bid": bid, "in": tin, "out": tout, "total": total,
            "duration_s": dur, "pass": passed,
        })

    n = len(rows)
    total_tokens = sum(r["total"] for r in rows)
    total_in = sum(r["in"] for r in rows)
    total_out = sum(r["out"] for r in rows)
    avg_tokens = round(total_tokens / n) if n else 0
    durs = [r["duration_s"] for r in rows if r["duration_s"] is not None]
    avg_duration = sum(durs) / len(durs) if durs else None
    median_duration = sorted(durs)[len(durs) // 2] if durs else None
    total_wall = sum(durs) if durs else 0

    W = 70
    line = "─" * W
    out: list[str] = [
        line,
        " TOKENS & TIMING  (tracked LLM calls; web-search tokens not metered)",
        line,
        f"   total tokens       {total_tokens:>13,}   "
        f"(in {_big(total_in)} · out {_big(total_out)})",
        f"   avg tokens / bench {avg_tokens:>13,}   over {n} benchmarks",
        f"   avg duration       {_dur(avg_duration).strip():>13}   "
        f"(median {_dur(median_duration).strip()})",
        f"   total agent wall   {_hms(total_wall):>13}   "
        f"({int(round(total_wall)):,} s active, hibernation excluded)",
        "",
        " PER-BENCHMARK  (id · verdict · active duration · tokens in+out)",
    ]
    for r in rows:
        v = "✓" if r["pass"] else "✗"
        out.append(
            f"   {r['bid']:8} {v}  {_dur(r['duration_s'])}   {_big(r['total']):>7}"
        )
    out.append(line)
    return "\n".join(out)


def write_summary(campaign: Path, summary: dict) -> Path:
    """Persist the human-readable ``summary.txt`` into the campaign dir.

    The machine-readable ``summary.json`` is no longer written — nothing read
    it, and ``summary.txt`` is the kept thesis artifact. Returns the txt path.

    Appends the ``TOKENS & TIMING`` + ``PER-BENCHMARK`` sections (durations and
    per-bench token spend, summed across the campaign) below the verdict table.
    """
    campaign.mkdir(parents=True, exist_ok=True)
    txt_path = campaign / "summary.txt"
    body = render(summary) + "\n\n" + render_token_timing(campaign, summary)
    txt_path.write_text(body + "\n", encoding="utf-8")
    return txt_path


def _tick_line(campaign: Path) -> str:
    s = summarize(campaign)
    t, sl = s["totals"], s["workers"]
    return (
        f"  workers {sl['done']}/{sl['total']} · "
        f"benchmarks {t['recorded']}/{t['total']} · "
        f"✓{t['pass']} ✗{t['fail']} ~{t['crash']}"
    )


def wait_for_done(campaign: Path, *, interval: float = 5.0) -> bool:
    """Block until every worker session has finished, ticking progress to stderr.

    Returns True if all workers finished, False if interrupted (Ctrl-C) or
    there are no worker markers to wait on. Either way the caller should
    still render whatever results exist.
    """
    total = worker_count(campaign)
    if total == 0:
        return False
    is_tty = sys.stderr.isatty()
    try:
        while done_count(campaign) < total:
            line = _tick_line(campaign)
            if is_tty:
                sys.stderr.write("\r\033[K" + line)
                sys.stderr.flush()
            else:
                sys.stderr.write(line + "\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        sys.stderr.write("\n  (interrupted — reporting partial results)\n")
        return False
    if is_tty:
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
    return True


def watch_and_report(campaign: Path, *, wait: bool = True, interval: float = 5.0) -> dict:
    """Wait (optionally) for the campaign to finish, then print + save.

    This is what ``launch_split.py`` runs in the launching terminal.
    """
    campaign = campaign.expanduser().resolve()
    if not campaign.is_dir():
        sys.exit(f"campaign dir not found: {campaign}")

    # Idempotency: a finished campaign has had its results/ + .done/ swept
    # (see below) and keeps only summary.txt. Re-reporting it must NOT rebuild
    # from the now-absent results/ — that would clobber the real summary.txt
    # with an all-missing one. Print the kept summary and return untouched.
    txt = campaign / "summary.txt"
    if not results_dir(campaign).exists() and txt.exists():
        print(txt.read_text(encoding="utf-8"))
        print(f"\n(already finished — {txt})")
        return {}

    finished = wait_for_done(campaign, interval=interval) if wait else False
    summary = summarize(campaign)
    txt_path = write_summary(campaign, summary)
    print(render(summary))
    print(f"\nsaved → {txt_path}")

    # On a confirmed-complete campaign, sweep the transient run-state dirs:
    # results/<bid>.json (per-bench IPC for the live dashboard + resume) and
    # .done/ (worker-exit markers). Their data is now folded into summary.txt
    # and the run dirs, so they are pure clutter once the run is over. Only
    # when the wait actually completed — a --no-wait snapshot or a Ctrl-C'd
    # wait leaves them so an in-flight campaign keeps its resume/IPC state.
    if finished:
        for d in (results_dir(campaign), done_dir(campaign), slices_dir(campaign)):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)

    return summary


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Aggregate + display a parallel benchmark campaign's results.")
    ap.add_argument("campaign_dir", type=Path,
                    help="the logs/<campaign>/ directory to report on")
    ap.add_argument("--no-wait", action="store_true",
                    help="report immediately on current state instead of "
                         "waiting for unfinished workers")
    ap.add_argument("--interval", type=float, default=5.0,
                    help="seconds between progress ticks while waiting (default 5)")
    args = ap.parse_args()
    watch_and_report(args.campaign_dir, wait=not args.no_wait, interval=args.interval)


if __name__ == "__main__":
    main()
