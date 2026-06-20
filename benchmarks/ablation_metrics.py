"""Deep per-run metrics for the ablation study — mined from ``full_logs.jsonl``.

``campaign_report.py`` builds ``summary.txt`` from the *transient*
``results/<id>.json`` files, which are swept once a campaign finishes. So for a
completed run the only durable record of *how* the agent worked (not just
pass/fail + token totals) is the per-benchmark ``full_logs.jsonl`` event stream.

This module mines that stream to answer the ablation questions ``summary.txt``
cannot:

  * **Dispatches** — how many test workers the planner spun up
    (``node_finished[node=executor]``).
  * **Dead-ends / barren dispatches** — executor runs that finished with
    ``findings_count == 0``. The agent paid full token + wall-clock cost for a
    worker that returned nothing. The displayed log flags these itself
    ("⚠ [executor] [ssti] produced 0 findings"). This is the headline
    efficiency signal: an ablation that removes useful guidance should make the
    agent *wander more* — more barren dispatches per solve.
  * **LLM calls / planner iterations** — control-loop length.
  * **Tool calls + tool failures** — ``bash_command`` count and
    ``bash_output`` with a non-zero ``exit_code``.
  * **Tokens** (in/out/reasoning/cached) — re-derived so this file is
    self-contained and cross-checks ``summary.txt``.

Verdict is taken from ``flag_auto_verified.matched == True`` (the system's own
flag verifier — NOT a grep of the expected flag, which is logged in every run
and would false-positive), cross-checked against the ``◆ ✓ FLAG FOUND`` /
``◇ ✗ no flag`` line in ``displayed_terminal_logs.log``.

Duplicate run dirs for one benchmark (failure reruns) are resolved
**latest-wins**, matching the curated ``summary.txt``.

Usage::

    # one run -> writes <campaign>/deep_metrics.txt (+ .json)
    uv run python -m benchmarks.ablation_metrics "logs/full_run_06-14_10h29m thesis"

    # several runs -> per-run files + a cross-run comparison to stdout and
    # logs/ablation_comparison.txt
    uv run python -m benchmarks.ablation_metrics "logs/full_run_06-14_10h29m thesis" \
        "logs/full_run_06-19_15h57m  ablation skill " ...
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median

_ID_RE = re.compile(r"(XBEN-\d+)")
# "(40m 25s, 4 findings: 4 info)"  /  "(8m 01s, 2 findings: 1 critical, 1 medium)"
_DUR_RE = re.compile(r"\((\d+)m\s+(\d+)s,")
# Final verdict line glyphs. ◆ + "✓ FLAG FOUND" = pass; ◇ + "✗ no flag" = fail.
_PASS_RE = re.compile(r"✓\s*FLAG FOUND")
_FAIL_RE = re.compile(r"✗\s*no flag")


def _benchmark_id(dirname: str) -> str | None:
    m = _ID_RE.search(dirname)
    return m.group(1) if m else None


def _timestamp_key(dirname: str) -> str:
    """Sortable timestamp portion of ``run-MM-DD_HHhMMmSSs_XBEN-NNN``.

    The date+time prefix sorts lexically within one campaign (same year), so
    the max key per id is the latest attempt — the latest-wins canonical run.
    """
    head = dirname.split("_XBEN", 1)[0]
    return head


def canonical_dirs(campaign: Path) -> dict[str, Path]:
    """``benchmark_id -> latest run dir`` for that id (latest-wins on reruns)."""
    by_id: dict[str, Path] = {}
    best_key: dict[str, str] = {}
    for d in campaign.iterdir():
        if not d.is_dir() or "_XBEN-" not in d.name:
            continue
        bid = _benchmark_id(d.name)
        if not bid:
            continue
        key = _timestamp_key(d.name)
        if bid not in best_key or key > best_key[bid]:
            best_key[bid] = key
            by_id[bid] = d
    return dict(sorted(by_id.items()))


def _verdict_from_display(run_dir: Path) -> tuple[bool | None, float | None]:
    """``(solved, duration_s)`` parsed from the final ◆/◇ verdict line.

    Returns ``(None, None)`` if the display log is absent/unreadable. ``solved``
    is None if no verdict glyph line is found (e.g. a hard crash mid-run).
    """
    log = run_dir / "displayed_terminal_logs.log"
    if not log.exists():
        return None, None
    solved: bool | None = None
    dur: float | None = None
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, None
    for line in text.splitlines():
        if "FLAG FOUND" in line or "no flag" in line:
            if _PASS_RE.search(line):
                solved = True
            elif _FAIL_RE.search(line):
                solved = False
            m = _DUR_RE.search(line)
            if m:
                dur = int(m.group(1)) * 60 + int(m.group(2))
    return solved, dur


def benchmark_metrics(run_dir: Path) -> dict:
    """Stream one benchmark's ``full_logs.jsonl`` into a metrics dict."""
    f = run_dir / "full_logs.jsonl"
    m = {
        "dir": run_dir.name,
        "llm_calls": 0,
        "tok_in": 0, "tok_out": 0, "tok_reason": 0, "tok_cached": 0,
        "planner_iters": 0,
        "dispatches": 0,          # executor worker runs
        "dead_ends": 0,           # executor runs with findings_count == 0
        "recon_runs": 0,
        "websearch_runs": 0,
        "summarizer_runs": 0,
        "findings_total": 0,      # Σ findings over executor + recon
        "tool_calls": 0,
        "tool_fail": 0,
        "flag_matched": False,
        "node_finished_total": 0,
        "has_logs": f.exists(),
    }
    if not f.exists():
        return m
    node_ts: list[str] = []
    try:
        with f.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                t = o.get("type")
                if t == "llm_end":
                    m["llm_calls"] += 1
                    m["tok_in"] += int(o.get("input_tokens") or 0)
                    m["tok_out"] += int(o.get("output_tokens") or 0)
                    m["tok_reason"] += int(o.get("reasoning_tokens") or 0)
                    m["tok_cached"] += int(o.get("cached_tokens") or 0)
                elif t == "node_finished":
                    m["node_finished_total"] += 1
                    node = o.get("node")
                    try:
                        fc = int(o.get("findings_count") or 0)
                    except (TypeError, ValueError):
                        fc = 0
                    if node == "planner":
                        m["planner_iters"] += 1
                    elif node == "executor":
                        m["dispatches"] += 1
                        m["findings_total"] += fc
                        if fc == 0:
                            m["dead_ends"] += 1
                    elif node == "recon":
                        m["recon_runs"] += 1
                        m["findings_total"] += fc
                    elif node == "web_search":
                        m["websearch_runs"] += 1
                    elif node == "summarizer":
                        m["summarizer_runs"] += 1
                    if o.get("ts"):
                        node_ts.append(o["ts"])
                elif t == "bash_command":
                    m["tool_calls"] += 1
                elif t == "bash_output":
                    ec = o.get("exit_code")
                    try:
                        eci = int(ec)
                    except (TypeError, ValueError):
                        eci = 0
                    if eci not in (0,):
                        m["tool_fail"] += 1
                elif t == "flag_auto_verified":
                    if str(o.get("matched")).lower() == "true":
                        m["flag_matched"] = True
    except OSError:
        pass

    solved_disp, dur_disp = _verdict_from_display(run_dir)
    m["solved_display"] = solved_disp
    m["duration_s"] = dur_disp
    # Primary verdict: the system's own flag verifier. Cross-check the display
    # glyph and record any disagreement for auditing.
    m["solved"] = bool(m["flag_matched"]) or (solved_disp is True)
    m["verdict_mismatch"] = (
        solved_disp is not None and bool(m["flag_matched"]) != solved_disp
    )
    m["tok_total"] = m["tok_in"] + m["tok_out"]
    m["productive_dispatches"] = m["dispatches"] - m["dead_ends"]
    m["dead_end_rate"] = (
        m["dead_ends"] / m["dispatches"] if m["dispatches"] else 0.0
    )
    return m


def run_metrics(campaign: Path) -> dict:
    """Aggregate every canonical benchmark in one campaign dir."""
    cdirs = canonical_dirs(campaign)
    per: dict[str, dict] = {}
    for bid, d in cdirs.items():
        per[bid] = benchmark_metrics(d)

    rows = list(per.values())
    solved_rows = [r for r in rows if r["solved"]]
    failed_rows = [r for r in rows if not r["solved"]]

    def _sum(key: str, rs=rows) -> int:
        # ``or 0`` (not get-default): a key can be present with a None value
        # (e.g. duration_s when no verdict line parsed) — coerce that to 0.
        return sum((r.get(key) or 0) for r in rs)

    def _avg(key: str, rs=rows) -> float:
        return (sum((r.get(key) or 0) for r in rs) / len(rs)) if rs else 0.0

    durs = [r["duration_s"] for r in rows if r.get("duration_s")]
    n = len(rows)
    agg = {
        "campaign": campaign.name,
        "n_benchmarks": n,
        "n_solved": len(solved_rows),
        "n_failed": len(failed_rows),
        "solve_rate": (len(solved_rows) / n) if n else 0.0,
        "verdict_mismatches": [b for b, r in per.items() if r.get("verdict_mismatch")],
        "tok_total": _sum("tok_total"),
        "tok_in": _sum("tok_in"),
        "tok_out": _sum("tok_out"),
        "tok_reason": _sum("tok_reason"),
        "tok_cached": _sum("tok_cached"),
        "avg_tok": _avg("tok_total"),
        "avg_tok_solved": _avg("tok_total", solved_rows),
        "avg_tok_failed": _avg("tok_total", failed_rows),
        "avg_llm_calls": _avg("llm_calls"),
        "avg_planner_iters": _avg("planner_iters"),
        "avg_dispatches": _avg("dispatches"),
        "avg_dispatches_solved": _avg("dispatches", solved_rows),
        "avg_dispatches_failed": _avg("dispatches", failed_rows),
        "avg_dead_ends": _avg("dead_ends"),
        "avg_dead_ends_solved": _avg("dead_ends", solved_rows),
        "avg_dead_ends_failed": _avg("dead_ends", failed_rows),
        "total_dispatches": _sum("dispatches"),
        "total_dead_ends": _sum("dead_ends"),
        "dead_end_rate": (_sum("dead_ends") / _sum("dispatches")) if _sum("dispatches") else 0.0,
        "avg_tool_calls": _avg("tool_calls"),
        "avg_tool_fail": _avg("tool_fail"),
        # Duration averages over benchmarks that HAVE a parsed duration only,
        # so an incomplete/crashed run (duration None) doesn't drag the mean to 0.
        "avg_duration_s": (sum(durs) / len(durs)) if durs else 0.0,
        "median_duration_s": median(durs) if durs else 0.0,
        "solved_ids": sorted(b for b, r in per.items() if r["solved"]),
        "failed_ids": sorted(b for b, r in per.items() if not r["solved"]),
        "per_benchmark": per,
    }
    return agg


def _big(t: float) -> str:
    if t >= 1_000_000:
        return f"{t / 1e6:.2f}M"
    if t >= 1_000:
        return f"{t / 1e3:.0f}k"
    return f"{t:.0f}"


def _dur(s) -> str:
    if not s:
        return "  ?  "
    s = int(round(s))
    return f"{s // 60:>2d}m {s % 60:02d}s"


def render_run(agg: dict) -> str:
    bar = "─" * 74
    L = [
        "═" * 74,
        f" DEEP METRICS — {agg['campaign']}",
        "═" * 74,
        f" {agg['n_benchmarks']} benchmarks (latest-wins) · "
        f"✓ {agg['n_solved']} / ✗ {agg['n_failed']} · "
        f"solve rate {100 * agg['solve_rate']:.1f}%",
        "",
        " EFFICIENCY (per benchmark, averaged)",
        bar,
        f"   tokens (in+out)        {_big(agg['avg_tok']):>10}   "
        f"(solved {_big(agg['avg_tok_solved'])} · failed {_big(agg['avg_tok_failed'])})",
        f"   LLM calls              {agg['avg_llm_calls']:>10.1f}",
        f"   planner iterations     {agg['avg_planner_iters']:>10.1f}",
        f"   worker dispatches      {agg['avg_dispatches']:>10.1f}   "
        f"(solved {agg['avg_dispatches_solved']:.1f} · failed {agg['avg_dispatches_failed']:.1f})",
        f"   dead-end dispatches    {agg['avg_dead_ends']:>10.1f}   "
        f"(solved {agg['avg_dead_ends_solved']:.1f} · failed {agg['avg_dead_ends_failed']:.1f})",
        f"   tool calls             {agg['avg_tool_calls']:>10.1f}   "
        f"(failed {agg['avg_tool_fail']:.1f})",
        f"   duration               {_dur(agg['avg_duration_s']):>10}   "
        f"(median {_dur(agg['median_duration_s'])})",
        "",
        " AGGREGATE",
        bar,
        f"   total tokens           {agg['tok_total']:>13,}   "
        f"(in {_big(agg['tok_in'])} · out {_big(agg['tok_out'])} · "
        f"reason {_big(agg['tok_reason'])} · cached {_big(agg['tok_cached'])})",
        f"   total dispatches       {agg['total_dispatches']:>13,}",
        f"   total dead-ends        {agg['total_dead_ends']:>13,}   "
        f"({100 * agg['dead_end_rate']:.1f}% of all dispatches were barren)",
    ]
    if agg["verdict_mismatches"]:
        L += ["", f"   ⚠ verdict mismatches (verifier vs display): "
              f"{', '.join(agg['verdict_mismatches'])}"]
    L += [
        "",
        " PER-BENCHMARK  (id · verdict · tokens · dispatch/dead-end · llm · tool-fail · dur)",
        bar,
    ]
    per = agg["per_benchmark"]
    for bid in sorted(per):
        r = per[bid]
        v = "✓" if r["solved"] else "✗"
        L.append(
            f"   {bid:9} {v}  {_big(r['tok_total']):>7}   "
            f"disp {r['dispatches']:>2} dead {r['dead_ends']:>2}   "
            f"llm {r['llm_calls']:>3}   tf {r['tool_fail']:>2}   {_dur(r.get('duration_s'))}"
        )
    L.append("═" * 74)
    return "\n".join(L)


def render_comparison(aggs: list[dict]) -> str:
    """Cross-run comparison table — the ablation money-shot."""
    bar = "═" * 110
    L = [bar, " ABLATION COMPARISON  (one capability removed per run)", bar, ""]
    hdr = (f"   {'run':<34} {'solve%':>7} {'tok/b':>8} {'tok/solve':>10} "
           f"{'disp/b':>7} {'dead/b':>7} {'dead%':>6} {'llm/b':>6} {'dur':>7}")
    L.append(hdr)
    L.append("   " + "─" * 104)
    for a in aggs:
        tok_per_solve = a["tok_total"] / a["n_solved"] if a["n_solved"] else 0
        name = a["campaign"][:34]
        L.append(
            f"   {name:<34} {100 * a['solve_rate']:>6.1f} "
            f"{_big(a['avg_tok']):>8} {_big(tok_per_solve):>10} "
            f"{a['avg_dispatches']:>7.1f} {a['avg_dead_ends']:>7.1f} "
            f"{100 * a['dead_end_rate']:>5.1f} {a['avg_llm_calls']:>6.1f} "
            f"{_dur(a['avg_duration_s']):>7}"
        )
    L += ["", bar]
    return "\n".join(L)


def write_run_files(campaign: Path, agg: dict) -> tuple[Path, Path]:
    txt = campaign / "deep_metrics.txt"
    js = campaign / "deep_metrics.json"
    txt.write_text(render_run(agg) + "\n", encoding="utf-8")
    js.write_text(json.dumps(agg, indent=2), encoding="utf-8")
    return txt, js


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("campaigns", nargs="+", type=Path,
                    help="one or more logs/<campaign>/ dirs")
    ap.add_argument("--out", type=Path, default=Path("logs/ablation_comparison.txt"),
                    help="cross-run comparison file (when >1 campaign)")
    args = ap.parse_args()

    aggs: list[dict] = []
    for c in args.campaigns:
        c = c.expanduser()
        if not c.is_dir():
            print(f"!! not a dir: {c}")
            continue
        agg = run_metrics(c)
        txt, js = write_run_files(c, agg)
        print(render_run(agg))
        print(f"saved → {txt}\n")
        aggs.append(agg)

    if len(aggs) > 1:
        comp = render_comparison(aggs)
        print(comp)
        args.out.write_text(comp + "\n", encoding="utf-8")
        print(f"\nsaved → {args.out}")


if __name__ == "__main__":
    main()
