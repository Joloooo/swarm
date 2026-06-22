#!/usr/bin/env python3
"""Quantify how often the SwarmAttacker agent reached for directory/parameter
brute-forcing (wordlist enumeration) across all benchmark runs, and whether that
was warranted — the evidence base for the ENUMERATION_DISCIPLINE prompt block in
src/nodes/base/system_prompt.py.

All log runs in logs/ predate the discipline prompt + the get_wordlist/list_wordlists
tools (both committed 2026-06-08 23:07; newest run started 16:01), so this is a clean
BASELINE of agent behaviour with NO discipline in place.

Methodology
-----------
Only AGENT-GENERATED fields are inspected (bash_command.cmd / bash_output.cmd).
The system prompt is never scanned — it names these tools and would inflate counts.
A run "brute-forced" iff it actually invoked a dedicated directory/param brute-force
tool (gobuster | ffuf | dirb | dirsearch | feroxbuster | wfuzz). Small hand-typed
curl path-guessing (a few literal paths) is deliberately NOT counted as enumeration.

Necessity ground truth comes from each benchmark.json description/tags:
  NEEDS  – intended path requires discovering an unlinked dir/file by guessing.
  MAYBE  – an unlinked endpoint *might* need light discovery (usually linked).
  NO     – the vulnerable surface is directly visible (form / login / id param /
           upload / template input).
"""
import json, re, glob, os, statistics
from collections import defaultdict, Counter

LOGS = os.path.join(os.path.dirname(__file__), "..", "logs")
BENCH = os.path.join(os.path.dirname(__file__), "..", "xbow-validation", "benchmarks")

TIER_A = re.compile(r'(^|[\s;&|(])(gobuster|ffuf|dirb|dirsearch|feroxbuster|wfuzz)\b', re.I | re.M)

# Only XBEN-084 explicitly mandates directory discovery ("Search for hidden directories").
NEEDS = {"XBEN-084"}
# These hint at finding an endpoint/file but it is usually linked or a well-known path.
MAYBE = {"XBEN-019", "XBEN-024", "XBEN-033", "XBEN-042", "XBEN-097", "XBEN-098"}


def bench_id(p):
    m = re.search(r'(XBEN-\d{3})', p)
    return m.group(1) if m else None


def classify(bid):
    return "NEEDS" if bid in NEEDS else "MAYBE" if bid in MAYBE else "NO"


def analyze(fp):
    """Per run: ran_tool, n_tool_invocations, first_tool_position, n_bash, durs, exits, timeouts."""
    n_bash = n_tool = 0
    first = None
    durs, exits, timeouts = [], [], 0
    for line in open(fp, errors="ignore"):
        try:
            d = json.loads(line)
        except Exception:
            continue
        t = d.get("type")
        if t == "bash_command":
            n_bash += 1
            if TIER_A.search(d.get("cmd", "") or ""):
                n_tool += 1
                if first is None:
                    first = n_bash
        elif t == "bash_output" and TIER_A.search(d.get("cmd", "") or ""):
            durs.append(d.get("duration_ms", 0) or 0)
            exits.append(d.get("exit_code"))
            if d.get("timed_out"):
                timeouts += 1
    return dict(ran=n_tool > 0, nt=n_tool, first=first, nb=n_bash,
                durs=durs, exits=exits, timeouts=timeouts)


def main():
    runs = []
    for fp in sorted(glob.glob(os.path.join(LOGS, "**", "full_logs.jsonl"), recursive=True)):
        bid = bench_id(fp)
        if not bid:
            continue
        r = analyze(fp)
        r["bid"] = bid
        r["fp"] = fp
        runs.append(r)

    n = len(runs)
    A = [r for r in runs if r["ran"]]
    nonA = [r for r in runs if not r["ran"]]
    healthy = [r for r in runs if r["nb"] >= 4]           # runs that actually got going
    healthy_A = [r for r in healthy if r["ran"]]

    print(f"total benchmark runs analysed            : {n}")
    print(f"runs that brute-forced (dedicated tool)  : {len(A)} ({100*len(A)/n:.1f}%)")
    print(f"  of HEALTHY runs (>=4 bash cmds)         : {len(healthy_A)}/{len(healthy)} ({100*len(healthy_A)/len(healthy):.1f}%)")
    tiny = sum(1 for r in nonA if r["nb"] <= 3)
    print(f"non-brute-force runs that crashed/empty  : {tiny}/{len(nonA)} (<=3 bash cmds)")

    # opening move
    firsts = sorted(r["first"] for r in A)
    print(f"\nopening move — first brute-force among bash cmds: median pos {statistics.median(firsts):.0f}")
    for thr in (2, 3, 5):
        c = sum(1 for f in firsts if f <= thr)
        print(f"  within first {thr} bash cmds: {c}/{len(A)} ({100*c/len(A):.0f}%)")

    # fixation
    print("\nfixation (multiple brute-force invocations in one run):")
    for thr in (2, 3, 5):
        print(f"  >= {thr}x: {sum(1 for r in A if r['nt'] >= thr)} runs")

    # distinct benchmarks
    perb = defaultdict(lambda: dict(runs=0, A=0))
    for r in runs:
        perb[r["bid"]]["runs"] += 1
        perb[r["bid"]]["A"] += 1 if r["ran"] else 0
    benches_A = sum(1 for b in perb.values() if b["A"])
    print(f"\ndistinct benchmarks brute-forced >=1x: {benches_A}/{len(perb)}")

    # necessity cross-tab
    print("\nnecessity cross-tab (per run):")
    cls = defaultdict(lambda: dict(runs=0, A=0))
    for r in runs:
        c = classify(r["bid"])
        cls[c]["runs"] += 1
        cls[c]["A"] += 1 if r["ran"] else 0
    for c in ("NEEDS", "MAYBE", "NO"):
        x = cls[c]
        if x["runs"]:
            print(f"  {c:6}: {x['A']:3}/{x['runs']:3} runs brute-forced ({100*x['A']/x['runs']:.0f}%)")
    nb = defaultdict(lambda: dict(b=0, A=0))
    for bid, b in perb.items():
        c = classify(bid)
        nb[c]["b"] += 1
        nb[c]["A"] += 1 if b["A"] else 0
    print("necessity cross-tab (per distinct benchmark, brute-forced ever):")
    for c in ("NEEDS", "MAYBE", "NO"):
        if nb[c]["b"]:
            print(f"  {c:6}: {nb[c]['A']}/{nb[c]['b']}")

    # cost
    all_durs = [d for r in runs for d in r["durs"]]
    all_exits = Counter(e for r in runs for e in r["exits"])
    succ = [d for r in runs for d, e in zip(r["durs"], r["exits"]) if e == 0]
    tos = sum(r["timeouts"] for r in runs)
    print(f"\ncost: {len(all_durs)} brute-force commands executed")
    print(f"  total wall-clock {sum(all_durs)/60000:.1f} min | successful (exit0) median {statistics.median(succ)/1000:.1f}s mean {statistics.mean(succ)/1000:.1f}s max {max(succ)/1000:.0f}s")
    notfound = all_exits.get(127, 0) + all_exits.get(-1, 0)
    print(f"  failed/errored: {sum(v for k,v in all_exits.items() if k not in (0,))} (incl. ~{notfound} tool-not-found / setup errors); timed out: {tos}")
    print("  -> on these tiny apps wall-clock is small; the real cost is turns, context, and tool-debugging churn.")

    # clean one-run-per-benchmark sweeps
    for tag, sub in (("1_full_run", "/1_full_run/"),
                     ("full_run_06-06 (laneA)", "/full_run_06-06_01h05m/")):
        seen = {}
        for r in runs:
            if sub in r["fp"] and "-laneB" not in r["fp"]:
                seen.setdefault(r["bid"], r)
        if seen:
            ran = sum(1 for r in seen.values() if r["ran"])
            print(f"\nclean sweep [{tag}]: {ran}/{len(seen)} benchmarks brute-forced ({100*ran/len(seen):.0f}%)")


if __name__ == "__main__":
    main()
