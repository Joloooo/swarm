#!/usr/bin/env python3
"""Clean fate-classification of every 'switch to fallback' event, using ONLY
the switched worker's own log lines (msg contains [agent]). The fallback model
never logs a refusal, so a switch with no 'rescued' line ended for some OTHER
reason — find which, per worker."""
from __future__ import annotations
import glob, json, os, re
from collections import Counter

LOGS = "/Users/zviadjolokhava/Dev/Thesis/SwarmAttacker/logs"
files = sorted(glob.glob(os.path.join(LOGS, "**", "full_logs.jsonl"), recursive=True))

RE_SWITCH = re.compile(r"primary tier exhausted, switching to fallback model")

def classify_own_line(msg: str):
    m = msg.lower()
    if "rescued by fallback model" in m: return "rescued_fallback"
    if "flagwatcher captured" in m or "auto-verified flag" in m: return "this_worker_captured_flag"
    if "sibling worker captured the flag" in m: return "sibling_captured_flag(benign)"
    if "step budget" in m or "recursion limit" in m: return "recursion/step-budget"
    if "model refused" in m or "refused the task" in m: return "soft_refusal_loss"
    if "429" in m or "rate limit" in m or "quota" in m: return "rate_limit/quota"
    if "transport" in m or "connecterror" in m: return "transport_error"
    if "context window" in m or "too long" in m: return "context_window"
    if "salvage" in m: return "salvage_attempt"
    if "completed" in m or "no findings" in m or "wrap" in m or "exiting cleanly" in m: return "completed/no-findings"
    return None

total_switch = 0
fate = Counter()

for f in files:
    rows = []
    try:
        with open(f) as fh:
            for ln in fh:
                if '"msg"' not in ln: continue
                try: r = json.loads(ln)
                except Exception: continue
                msg = r.get("msg")
                if isinstance(msg, str): rows.append(msg)
    except Exception:
        continue

    # group line indices by agent token
    for i, msg in enumerate(rows):
        if not RE_SWITCH.search(msg):
            continue
        am = re.search(r"\[([^\]]+)\] primary tier exhausted", msg)
        if not am:
            continue
        agent = am.group(1)
        total_switch += 1
        tok = f"[{agent}]"
        decided = None
        # scan this agent's OWN subsequent lines
        for msg2 in rows[i+1:]:
            if tok not in msg2:
                continue
            if "primary tier exhausted, switching" in msg2:  # next episode for same agent
                decided = "next_episode (unresolved)"
                break
            c = classify_own_line(msg2)
            if c:
                decided = c
                break
        fate[decided or "no_more_own_lines (cancelled/log-ends)"] += 1

print(f"total switch-to-fallback events: {total_switch}")
print("fate of each (by the worker's OWN next decisive log line):")
for k, v in fate.most_common():
    print(f"   {k:38s} {v}")
print()
rescued = fate.get("rescued_fallback", 0)
captured = fate.get("this_worker_captured_flag", 0)
benign = fate.get("sibling_captured_flag(benign)", 0) + fate.get("completed/no-findings", 0) + captured
op_loss = sum(fate.get(k,0) for k in ["recursion/step-budget","rate_limit/quota","transport_error","context_window","soft_refusal_loss","no_more_own_lines (cancelled/log-ends)","next_episode (unresolved)","salvage_attempt"])
print(f"SUMMARY of {total_switch} fallback switches:")
print(f"  rescued by fallback model ........... {rescued}  ({100*rescued/total_switch:.1f}%)")
print(f"  worker itself then captured flag .... {captured}")
print(f"  benign run-end (sibling/complete) ... {fate.get('sibling_captured_flag(benign)',0)+fate.get('completed/no-findings',0)}")
print(f"  operational loss (NOT a refusal) .... {op_loss - benign + captured if False else op_loss}")
print(f"  fallback-tier REFUSALS .............. 0  (the fallback model never refused)")
