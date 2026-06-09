#!/usr/bin/env python3
"""Ad-hoc analysis: cyber_policy refusal-recovery effectiveness across ALL logs.

Reconstructs each refusal "episode" from the retry-ladder log lines in every
full_logs.jsonl under logs/, then reports per-step / per-attempt rescue rates.

Episode model (see src/refusals/retry.py):
  - Preventive vocab filter (always-on)  -> INFO "preventive vocab filter applied"
  - Tier-1 primary retry x3              -> WARN "worker refused (tier=primary, attempt=X/3)"
  - Sticky fallback routing              -> INFO "dispatching directly on the fallback model"
                                            / "starting directly on fallback model"
  - Tier-2 fallback retry x3             -> WARN "worker refused (tier=fallback, attempt=X/3)"
                                            INFO "rescued by fallback model on attempt N"
                                            INFO "primary tier exhausted, switching to fallback model"
                                            INFO "primary tier exhausted, no fallback factory supplied"

KEY ASYMMETRY: a *primary* success emits NO log (the loop just returns), so primary
rescue is inferred from a gap in the attempt sequence (refused at 1 but never at 2 =>
attempt-2 rescued it). A *fallback* success is logged explicitly.
"""
from __future__ import annotations
import glob, json, os, re
from collections import defaultdict, Counter

LOGS = "/Users/zviadjolokhava/Dev/Thesis/SwarmAttacker/logs"

RE_PRIMARY  = re.compile(r"\[([^\]]+)\] worker refused \(tier=primary, attempt=(\d+)/(\d+)\)")
RE_FALLBACK = re.compile(r"\[([^\]]+)\] worker refused \(tier=fallback, attempt=(\d+)/(\d+)\)")
RE_RESCUED  = re.compile(r"\[([^\]]+)\] rescued by fallback model on attempt (\d+)")
RE_SWITCH   = re.compile(r"\[([^\]]+)\] primary tier exhausted, switching to fallback model")
RE_NOFB     = re.compile(r"\[([^\]]+)\] primary tier exhausted, no fallback factory supplied")
RE_STICKY   = re.compile(r"\[([^\]]+)\] (?:config .* refused on the primary model earlier this run|starting directly on fallback model)")
RE_VOCAB    = re.compile(r"\[([^\]]+)\] preventive vocab filter applied: (\d+) sys \+ (\d+) seed")

files = sorted(glob.glob(os.path.join(LOGS, "**", "full_logs.jsonl"), recursive=True))

# Per (file, agent) ordered event stream
events = defaultdict(list)  # (file, agent) -> list of (kind, attempt, raw)
vocab_subs = []             # (sys, seed) per applied line
vocab_applied_count = 0
files_with_refusals = set()
refusal_skill_counter = Counter()  # agent prefix -> count of attempt=1 primary/sticky episodes

for f in files:
    try:
        with open(f, "r") as fh:
            for line in fh:
                if "worker refused" not in line and "fallback model" not in line \
                   and "vocab filter applied" not in line and "tier exhausted" not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                msg = rec.get("msg", "")
                if not isinstance(msg, str):
                    continue
                m = RE_PRIMARY.search(msg)
                if m:
                    events[(f, m.group(1))].append(("P", int(m.group(2)), msg))
                    files_with_refusals.add(f); continue
                m = RE_FALLBACK.search(msg)
                if m:
                    events[(f, m.group(1))].append(("F", int(m.group(2)), msg)); continue
                m = RE_RESCUED.search(msg)
                if m:
                    events[(f, m.group(1))].append(("RFB", int(m.group(2)), msg)); continue
                m = RE_SWITCH.search(msg)
                if m:
                    events[(f, m.group(1))].append(("SWITCH", 0, msg)); continue
                m = RE_NOFB.search(msg)
                if m:
                    events[(f, m.group(1))].append(("NOFB", 0, msg)); continue
                m = RE_STICKY.search(msg)
                if m:
                    events[(f, m.group(1))].append(("STICKY", 0, msg)); continue
                m = RE_VOCAB.search(msg)
                if m:
                    vocab_applied_count += 1
                    vocab_subs.append((int(m.group(2)), int(m.group(3)))); continue
    except Exception as e:
        print("skip", f, e)

# ---- Episode reconstruction ----
# An episode is a maximal run for one (file, agent). A new episode begins on a
# primary attempt==1, or on a STICKY marker, when no episode is currently open
# at primary state.
episodes = []  # dicts

def finalize(ep):
    if ep is None:
        return
    episodes.append(ep)

for key, evs in events.items():
    f, agent = key
    ep = None
    for kind, attempt, _ in evs:
        if kind == "P":
            if attempt == 1:
                # new primary episode
                finalize(ep)
                ep = dict(file=f, agent=agent, primary=set(), fallback=set(),
                          switched=False, nofb=False, rescued_fb=None, sticky=False)
            if ep is None:  # primary attempt>1 with no opener (shouldn't happen) -> start
                ep = dict(file=f, agent=agent, primary=set(), fallback=set(),
                          switched=False, nofb=False, rescued_fb=None, sticky=False)
            ep["primary"].add(attempt)
        elif kind == "STICKY":
            finalize(ep)
            ep = dict(file=f, agent=agent, primary=set(), fallback=set(),
                      switched=False, nofb=False, rescued_fb=None, sticky=True)
        elif kind == "SWITCH":
            if ep is None:
                ep = dict(file=f, agent=agent, primary=set(), fallback=set(),
                          switched=False, nofb=False, rescued_fb=None, sticky=False)
            ep["switched"] = True
        elif kind == "NOFB":
            if ep is None:
                ep = dict(file=f, agent=agent, primary=set(), fallback=set(),
                          switched=False, nofb=False, rescued_fb=None, sticky=False)
            ep["nofb"] = True
        elif kind == "F":
            if ep is None:
                ep = dict(file=f, agent=agent, primary=set(), fallback=set(),
                          switched=False, nofb=False, rescued_fb=None, sticky=True)
            ep["fallback"].add(attempt)
        elif kind == "RFB":
            if ep is None:
                ep = dict(file=f, agent=agent, primary=set(), fallback=set(),
                          switched=False, nofb=False, rescued_fb=None, sticky=True)
            ep["rescued_fb"] = attempt
            finalize(ep); ep = None
    finalize(ep)

# ---- Classify outcomes ----
def skill_of(agent):
    # executor-0 -> executor; vulntype-ssti -> vulntype-ssti; keep as-is otherwise
    return re.sub(r"-\d+$", "", agent)

P1 = P2 = P3 = 0          # episodes that refused at primary attempt 1 / reached 2 / reached 3
prim_rescue2 = prim_rescue3 = 0
reached_fallback = 0
sticky_episodes = 0
fb1 = fb2 = fb3 = 0
fb_rescue1 = fb_rescue2 = fb_rescue3 = 0
lost = 0                  # all tiers exhausted (RefusalError -> salvage)
lost_nofb = 0             # primary exhausted, no fallback wired
rescued_primary_total = 0
rescued_fallback_total = 0
outcome_counter = Counter()

for ep in episodes:
    P = ep["primary"]; F = ep["fallback"]
    if ep["sticky"]:
        sticky_episodes += 1
    if P:
        refusal_skill_counter[skill_of(ep["agent"])] += 1
    elif ep["sticky"]:
        refusal_skill_counter[skill_of(ep["agent"])] += 1

    pmax = max(P) if P else 0
    # primary funnel
    if 1 in P: P1 += 1
    if 2 in P: P2 += 1
    if 3 in P: P3 += 1

    went_fallback = ep["switched"] or bool(F) or ep["rescued_fb"] is not None or ep["sticky"]

    # primary rescue (implicit): refused then a gap, never exhausted to fallback
    if P and not went_fallback and not ep["nofb"]:
        if pmax == 1:
            prim_rescue2 += 1; rescued_primary_total += 1; outcome_counter["rescued@primary-retry1(att2)"] += 1
        elif pmax == 2:
            prim_rescue3 += 1; rescued_primary_total += 1; outcome_counter["rescued@primary-retry2(att3)"] += 1
        elif pmax == 3:
            # refused all 3 but no switch/nofb logged -> treat as exhausted primary (rare)
            lost_nofb += 1; outcome_counter["primary-exhausted(no-marker)"] += 1
    elif P and ep["nofb"]:
        lost_nofb += 1; outcome_counter["lost@primary-exhausted-no-fallback"] += 1

    # fallback funnel
    if went_fallback and not ep["nofb"]:
        reached_fallback += 1
        if 1 in F: fb1 += 1
        if 2 in F: fb2 += 1
        if 3 in F: fb3 += 1
        if ep["rescued_fb"] is not None:
            rescued_fallback_total += 1
            if ep["rescued_fb"] == 1: fb_rescue1 += 1; outcome_counter["rescued@fallback-att1"] += 1
            elif ep["rescued_fb"] == 2: fb_rescue2 += 1; outcome_counter["rescued@fallback-att2"] += 1
            elif ep["rescued_fb"] == 3: fb_rescue3 += 1; outcome_counter["rescued@fallback-att3"] += 1
        else:
            # reached fallback, no rescue logged -> fallback exhausted -> LOST
            lost += 1; outcome_counter["lost@all-tiers-exhausted"] += 1

def pct(a, b):
    return f"{100.0*a/b:.1f}%" if b else "n/a"

print("="*78)
print("CYBER_POLICY REFUSAL-RECOVERY ANALYSIS — all logs/")
print("="*78)
print(f"full_logs.jsonl files scanned ........ {len(files)}")
print(f"files containing >=1 refusal ......... {len(files_with_refusals)}")
print(f"reconstructed refusal episodes ....... {len(episodes)}")
print(f"  (an episode = one astream_with_refusal_retry invocation that refused >=1x)")
print()
print("-"*78)
print("STEP 1 — Preventive vocab filter (always-on, before tier-1)")
print("-"*78)
tot_sys = sum(s for s,_ in vocab_subs); tot_seed = sum(s for _,s in vocab_subs)
nz = [v for v in vocab_subs if v[0] or v[1]]
print(f"calls where filter changed >=1 token . {vocab_applied_count}")
print(f"  total sys substitutions ............ {tot_sys}")
print(f"  total seed substitutions ........... {tot_seed}")
if vocab_applied_count:
    print(f"  avg subs per changed call .......... {(tot_sys+tot_seed)/vocab_applied_count:.2f}")
print("  (effectiveness not directly measurable here: filter is preventive, no counterfactual logged)")
print()
print("-"*78)
print("STEP 2 — Tier-1 PRIMARY retry x3   (attempt 1 = initial, 2 = retry#1, 3 = retry#2)")
print("-"*78)
print(f"episodes refused at primary attempt 1  {P1}")
print(f"  -> rescued by retry#1 (attempt 2) .. {prim_rescue2}   ({pct(prim_rescue2,P1)} of attempt-1 refusals)")
print(f"  -> still refused at attempt 2 ...... {P2}   ({pct(P2,P1)} survived to retry#2)")
print(f"     -> rescued by retry#2 (attempt 3) {prim_rescue3}   ({pct(prim_rescue3,P2)} of attempt-2 refusals)")
print(f"     -> still refused at attempt 3 ... {P3}   ({pct(P3,P2)} of attempt-2 refusals)")
print(f"  => primary tier rescued total ...... {rescued_primary_total}   ({pct(rescued_primary_total,P1)} of all primary refusals)")
print(f"  => primary tier exhausted .......... {P3}   ({pct(P3,P1)} of all primary refusals went to tier-2/loss)")
print()
print("CONDITIONAL per-retry success (the decay you predicted):")
print(f"  P(rescue | refused once)              = {pct(prim_rescue2,P1)}   [retry #1]")
print(f"  P(rescue | survived to 2nd refusal)   = {pct(prim_rescue3,P2)}   [retry #2]")
print(f"  P(rescue | survived to 3rd refusal)   = 0.0%  (attempt 3 is the last primary try)")
print()
print("-"*78)
print("STEP 3 — Sticky-fallback routing (skip primary for configs that already refused)")
print("-"*78)
print(f"episodes that started directly on fallback (sticky) . {sticky_episodes}")
print(f"  primary attempts SAVED (3 per sticky episode) ..... ~{sticky_episodes*3}")
print()
print("-"*78)
print("STEP 4 — Tier-2 FALLBACK model retry x3 (gpt-5.4 @ low)")
print("-"*78)
print(f"episodes that reached the fallback tier  {reached_fallback}")
print(f"  refused at fallback attempt 1 ........ {fb1}")
print(f"     rescued at fallback attempt 1 ..... {fb_rescue1}")
print(f"  refused at fallback attempt 2 ........ {fb2}")
print(f"     rescued at fallback attempt 2 ..... {fb_rescue2}")
print(f"  refused at fallback attempt 3 ........ {fb3}")
print(f"     rescued at fallback attempt 3 ..... {fb_rescue3}")
print(f"  => fallback rescued total ............ {rescued_fallback_total}  ({pct(rescued_fallback_total,reached_fallback)} of episodes reaching fallback)")
print(f"  => fallback exhausted (LOST) ......... {lost}  ({pct(lost,reached_fallback)} of episodes reaching fallback)")
print()
print("-"*78)
print("STEP 5 — Post-exhaustion salvage (last resort: only when ALL tiers fail)")
print("-"*78)
print(f"episodes lost (all tiers exhausted) ........ {lost}")
print(f"episodes lost (primary exhausted, no fallback) {lost_nofb}")
print("  (salvage tries to recover a finding/flag from partial messages; see salvage stats below)")
print()
print("="*78)
print("OVERALL FUNNEL  (every episode that hit >=1 cyber_policy refusal)")
print("="*78)
total_ep = len(episodes)
total_rescued = rescued_primary_total + rescued_fallback_total
total_lost = lost + lost_nofb
print(f"  total episodes ............ {total_ep}")
print(f"  rescued (any tier) ........ {total_rescued}   ({pct(total_rescued,total_ep)})")
print(f"    via primary retry ....... {rescued_primary_total}   ({pct(rescued_primary_total,total_ep)})")
print(f"    via fallback model ...... {rescued_fallback_total}   ({pct(rescued_fallback_total,total_ep)})")
print(f"  LOST (worker killed) ...... {total_lost}   ({pct(total_lost,total_ep)})")
print()
print("Outcome breakdown:")
for k, v in outcome_counter.most_common():
    print(f"    {k:42s} {v:5d}  ({pct(v,total_ep)})")
print()
print("="*78)
print("TOP SKILLS BY REFUSAL EPISODES")
print("="*78)
for skill, n in refusal_skill_counter.most_common(20):
    print(f"    {skill:36s} {n:5d}")
