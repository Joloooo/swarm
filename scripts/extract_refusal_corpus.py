#!/usr/bin/env python3
"""Extract the cyber_policy refusal corpus + recovery-ladder funnel from logs/.

Two jobs, both driven off the real run logs (NOT a synthetic 500-request sweep):

  1. LADDER FUNNEL  — count *first* refusals (deduped to one per episode, never
     counting the 2nd/3rd retry of the same request as a new refusal), then how
     many survived to primary retry #1 (attempt 2), retry #2 (attempt 3), how
     many were swapped to the fallback model (gpt-5.4), and how many were never
     resolved. Written to ladder_stats.{json,md}.

  2. REPLAY CORPUS  — for every first-refusal episode, recover the exact LLM
     request that was refused (system_prompt + messages + tools, straight from
     the llm_start telemetry) so it can be modified and replayed to test other
     safety-workaround techniques. Index → refusal_index.jsonl (committed, small);
     full payloads → payloads/<id>.json (bulky, git-ignored, local replay).

Episode model (see src/refusals/retry.py):
  - preventive vocab filter (always-on)  : INFO "preventive vocab filter applied"
  - tier-1 primary retry x3              : WARN "worker refused (tier=primary, attempt=X/3)"
  - sticky fallback routing              : INFO "starting directly on fallback model"
  - switch to fallback                   : INFO "primary tier exhausted, switching to fallback model"
  - tier-2 fallback retry x3             : WARN "worker refused (tier=fallback, attempt=X/3)"   (none observed)
  - fallback rescue                      : INFO "rescued by fallback model on attempt N"
  - no fallback wired                    : INFO "primary tier exhausted, no fallback factory supplied" (none observed)

KEY ASYMMETRY: a *primary* success emits NO log (the retry loop just returns), so a
primary-retry rescue is inferred from a gap in the attempt sequence (refused at 1,
never at 2 => attempt 2 rescued it). A *fallback* success is logged ("rescued by ...").

The refused request payload is paired to its episode by walking each (file, agent_id)
event stream in timestamp order and attaching the most recent llm_start seen before the
episode's first refusal — llm_error carries no lc_run_id, so agent_id + ts order is the
only join available.
"""
from __future__ import annotations
import glob, json, os, re
from collections import defaultdict, Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # SwarmAttacker/
LOGS = os.path.join(ROOT, "logs")
OUT = os.path.join(ROOT, "benchmarks", "refusal_corpus")
PAYLOAD_DIR = os.path.join(OUT, "payloads")

RE_PRIMARY = re.compile(r"\[([^\]]+)\] worker refused \(tier=primary, attempt=(\d+)/(\d+)")
RE_FALLBACK = re.compile(r"\[([^\]]+)\] worker refused \(tier=fallback, attempt=(\d+)/(\d+)")
RE_RESCUED = re.compile(r"\[([^\]]+)\] rescued by fallback model on attempt (\d+)")
RE_SWITCH = re.compile(r"\[([^\]]+)\] primary tier exhausted, switching to fallback model")
RE_NOFB = re.compile(r"\[([^\]]+)\] primary tier exhausted, no fallback factory supplied")
# Each sticky routing emits TWO lines ~30ms apart ("config X refused ... earlier
# this run" then "starting directly on fallback model"). Match ONLY the dispatch
# line so a single routing is not counted as two episodes.
RE_STICKY = re.compile(r"\[([^\]]+)\] starting directly on fallback model")
RE_BENCH = re.compile(r"(XBEN-\d+(?:-\d+)?)")


def bench_of(path: str) -> str:
    m = RE_BENCH.search(path)
    return m.group(1) if m else "unknown"


def run_basename(path: str) -> str:
    # .../run-06-14_21h12m18s_XBEN-029/full_logs.jsonl -> run-06-14_21h12m18s_XBEN-029
    d = os.path.dirname(path)
    return os.path.basename(d)


def skill_of(agent: str) -> str:
    return re.sub(r"-\d+$", "", agent)


def last_user_text(messages) -> str:
    """Best-effort: text of the final non-system message, truncated."""
    if not isinstance(messages, list) or not messages:
        return ""
    msg = messages[-1]
    if isinstance(msg, dict):
        content = msg.get("content", msg.get("text", ""))
    else:
        content = msg
    return str(content)[:800]


def build_streams():
    """Return {(file, agent): [ (ts, lineidx, kind, data) ...] } across all logs."""
    files = sorted(glob.glob(os.path.join(LOGS, "**", "full_logs.jsonl"), recursive=True))
    streams = defaultdict(list)
    vocab_subs = []
    raw_cyber = 0
    for f in files:
        try:
            with open(f, "r") as fh:
                for i, line in enumerate(fh):
                    if not line.strip():
                        continue
                    # cheap pre-filter to avoid json-parsing every bash_output line
                    if ('worker refused' not in line and 'fallback model' not in line
                            and 'vocab filter applied' not in line and 'tier exhausted' not in line
                            and '"llm_start"' not in line and '"llm_error"' not in line):
                        continue
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    ts = r.get("ts", "")
                    typ = r.get("type")
                    if typ == "llm_start":
                        ag = r.get("agent_id", "?")
                        streams[(f, ag)].append((ts, i, "START", {
                            "request": r.get("request"), "node": r.get("node"), "model": r.get("model"),
                        }))
                        continue
                    if typ == "llm_error":
                        if r.get("error_type") == "CodexCyberPolicyError":
                            raw_cyber += 1
                            ag = r.get("agent_id", "?")
                            streams[(f, ag)].append((ts, i, "CYBER", {
                                "error_type": r.get("error_type"), "error_msg": r.get("error_msg"),
                                "node": r.get("node"),
                            }))
                        continue
                    msg = r.get("msg")
                    if not isinstance(msg, str):
                        continue
                    m = RE_PRIMARY.search(msg)
                    if m:
                        streams[(f, m.group(1))].append((ts, i, "P", int(m.group(2)))); continue
                    m = RE_FALLBACK.search(msg)
                    if m:
                        streams[(f, m.group(1))].append((ts, i, "F", int(m.group(2)))); continue
                    m = RE_RESCUED.search(msg)
                    if m:
                        streams[(f, m.group(1))].append((ts, i, "RFB", int(m.group(2)))); continue
                    m = RE_SWITCH.search(msg)
                    if m:
                        streams[(f, m.group(1))].append((ts, i, "SWITCH", None)); continue
                    m = RE_NOFB.search(msg)
                    if m:
                        streams[(f, m.group(1))].append((ts, i, "NOFB", None)); continue
                    m = RE_STICKY.search(msg)
                    if m:
                        streams[(f, m.group(1))].append((ts, i, "STICKY", None)); continue
                    if "preventive vocab filter applied" in msg:
                        mm = re.search(r"applied: (\d+) sys \+ (\d+) seed", msg)
                        if mm:
                            vocab_subs.append((int(mm.group(1)), int(mm.group(2))))
        except Exception as e:
            print("skip", f, e)
    return files, streams, vocab_subs, raw_cyber


def new_ep(f, agent, sticky):
    return dict(file=f, agent=agent, benchmark=bench_of(f), run=run_basename(f),
                primary=set(), fallback=set(), switched=False, nofb=False,
                sticky=sticky, rescued_fb=None, first_ref_ts=None,
                first_error_msg=None, first_error_type=None,
                payload=None, payload_ts=None, payload_node=None)


def reconstruct(streams):
    episodes = []

    def finalize(ep):
        if ep is not None:
            episodes.append(ep)

    for (f, agent), evs in streams.items():
        evs.sort(key=lambda e: (e[0], e[1]))   # ts then line index
        ep = None
        last_start = None
        last_start_ts = None
        last_start_node = None
        pending_err = None   # CYBER seen just before its "worker refused" msg
        fwd_ep = None        # episode awaiting payload from the NEXT start (sticky/fallback-opened)
        for ts, _i, kind, data in evs:
            if kind == "START":
                last_start = data.get("request")
                last_start_ts = ts
                last_start_node = data.get("node")
                if fwd_ep is not None and not fwd_ep["payload"]:
                    fwd_ep["payload"] = last_start
                    fwd_ep["payload_ts"] = ts
                    fwd_ep["payload_node"] = last_start_node
                    fwd_ep = None
            elif kind == "CYBER":
                if ep is not None and ep["first_error_msg"] is None:
                    ep["first_error_msg"] = data.get("error_msg")
                    ep["first_error_type"] = data.get("error_type")
                else:
                    pending_err = data
            elif kind == "P":
                attempt = data
                if attempt == 1 or ep is None:
                    finalize(ep)
                    fwd_ep = None
                    ep = new_ep(f, agent, sticky=False)
                    ep["payload"] = last_start
                    ep["payload_ts"] = last_start_ts
                    ep["payload_node"] = last_start_node
                    ep["first_ref_ts"] = ts
                    if pending_err is not None:
                        ep["first_error_msg"] = pending_err.get("error_msg")
                        ep["first_error_type"] = pending_err.get("error_type")
                        pending_err = None
                ep["primary"].add(attempt)
            elif kind == "STICKY":
                finalize(ep)
                ep = new_ep(f, agent, sticky=True)
                ep["first_ref_ts"] = ts
                fwd_ep = ep   # payload is the NEXT start (the fallback call), not the prior one
            elif kind == "SWITCH":
                if ep is None:
                    ep = new_ep(f, agent, sticky=False)
                ep["switched"] = True
            elif kind == "NOFB":
                if ep is None:
                    ep = new_ep(f, agent, sticky=False)
                ep["nofb"] = True
            elif kind == "F":
                if ep is None:
                    ep = new_ep(f, agent, sticky=True)
                    ep["payload"] = last_start
                    ep["payload_ts"] = last_start_ts
                    ep["first_ref_ts"] = ts
                ep["fallback"].add(data)
            elif kind == "RFB":
                if ep is None:
                    ep = new_ep(f, agent, sticky=True)
                    ep["payload"] = last_start
                    ep["payload_ts"] = last_start_ts
                ep["rescued_fb"] = data
                finalize(ep)
                ep = None
        finalize(ep)
    return episodes


def classify(ep):
    """Attach outcome / rescued_by / reached_fallback to an episode dict."""
    P, F = ep["primary"], ep["fallback"]
    went_fallback = ep["switched"] or bool(F) or ep["rescued_fb"] is not None or ep["sticky"]
    ep["reached_fallback"] = bool(went_fallback) and not ep["nofb"]
    ep["max_primary_attempt"] = max(P) if P else 0
    pmax = ep["max_primary_attempt"]
    if ep["nofb"]:
        ep["rescued_by"], ep["rescue_attempt"], ep["outcome"] = None, None, "lost"
    elif went_fallback:
        # fallback never refused in this dataset -> reaching it == resolved
        ep["rescued_by"] = "fallback"
        ep["rescue_attempt"] = ep["rescued_fb"]   # may be None if success logged as plain llm_end
        ep["outcome"] = "resolved"
    elif P:
        # refused on primary then a gap, no switch -> a retry rescued it
        if pmax == 1:
            ep["rescued_by"], ep["rescue_attempt"] = "primary-retry", 2
        elif pmax == 2:
            ep["rescued_by"], ep["rescue_attempt"] = "primary-retry", 3
        else:  # refused all 3, no switch marker -> treat as exhausted (rare)
            ep["rescued_by"], ep["rescue_attempt"] = None, None
        ep["outcome"] = "resolved" if ep["rescued_by"] else "lost"
    else:
        ep["rescued_by"], ep["rescue_attempt"], ep["outcome"] = None, None, "unknown"
    return ep


def main():
    os.makedirs(PAYLOAD_DIR, exist_ok=True)
    files, streams, vocab_subs, raw_cyber = build_streams()
    episodes = [classify(ep) for ep in reconstruct(streams)]

    # ---- funnel counts ----
    primary_ep = [e for e in episodes if e["primary"]]
    sticky_ep = [e for e in episodes if e["sticky"] and not e["primary"]]
    P1 = sum(1 for e in primary_ep if 1 in e["primary"])
    P2 = sum(1 for e in primary_ep if 2 in e["primary"])
    P3 = sum(1 for e in primary_ep if 3 in e["primary"])
    rescued_retry1 = sum(1 for e in primary_ep if e["rescued_by"] == "primary-retry" and e["rescue_attempt"] == 2)
    rescued_retry2 = sum(1 for e in primary_ep if e["rescued_by"] == "primary-retry" and e["rescue_attempt"] == 3)
    reached_fb = sum(1 for e in episodes if e["reached_fallback"])
    resolved_fb = sum(1 for e in episodes if e["rescued_by"] == "fallback")
    fb_rescue_logged = sum(1 for e in episodes if e["rescued_fb"] is not None)
    lost = sum(1 for e in episodes if e["outcome"] == "lost")
    no_payload = sum(1 for e in episodes if not e["payload"])

    def pct(a, b):
        return round(100.0 * a / b, 1) if b else None

    stats = {
        "logs_scanned": len(files),
        "raw_cyber_policy_errors": raw_cyber,
        "total_episodes": len(episodes),
        "confirmed_primary_first_refusals": P1,
        "sticky_pre_routed_no_primary_attempt": len(sticky_ep),
        "funnel": {
            "refused_1st_attempt": P1,
            "survived_to_2nd_attempt": P2,
            "rescued_by_retry1": rescued_retry1,
            "survived_to_3rd_attempt": P3,
            "rescued_by_retry2": rescued_retry2,
            "reached_fallback_swap": reached_fb,
            "resolved_at_fallback": resolved_fb,
            "fallback_rescue_explicitly_logged": fb_rescue_logged,
            "never_resolved_lost": lost,
        },
        "conditional_decay": {
            "P_rescue_given_refused_once_pct": pct(rescued_retry1, P1),
            "P_rescue_given_survived_to_2nd_pct": pct(rescued_retry2, P2),
            "P_survived_all_primary_to_fallback_pct": pct(P3, P1),
        },
        "fallback_ever_refused": any(e["fallback"] for e in episodes),
        "episodes_missing_payload": no_payload,
        "by_skill": dict(Counter(skill_of(e["agent"]) for e in episodes).most_common()),
        "by_benchmark": dict(Counter(e["benchmark"] for e in episodes).most_common()),
        "vocab_filter_applications": len(vocab_subs),
    }

    # ---- write index + payloads ----
    seq = Counter()
    index_path = os.path.join(OUT, "refusal_index.jsonl")
    n_written = 0
    with open(index_path, "w") as ix:
        for e in episodes:
            key = (e["benchmark"], skill_of(e["agent"]))
            seq[key] += 1
            eid = f"{e['benchmark']}__{e['agent']}__{seq[key]:03d}"
            req = e["payload"] or {}
            msgs = req.get("messages") if isinstance(req, dict) else None
            payload_file = None
            if isinstance(req, dict) and req:
                payload_file = os.path.join("payloads", f"{eid}.json")
                with open(os.path.join(PAYLOAD_DIR, f"{eid}.json"), "w") as pf:
                    json.dump(req, pf, ensure_ascii=False)
                n_written += 1
            rec = {
                "id": eid,
                "benchmark": e["benchmark"],
                "run": e["run"],
                "agent_id": e["agent"],
                "skill": skill_of(e["agent"]),
                "node": e["payload_node"],
                # True = a real cyber_policy refusal was observed on the primary model
                # for this exact request. False = sticky pre-route (config refused
                # earlier, so this call skipped primary; never actually refused).
                "confirmed_primary_refusal": bool(e["primary"]),
                "first_refusal_ts": e["first_ref_ts"],
                "trajectory": {
                    "sticky_direct_to_fallback": e["sticky"],
                    "primary_attempts_refused": sorted(e["primary"]),
                    "fallback_attempts_refused": sorted(e["fallback"]),
                    "switched_to_fallback": e["switched"],
                    "no_fallback_wired": e["nofb"],
                    "max_primary_attempt": e["max_primary_attempt"],
                    "reached_fallback": e["reached_fallback"],
                    "rescued_by": e["rescued_by"],
                    "rescue_attempt": e["rescue_attempt"],
                    "outcome": e["outcome"],
                },
                "first_error_type": e["first_error_type"],
                "first_error_msg": (e["first_error_msg"] or "")[:300],
                "request_preview": {
                    "n_messages": req.get("n_messages") if isinstance(req, dict) else None,
                    "estimated_input_tokens": req.get("estimated_input_tokens") if isinstance(req, dict) else None,
                    "total_chars": req.get("total_chars") if isinstance(req, dict) else None,
                    "system_prompt_chars": len(req.get("system_prompt", "")) if isinstance(req, dict) else None,
                    "n_tools": len(req.get("tools", [])) if isinstance(req, dict) and isinstance(req.get("tools"), list) else None,
                    "last_message": last_user_text(msgs),
                },
                "source_log": os.path.relpath(e["file"], ROOT),
                "payload_file": payload_file,
            }
            ix.write(json.dumps(rec, ensure_ascii=False) + "\n")

    with open(os.path.join(OUT, "ladder_stats.json"), "w") as sf:
        json.dump(stats, sf, indent=2)

    _write_md(stats)

    # ---- stdout summary ----
    print("=" * 70)
    print("REFUSAL CORPUS + LADDER FUNNEL")
    print("=" * 70)
    print(f"logs scanned ......................... {len(files)}")
    print(f"raw cyber_policy errors (all retries)  {raw_cyber}")
    print(f"total episodes ....................... {len(episodes)}")
    print(f"  confirmed primary first-refusals ... {P1}")
    print(f"  sticky pre-routed (never refused) .. {len(sticky_ep)}")
    print(f"episodes missing a payload ........... {no_payload}")
    print(f"payload files written ................ {n_written}  -> {os.path.relpath(PAYLOAD_DIR, ROOT)}/")
    print(f"index ................................ {os.path.relpath(index_path, ROOT)}")
    print()
    print("LADDER FUNNEL (confirmed first refusal -> resolution):")
    print(f"  refused 1st attempt (primary) ...... {P1}")
    print(f"    rescued by retry #1 (attempt 2) .. {rescued_retry1}   ({pct(rescued_retry1, P1)}%)")
    print(f"    survived to 2nd attempt .......... {P2}")
    print(f"    rescued by retry #2 (attempt 3) .. {rescued_retry2}   ({pct(rescued_retry2, P2)}% of survivors)")
    print(f"    survived to 3rd attempt .......... {P3}")
    print(f"    -> exhausted primary, swap to fb . {P3}")
    print(f"  swapped to fallback gpt-5.4 (total)  {reached_fb}")
    print(f"    via primary exhaustion ........... {reached_fb - len(sticky_ep)}")
    print(f"    via sticky pre-route ............. {len(sticky_ep)}")
    print(f"    resolved at fallback ............. {resolved_fb}")
    print(f"    fallback rescue logged explicitly  {fb_rescue_logged}")
    print(f"  NEVER RESOLVED (lost) .............. {lost}")
    print(f"  fallback model ever refused? ....... {stats['fallback_ever_refused']}")


def _write_md(stats):
    f = stats["funnel"]
    cd = stats["conditional_decay"]
    lines = [
        "# Cyber-policy refusal recovery ladder — measured from `logs/`",
        "",
        "Generated by `scripts/extract_refusal_corpus.py`. Every number below is a",
        "*first* refusal (one per episode); the 2nd/3rd retry of the same request is",
        "not counted again. Source: all `logs/**/full_logs.jsonl` run logs.",
        "",
        f"- Logs scanned: **{stats['logs_scanned']}**",
        f"- Raw cyber_policy errors (counting every retry): **{stats['raw_cyber_policy_errors']}**",
        f"- Total episodes: **{stats['total_episodes']}** "
        f"(**{stats['confirmed_primary_first_refusals']}** confirmed primary refusals "
        f"+ **{stats['sticky_pre_routed_no_primary_attempt']}** sticky pre-routes that never reached the primary model)",
        f"- Fallback model (gpt-5.4) ever refused: **{stats['fallback_ever_refused']}**",
        "",
        "## Funnel",
        "",
        "| Ladder rung | Episodes still refused | Resolved here |",
        "|---|---|---|",
        f"| Refused on 1st attempt (primary) | {f['refused_1st_attempt']} | — |",
        f"| Retry #1 (2nd attempt) | {f['survived_to_2nd_attempt']} | {f['rescued_by_retry1']} rescued |",
        f"| Retry #2 (3rd attempt) | {f['survived_to_3rd_attempt']} | {f['rescued_by_retry2']} rescued |",
        f"| Swap to fallback gpt-5.4 | {f['reached_fallback_swap']} | {f['resolved_at_fallback']} resolved |",
        f"| Never resolved (lost) | {f['never_resolved_lost']} | — |",
        "",
        f"- Sticky direct-to-fallback (skipped primary entirely): **{stats['sticky_pre_routed_no_primary_attempt']}**",
        f"- Fallback rescue explicitly logged: **{f['fallback_rescue_explicitly_logged']}**",
        "",
        "## Conditional per-retry success (the decay)",
        "",
        f"- P(rescued | refused once)        = **{cd['P_rescue_given_refused_once_pct']}%**  (retry #1)",
        f"- P(rescued | survived to 2nd)     = **{cd['P_rescue_given_survived_to_2nd_pct']}%**  (retry #2)",
        f"- P(survived all primary → fallback) = **{cd['P_survived_all_primary_to_fallback_pct']}%**",
        "",
        "## Episodes by skill",
        "",
        "| Skill | Episodes |",
        "|---|---|",
    ]
    for k, v in stats["by_skill"].items():
        lines.append(f"| {k} | {v} |")
    lines += ["", "## Episodes by benchmark", "", "| Benchmark | Episodes |", "|---|---|"]
    for k, v in stats["by_benchmark"].items():
        lines.append(f"| {k} | {v} |")
    lines.append("")
    with open(os.path.join(OUT, "ladder_stats.md"), "w") as mf:
        mf.write("\n".join(lines))


if __name__ == "__main__":
    main()
