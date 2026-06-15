#!/usr/bin/env python3
"""Build the safety-test working set under logs/safety_tests/.

Collects the confirmed cyber_policy refusals into two self-contained JSONL files
so other safety-workaround techniques can be tried by mutating the exact request
that was refused and replaying it:

  refusals_all_598.jsonl          all 598 requests refused on the first try
  refusals_swap_needed_348.jsonl  the 348 that survived all 3 same-model retries
                                  and only cleared after the swap to gpt-5.4 --
                                  i.e. the hard tail where retrying did NOT work

Each line embeds the full request (`system_prompt` + `messages` + `tools`) so it
is replayable on its own, plus the production trajectory for reference. Source of
truth is benchmarks/refusal_corpus/ (regenerate it first with
extract_refusal_corpus.py). The full payloads stay in the corpus too; this script
copies them into the aggregate files rather than moving them, so the committed
corpus index stays valid. logs/ is git-ignored, so this working set is local.
"""
from __future__ import annotations
import json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # SwarmAttacker/
CORPUS = os.path.join(ROOT, "benchmarks", "refusal_corpus")
OUT = os.path.join(ROOT, "logs", "safety_tests")


def load_index():
    with open(os.path.join(CORPUS, "refusal_index.jsonl")) as fh:
        return [json.loads(l) for l in fh if l.strip()]


def load_payload(rec):
    pf = rec.get("payload_file")
    if not pf:
        return None
    path = os.path.join(CORPUS, pf)
    if not os.path.exists(path):
        return None
    with open(path) as fh:
        return json.load(fh)


def record(rec, req):
    t = rec["trajectory"]
    return {
        "id": rec["id"],
        "benchmark": rec["benchmark"],
        "skill": rec["skill"],
        "agent_id": rec["agent_id"],
        "run": rec["run"],
        "production_trajectory": {
            "primary_attempts_refused": t["primary_attempts_refused"],
            "max_primary_attempt": t["max_primary_attempt"],
            "reached_fallback": t["reached_fallback"],
            "rescued_by": t["rescued_by"],
            "rescue_attempt": t["rescue_attempt"],
            "outcome": t["outcome"],
        },
        "first_error_msg": rec["first_error_msg"],
        "source_log": rec["source_log"],
        "request": req,   # {system_prompt, messages, tools, ...} or null (8 telemetry gaps)
    }


def write(path, recs):
    n_req = 0
    with open(path, "w") as fh:
        for rec in recs:
            req = load_payload(rec)
            if req is not None:
                n_req += 1
            fh.write(json.dumps(record(rec, req), ensure_ascii=False) + "\n")
    return len(recs), n_req


def main():
    os.makedirs(OUT, exist_ok=True)
    idx = load_index()
    confirmed = [r for r in idx if r["confirmed_primary_refusal"]]
    swap_needed = [r for r in confirmed if r["trajectory"]["reached_fallback"]]

    all_path = os.path.join(OUT, "refusals_all_598.jsonl")
    swap_path = os.path.join(OUT, "refusals_swap_needed_348.jsonl")
    n_all, n_all_req = write(all_path, confirmed)
    n_swap, n_swap_req = write(swap_path, swap_needed)

    readme = f"""# Safety-test working set

Local replay material for trying additional safety-workaround techniques on the
requests the classifier actually refused. Regenerate with
`python3 scripts/build_safety_test_set.py` (reads benchmarks/refusal_corpus/).

| File | Records | With request payload | What |
|---|---|---|---|
| `refusals_all_598.jsonl` | {n_all} | {n_all_req} | Every request refused on the first try (the full corpus). |
| `refusals_swap_needed_348.jsonl` | {n_swap} | {n_swap_req} | The hard tail: survived all 3 same-model retries, only cleared after the swap to gpt-5.4. Test new techniques here -- this is where retrying did NOT work. |

Each line: `id`, `benchmark`, `skill`, `run`, `production_trajectory`,
`first_error_msg`, `source_log`, and `request` (the full
`system_prompt` + `messages` + `tools`, replayable as-is; `null` for the 8 of 598
that hit a telemetry gap where the request was never logged).

To run a technique: load a line, mutate `request` (apply the technique), re-issue
it on the primary model, and record whether it still refuses.
"""
    with open(os.path.join(OUT, "README.md"), "w") as fh:
        fh.write(readme)

    print(f"wrote {os.path.relpath(all_path, ROOT)}  ({n_all} records, {n_all_req} with payload)")
    print(f"wrote {os.path.relpath(swap_path, ROOT)}  ({n_swap} records, {n_swap_req} with payload)")
    print(f"wrote {os.path.relpath(os.path.join(OUT, 'README.md'), ROOT)}")


if __name__ == "__main__":
    main()
