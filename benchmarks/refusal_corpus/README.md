# Refusal corpus & recovery-ladder funnel

Real cyber_policy refusals harvested from the SwarmAttacker run logs (`logs/`),
deduped to one record per *first* refusal. This is the evidence base for the
thesis "Safety Methods Tested" section (Table 4.2 / `sec:safety-methods-tested`)
**and** the replay material for testing additional safety-workaround techniques.

Regenerate everything with:

```bash
python3 scripts/extract_refusal_corpus.py
```

## Why this exists

The recovery ladder in `src/refusals/retry.py` already ran over hundreds of real
refusals during benchmarking. Instead of a synthetic 500-request sweep, the
adopted-rung numbers are harvested straight from what actually happened. Each
rung is only ever asked to clear what the rung above it could not, so the funnel
measures the *marginal* value of each technique — which is exactly the claim
Table 4.2 makes ("a technique earns its place only if it cleared refusals the
baseline did not").

## Files

| File | Committed? | What |
|---|---|---|
| `ladder_stats.json` | yes | Funnel counts + conditional decay, machine-readable (fills Table 4.2). |
| `ladder_stats.md` | yes | Same numbers, human-readable, plus per-skill / per-benchmark breakdown. |
| `refusal_index.jsonl` | yes | One line per episode: trajectory, outcome, error, preview, and an exact reference to the source log + the full payload file. |
| `payloads/<id>.json` | **no** (git-ignored, ~100 MB) | The full refused request (`system_prompt` + `messages` + `tools`), replayable as-is. Regenerable from logs. |

## The funnel (measured, not estimated)

Every cyber_policy refusal was eventually resolved — **0 lost**. The fallback
model (gpt-5.4) never refused once.

```
598 confirmed primary first-refusals
 ├─ 184 rescued by retry #1 (same model, attempt 2)   — 30.8%
 ├─  66 rescued by retry #2 (same model, attempt 3)   — 16.0% of survivors
 └─ 348 exhausted all 3 primary attempts ─┐
                                          ├─→ 478 swapped to fallback gpt-5.4 → 478 resolved (0 refused)
130 sticky pre-routes (skipped primary) ──┘
```

`confirmed_primary_refusal = false` marks the 130 sticky records: their config
had already refused earlier in the run, so the call skipped the primary model
and went straight to the fallback. They never actually refused — keep them out
of any "refusal rate" denominator. For replaying refusals, filter to
`confirmed_primary_refusal = true` (590 of which carry a payload; 8 hit a
telemetry gap where the `llm_start` was not logged and have `payload_file = null`).

## Using it to test other techniques

The whole point: take a request the filter *actually* refused, modify it, and
replay to see whether technique X gets it through — and crucially, test each
technique at the ladder rung where it would actually slot in (see Table 4.2
discussion). Useful filters over `refusal_index.jsonl`:

- **All confirmed refusals** (baseline-level techniques, e.g. authorization
  framing): `confirmed_primary_refusal == true`.
- **The hard tail** — where retrying the same model did *not* work, so a new
  technique has real room to help: `trajectory.reached_fallback == true`
  (these survived all 3 primary attempts). 348 of these.
- **By weakness class**: filter on `skill` or `benchmark`.

Example — load every request that needed the fallback (retry-same-model failed):

```python
import json, pathlib
base = pathlib.Path("benchmarks/refusal_corpus")
for line in (base / "refusal_index.jsonl").open():
    rec = json.loads(line)
    if rec["confirmed_primary_refusal"] and rec["trajectory"]["reached_fallback"] and rec["payload_file"]:
        req = json.loads((base / rec["payload_file"]).read_text())
        # req = {"system_prompt": ..., "messages": [...], "tools": [...]}
        # mutate req (apply technique), re-issue on the primary model, record pass/fail
```

## Record schema (`refusal_index.jsonl`)

```jsonc
{
  "id": "XBEN-029__sqli__004",          // benchmark__agent__seq
  "benchmark": "XBEN-029", "run": "run-...", "agent_id": "sqli", "skill": "sqli",
  "confirmed_primary_refusal": true,    // false = sticky pre-route, never refused
  "first_refusal_ts": "2026-...",
  "trajectory": {
    "primary_attempts_refused": [1,2,3], "fallback_attempts_refused": [],
    "switched_to_fallback": true, "reached_fallback": true,
    "rescued_by": "fallback",           // "primary-retry" | "fallback" | null
    "rescue_attempt": null, "outcome": "resolved"   // "resolved" | "lost"
  },
  "first_error_type": "CodexCyberPolicyError",
  "first_error_msg": "This content was flagged for possible cybersecurity risk...",
  "request_preview": { "n_messages": 9, "estimated_input_tokens": 41000,
                       "system_prompt_chars": 23470, "n_tools": 12, "last_message": "..." },
  "source_log": "logs/.../full_logs.jsonl",        // exact provenance
  "payload_file": "payloads/XBEN-029__sqli__004.json"   // full replayable request, or null
}
```
