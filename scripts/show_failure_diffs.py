"""For each plain×3-failing case, show what was added in the failing
call vs the previous successful call.

Logic: for each rejected request file, find the agent's previous
phase=start event in llm_calls.jsonl. The trailing assistant +
tool messages added between those two starts are the "new content"
that took the prompt from accepted → refused.
"""

from __future__ import annotations

import json
from pathlib import Path

LOG = Path("/Users/zviadjolokhava/My Drive/Thesis/SwarmAttacker/logs/run-XBEN-006-24__2026-05-09_18h07m14s/llm_calls.jsonl")
REJ = LOG.parent / "rejected_requests"

# The 6 cases where plain × 3 failed in v2
PLAIN_FAILING = [
    "executor-0__2026-05-09T18-12-35.181.json",       # 21 msgs
    "executor-2__2026-05-09T18-15-05.544.json",       # 6 msgs
    "methodology-fuzzing__2026-05-09T18-11-26.488.json",  # 16 msgs
    "owasp-input-validation__2026-05-09T18-15-12.506.json",  # 8 msgs
    "vulntype-idor__2026-05-09T18-15-18.379.json",    # 8 msgs
    "vulntype-information-disclosure__2026-05-09T18-11-44.154.json",  # 14 msgs
]


def main() -> None:
    calls = [json.loads(l) for l in LOG.read_text().splitlines()]

    # Index starts by agent_id
    starts_by_agent: dict[str, list] = {}
    for c in calls:
        if c.get("phase") == "start" and "request" in c:
            starts_by_agent.setdefault(c["agent_id"], []).append(c)
    for k in starts_by_agent:
        starts_by_agent[k].sort(key=lambda x: x["ts"])

    print("# Diff: failing call vs previous (passing) call\n")

    for fname in PLAIN_FAILING:
        path = REJ / fname
        if not path.exists():
            print(f"## {fname} — file missing\n")
            continue
        agent_id = fname.split("__")[0]
        rejected_req = json.loads(path.read_text())

        # Find the matching start in the log (by message count)
        starts = starts_by_agent.get(agent_id, [])
        # The rejected request is the LAST start before the error (which
        # is what we already extracted). Find its index in starts.
        target_n = rejected_req["n_messages"]
        # Find the start whose n_messages matches and is the latest one
        candidates = [s for s in starts if s["request"]["n_messages"] == target_n]
        if not candidates:
            print(f"## {agent_id} ({target_n} msgs) — no matching start in log\n")
            continue
        cur = candidates[-1]
        cur_idx = starts.index(cur)
        prev = starts[cur_idx - 1] if cur_idx > 0 else None

        print(f"## {agent_id} — {target_n} msgs (~{rejected_req.get('estimated_input_tokens')} tokens)")
        if prev is None:
            print("  No previous start (this was the first call).\n")
            continue
        prev_n = prev["request"]["n_messages"]
        added = target_n - prev_n
        print(f"  Previous call had {prev_n} messages; failing call had {target_n}.")
        print(f"  → {added} message(s) added between calls.\n")

        # Show the added messages (the tail of cur's request that wasn't in prev)
        added_msgs = rejected_req["messages"][prev_n:]
        for i, m in enumerate(added_msgs):
            role = m["role"]
            print(f"  ### Added message [{prev_n + i}] role={role}")
            if role == "assistant" and m.get("tool_calls"):
                for tc in m["tool_calls"]:
                    name = tc.get("name", "?")
                    args = tc.get("args", {})
                    if "reasoning" in args:
                        print(f"    tool_call: {name}")
                        print(f"      reasoning: {args['reasoning'][:400]!r}")
                    if "command" in args:
                        cmd = args["command"]
                        print(f"      command: {cmd[:600]!r}")
                    if "url" in args:
                        print(f"      url: {args['url']!r}")
                    if "data" in args:
                        print(f"      data: {str(args['data'])[:400]!r}")
            elif role == "tool":
                content = m.get("content", "")
                preview = content[:800] if isinstance(content, str) else str(content)[:800]
                print(f"    tool_output ({len(content)} chars):")
                for line in preview.split("\n")[:25]:
                    print(f"      {line}")
                if len(content) > 800:
                    print(f"      ... [truncated, full {len(content)} chars]")
            print()
        print()


if __name__ == "__main__":
    main()
