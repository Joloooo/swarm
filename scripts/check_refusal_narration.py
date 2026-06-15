#!/usr/bin/env python3
"""Re-run the v5 "is the refusal trigger in the model's own narration?" check
at scale, over every refused request in logs/ (not just the 47 of 2026-05-24).

For each CodexCyberPolicyError, recover the request that was refused (the
preceding llm_start's request.messages for that agent) and ask: did the model's
OWN generated output (assistant-role messages) carry any prose narration, and
did any vocabulary trigger word sit in it? If the answer is ~never, then
filtering LLM-generated output would target content that is not there, and the
preventive input-only filter is the right design.

Reuses the same agent_id + timestamp pairing as extract_refusal_corpus.py
(llm_error carries no lc_run_id). Read-only.
"""
from __future__ import annotations
import glob, json, os
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, "logs")

import sys
sys.path.insert(0, ROOT)
from src.refusals.vocabulary import filter_text  # faithful trigger check


def refused_requests():
    """Yield request dicts for every CodexCyberPolicyError, paired by
    agent_id + ts order to the llm_start that immediately preceded it."""
    files = sorted(glob.glob(os.path.join(LOGS, "**", "full_logs.jsonl"), recursive=True))
    for f in files:
        per_agent_last_start = {}
        rows = []
        try:
            with open(f) as fh:
                for i, line in enumerate(fh):
                    if '"llm_start"' not in line and '"llm_error"' not in line:
                        continue
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    if r.get("type") in ("llm_start", "llm_error"):
                        rows.append((r.get("ts", ""), i, r))
        except Exception:
            continue
        rows.sort(key=lambda x: (x[0], x[1]))
        for _ts, _i, r in rows:
            ag = r.get("agent_id", "?")
            if r.get("type") == "llm_start":
                per_agent_last_start[ag] = r.get("request")
            elif r.get("type") == "llm_error" and r.get("error_type") == "CodexCyberPolicyError":
                req = per_agent_last_start.get(ag)
                if isinstance(req, dict):
                    yield req


def main():
    total = 0
    with_assistant_msg = 0       # >=1 assistant-role message at all
    with_narration = 0           # >=1 assistant message, content > 200 chars
    trigger_in_narration = 0     # trigger word in assistant content (>200)
    trigger_in_any_assistant = 0 # trigger word in ANY assistant content (any length)
    trigger_in_toolcall_args = 0 # trigger word in an assistant tool_call arg
    max_assistant_content = 0

    for req in refused_requests():
        total += 1
        msgs = req.get("messages") or []
        assistants = [m for m in msgs if isinstance(m, dict) and m.get("role") == "assistant"]
        if assistants:
            with_assistant_msg += 1
        had_narration = False
        trig_narr = False
        trig_any = False
        trig_args = False
        for m in assistants:
            c = m.get("content") or ""
            if not isinstance(c, str):
                c = str(c)
            max_assistant_content = max(max_assistant_content, len(c))
            if len(c) > 200:
                had_narration = True
            _, subs = filter_text(c)
            if subs:
                trig_any = True
                if len(c) > 200:
                    trig_narr = True
            for tc in (m.get("tool_calls") or []):
                args = tc.get("args") or {}
                for v in args.values():
                    if isinstance(v, str):
                        _, s2 = filter_text(v)
                        if s2:
                            trig_args = True
        if had_narration:
            with_narration += 1
        if trig_narr:
            trigger_in_narration += 1
        if trig_any:
            trigger_in_any_assistant += 1
        if trig_args:
            trigger_in_toolcall_args += 1

    def pct(a):
        return f"{100.0*a/total:.1f}%" if total else "n/a"

    print("=" * 64)
    print("REFUSAL-NARRATION CHECK  (scaled replication of the v5 0/47 result)")
    print("=" * 64)
    print(f"refused requests examined .............. {total}")
    print(f"  with >=1 assistant message ........... {with_assistant_msg}  ({pct(with_assistant_msg)})")
    print(f"  with assistant NARRATION (>200 chars)  {with_narration}  ({pct(with_narration)})")
    print(f"  trigger word in that narration ....... {trigger_in_narration}  ({pct(trigger_in_narration)})")
    print(f"  trigger word in ANY assistant text ... {trigger_in_any_assistant}  ({pct(trigger_in_any_assistant)})")
    print(f"  trigger word in a tool_call arg ...... {trigger_in_toolcall_args}  ({pct(trigger_in_toolcall_args)})")
    print(f"  longest assistant content seen ....... {max_assistant_content} chars")
    print()
    print("Interpretation: if 'trigger word in narration' is ~0, the refusal")
    print("trigger is the opening payload, not the model's own output, so")
    print("filtering LLM-generated output targets content that is not there.")


if __name__ == "__main__":
    main()
