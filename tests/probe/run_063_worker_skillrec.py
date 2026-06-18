"""Ad-hoc Level-1 A/B: does the EXECUTOR (input-validation worker), at the step
where it has already SEEN the echo/reflection evidence, recommend the `ssti`
specialist — IF we give it a real skill-recommendation capability (the dispatch
catalog + a "recommend the next specialist" task)?

This is the upstream half of the fix. run_063_planner_ssti.py proved the planner
dispatches ssti 5/5 IF a "send ssti" lead is on its hint list, but 0/5 without
one. SOMETHING must produce that lead. The worker that probed the surface is the
natural source — but only if it RECOGNISES the pattern as ssti. run_063_ssti_redirect.py
showed that merely nagging the worker to redirect yields 0/5 (it reached for
xss/auth, never ssti) — because it was never shown the skill catalog that names
the ssti tell. This spike adds that capability.

Reflection point: input-validation executor call at full_logs line 525 (ts
00:04:46, 063 run logs/full_run_06-13_23h46m). Its input tool messages already
contain the echo evidence: `term=١٢٣` -> `"loan_term_amount": "123"` recomputing
the total. (Same captured asset as run_063_ssti_redirect.py.)

Arms (each replayed N×, scored by the REAL src/ _extract_verdicts + a recommend
parser):
  CONTROL    captured call, unchanged.
  SKILL-REC  + a skill-recommendation capability: the real planner dispatch
             catalog (_SKILLS_MENU — the SAME canonical skill descriptions,
             including the ssti "Use when / single tell" entry) plus a task to
             recommend which specialist the planner should dispatch next, matched
             to the catalog by described mechanism.

NON-OVERFIT: the capability names NO benchmark/flag/answer. It asks the worker to
match observed behavior to the catalog's skill descriptions and recommend
accordingly — a general routing task. The scorer checks ssti only because it is
this surface's correct class; the worker could equally (wrongly) pick xss/auth as
in the redirect spike, which is exactly what we are measuring.

    uv run python -m tests.probe.run_063_worker_skillrec [-n N] [--arms ...]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys

from langchain_core.messages import AIMessage, BaseMessage, SystemMessage

from .capture import reconstruct_messages
from .loader import FIXTURES_DIR
from .replay import replay_once, resolve_tools
from .runtime import reset_process_state

CAPTURED = "063-input-validation-ssti-redirect.captured.json"


def _skill_rec_block() -> str:
    """The skill-recommendation capability — the REAL dispatch catalog + a
    recommend task. Imported from src/ so the catalog never drifts."""
    import src.graph  # noqa: F401  (break the loader circular import)
    from src.nodes.planner import _SKILLS_MENU

    return (
        "## Recommend the next specialist (REQUIRED before you stop)\n"
        "You are one specialist in a swarm; you cannot dispatch other workers, but "
        "the planner can. Based ONLY on what you actually observed this run, "
        "recommend which specialist skill(s) the planner should dispatch next to "
        "convert your observations into impact. Match the BEHAVIOURS you saw "
        "(how inputs were filtered, transformed, reflected, stored, or routed) to "
        "the skill catalog below by each skill's described mechanism / 'Use when' / "
        "'Signals' — pick the skill whose mechanism fits your evidence, even if it "
        "is not your own class. Emit one line per recommendation:\n"
        "  Recommend: <exact skill name> — <one-line reason tied to a concrete observation>\n\n"
        "### Dispatchable specialist catalog\n" + _SKILLS_MENU
    )


def _with_skill_rec(messages: list[BaseMessage]) -> list[BaseMessage]:
    block = "\n\n" + _skill_rec_block()
    out, patched = [], False
    for m in messages:
        if not patched and isinstance(m, SystemMessage) and isinstance(m.content, str):
            m = m.model_copy(update={"content": m.content + block})
            patched = True
        out.append(m)
    return out


ARMS = {
    "CONTROL": lambda m: list(m),
    "SKILL-REC": _with_skill_rec,
}

_REC_RE = re.compile(r"(?:Recommend|Redirect|hand[\s-]?off)\s*[:\-][^\n]*", re.IGNORECASE)
_SKILL_RE = re.compile(r"\bssti\b", re.IGNORECASE)


def _score(text: str):
    """Did the worker recommend ssti? Returns (recommended_ssti, rec_lines,
    routing_classes). Authoritative: the real _extract_verdicts Redirect parser
    (routing Signal vuln_class=='ssti'); plus a recommend-line regex for the new
    Recommend: channel that the production parser does not (yet) read."""
    from src.nodes.base.worker.verdicts import _extract_verdicts

    rec_lines = _REC_RE.findall(text)
    rec_ssti = any(_SKILL_RE.search(line) for line in rec_lines)
    # input-validation owns a multi-class set (mirrors
    # EXECUTOR_SKILLS["input-validation"].owns); pass it so the replay matches
    # production, where the executor node stamps owned_classes onto the config.
    _iv_owns = frozenset({"lfi", "rce", "crlf", "xxe", "insecure-file-uploads"})
    sigs = _extract_verdicts([AIMessage(content=text)], "input-validation", "input-validation", _iv_owns)
    routing = [getattr(s, "vuln_class", "") for s in sigs if getattr(s, "kind", "") == "routing"]
    routing_ssti = any("ssti" in (c or "").lower() for c in routing)
    return (rec_ssti or routing_ssti), rec_lines, routing


async def _arm(name: str, messages: list[BaseMessage], tools: list, n: int, sink: list) -> int:
    hits = 0
    print(f"\n===== {name} arm (×{n}) =====", file=sys.stderr)
    for i in range(n):
        reset_process_state()
        r = await replay_once(messages, tools=tools)
        rec_ssti, rec_lines, routing = _score(r.text)
        if rec_ssti:
            hits += 1
        tc = [t.get("name") for t in r.tool_calls]
        sink.append({"arm": name, "sample": i + 1, "rec_ssti": rec_ssti,
                     "rec_lines": rec_lines, "routing": routing,
                     "tool_calls": tc, "text": r.text})
        short = [ln[:80] for ln in rec_lines]
        wrap = "WRAPPED" if r.text.strip() else f"TOOL_CALL{tc}"
        print(f"[{name} {i+1}/{n}] {wrap} REC_SSTI={rec_ssti} routing={routing} recs={short}")
    print(f"--- {name}: recommended-ssti {hits}/{n} ---")
    return hits


async def _main(n: int, arms: list[str]) -> int:
    event = json.loads((FIXTURES_DIR / CAPTURED).read_text())
    messages = reconstruct_messages(event)
    tools = resolve_tools(["bash"])

    print(f"063 worker skill-recommendation A/B ×{n} (real model); arms={arms}\n"
          f"  step 525 already holds echo evidence (term=١٢٣ -> \"123\").\n", file=sys.stderr)
    sink: list = []
    results = {}
    for arm in arms:
        results[arm] = await _arm(arm, ARMS[arm](messages), tools, n, sink)

    out_path = FIXTURES_DIR / "063-worker-skillrec.outputs.json"
    out_path.write_text(json.dumps(sink, indent=1))
    print("\n==== RESULT (worker recommends the ssti specialist) ====")
    for arm in arms:
        print(f"  {arm:12} recommended-ssti {results[arm]}/{n}")
    print(f"  raw outputs saved -> {out_path.name}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="python -m tests.probe.run_063_worker_skillrec")
    ap.add_argument("-n", type=int, default=5)
    ap.add_argument("--arms", default="CONTROL,SKILL-REC")
    args = ap.parse_args()
    arms = [a.strip() for a in args.arms.split(",") if a.strip() in ARMS]
    raise SystemExit(asyncio.run(_main(args.n, arms)))
