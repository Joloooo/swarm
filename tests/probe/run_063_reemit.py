"""Ad-hoc Level-1 A/B: does a re-dispatched business-logic worker RE-EMIT a
finding that is ALREADY in its 'Confirmed findings so far' seed — and does the
finding-novelty + chaining rule stop it?

Reflection point: business-logic executor call #8 of the 063 run
(``logs/full_run_06-13_15h42m/run-..._XBEN-063``), dispatch 2. By this turn the
HIGH finding "Client-controlled loan terms allow arbitrary/negative repayment
state" is ALREADY listed in the worker's "Confirmed findings so far" block, yet
the real run re-emitted it (the ▣ at 15:58:51).

  CONTROL = captured call replayed UNCHANGED.
  TEST    = same call with the novelty/chaining rule appended to the SYSTEM
            prompt (where the executor's finding-output contract lives), i.e. a
            faithful preview of the src/ change we would ship.

Scorer reuses the REAL production parser
``src.nodes.base.worker.findings._extract_findings`` (import-only, no drift): a
"loan re-emission" is a parsed Finding whose title names the already-confirmed
loan vuln — exactly what production turns into a ▣ line. Crude-append spike per
SKILL §3 (throwaway basis): a clean win here justifies wiring the rule into the
real builder and re-confirming, not shipping on this alone.

    uv run python -m tests.probe.run_063_reemit [-n N]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from langchain_core.messages import AIMessage, BaseMessage, SystemMessage

from .capture import reconstruct_messages
from .loader import FIXTURES_DIR
from .replay import replay_once, resolve_tools
from .runtime import reset_process_state

CAPTURED = "063-business-logic-reemit.captured.json"


def _with_rule(messages: list[BaseMessage]) -> list[BaseMessage]:
    """Append the REAL src/ ``FINDING_NOVELTY_RULE`` to the SystemMessage.

    ``build_prompt("executor")`` now ends with this exact block, so appending it to
    the captured system message reproduces the SHIPPED prompt (the rule is the
    final joined part) — this is the real code path, not a copy, so the re-run
    confirms the change we actually merged."""
    from src.nodes.base.system_prompt import FINDING_NOVELTY_RULE

    rule = "\n\n" + FINDING_NOVELTY_RULE
    out: list[BaseMessage] = []
    patched = False
    for m in messages:
        if not patched and isinstance(m, SystemMessage) and isinstance(m.content, str):
            m = m.model_copy(update={"content": m.content + rule})
            patched = True
        out.append(m)
    if not patched:  # no system msg — fall back to first message
        messages[0] = messages[0].model_copy(
            update={"content": (messages[0].content or "") + rule}
        )
    return out


def _restates_confirmed(f) -> bool:
    """True iff this parsed Finding RESTATES the already-confirmed HIGH finding
    'Client-controlled loan terms allow arbitrary/negative repayment state'
    (manipulation: attacker-controlled loan VALUES are accepted/persisted) — as
    opposed to a genuinely NEW finding (e.g. the LOW loan-workflow CRASH bug).
    Content-based so it is robust to severity/wording drift."""
    t = ((getattr(f, "title", "") or "") + " " + (getattr(f, "description", "") or "")).lower()
    if "loan" not in t:
        return False
    crash = any(w in t for w in ("crash", "unhandled", " 500", "traceback", "internal server error"))
    if crash:                      # the NEW finding the rule redirected toward
        return False
    manip_subject = ("client-controlled" in t or "attacker-controlled" in t
                     or "user-supplied" in t or "client controlled" in t)
    manip_effect = (any(v in t for v in ("invalid", "negative", "arbitrary", "free-loan", "payoff", "overpay"))
                    and any(s in t for s in ("repayment", "financial", "loan term", "loan field",
                                             "loan state", "loan amount", "repaid", "persist", "accept", "allow")))
    return manip_subject or manip_effect


def _classify(text: str):
    """Parse output as production does, split into confirmed-restatements vs new."""
    from src.nodes.base.worker.findings import _extract_findings

    allf = _extract_findings([AIMessage(content=text)], "business-logic")
    restate = [f for f in allf if _restates_confirmed(f)]
    new = [f for f in allf if f not in restate]
    return allf, restate, new


async def _arm(name: str, messages: list[BaseMessage], tools: list, n: int, sink: list) -> tuple[int, int]:
    restate_hits = new_hits = 0
    print(f"\n===== {name} arm (×{n}) =====", file=sys.stderr)
    for i in range(n):
        reset_process_state()
        r = await replay_once(messages, tools=tools)
        allf, restate, new = _classify(r.text)
        if restate:
            restate_hits += 1
        if new:
            new_hits += 1
        sink.append({"arm": name, "sample": i + 1, "text": r.text,
                     "tool_calls": [t.get("name") for t in r.tool_calls]})
        print(
            f"[{name} {i + 1}/{n}] tool_calls={[t.get('name') for t in r.tool_calls]} "
            f"text={len(r.text)}c findings={len(allf)} "
            f"RESTATES_CONFIRMED={len(restate)} new={len(new)}"
        )
        for f in allf:
            tag = "RESTATE-CONFIRMED" if f in restate else "NEW"
            print(f"      • [{getattr(f,'severity','?')}] ({tag}) {getattr(f,'title','')[:74]}")
    print(f"--- {name}: restates-confirmed in {restate_hits}/{n}, any-new in {new_hits}/{n} ---")
    return restate_hits, new_hits


async def _main(n: int) -> int:
    event = json.loads((FIXTURES_DIR / CAPTURED).read_text())
    messages = reconstruct_messages(event)
    tools = resolve_tools(["bash"])

    print(
        f"063 business-logic re-emit A/B — replaying call #8 ×{n} (real model)\n"
        f"  loan finding IS already in the 'Confirmed findings so far' seed.\n",
        file=sys.stderr,
    )
    sink: list = []
    c_restate, c_new = await _arm("CONTROL", messages, tools, n, sink)
    t_restate, t_new = await _arm("TEST-rule", _with_rule(messages), tools, n, sink)

    out_path = FIXTURES_DIR / "063-business-logic-reemit.outputs.json"
    out_path.write_text(json.dumps(sink, indent=1))

    print(
        f"\n==== RESULT (restates the already-confirmed HIGH loan finding) ====\n"
        f"  CONTROL : {c_restate}/{n}   (and emitted some NEW finding {c_new}/{n})\n"
        f"  TEST    : {t_restate}/{n}   (and emitted some NEW finding {t_new}/{n})\n"
        f"  raw outputs saved → {out_path.name}"
    )
    print(
        "  (hypothesis confirmed iff CONTROL restates and TEST stops restating)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="python -m tests.probe.run_063_reemit")
    ap.add_argument("-n", type=int, default=3, help="samples per arm (default 3)")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(_main(args.n)))
