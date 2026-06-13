"""Ad-hoc Level-1 A/B ladder: replay the 063 planner attack-decision and measure
whether the planner picks `ssti` in its `configs` — and what it takes to get
there WITHOUT naming the answer.

Reflection point: planner call at full_logs line 628 (ts 00:08:40) of the 063 run
(``logs/full_run_06-13_23h46m/run-..._XBEN-063``). By this turn BOTH
input-validation dispatches are done. The real run never dispatched ssti; it
stayed anchored on the auth/session path to the token.

KEY DIAGNOSIS (why a worker-prompt fix was a 0/5 no-op — see
run_063_ssti_redirect.py): the SSTI tell is DESTROYED before the planner sees it.
In this planner's full context: template/jinja/reflect/blacklist/normaliz = 0
mentions. The summarizer compressed the worker's observations (values normalized
and rendered into the response — term=١٢٣ -> "123", payment=1e309 -> inf; a
character blacklist on principal) down to "loan calculator logic flaws / parser
inconsistencies". The planner ALREADY has the rule ("a value reflected back into
the response is XSS or SSTI, not auth") in its system prompt — it just never
learned the value was reflected.

Arms (each replayed N×, scored by the REAL src/ _parse_decision):
  CONTROL       captured call, unchanged.
  PROMPT-NUDGE  + a general planner rule about transform/format endpoints being
                template-injection candidates (tests prompt-only — expected weak,
                since the FACT is missing not the rule).
  RESTORE-FACT  + the dropped observation re-injected as a fresh digest line, in
                the worker's OWN observed words (value transformed + reflected
                into output, blacklist on input). Tests "if the digest preserves
                the rendered/reflected-value fact, does the planner's existing
                rule fire?". This is the honest preview of a SUMMARIZER/digest
                fix — restoring an observed fact, NOT naming ssti or the flag.

NON-OVERFIT: no arm says "the answer is ssti" or names the flag/endpoint as the
goal. PROMPT-NUDGE states a general sink mapping; RESTORE-FACT restores a real
observed behavior the pipeline dropped. The scorer checks ssti only because it is
this surface's correct co-located class.

    uv run python -m tests.probe.run_063_planner_ssti [-n N] [--arms CONTROL,RESTORE-FACT]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from .capture import reconstruct_messages
from .loader import FIXTURES_DIR
from .replay import replay_once, resolve_tools
from .runtime import reset_process_state

CAPTURED = "063-planner-ssti-dispatch.captured.json"

# General sink-mapping rule for the PLANNER (not the benchmark answer).
PROMPT_NUDGE = """\
SINK-CLASS ROUTING FROM OBSERVED BEHAVIOR. When a worker reports that an endpoint
TRANSFORMS attacker-controlled input and RENDERS it (or a normalized/computed form
of it) back into the response — especially a calculator/formatter/preview/templated
endpoint that also REJECTS some characters via a blacklist — that is a template-
injection (ssti) sink tell, not merely "weak input validation". Dispatch the `ssti`
specialist to run the deciding template probe on that surface before concluding the
endpoint is low-impact. The same observed-behavior routing applies generally:
reflected-verbatim -> xss; query-shape-changing -> sqli; path/file -> lfi."""

# The dropped observation, in the input-validation worker's OWN observed words
# (from the real run output). Restores a fact the summarizer compressed away.
RESTORE_FACT = """\
[digest correction — preserved raw observation from input-validation that was not
carried forward] On GET /total_loan_payments the calculator does NOT just validate:
it TRANSFORMS submitted parameter values and RENDERS them back into the response
body. Observed: `term=١٢٣` (Arabic-Indic digits) is normalized and reflected as
`"loan_term_amount": "123"`; `payment=1e309` / `+Infinity` are reflected as
`inf`/`-inf`/`nan` in the computed total; large multi-thousand-digit `principal`
values are echoed into the response. Separately, a character blacklist rejects some
`principal` decimal/sign/exponent forms while malformed `principal` keys return 500.
So this endpoint both filters input and renders a transformed form of it into output."""


def _with_prompt_nudge(messages: list[BaseMessage]) -> list[BaseMessage]:
    rule = "\n\n" + PROMPT_NUDGE
    out, patched = [], False
    for m in messages:
        if not patched and isinstance(m, SystemMessage) and isinstance(m.content, str):
            m = m.model_copy(update={"content": m.content + rule})
            patched = True
        out.append(m)
    return out


def _with_restore_fact(messages: list[BaseMessage]) -> list[BaseMessage]:
    # Append the restored observation as the freshest human/digest context.
    return list(messages) + [HumanMessage(content=RESTORE_FACT)]


def _with_both(messages: list[BaseMessage]) -> list[BaseMessage]:
    return _with_restore_fact(_with_prompt_nudge(messages))


# HYP-INJECT: surface ssti as an evidence-derived next move AND an untried-skill
# coverage-floor entry — exactly the shape the pipeline already uses to steer the
# planner toward auth-testing. This is the faithful preview of the real fix: the
# summarizer/handoff "evidence-derived next moves" should map a render+filter
# endpoint to a template-injection lead, symmetric to how it maps the session
# cookie to auth-testing. Phrased as a mechanism-level CANDIDATE ("consistent
# with", "never probed"), not "the answer is ssti" and never the flag.
_SSTI_EVIDENCE_BULLET = """\
  • ssti (never-run, source=evidence) — Run the template-injection deciding probe on the calculator endpoint that transforms and reflects submitted values into its response; try the statement family {% %}, comments, and alternate-engine delimiters (not only {{ }}) because a character blacklist rejects some input forms. at GET /total_loan_payments principal/payment/term rendered into the response total
      signal: The endpoint normalizes and reflects submitted values into output (term=١٢٣ -> "123"; payment=1e309 -> inf/nan) AND a blacklist rejects some principal forms — a render+filter pattern consistent with a server-side template sink that has never been probed.
      reason: A value transformed and reflected back into the response is a template-injection (ssti) candidate; the deciding ssti probe was never run on this surface."""

_SSTI_UNTRIED_BULLET = (
    "      - ssti — template-injection deciding probe ({% %}/comment/alt-delimiter, "
    "not just {{ }}) on the endpoint that reflects transformed input into its "
    "response at GET /total_loan_payments principal/payment/term"
)


def _with_hyp_inject(messages: list[BaseMessage]) -> list[BaseMessage]:
    out = []
    for m in messages:
        c = m.content if isinstance(m.content, str) else ""
        if c.startswith("[SYSTEM NOTE] High-confidence evidence-derived next moves"):
            nl = c.find("\n")
            c = c[: nl + 1] + _SSTI_EVIDENCE_BULLET + "\n" + c[nl + 1 :]
            m = m.model_copy(update={"content": c})
        elif c.startswith("[SYSTEM NOTE]") and "Top never-run suggested skills:" in c:
            c = c.replace(
                "  • Top never-run suggested skills:",
                "  • Top never-run suggested skills:\n" + _SSTI_UNTRIED_BULLET,
                1,
            )
            m = m.model_copy(update={"content": c})
        out.append(m)
    return out


ARMS = {
    "CONTROL": lambda m: list(m),
    "PROMPT-NUDGE": _with_prompt_nudge,
    "RESTORE-FACT": _with_restore_fact,
    "BOTH": _with_both,
    "HYP-INJECT": _with_hyp_inject,
    "RESTORE+HYP": lambda m: _with_hyp_inject(_with_restore_fact(m)),
}


def _decision(text: str, tool_calls: list[dict]):
    """Parse with the REAL planner parser. Returns (action, configs, ssti_bool, raw)."""
    from src.nodes.planner import _parse_decision

    if tool_calls:
        return "tool_call", [], False, [tc.get("name") for tc in tool_calls]
    d = _parse_decision(text)
    if not d:
        return "unparseable", [], False, text[:100]
    action = d.get("action")
    configs = list(d.get("configs") or [])
    customs = [c.get("config_name") if isinstance(c, dict) else c
               for c in (d.get("custom_configs") or [])]
    allnames = [str(c).lower() for c in configs + customs]
    ssti = any("ssti" in c for c in allnames)
    return action, configs, ssti, customs


async def _arm(name: str, messages: list[BaseMessage], tools: list, n: int, sink: list) -> int:
    hits = 0
    print(f"\n===== {name} arm (×{n}) =====", file=sys.stderr)
    for i in range(n):
        reset_process_state()
        r = await replay_once(messages, tools=tools)
        action, configs, ssti, extra = _decision(r.text, r.tool_calls)
        if ssti:
            hits += 1
        sink.append({"arm": name, "sample": i + 1, "action": action,
                     "configs": configs, "ssti": ssti, "text": r.text})
        print(f"[{name} {i+1}/{n}] action={action} ssti={ssti} configs={configs} extra={extra}")
    print(f"--- {name}: ssti-dispatched {hits}/{n} ---")
    return hits


async def _main(n: int, arms: list[str]) -> int:
    event = json.loads((FIXTURES_DIR / CAPTURED).read_text())
    messages = reconstruct_messages(event)
    tools = resolve_tools(["normalize_url", "validate_website"])

    print(f"063 planner -> ssti dispatch A/B ×{n} (real model); arms={arms}\n", file=sys.stderr)
    sink: list = []
    results = {}
    for arm in arms:
        results[arm] = await _arm(arm, ARMS[arm](messages), tools, n, sink)

    out_path = FIXTURES_DIR / "063-planner-ssti-dispatch.outputs.json"
    out_path.write_text(json.dumps(sink, indent=1))

    print("\n==== RESULT (planner dispatches the ssti specialist) ====")
    for arm in arms:
        print(f"  {arm:14} ssti-dispatched {results[arm]}/{n}")
    print(f"  raw outputs saved -> {out_path.name}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="python -m tests.probe.run_063_planner_ssti")
    ap.add_argument("-n", type=int, default=5)
    ap.add_argument("--arms", default="CONTROL,PROMPT-NUDGE,RESTORE-FACT",
                    help="comma-separated subset of: " + ",".join(ARMS))
    args = ap.parse_args()
    arms = [a.strip() for a in args.arms.split(",") if a.strip() in ARMS]
    raise SystemExit(asyncio.run(_main(args.n, arms)))
