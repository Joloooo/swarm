"""Ad-hoc Level-1 A/B: when the ``input-validation`` worker has CONFIRMED weak
numeric validation on the loan calculator (a blacklist on ``principal`` + values
that normalize/render into the response), does it ALSO raise the co-located
template sink as an ``ssti`` lead — or does it bury it by closing in-lane?

Reflection point: the last ``input-validation`` executor call of the 063 run
(``logs/full_run_06-13_23h46m/run-..._XBEN-063``, dispatch 2, ts 00:04:46,
full_logs line 525). The real output of THIS call was the closing VERDICT:

    Class: input-validation · Probe run: yes · Outcome: confirmed (0.95)
    Note: ...did not convert them into data disclosure, code execution, or token

i.e. it confirmed its own class and emitted **no Redirect line** — even though
the same evidence (a `{`/decimal blacklist on a value that renders into the JSON
output) is the textbook SSTI-into-rendered-output tell the benchmark is built on.
063's flag path IS ssti, and the ``ssti`` specialist was never dispatched this
run because no worker ever raised it.

  CONTROL = captured call replayed UNCHANGED.
  TEST    = same call with the SINK-HANDOFF rule appended to the SYSTEM prompt
            (where the executor's VERDICT contract lives) — a faithful preview of
            the src/ change we would ship (extend VERDICT_SCHEMA).

Scorer reuses the REAL production parser ``_extract_verdicts`` + ``_redirect_class``
(import-only, no drift): a "raised ssti" is a parsed routing Signal with
``vuln_class == "ssti"`` — exactly what production turns into an ssti hypothesis
bucket the planner can dispatch. Crude-append spike per SKILL §3 (throwaway
basis): a clean win justifies wiring the rule into the real VERDICT_SCHEMA and
re-confirming, not shipping on this alone.

NON-OVERFIT NOTE: the rule names NO benchmark, endpoint, or flag. It states the
general principle — when a value you control is FILTERED and/or RENDERED into the
response, that is a sink that may belong to another class (ssti / xss / sqli);
hand it off via Redirect even when your own class is confirmed. The scorer checks
``ssti`` only because that is THIS surface's correct co-located class; the rule
would equally fire xss/sqli elsewhere.

    uv run python -m tests.probe.run_063_ssti_redirect [-n N]
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

CAPTURED = "063-input-validation-ssti-redirect.captured.json"

# The candidate rule. General sink-handoff principle — NOT the benchmark answer.
# A faithful preview of an addition to VERDICT_SCHEMA (system_prompt.py).
SINK_HANDOFF_RULE = """\
CONFIRMING YOUR OWN CLASS DOES NOT BURY A CO-LOCATED SINK. A single surface can
carry more than one class's sink at once. If, while testing your assigned class,
you observe that a value YOU control is (a) FILTERED by a character/keyword
blacklist, and/or (b) REFLECTED or RENDERED back into the response (its content,
or a transformed form of it, appears in the output), that is positive evidence of
a sink that may belong to a DIFFERENT class than yours — even if your own class
is also confirmed here. Map the tell to the candidate class and emit a `Redirect`
line naming it, so that class's specialist gets dispatched. Common mappings:
a value that is blacklisted AND rendered into output -> template injection (ssti);
a value reflected verbatim into HTML -> xss; a value that changes a query's shape
-> sqli; a value used as a path/file -> lfi. A confirmed in-lane verdict is NOT a
reason to omit the Redirect: raise the co-located lead, do not let it die in your
lane."""


def _with_rule(messages: list[BaseMessage]) -> list[BaseMessage]:
    """Append the SINK_HANDOFF_RULE to the SystemMessage (where the VERDICT
    contract lives). Crude-append spike: this previews adding the block to the
    real VERDICT_SCHEMA, which is concatenated into the executor system prompt."""
    rule = "\n\n" + SINK_HANDOFF_RULE
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


def _score(text: str):
    """Parse the output as production does. Returns (verdict_outcome, raised_ssti,
    named_template_but_parser_missed).

    - raised_ssti: a real routing Signal with vuln_class=="ssti" (what production
      turns into an ssti hypothesis bucket) — the authoritative success metric.
    - named_template_but_parser_missed: the output names ssti/template/jinja in a
      Redirect line but _redirect_class did NOT map it to ssti (would expose a
      parser gap — "template"/"jinja" are not in _REDIRECT_CLASSES)."""
    import re as _re

    from src.nodes.base.skill_runner import _extract_verdicts

    sigs = _extract_verdicts([AIMessage(content=text)], "input-validation", "input-validation")
    verdict = next((s for s in sigs if getattr(s, "source", "") == "executor_verdict"
                    and getattr(s, "kind", "") in ("confirm", "refute", "observation")), None)
    outcome = "none"
    if verdict is not None:
        outcome = {"confirm": "confirmed", "refute": "refuted",
                   "observation": "inconclusive"}.get(verdict.kind, verdict.kind)
    raised_ssti = any(
        "ssti" in (getattr(s, "vuln_class", "") or "").lower()
        and getattr(s, "kind", "") == "routing"
        for s in sigs
    )
    # coarse: did it WRITE a redirect-ish line naming the template class at all?
    redir_line = ""
    mm = _re.search(r"Redirect:\s*(.+)", text, _re.IGNORECASE)
    if mm:
        redir_line = mm.group(1).strip()
    named_template = bool(_re.search(r"ssti|template|jinja", redir_line, _re.IGNORECASE))
    parser_missed = named_template and not raised_ssti
    return outcome, raised_ssti, named_template, parser_missed, sigs


async def _arm(name: str, messages: list[BaseMessage], tools: list, n: int, sink: list):
    raised = 0
    named = 0
    missed = 0
    print(f"\n===== {name} arm (×{n}) =====", file=sys.stderr)
    for i in range(n):
        reset_process_state()
        r = await replay_once(messages, tools=tools)
        outcome, raised_ssti, named_template, parser_missed, sigs = _score(r.text)
        if raised_ssti:
            raised += 1
        if named_template:
            named += 1
        if parser_missed:
            missed += 1
        sink.append({"arm": name, "sample": i + 1, "text": r.text,
                     "tool_calls": [t.get("name") for t in r.tool_calls],
                     "outcome": outcome, "raised_ssti": raised_ssti,
                     "named_template": named_template})
        classes = [getattr(s, "vuln_class", "") + ":" + getattr(s, "kind", "") for s in sigs]
        print(
            f"[{name} {i + 1}/{n}] tool_calls={[t.get('name') for t in r.tool_calls]} "
            f"text={len(r.text)}c verdict={outcome} "
            f"RAISED_SSTI={raised_ssti} named_template={named_template} "
            f"parser_missed={parser_missed} signals={classes}"
        )
    print(f"--- {name}: raised-ssti {raised}/{n}, named-template {named}/{n}, "
          f"parser-missed {missed}/{n} ---")
    return raised, named, missed


async def _main(n: int) -> int:
    event = json.loads((FIXTURES_DIR / CAPTURED).read_text())
    messages = reconstruct_messages(event)
    tools = resolve_tools(["bash"])

    print(
        f"063 input-validation -> ssti redirect A/B — replaying the closing call ×{n} (real model)\n"
        f"  worker CONFIRMED weak validation + saw a blacklisted/rendered value;\n"
        f"  does it RAISE the co-located template sink as an ssti lead?\n",
        file=sys.stderr,
    )
    sink: list = []
    c_raised, c_named, c_missed = await _arm("CONTROL", messages, tools, n, sink)
    t_raised, t_named, t_missed = await _arm("TEST-rule", _with_rule(messages), tools, n, sink)

    out_path = FIXTURES_DIR / "063-input-validation-ssti-redirect.outputs.json"
    out_path.write_text(json.dumps(sink, indent=1))

    print(
        f"\n==== RESULT (worker raises a real ssti routing lead in its verdict) ====\n"
        f"  CONTROL : raised-ssti {c_raised}/{n}   (named-template {c_named}/{n}, parser-missed {c_missed}/{n})\n"
        f"  TEST    : raised-ssti {t_raised}/{n}   (named-template {t_named}/{n}, parser-missed {t_missed}/{n})\n"
        f"  raw outputs saved -> {out_path.name}"
    )
    print(
        "  (hypothesis confirmed iff CONTROL ~0/N and TEST ~N/N raised-ssti;\n"
        "   high named-template but low raised-ssti => add 'template'/'jinja' to _REDIRECT_CLASSES)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="python -m tests.probe.run_063_ssti_redirect")
    ap.add_argument("-n", type=int, default=5, help="samples per arm (default 5)")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(_main(args.n)))
