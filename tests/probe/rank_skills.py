"""Diagnostic Level-1 probe: on the REAL captured planner context, replace the
decision ask with a "rank the skills you'd use, with reasons for and against"
ask, and send it to the REAL model N times.

This does NOT test a shippable prompt — it is an investigative what-if to see
WHY the planner ranks skills the way it does, and specifically where (and why)
`deserialization` lands. The full real context (recon, hypotheses, skill menu)
is preserved verbatim; only the final instruction changes. Crude-splice class
(SKILL §3): never a kept corpus result, just a probe that gives us feedback.

    uv run python -m tests.probe.rank_skills [-n N] [--captured FILE]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import re
import sys

from langchain_core.messages import HumanMessage

from .capture import reconstruct_messages
from .loader import FIXTURES_DIR, load_captured_event, load_fixture
from .replay import replay_once

RANK_INSTRUCTION = """\
STOP. This turn is NOT a dispatch turn. The "Available actions" / decision-block
requirement in your system prompt is SUSPENDED for this one turn. An
`{"action": ...}` / `configs` block this turn is INVALID and will be discarded —
do not emit one.

Your ONLY task this turn: using everything above (recon, the
converging/committed hypotheses, the handoffs, and the pre-registered skill menu
in your system prompt), RANK the skills most likely to help capture the flag on
THIS target, best first, with reasons for and against each.

Output ONLY a single fenced ```json block, no prose before or after, in exactly
this shape:

{
  "ranking": [
    {
      "skill": "<exact skill name from the menu>",
      "pros": ["reason this skill is likely to help here", "..."],
      "cons": ["reason this skill may not help / is lower priority", "..."]
    }
  ]
}

Rules:
- List up to 10 skills, ordered most-likely-to-help first.
- Use the exact skill names from the pre-registered menu (e.g. ssrf, sqli,
  deserialization, insecure-file-uploads, ssti, idor, ...).
- pros and cons are each 0-3 short, concrete, evidence-grounded reasons. If a
  skill has no real pro, give an empty list; same for cons. Do not pad.
- Rank on what the recon/evidence actually supports — not generic priors.
- Again: output the ranking JSON ONLY. No action block.
"""


# Synthetic recon discovery — what a good content-discovery + source-mining
# pass (the new recon defaults) would plausibly surface on this target. It
# reports only the DISCOVERED SURFACE (a served subdir with an upload endpoint
# and a path-reading endpoint), NOT the vulnerability class — the planner must
# still reason that an upload feeding a PHP path-read is a deser/PHAR sink. This
# is the experimental manipulation that tests the causal claim "if recon finds
# the sink, deser ranks up"; it is not shipped behaviour.
INJECT_SINK_NOTE = """\
[SYSTEM NOTE] Recon update — content-discovery + source-mining pass just
completed:
  - The served Dockerfile (GET /Dockerfile) contains `COPY . /var/www/html`, so
    the ENTIRE source tree is reachable over HTTP, not just the linked pages.
  - Sweeping nested directories found a subdirectory `/skumodel-srv/` (the
    internal "SKU model API" the homepage referenced as 127.0.0.1:4455 is the
    same code, now reachable directly under the web root).
  - `/skumodel-srv/sku_process.php` accepts a POST `data` value and writes it to
    a file on disk (an upload/write primitive).
  - `/skumodel-srv/read_sku.php` takes a `file_path` parameter and reads /
    processes that file path server-side (PHP file/path handling).
  - Reading `read_sku.php` source shows it passes `file_path` into PHP
    filesystem functions that operate on the supplied path.
"""


def _load_event(captured: str | None, fx) -> dict:
    if not captured:
        return load_captured_event(fx)
    p = pathlib.Path(captured)
    if not p.is_absolute() and not p.exists():
        p = FIXTURES_DIR / captured
    return json.loads(p.read_text())


def _extract_json(text: str) -> dict | None:
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    blob = m.group(1) if m else None
    if blob is None:
        i, j = text.find("{"), text.rfind("}")
        blob = text[i : j + 1] if i != -1 and j > i else None
    if not blob:
        return None
    try:
        return json.loads(blob)
    except Exception:
        return None


def _render(sample_i: int, n: int, text: str) -> bool:
    data = _extract_json(text)
    if not data or "ranking" not in data:
        print(f"\n[sample {sample_i}/{n}] UNPARSEABLE — head: {text[:200]!r}")
        return False
    ranking = data["ranking"]
    deser_rank = next(
        (k + 1 for k, r in enumerate(ranking)
         if "deser" in str(r.get("skill", "")).lower()),
        None,
    )
    tag = f"deser @ rank {deser_rank}" if deser_rank else "deser ABSENT from ranking"
    print(f"\n[sample {sample_i}/{n}] {len(ranking)} skills — {tag}")
    for k, r in enumerate(ranking):
        skill = r.get("skill", "?")
        print(f"  {k + 1:2d}. {skill}")
        for p in r.get("pros", []) or []:
            print(f"        + {p}")
        for c in r.get("cons", []) or []:
            print(f"        - {c}")
    return bool(deser_rank)


async def _main(n: int, captured: str | None, inject_sink: bool) -> int:
    fx = load_fixture("092-planner-deser-dispatch.yaml")
    event = _load_event(captured, fx)
    messages = reconstruct_messages(event)
    if inject_sink:
        messages.append(HumanMessage(content=INJECT_SINK_NOTE))
    messages.append(HumanMessage(content=RANK_INSTRUCTION))

    label = (captured or "wave1 (15:48)") + (" +injected-sink" if inject_sink else "")
    print(f"ranking probe on {label} ×{n} (real model, no tools bound) …", file=sys.stderr)
    deser_present = 0
    for i in range(n):
        r = await replay_once(messages, tools=None)
        if _render(i + 1, n, r.text):
            deser_present += 1
    print(f"\n=== deserialization present in the ranking in {deser_present}/{n} samples ===")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=3)
    ap.add_argument("--captured", default=None, help="captured.json to use (default wave1)")
    ap.add_argument("--inject-sink", action="store_true",
                    help="inject a synthetic recon discovery of the served upload/path sink")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(_main(args.n, args.captured, args.inject_sink)))
