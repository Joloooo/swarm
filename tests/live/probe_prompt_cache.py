"""Live probe: does a per-conversation ``prompt_cache_key`` actually
improve Codex prompt-cache hit rates? (paired, controlled)

NOT a pytest — makes real network calls to the ChatGPT Codex backend with
your ``~/.codex`` OAuth tokens. Run by hand:

    cd SwarmAttacker
    uv run python tests/live/probe_prompt_cache.py

Why a paired design
===================
The backend's prefix cache is shared, time-varying and noisy, so comparing
a "with key" run against a separate "without key" run is confounded — the
first run warms the second, and backend load drifts between them. Instead
we run BOTH conditions in the SAME instant on UNIQUE content:

each turn fires 4 calls concurrently —
  NK1, NK2 : prompt_cache_key OFF  (legacy un-pinned routing)
  K1,  K2  : auto per-conversation key (distinct run_ids => isolated)

Every session has its OWN unique per-turn content (tagged by session id +
a fresh run nonce), so no session can free-ride on another's cached prefix.
All four share one big, stable system prompt — exactly like two concurrent
SwarmAttacker sessions both running ``recon`` — so the shared system prefix
is cacheable for everyone; the ONLY thing the key can buy is keeping each
session's OWN growing conversation prefix pinned to one instance.

Clean expectation if the key works on this backend:
  * NK sessions hit only the shared system-prefix floor (low, and the % sags
    as their unique tail grows);
  * K sessions hit system + their own history (high, stays high).

It also replays a worker prefix as a ``__summary`` call (the original
"58 K fresh at 0 %" complaint) with the worker's key vs with the key off.
"""

from __future__ import annotations

import asyncio
import uuid

from langchain_core.messages import HumanMessage, SystemMessage

# Load src.graph first so provider finishes initialising before we import
# get_llm (provider -> graph -> nodes -> planner -> provider.get_llm cycle).
import src.graph  # noqa: F401,E402

from src.llm import codex as codex_mod  # noqa: E402
from src.llm.callbacks import make_call_config  # noqa: E402
from src.llm.provider import LLMConfig, Provider, get_llm  # noqa: E402

# Fresh nonce per probe run so we never reuse a prefix cached by an earlier
# run of this script (which would inflate "no-key" hits).
RUN_NONCE = uuid.uuid4().hex[:8]

_PARA = (
    "You are a careful general-purpose assistant. You organise notes, "
    "summarise documents, and answer factual questions about logistics and "
    "inventory. Keep internal notes terse and well structured. "
)
# Shared across all sessions (~6 K tokens), but unique to THIS run.
SYSTEM_PROMPT = (_PARA * 90).strip() + f"\n\nSession namespace {RUN_NONCE}."
SYSTEM_PROMPT += "\n\nWhen asked anything, reply with only the word: ok"

TURNS = 10


def _tool_result(session: str, turn: int) -> str:
    """~1.5 K-token synthetic content unique to (run, session, turn)."""
    head = f"[{RUN_NONCE}/{session} record #{turn}] "
    return head + ("inventory-row-token " * 280) + f"end-{session}-{turn}"


def _hit(um: dict) -> tuple[int, int]:
    return int(um.get("input_tokens") or 0), int(um.get("cached_tokens") or 0)


async def _call(model, messages, *, run_id, agent_id):
    # IMPORTANT: the cache-key override lives on the MODEL INSTANCE
    # (model.prompt_cache_key), so each condition gets its OWN model and we
    # never mutate it mid-run. An earlier version set the attribute inside
    # this coroutine, which raced under asyncio.gather — the keyed sessions'
    # ``None`` clobbered the unkeyed sessions' ``"off"`` and every call ended
    # up keyed, making the control group fake. Per-instance config fixes that.
    cfg = make_call_config(run_id=run_id, agent_id=agent_id, node="probe")
    resp = await model.ainvoke(messages, config=cfg)
    return _hit(resp.usage_metadata or {})


# Four sessions: 2 unkeyed, 2 auto-keyed (distinct run_ids). ``model`` is
# filled in by main() with a per-condition instance.
SESSIONS = [
    {"id": "NK1", "run_id": "probe-nk-1", "cond": "off"},
    {"id": "NK2", "run_id": "probe-nk-2", "cond": "off"},
    {"id": "K1",  "run_id": "probe-k-1",  "cond": "auto"},
    {"id": "K2",  "run_id": "probe-k-2",  "cond": "auto"},
]


def _pct(inp, cached) -> float:
    return 100 * cached / inp if inp else 0.0


async def run_paired(models):
    state = {s["id"]: [SystemMessage(content=SYSTEM_PROMPT),
                       HumanMessage(content=f"Begin {s['id']}. Reply: ok")]
             for s in SESSIONS}
    results = {s["id"]: [] for s in SESSIONS}
    print(f"\n{'turn':>4} | " + " | ".join(f"{s['id']:>13}" for s in SESSIONS))
    print(f"{'':>4} | " + " | ".join(
        f"{('OFF' if s['cond']=='off' else 'KEY'):>13}" for s in SESSIONS))
    for t in range(1, TURNS + 1):
        for s in SESSIONS:
            state[s["id"]].append(HumanMessage(content=_tool_result(s["id"], t)))
        pairs = await asyncio.gather(*[
            _call(models[s["cond"]], state[s["id"]], run_id=s["run_id"],
                  agent_id="recon")
            for s in SESSIONS
        ])
        cells = []
        for s, (inp, cached) in zip(SESSIONS, pairs):
            results[s["id"]].append((inp, cached))
            cells.append(f"{_pct(inp,cached):5.1f}% {cached//1000:2d}k")
        print(f"{t:>4} | " + " | ".join(f"{c:>13}" for c in cells))
    return results


async def run_summary_reuse(models):
    """Build a keyed worker prefix, then fire its __summary twice: once with
    the worker's key (should land hot), once with the key off (control).
    Sequential, so no shared-state race; uses the per-condition models."""
    run_id = f"probe-sum-{RUN_NONCE}"
    msgs = [SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content="Begin SUM. Reply: ok")]
    for t in range(1, 7):
        msgs.append(HumanMessage(content=_tool_result("SUM", t)))
        await _call(models["auto"], msgs, run_id=run_id, agent_id="recon")
    tail = msgs + [HumanMessage(content="STOP. Summarize the above. Reply: ok")]
    with_key = await _call(models["auto"], tail, run_id=run_id,
                           agent_id="recon__summary")
    off_key = await _call(models["off"], tail, run_id=run_id,
                          agent_id="recon__summary")
    return with_key, off_key


def _reuse_avg(res) -> float:
    tail = res[1:]
    return sum(_pct(i, c) for i, c in tail) / len(tail) if tail else 0.0


def _n_good(res, thresh=50) -> int:
    return sum(1 for i, c in res[1:] if _pct(i, c) >= thresh)


async def main():
    # One model per condition, configured ONCE here and never mutated during
    # the concurrent calls — see the race note in _call().
    cfg = LLMConfig(provider=Provider.CODEX, reasoning_effort="low")
    model_auto = get_llm(cfg)
    model_auto.prompt_cache_key = "auto"      # opt in to per-conversation key
    model_off = get_llm(cfg)
    model_off.prompt_cache_key = "off"        # default: send no key
    models = {"auto": model_auto, "off": model_off}
    print(f"model={model_auto.model}  pid_nonce={codex_mod._PROCESS_CACHE_NONCE}  "
          f"run_nonce={RUN_NONCE}  system_chars={len(SYSTEM_PROMPT)}")

    results = await run_paired(models)
    sk, so = await run_summary_reuse(models)

    rejected = "prompt_cache_key" in codex_mod._UNSUPPORTED_OPTIONAL_REQUEST_KEYS
    print("\n" + "=" * 70)
    print("VERDICT  (reuse = mean hit% over turns 2..N; first turn is cold)")
    print("=" * 70)
    print(f"backend accepted prompt_cache_key: {not rejected}")
    nk = [r for s, r in results.items() if s.startswith("NK")]
    ke = [r for s, r in results.items() if s.startswith("K")]
    for sid, r in results.items():
        cond = "OFF" if sid.startswith("NK") else "KEY"
        print(f"  {sid} ({cond})  reuse-hit avg={_reuse_avg(r):5.1f}%   "
              f"calls>=50%: {_n_good(r)}/{len(r)-1}")
    nk_avg = sum(_reuse_avg(r) for r in nk) / len(nk)
    ke_avg = sum(_reuse_avg(r) for r in ke) / len(ke)
    print(f"\n  NO-KEY mean reuse-hit : {nk_avg:5.1f}%")
    print(f"  KEYED  mean reuse-hit : {ke_avg:5.1f}%")
    print(f"  delta (keyed - nokey) : {ke_avg - nk_avg:+5.1f} points")
    print(f"\n  summary reuse WITH worker key: {_pct(*sk):5.1f}% "
          f"(in={sk[0]}, cached={sk[1]})")
    print(f"  summary reuse with key OFF   : {_pct(*so):5.1f}% "
          f"(in={so[0]}, cached={so[1]})")


if __name__ == "__main__":
    asyncio.run(main())
