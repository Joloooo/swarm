"""Live capability probe: does the ChatGPT Codex backend support
``store: true`` + ``previous_response_id`` chaining?

NOT a pytest — makes a few real calls to chatgpt.com/backend-api/codex with
your ``~/.codex`` OAuth tokens. Run by hand:

    cd SwarmAttacker
    uv run python tests/live/probe_response_chaining.py

Why this exists
===============
The cheaper alternative to re-sending a worker's whole growing transcript
each turn is the Responses API's native chaining: persist a response
(``store: true``) and reference it on the next call via
``previous_response_id``, sending only the NEW input. If that works, the
chained call's BILLED input tokens should collapse to ~just the new message
(the prior context lives server-side), which would crush the ~3.5 M
reprocessed-tokens/run cost — and a ``__summary`` could chain off the
worker's last response and send only the tail instead of replaying ~58 K.

BUT the Codex CLI talks to this backend with ``store: false`` +
``include:["reasoning.encrypted_content"]`` (stateless chaining), which
suggests the subscription proxy may be store:false-only and reject
``store: true`` / ``previous_response_id`` the same way it rejects
``prompt_cache_retention``. This probe settles it empirically before any
architecture work.

It tests three request shapes and reports, for each: HTTP status, whether
it errored, the returned response id, and the BILLED input_tokens:
  1. baseline           store:false, full input            (today's shape)
  2. store-true         store:true,  full input            (can we even store?)
  3. chained            store:true,  previous_response_id + tiny new input
If (3) succeeds AND its input_tokens << (2), chaining works and is worth it.
"""

from __future__ import annotations

import json

import httpx

from src.llm.codex import CODEX_API_ENDPOINT, load_tokens

_FILLER = ("inventory row token sequence for logistics planning. " * 120).strip()
SYSTEM = "You are a terse assistant. Reply with only the word: ok"


def _headers(tokens) -> dict:
    h = {
        "Authorization": f"Bearer {tokens.access_token}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if tokens.account_id:
        h["ChatGPT-Account-Id"] = tokens.account_id
    return h


def _user(text: str) -> dict:
    return {"type": "message", "role": "user",
            "content": [{"type": "input_text", "text": text}]}


def post(tokens, body: dict) -> dict:
    """POST one Responses request, drain the SSE stream, return a summary."""
    out = {"status": None, "error": None, "id": None,
           "input_tokens": None, "cached_tokens": None}
    try:
        with httpx.Client(timeout=120.0) as client:
            with client.stream("POST", CODEX_API_ENDPOINT,
                               json=body, headers=_headers(tokens)) as resp:
                out["status"] = resp.status_code
                if resp.status_code != 200:
                    out["error"] = resp.read().decode("utf-8", "replace")[:300]
                    return out
                for line in resp.iter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if not data or data == "[DONE]":
                        continue
                    evt = json.loads(data)
                    et = evt.get("type", "")
                    if et == "response.failed":
                        err = (evt.get("response") or {}).get("error") or {}
                        out["error"] = json.dumps(err)[:300]
                    if et in ("response.completed", "response.done"):
                        r = evt.get("response") or {}
                        out["id"] = r.get("id")
                        u = r.get("usage") or {}
                        out["input_tokens"] = u.get("input_tokens")
                        out["cached_tokens"] = (
                            (u.get("input_tokens_details") or {}).get("cached_tokens"))
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"[:300]
    return out


def _base_body(store: bool, input_items: list[dict]) -> dict:
    return {
        "model": "gpt-5.5",
        "input": input_items,
        "store": store,
        "stream": True,
        "include": ["reasoning.encrypted_content"],
        "instructions": SYSTEM,
        "reasoning": {"effort": "low", "summary": "auto"},
    }


def _show(label, r):
    print(f"  {label:24} status={r['status']} "
          f"input_tokens={r['input_tokens']} cached={r['cached_tokens']} "
          f"id={(r['id'] or '')[:24]!r}"
          + (f"\n      ERROR: {r['error']}" if r["error"] else ""))


def main():
    tokens = load_tokens()
    print("endpoint:", CODEX_API_ENDPOINT)
    big = [_user(f"Context block:\n{_FILLER}\n\nAcknowledge with: ok")]

    print("\n[1] baseline (store:false, full input):")
    r1 = post(tokens, _base_body(False, big))
    _show("store:false full", r1)

    print("\n[2] store:true, full input (can the backend store at all?):")
    r2 = post(tokens, _base_body(True, big))
    _show("store:true full", r2)

    print("\n[3] chained (store:true, previous_response_id + tiny new input):")
    if not r2["id"]:
        print("  SKIP — call [2] returned no response id "
              "(store:true likely unsupported), so chaining can't be tested.")
        r3 = None
    else:
        body = _base_body(True, [_user("Now reply with only: done")])
        body["previous_response_id"] = r2["id"]
        r3 = post(tokens, body)
        _show("chained", r3)

    print("\n" + "=" * 60)
    print("VERDICT")
    print("=" * 60)
    store_ok = bool(r2["id"]) and not r2["error"]
    print(f"store:true accepted:           {store_ok}")
    if r3 and not r3["error"] and r3["input_tokens"] is not None:
        full = r2["input_tokens"] or 0
        chained = r3["input_tokens"]
        print(f"previous_response_id accepted: True")
        print(f"  full-input call billed:   {full} input tokens")
        print(f"  chained call billed:      {chained} input tokens")
        if full and chained < full * 0.5:
            print(f"  => CHAINING CUTS INPUT ~{100*(1-chained/full):.0f}% "
                  f"— worth pursuing.")
        else:
            print(f"  => chaining did NOT reduce billed input — not worth it.")
    else:
        print("previous_response_id accepted: False (or errored) "
              "— chaining unusable on this backend; same wall as cache_key.")


if __name__ == "__main__":
    main()
