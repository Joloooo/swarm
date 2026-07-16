"""Live probe for Codex backend prompt-cache routing variants.

NOT a pytest. This sends real requests to
``chatgpt.com/backend-api/codex/responses`` using ``~/.codex/auth.json``.

Run:

    cd SwarmAttacker
    uv run python tests/live/probe_cache_routing_variants.py

The probe compares several client-controllable routing hypotheses in one
paired run. Each arm has its own unique prompt namespace and a monotonically
growing input list, so a healthy per-conversation prefix cache should approach
high cache reuse after the first turn.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from src.llm.codex import CODEX_API_ENDPOINT, load_tokens


SYSTEM_FILLER = (
    "You are a terse assistant for a cache-routing experiment. "
    "You organize inventory notes and reply with only the word ok. "
)

TOOL_SCHEMA = [{
    "type": "function",
    "name": "noop",
    "description": "Do not call this tool in the cache-routing probe.",
    "parameters": {
        "type": "object",
        "properties": {
            "note": {"type": "string"},
        },
        "required": ["note"],
        "additionalProperties": False,
    },
}]


def user(text: str) -> dict[str, Any]:
    return {
        "type": "message",
        "role": "user",
        "content": [{"type": "input_text", "text": text}],
    }


@dataclass
class Arm:
    name: str
    persistent: bool
    prompt_cache_key: bool = False
    user_field: bool = False
    messages: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    client: httpx.AsyncClient | None = None


def headers(tokens) -> dict[str, str]:
    out = {
        "Authorization": f"Bearer {tokens.access_token}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if tokens.account_id:
        out["ChatGPT-Account-Id"] = tokens.account_id
    return out


def request_body(arm: Arm, nonce: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": "gpt-5.5",
        "input": arm.messages,
        "store": False,
        "stream": True,
        "include": ["reasoning.encrypted_content"],
        "instructions": (
            f"Probe nonce: {nonce}. Arm: {arm.name}.\n\n"
            + (SYSTEM_FILLER * 120).strip()
            + "\nAlways answer with exactly: ok"
        ),
        "tools": TOOL_SCHEMA,
        "reasoning": {"effort": "low", "summary": "auto"},
    }
    if arm.prompt_cache_key:
        body["prompt_cache_key"] = f"cache-routing:{nonce}:{arm.name}"
    if arm.user_field:
        body["user"] = f"cache-routing:{nonce}:{arm.name}"
    return body


async def post_once(
    client: httpx.AsyncClient,
    tokens,
    arm: Arm,
    nonce: str,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": None,
        "http_version": None,
        "input_tokens": 0,
        "cached_tokens": 0,
        "error": None,
        "response_id": None,
    }
    try:
        async with client.stream(
            "POST",
            CODEX_API_ENDPOINT,
            json=request_body(arm, nonce),
            headers=headers(tokens),
        ) as resp:
            out["status"] = resp.status_code
            out["http_version"] = resp.http_version
            if resp.status_code != 200:
                out["error"] = (await resp.aread()).decode(
                    "utf-8", "replace",
                )[:500]
                return out

            data_lines: list[str] = []
            async for raw in resp.aiter_lines():
                if raw:
                    if raw.startswith("data:"):
                        data_lines.append(raw[5:].lstrip())
                    continue
                if not data_lines:
                    continue
                payload = "\n".join(data_lines)
                data_lines = []
                if payload.strip() == "[DONE]":
                    continue
                try:
                    event = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                etype = event.get("type")
                if etype == "response.failed":
                    out["error"] = json.dumps(
                        (event.get("response") or {}).get("error") or {},
                    )[:500]
                if etype in ("response.completed", "response.done"):
                    response = event.get("response") or {}
                    usage = response.get("usage") or {}
                    details = usage.get("input_tokens_details") or {}
                    out["response_id"] = response.get("id")
                    out["input_tokens"] = int(usage.get("input_tokens") or 0)
                    out["cached_tokens"] = int(details.get("cached_tokens") or 0)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"[:500]
    return out


async def call_arm(tokens, arm: Arm, nonce: str) -> dict[str, Any]:
    http2 = bool(getattr(call_arm, "http2", False))
    if arm.persistent:
        if arm.client is None:
            arm.client = httpx.AsyncClient(timeout=120.0, http2=http2)
        return await post_once(arm.client, tokens, arm, nonce)
    async with httpx.AsyncClient(timeout=120.0, http2=http2) as client:
        return await post_once(client, tokens, arm, nonce)


def pct(row: dict[str, Any]) -> float:
    inp = int(row.get("input_tokens") or 0)
    cached = int(row.get("cached_tokens") or 0)
    return 100.0 * cached / inp if inp else 0.0


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total_in = sum(int(r.get("input_tokens") or 0) for r in rows)
    total_cached = sum(int(r.get("cached_tokens") or 0) for r in rows)
    return {
        "calls": len(rows),
        "input_tokens": total_in,
        "cached_tokens": total_cached,
        "cached_pct": round(100.0 * total_cached / total_in, 1)
        if total_in else 0.0,
        "zero_cache_calls": sum(
            1 for r in rows if int(r.get("cached_tokens") or 0) == 0
        ),
        "high_cache_calls": sum(1 for r in rows if pct(r) >= 80.0),
        "turn_pcts": [round(pct(r), 1) for r in rows],
        "errors": [r for r in rows if r.get("error")],
    }


def turn_text(nonce: str, arm: Arm, turn: int) -> str:
    return (
        f"[{nonce}/{arm.name}/turn-{turn}] "
        + ("inventory-row-token " * 180)
        + f"end-{arm.name}-{turn}. Reply ok."
    )


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--turns", type=int, default=6)
    ap.add_argument("--http2", action="store_true")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    call_arm.http2 = args.http2  # type: ignore[attr-defined]

    nonce = uuid.uuid4().hex[:8]
    tokens = load_tokens()
    arms = [
        Arm("fresh_off", persistent=False),
        Arm("persist_off", persistent=True),
        Arm("fresh_key", persistent=False, prompt_cache_key=True),
        Arm("persist_key", persistent=True, prompt_cache_key=True),
        Arm("persist_user", persistent=True, user_field=True),
    ]
    for arm in arms:
        arm.messages.append(user(f"Begin {arm.name} nonce {nonce}. Reply ok."))

    print(f"endpoint={CODEX_API_ENDPOINT}")
    print(
        f"nonce={nonce} turns={args.turns} requests={args.turns * len(arms)} "
        f"http2={args.http2}"
    )
    print("arms=" + ", ".join(a.name for a in arms))
    print()

    try:
        for turn in range(1, args.turns + 1):
            for arm in arms:
                arm.messages.append(user(turn_text(nonce, arm, turn)))
            rows = await asyncio.gather(*[
                call_arm(tokens, arm, nonce) for arm in arms
            ])
            cells = []
            for arm, row in zip(arms, rows):
                row["turn"] = turn
                row["arm"] = arm.name
                arm.results.append(row)
                cells.append(
                    f"{arm.name}={pct(row):5.1f}%"
                    f"({row.get('cached_tokens')}/{row.get('input_tokens')})"
                    + (" ERR" if row.get("error") else "")
                )
            print(f"turn {turn:02d}: " + " | ".join(cells))
    finally:
        await asyncio.gather(*[
            arm.client.aclose() for arm in arms if arm.client is not None
        ])

    report = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "nonce": nonce,
        "turns": args.turns,
        "http2": args.http2,
        "endpoint": CODEX_API_ENDPOINT,
        "summaries": {arm.name: summarize(arm.results) for arm in arms},
        "results": {arm.name: arm.results for arm in arms},
    }

    print("\nSUMMARY")
    for arm in arms:
        s = report["summaries"][arm.name]
        print(
            f"{arm.name:12} cached={s['cached_pct']:5.1f}% "
            f"zero={s['zero_cache_calls']}/{s['calls']} "
            f"high={s['high_cache_calls']}/{s['calls']} "
            f"pcts={s['turn_pcts']}"
        )
        if s["errors"]:
            print(f"  errors={s['errors']}")

    out = args.out
    if not out:
        out = f"logs/cache-routing-probe-{nonce}.json"
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
