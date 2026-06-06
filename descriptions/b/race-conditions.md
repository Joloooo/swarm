# race-conditions — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A counter/balance/quota that goes DOWN on each use and gates an action** — "5 free trials left", wallet balance, store credit, points balance, remaining votes, seats/tickets remaining, API calls remaining. If you see a number that is decremented as a precondition for a privileged or valuable action → race candidate.
- **A "single-use" or "one-time" anything** — single-use coupon/voucher/gift-card code, one-time password (OTP), email-verification link, magic login link, password-reset token, invite token, referral bonus. If the app advertises or implies "this can only be used once" → race the consumption step.
- **A response that says "already used" / "already redeemed" / "limit reached" on the SECOND sequential request** — that error string is the tell that the app guards uniqueness, and the question is only whether that guard is atomic. If sequential request #2 returns `409 Conflict`, `400 "code already redeemed"`, `429`, or `403 "limit exceeded"` → fire concurrent requests at request #1's exact form.
- **A multi-step state machine with discrete steps** — `/cart → /checkout → /confirm`, `/transfer → /confirm`, `/withdraw`, `/apply-coupon`, `/2fa/verify`, `/order/finalize`. Any endpoint named `confirm`, `commit`, `finalize`, `submit`, `redeem`, `claim`, `apply`, `capture`, `settle` is a read-modify-write commit point → submit it twice in parallel.
- **A permission/ownership check that is visibly separate from the action it guards** — e.g. you can observe a "validate" call distinct from an "execute" call, or a flow that checks a resource exists/belongs-to-you and then acts on it. TOCTOU candidate: delete/modify the resource between check and use.
- **HTTP/2 (`h2`) or HTTP/1.1 keep-alive supported on the target** — recon showing `ALPN: h2` in the TLS handshake, `HTTP/2` in response, or persistent connections means single-packet / last-byte sync is feasible. Protocol support itself is a green light to attempt tight synchronization.
- **Optimistic-concurrency markers in responses** — `ETag`, `If-Match`, a `version`/`__v`/`revision`/`updatedAt` field in JSON, or `Last-Modified`. These reveal a read-modify-write design; if `If-Match` is optional or the version is accepted-but-not-enforced on all paths → race.
- **Idempotency-Key support that looks app-level rather than DB-level** — an `Idempotency-Key` / `X-Request-ID` header is accepted, but you can vary the key, or the same key is honored across different users/paths. Cache-before-commit window is a strong race surface.
- **Inventory / availability that updates after a delay** — "12 in stock" that doesn't decrement instantly, or a booking that shows "available" right up until you confirm → over-issuance/double-booking race.
- **Per-IP or per-connection rate limiting** (you see `429` keyed to your IP, `X-RateLimit-Remaining` headers) — edge-only throttles are bypassable with parallel sessions/IPs, and the underlying counter is often non-atomic → burst before the counter propagates.
- **PHP / `PHPSESSID` cookie present** — default PHP serializes same-session requests via `session_start()` file locks; this is a *specific* tell that you must mint multiple distinct sessions to actually achieve concurrency. Seeing `PHPSESSID` tells you both that a naive parallel test will fail AND how to fix it.

## Use-case scenarios

- **Financial / value-bearing surfaces.** Anywhere money, credits, loyalty points, gift-card balances, or refunds move. The classic targets: redeem the same gift card N times, withdraw/transfer the same balance N times so total withdrawn > balance, apply a single-use coupon to N concurrent carts, or fire refund + new-purchase to net positive value. This is the highest-value scenario because the invariant ("you cannot spend money you don't have", "this code works once") is concrete and the impact is direct.

- **Quota / limit bypass.** "One signup bonus per user", "max 3 votes", "10 free API calls", "1 vote per poll", "first 100 sign-ups get X". The limit is a counter checked then incremented; concurrent requests all pass the check before any increment lands. Use when the target gives anything scarce or rate-limited where exceeding the cap is itself the goal (gold-rush sign-ups, vote stuffing, free-tier abuse).

- **Auth / token consumption.** Single-use reset tokens, OTPs, magic links, invite codes. Concurrently consuming one token to mint multiple sessions, or racing OTP attempts to bypass an attempt-limiter. Also the email/username-swap race: parallel changes between attacker and victim addresses can route a confirmation link to the wrong inbox → account takeover. Use whenever you find a one-time credential or a verification step.

- **Multi-step workflows / state machines.** Checkout confirm, order finalize, subscription upgrade, application submit. Submit the *same* commit step twice within the race window so the "have I already done this?" guard reads stale state both times. Use whenever the happy path is "do step, then mark step done" with a gap between.

- **TOCTOU on resources.** A check ("does this file/order/account exist and belong to me?") separated in time from the use ("act on it"). Delete, modify, or re-own the resource in the gap. Use for file-permission changes, share-link generation, multi-part upload finalize, and approval/cancellation workflows.

- **Cross-service / async surfaces.** Sagas, queues, webhooks, background jobs (export/import create→finalize), eventual-consistency windows where you act in Service B before Service A's write is visible, and retry storms that cause duplicate side effects via at-least-once delivery. Use when recon reveals a job system, message queue, or "processing…" async state.

- **GraphQL / WebSocket / batch.** Batched mutations, aliased duplicate mutations in one request, persisted queries, or per-message WebSocket actions where only the handshake is authorized. Use when the same state change is reachable through a channel whose per-operation guards differ from REST.

## Concrete tells (request → response examples)

- **The decisive sequential-vs-parallel split.**
  - Sequential probe: `POST /redeem {code: GIFT100}` twice in series → first returns `200 {"balance": 100}`, second returns `409 {"error": "code already redeemed"}`.
  - This confirms there IS a uniqueness guard. Now the actual race test: fire 10× `POST /redeem {code: GIFT100}` in a single HTTP/2 packet → if you get **multiple `200`s** (e.g. balance credited 4×) instead of one `200` + nine `409`s → race confirmed.

- **Withdraw / balance conservation.**
  - Account has balance 100. Sequential: `POST /withdraw {amount: 100}` → `200`, then `200` second time → `400 "insufficient funds"`.
  - Parallel: 5× `POST /withdraw {amount: 100}` simultaneously → if 3 return `200 {"withdrawn": 100}` and the ledger shows 300 withdrawn from a 100 balance → lost-update race.

- **Quota counter.**
  - `GET /me` shows `{"free_trials_remaining": 1}`. Sequential second `POST /start-trial` → `403 "limit reached"`.
  - 20× `POST /start-trial` in parallel → multiple `200`s, then `GET /me` shows `{"free_trials_remaining": -4}` (negative counter is a smoking gun) → race.

- **One-time token.**
  - `POST /reset/confirm {token: T, password: A}` → `200`. Repeat → `400 "token expired/used"`.
  - Parallel 10× with the same token but different `session` slots / no session → multiple `200`s and multiple valid sessions minted → token-consumption race.

- **Negative / impossible aggregates after a burst.** Any post-burst state read that shows a count below zero, more rows than the limit, a balance that increased when it should only have decreased, or two `2xx`s carrying the same correlation/transaction ID → durable race evidence.

- **Protocol probe.** `curl -sI --http2 https://target/` returning `HTTP/2` (or TLS `ALPN: h2`) confirms single-packet attack feasibility; on HTTP/1.1 keep-alive, last-byte synchronization is the fallback.

## When NOT to use it / easily-confused-with

- **A finding requires a DUPLICATE-EFFECT PROOF, not just "I sent parallel requests".** N concurrent attempts must produce N (or > limit) *durable* completed effects where only 1 should. If you cannot show a persisted, reproducible state delta (extra ledger rows, negative counter, multiple valid sessions), do not claim a race. A single 2xx among many 4xxs is the *correct, secure* behavior.
- **Properly guarded uniqueness is NOT a vuln.** If the second sequential request fails AND parallel requests also all fail except one, the guard is atomic (DB unique index, `ON CONFLICT`, serializable transaction, correct Redis `SET NX EX` / fencing token, or a queue). Rule these out first — seeing `409`/`400 "already used"` on the *parallel* attempts means the defense holds.
- **Rate limiting that rejects with atomic counters is not a race** — it is just working. Only escalate if you observe the counter going negative/inconsistent or the IP-only enforcement is bypassable.
- **Not IDOR.** "I can act on another user's resource by changing an ID" is **idor** / **access-control**, not a race — unless the only way through is to win a check-vs-use timing window (then it's race+IDOR chaining). If no concurrency is needed to reach the resource, route to access control.
- **Not business-logic-alone.** "The app lets me apply two different coupons that shouldn't stack" reachable *sequentially* is a **business-logic** flaw, not a race. Race applies specifically when the bug only appears under *concurrent* requests and vanishes when done one at a time.
- **Not injection.** If a value is reflected/evaluated (SQL, command, template), that is **sqli / command-injection / SSTI** — race is about timing of legitimate operations, not malicious payloads. A coupon code that triggers an error suggesting evaluation belongs to an injection skill.
- **Idempotent-by-design operations** (PUT that sets an absolute value, operations behind enforced ETag/If-Match) generally cannot race meaningfully — confirm the operation is read-modify-write (relative/incremental, "consume", "deduct") before investing.
- **Single-packet attacks need HTTP/2** — on a pure HTTP/1.1 target without keep-alive, tight microsecond synchronization may be impossible and a slow/jittery network can hide a real bug, producing false negatives. Don't conclude "not vulnerable" from a high-jitter cross-continent test; prefer warmed connections and same-region proximity.

B:race-conditions done

