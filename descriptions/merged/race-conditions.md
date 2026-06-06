# race-conditions — when to use

TOCTOU (time-of-check / time-of-use): the app makes an authorization or state
decision at one moment and acts on it a moment later, and the gap between the
two can be raced with concurrent requests. Fire this skill on the **shape of a
decoupled check on a privileged or single-use operation** — a permission/role
check separated from the action it guards, or a workflow that should only
succeed once — not only when an obvious coupon/payment surface appears.

## Trigger signals (dispatch the moment you observe…)

- **A privileged route that returns 200 + the full protected page body, then denies you in an overlay/modal/banner.** Render-first/deny-late is the canonical TOCTOU shape: the server computes and returns the protected content (e.g. an admin Dashboard) and *then* bolts a check on top (a Bootstrap error modal reading "Only administrator users can open this section."), rather than a hard `403`/redirect. Race concurrent requests to the privileged action so one lands in the window before the role check binds (or while it reads stale state).
- **A login leaks a low-privilege account AND there is an admin-gated route it cannot reach.** A working `test:test` / `demo:demo` (default_credentials) plus an `/admin_panel` / `/admin` / `/settings` route that says "admins only" — you have a valid session to *start* the protected request and a check standing between you and the action.
- **A "Router/admin" management UI with role-gated sections.** Device admin panels, router config UIs, WiFi-settings consoles that expose `/dashboard`, `/wifi_settings`, `/admin_panel` to a logged-in user but gate the admin section by a server-side role flag.
- **A counter/balance/quota that goes DOWN on each use and gates an action** — "5 free trials left", wallet balance, store credit, points balance, remaining votes, seats/tickets remaining, API calls remaining. A number decremented as a precondition for a privileged or valuable action is a race candidate.
- **A "single-use" / "one-time" anything** — single-use coupon/voucher/gift-card code, OTP, email-verification link, magic login link, password-reset token, invite token, referral bonus. If the operation should only succeed once, race the consumption step.
- **A response that says "already used" / "already redeemed" / "limit reached" on the SECOND sequential request** — `409 Conflict`, `400 "code already redeemed"`, `429`, `403 "limit exceeded"`. That error string proves the app guards uniqueness; the only open question is whether the guard is atomic. Fire concurrent requests at request #1's exact form.
- **A multi-step state machine with discrete steps** — `/cart → /checkout → /confirm`, `/transfer → /confirm`, `/withdraw`, `/apply-coupon`, `/2fa/verify`. Any endpoint named `confirm`, `commit`, `finalize`, `submit`, `redeem`, `claim`, `apply`, `capture`, or `settle` is a read-modify-write commit point — submit it twice in parallel.
- **A check → reserve → commit (or check → act) gap with no visible locking** — verify balance then debit, check permission then perform, reserve seat then confirm, validate-call distinct from execute-call. Fire the second phase before the first commits.
- **An auth/permission decision that depends on mutable state you can change mid-request** — delete/flip/re-own the guarded resource, or escalate the session, in the window between the check and the use.
- **HTTP/2 (`h2`) or HTTP/1.1 keep-alive on the target** — `ALPN: h2` in the TLS handshake, `HTTP/2` in a response, or persistent connections mean single-packet / last-byte sync is feasible. Protocol support is a green light to attempt tight synchronization.
- **Optimistic-concurrency markers in responses** — `ETag`, `If-Match`, a `version`/`__v`/`revision`/`updatedAt` field, or `Last-Modified` reveal a read-modify-write design. If `If-Match` is optional or the version is accepted-but-not-enforced on some paths → race.
- **Idempotency-Key support that looks app-level rather than DB-level** — an `Idempotency-Key` / `X-Request-ID` header is accepted but you can vary the key, or the same key is honored across different users/paths. Cache-before-commit window is a strong race surface.
- **Inventory / availability that updates after a delay** — "12 in stock" that doesn't decrement instantly, or a booking that shows "available" right up until you confirm → over-issuance / double-booking.
- **Per-IP or per-connection rate limiting** — `429` keyed to your IP, `X-RateLimit-Remaining` headers. Edge-only throttles are bypassable with parallel sessions/IPs, and the underlying counter is often non-atomic → burst before the counter propagates.
- **PHP / `PHPSESSID` cookie present** — default PHP serializes same-session requests via `session_start()` file locks. This tells you both that a naive parallel test will fail AND how to fix it: mint multiple distinct sessions to actually achieve concurrency.

## Use-case scenarios

- **Authorization TOCTOU on admin-gated routes.** A non-admin session can *reach* a privileged endpoint and the server's answer is "here is the page, but you're not allowed" — the protected work is done before (or independently of) the gate. Fire many concurrent requests to the privileged action so one slips through before the role/permission check is applied (or while it reads stale state). Obtain a valid baseline session from the leaked account first (default_credentials). Distinct from IDOR/BFLA: you are not forging an identity or exploiting a missing function-level check, you are racing a *correctly-named-but-late* check.
- **Financial / value-bearing surfaces.** Anywhere money, credits, loyalty points, gift-card balances, or refunds move. Redeem the same gift card N times; withdraw/transfer the same balance N times so total withdrawn > balance; apply a single-use coupon to N concurrent carts; fire refund + new-purchase to net positive value. Highest-value scenario — the invariant ("you cannot spend money you don't have", "this code works once") is concrete and the impact is direct.
- **Quota / limit bypass.** "One signup bonus per user", "max 3 votes", "10 free API calls", "first 100 sign-ups get X". The limit is a counter checked then incremented; concurrent requests all pass the check before any increment lands. Use when exceeding a scarce/rate-limited cap is itself the goal (gold-rush sign-ups, vote stuffing, free-tier abuse).
- **Auth / token consumption.** Single-use reset tokens, OTPs, magic links, invite codes. Concurrently consume one token to mint multiple sessions, or race OTP attempts to bypass an attempt-limiter or the MFA-check-vs-resource-access window. Also the email/username-swap race: parallel changes between two addresses route a confirmation link to the wrong inbox → account takeover.
- **Multi-step workflows / state machines.** Checkout confirm, order finalize, subscription upgrade, application submit. Submit the *same* commit step twice within the race window so the "have I already done this?" guard reads stale state both times. Applies whenever the happy path is "do step, then mark step done" with a gap between.
- **TOCTOU on resources.** A check ("does this file/order/account exist and belong to me?") separated in time from the use ("act on it"). Delete, modify, or re-own the resource in the gap. File-permission changes, share-link generation, multi-part upload finalize, approval/cancellation workflows.
- **Cross-service / async surfaces.** Sagas, queues, webhooks, background jobs (export/import create→finalize), eventual-consistency windows where you act in Service B before Service A's write is visible, retry storms causing duplicate side effects via at-least-once delivery. Use when recon reveals a job system, message queue, or "processing…" async state.
- **GraphQL / WebSocket / batch.** Batched mutations, aliased duplicate mutations in one request, persisted queries, or per-message WebSocket actions where only the handshake is authorized. Use when the same state change is reachable through a channel whose per-operation guards differ from REST.

The strongest cue is the instant a logged-in but under-privileged user hits an admin route and gets a *soft* denial layered over real content — stop trying to forge a role and race the action instead, before reaching for SSRF/smuggling/method tricks.

## Concrete tells (request → response examples)

- **Render-then-deny on the admin route.**
  ```
  POST /login  username=test&password=test   → 302 Location: /dashboard   (leaked low-priv account works)
  GET  /dashboard                              → 200  "Welcome to the Router XYZ Dashboard"
  GET  /admin_panel   (as test user)           → 200  <h1>Welcome to the Dashboard</h1>
                                                      <div id="errorModal"> … "Only administrator users
                                                      can open this section." … $('#errorModal').modal('show');
  ```
  The endpoint serves the protected body and applies the role check as a *late overlay*, not a hard `403`/redirect → race concurrent `GET /admin_panel` (and any admin state-change it exposes) to land before the check binds.

- **The decisive sequential-vs-parallel split.** Sequential `POST /redeem {code: GIFT100}` twice in series → first `200 {"balance": 100}`, second `409 {"error": "code already redeemed"}` (confirms a uniqueness guard exists). Now race it: fire 10× `POST /redeem {code: GIFT100}` in a single HTTP/2 packet → **multiple `200`s** (balance credited 4×) instead of one `200` + nine `409`s = race confirmed.

- **Withdraw / balance conservation.** Balance 100. Sequential `POST /withdraw {amount: 100}` → `200`, then `400 "insufficient funds"`. Parallel 5× simultaneously → if 3 return `200 {"withdrawn": 100}` and the ledger shows 300 withdrawn from a 100 balance → lost-update race.

- **Quota counter.** `GET /me` shows `{"free_trials_remaining": 1}`; sequential second `POST /start-trial` → `403 "limit reached"`. Fire 20× `POST /start-trial` in parallel → multiple `200`s, then `GET /me` shows `{"free_trials_remaining": -4}` (a negative counter is the smoking gun).

- **One-time token.** `POST /reset/confirm {token: T, password: A}` → `200`; repeat → `400 "token expired/used"`. Parallel 10× with the same token but different `session` slots / no session → multiple `200`s and multiple valid sessions minted → token-consumption race.

- **Negative / impossible aggregates after a burst.** Any post-burst state read showing a count below zero, more rows than the limit, a balance that increased when it should only decrease, or two `2xx`s carrying the same correlation/transaction ID → durable race evidence.

- **Protocol probe.** `curl -sI --http2 https://target/` returning `HTTP/2` (or TLS `ALPN: h2`) confirms single-packet feasibility; on HTTP/1.1 keep-alive, last-byte synchronization is the fallback.

## Key techniques

- Establish the uniqueness guard with sequential probes first (request #2 fails), then race request #1's *exact* form with many simultaneous requests.
- Synchronize tightly: HTTP/2 single-packet attack, or HTTP/1.1 last-byte sync over warmed keep-alive connections.
- With `PHPSESSID` or any same-session lock, mint multiple distinct sessions so the requests are not serialized.
- Read durable state after the burst to prove the effect (extra ledger rows, negative counter, >1 valid session, count above the cap).

## When NOT to use it / easily-confused-with

- **A finding requires a DUPLICATE-EFFECT PROOF, not just "I sent parallel requests".** N concurrent attempts must produce N (or > limit) *durable* completed effects where only 1 should. Without a persisted, reproducible state delta, do not claim a race. A single `2xx` among many `4xx`s is the correct, secure behavior.
- **A hard `403`/redirect with NO protected content is access control, not a race.** If the privileged route returns a bare `403`, a login redirect, or an empty "forbidden" page (no real admin body), the check is enforced *before* the work → BFLA / auth-bypass. The race signal is specifically "I can see the protected output and the denial is bolted on" or "this action should be one-shot."
- **Properly guarded uniqueness is NOT a vuln.** If the second sequential request fails AND parallel requests all fail except one, the guard is atomic (DB unique index, `ON CONFLICT`, serializable transaction, correct Redis `SET NX EX` / fencing token, or a queue). `409`/`400 "already used"` on the *parallel* attempts means the defense holds.
- **Rate limiting with atomic counters is not a race** — it is just working. Escalate only if the counter goes negative/inconsistent or the IP-only enforcement is bypassable.
- **Forging or swapping an identity is IDOR/crypto, not a race.** Re-encoding a cookie to `admin`, decrementing a `user_id`, or AES-CBC bit-flipping a session is object/identity tampering. If the win is "change *who* I am" → IDOR/crypto. If no concurrency is needed to reach the resource → access control. They co-occur on default_credentials + admin-route targets, so co-dispatch — but unless the only way through is winning a check-vs-use timing window (race+IDOR chaining), route the identity work elsewhere.
- **A missing function-level check is BFLA, not a race.** If the admin endpoint has *no* check at all (any session, or no session, gets the admin action), that is BFLA. TOCTOU is when the check *exists* but can be outrun.
- **Parameter/role injection is not a race.** Adding a privileged field or header (`{'username':'test','role':'admin'}`, `role=administrator`, `X-Forwarded-For: 127.0.0.1`), method tricks (`OPTIONS/TRACE/PROPFIND`), or path-normalization (`/admin_panel/..;/`, `%2f`) is auth-bypass / mass-assignment / parameter-pollution, not a concurrency test.
- **Sequentially-reachable logic flaws are not races.** "The app lets me apply two coupons that shouldn't stack" reachable one-at-a-time is a business-logic flaw. Race applies only when the bug appears under *concurrent* requests and vanishes when done sequentially.
- **Reflected/evaluated values are injection, not a race.** SQL/command/template evaluation belongs to sqli / command-injection / SSTI. Race is about timing of legitimate operations, not malicious payloads.
- **Idempotent-by-design operations** (a `PUT` that sets an absolute value, anything behind enforced `ETag`/`If-Match`) generally cannot race meaningfully. Confirm the operation is read-modify-write (relative/incremental, "consume", "deduct") before investing.
- **Parallel directory/port enumeration is not a race attack.** Using threads/`concurrent.futures` to brute-force *different* paths or ports is just fast recon. A TOCTOU race fires many requests at the *same* endpoint/operation simultaneously to hit a timing window.
- **Single-packet attacks need HTTP/2.** On a pure HTTP/1.1 target without keep-alive, microsecond synchronization may be impossible and a slow/jittery network can hide a real bug → false negatives. Don't conclude "not vulnerable" from a high-jitter cross-continent test; prefer warmed connections and same-region proximity.
