# business-logic — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A multi-step workflow with a visible step sequence** (cart → shipping → payment → confirm; or register → verify-email → activate; or request-reset → token → set-password). If the steps are driven by distinct endpoints and a state token (`step=3`, `stepToken`, `orderStatus=pending`) → this skill applies. The tell is *order matters*, which means it can be broken.
- **A client-submitted value the server should own.** If a request body or hidden form field carries `price`, `amount`, `total`, `quantity`, `qty`, `discount`, `couponValue`, `role`, `isAdmin`, `tier`, `plan`, `credits`, `balance`, `shippingCost` → tamper it. If the response reflects your altered value back (cheaper price accepted, role upgraded) → confirmed.
- **A numeric parameter that the app treats as positive.** If you can send `quantity=-1`, `amount=0`, `price=0.001`, `qty=2147483648`, or scientific notation `1e-5` and the server does not reject it → parameter-tampering / numeric-boundary flaw.
- **An identifier in a URL or body that is sequential or guessable.** `/account/1042`, `?order_id=553`, `?user=7`, `invoiceId`, `tenant=acme`. If incrementing/swapping the ID returns another principal's data or lets you act on their resource (the authorization-by-logic / IDOR overlap) → this skill.
- **A sensitive operation with no apparent throttle.** Login, password-reset, OTP/2FA verify, coupon-apply, "resend code", checkout. If 50 rapid requests all return 200 with no `429`, no `Retry-After`, no lockout, no CAPTCHA escalation → rate-limit / quota flaw.
- **Idempotency or de-dup machinery you can see.** `Idempotency-Key` header, `requestId`, `nonce`, `transactionId`. If reusing a stale key with different content is accepted, or omitting it lets the action run twice → idempotency-scope flaw.
- **State that should be one-shot but isn't enforced.** A coupon/voucher/gift-card code, a "claim free trial" action, a referral bonus, a one-vote-per-user poll. If applying it twice (sequentially or in parallel) both succeed → once-per-user / conservation-of-value break.
- **Two requests with different content-types or methods hit different validation.** If `Content-Type: application/json` enforces a rule but `application/x-www-form-urlencoded` or `multipart` skips it, or a `GET` performs a state change → bypass surface.
- **Any place where value is created, moved, or destroyed.** Refund, credit issuance, transfer, withdrawal, points/loyalty, store balance, wallet. If you can refund more than was captured, transfer money you don't have, or refund after consuming the benefit → core business-logic finding.
- **A response that grants something based on a flag you control.** `"verified": true`, `"paid": true`, `"approved": true`, `"premium": true` echoed from your request rather than computed server-side → trust-the-client flaw.

## Use-case scenarios

- **E-commerce / checkout flows.** Anywhere there is a cart, a quote, a discount engine, shipping tiers, or a final "confirm order" step. The right move when you can manipulate price/quantity, stack discounts, change the cart after a discount locks in, keep free shipping after removing the qualifying item, or replay a confirm request with a swapped total. Especially when the price is sent from the client and only "validated" superficially.
- **Payment / refund / credit flows.** Auth→capture→void→refund sequences. Dispatch here when you can call `refund` before `capture`, issue multiple partial refunds summing above the captured amount, refund after a digital good was downloaded, or double-issue a credit via two channels (API + admin tool).
- **Account lifecycle and authorization-by-logic.** Signup, email verification, trial activation, upgrade/downgrade, role transitions, approval workflows. The right skill when a workflow step that grants privilege can be skipped, when a downgrade leaves stale premium capabilities, or when an `approve`/`finalize` endpoint can be hit directly without the preceding `submit`/`verify`.
- **Password-reset and OTP flows.** These are state machines: request token → receive token → set new password. Dispatch here for step-skipping (set-password without a valid token), token reuse across accounts, reset-for-another-user-by-ID, or unbounded token-guessing because there's no rate limit (overlaps with auth-testing — see below).
- **Multi-tenant / SaaS B2B.** Seat licensing, usage metering, per-org quotas, organization-scoped data. Use when actions might bleed across tenants (a counter or credit updated without the tenant key in scope), when you can race seat assignment to exceed the purchased count, or when usage can be under-reported to dodge billing.
- **Quota, limit, and inventory enforcement.** Daily/monthly caps, inventory holds, "one per customer," API usage counters. Dispatch when you can slice a constrained action into many sub-threshold actions, exploit a reset boundary (T-1s and T+1s around a UTC midnight reset), or reserve-without-releasing to leak inventory.
- **Race conditions / TOCTOU.** Any operation where a check (balance ≥ price, seats < limit, voucher unused) precedes a state change. Dispatch when you can fire the same request concurrently (`curl --parallel`, `xargs -P`) to slip multiple operations between the check and the update — double-spend, double-claim, over-redeem.
- **Event-driven / async backends.** Webhooks, queue workers, cron/backfill jobs, sagas. Use when a webhook can be replayed to trigger duplicate fulfillment, when a background job re-runs without an idempotent guard, or when a compensation step can fire without the original success.

## Concrete tells (request → response examples)

- **Price tampering accepted.**
  `POST /api/checkout {"item":"X","price":0.01}` → `200 {"status":"ok","charged":0.01}` instead of the catalog price. Server trusted the client total.
- **Negative quantity yields a credit.**
  `POST /cart/add {"sku":"X","qty":-3}` → cart total drops or balance increases. The skill applies the moment a negative or zero numeric is not rejected.
- **Step skip via direct call.**
  `POST /order/confirm {"orderId":"77"}` *without* having called `/order/pay` → `200 "Order confirmed"` while `orderStatus` was never `paid`. State machine doesn't enforce preconditions.
- **Coupon re-use / stacking.**
  Apply `SAVE50` twice (or in two parallel requests) → both return `200 applied`, discount stacks beyond intended. Once-per-user not enforced atomically.
- **No rate limit on sensitive op.**
  100× `POST /login` or `POST /reset/verify` in <2s → all `200`/`401`, never a `429`, never `Retry-After`, no lockout. Brute-force / abuse open.
- **IDOR-by-logic.**
  `GET /api/invoice/1041` returns yours; `GET /api/invoice/1042` → `200` with another user's invoice, no `403`. Authorization decided by reachability, not identity.
- **Idempotency key reusable across principals.**
  Capture a victim's `Idempotency-Key`, replay your own request with it → server returns the *cached* prior result or merges actions. Key scoped to path, not user.
- **Race double-spend.**
  Fire `POST /wallet/redeem {"code":"GIFT"}` ×20 in parallel → 3 of them succeed before the "used" flag commits. Confirmed by the balance increasing more than once.
- **Method/content-type bypass.**
  `POST /admin/promote` → `403`, but `GET /admin/promote?user=me` or the same body as `multipart/form-data` → `200`. Validation lives on only one path.

## When NOT to use it / easily-confused-with

- **A reflected or stored value that runs/renders is XSS or injection, not business logic.** If your input is *evaluated* (script executes, template renders, SQL alters the query) → route to the relevant injection/XSS skill. Business-logic is about the app *accepting an action it shouldn't*, not about code execution.
- **IDOR overlap — pick by the win condition.** If the only flaw is "object reference not checked against the session" and there's no workflow/value dimension, an access-control/IDOR skill may be tighter. Use business-logic when the IDOR is part of a *flow* (operate on another's resource mid-workflow) or when value/state invariants are the prize. They overlap; prefer this skill when the exploit is a *sequence* of requests, not a single reference swap.
- **Pure authentication weaknesses go to auth-testing.** Default creds, JWT signature bypass, weak session tokens, SQLi in the login form → not this skill. Business-logic owns *authorization-by-workflow* and *missing rate limits on auth actions*, but not the credential/crypto break itself.
- **A missing security header, verbose error, or version disclosure is not business logic.** Those are config/info-disclosure findings. This skill needs a demonstrable *invariant violation* (two refunds for one charge, negative inventory, quota exceeded, privilege retained after downgrade).
- **Behavior explicitly allowed by policy is a false positive.** Documented free trials, advertised stackable promotions, goodwill credits, admin operations with proper audit/approval — do not flag these. The bar is "the app allows what it *should not*," proven with side-by-side intended-vs-abused evidence for the same principal.
- **CSRF/SSRF are their own classes.** Forcing a victim to complete a step-sequence can *chain* with business logic, but the cross-site request forgery primitive itself, or a server-side request to an internal URL, belongs to those dedicated skills. Dispatch business-logic only when the core defect is the application's own rules being broken.

B:business-logic done

