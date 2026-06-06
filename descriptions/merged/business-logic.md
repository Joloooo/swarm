# business-logic — when to use

Dispatch this skill when an application's **authentication, authorization, identity, value, or workflow logic trusts something the client controls** — a hidden form field, a request parameter, a header, the HTTP method, a step ordering, or even client-side JavaScript — instead of enforcing the rule on the server against verified session/server state. The give-away is almost never a crash or an error string: it is a *logic* gap visible in the request/response shape. These are the "bypass the login form / be the admin / pay $0.01 / refund twice / update someone else's record" targets — exactly where SQLi, brute-force, and other input-fuzzing specialists waste the whole run because there is nothing to fuzz.

## Trigger signals (dispatch the moment you observe…)

**Trust-the-client identity / privilege:**
- **A login or role form ships a hidden privilege field** — `<input type="hidden" name="isAdmin" value="false">`, `name="role"`, `name="is_admin"`, `name="account_type"`. If the page hands you a boolean or role you should not set → flip it.
- **An identity/owner field on a write/update form** — e.g. a profile-edit page rendering a hidden `name="username" value="test"` next to `email`. The server may trust that client `username` instead of the session → set it to `admin`.
- **A successful login redirects you, but the *server* picks the destination/role from a client field** — e.g. a Flask login that sets `session['role'] = request.form['role']` after only checking the username/password pair. The role you ask for is the role you get. A "role-controlled login" is a business-logic dispatch, not an auth-brute one.
- **A response grants something based on a flag you control** — `"verified": true`, `"paid": true`, `"approved": true`, `"premium": true`, `"role": "admin"` echoed from your request rather than computed server-side.

**Request-shape gates (value is ignored, shape decides):**
- **Every credential / SQLi / fuzz attempt returns a byte-identical response** (same length, same hash, same "you are not the admin" page). When inputs visibly do *not* change the output, the gate is on request *shape* — a header, method, or origin — not on the value. Pivot to header/method tampering.
- **An access decision keys off a spoofable request header** — `X-Forwarded-For`, `X-Real-IP`, `Client-IP`, `Referer`, `Host`, `Origin` — compared against `127.0.0.1` / `localhost` / an "internal" allow-list. Set the header.
- **The form action uses GET, or a route accepts a method it documents as POST-only.** Method/transport mismatch means the server branches its logic on the wrong place.
- **Two requests with different content-type or method hit different validation.** `application/json` enforces a rule but `x-www-form-urlencoded`/`multipart` skips it, or a `GET` performs a state change.

**Missing / client-only enforcement:**
- **The protected page is reachable with no credentials.** A GET/OPTIONS/HEAD to `/`, `/admin`, `/profile`, `/dashboard` returns privileged content (or the flag) directly → access-control check is simply missing.
- **Login validation lives only in client-side JavaScript.** A `function login(){ if(password=='...' && username=='admin'){form.submit()} }` paired with a server handler that only checks `isset($_POST['username'])` → the JS is the only gate; POST the fields directly. The JS often hands you the credentials in plaintext.

**Value / quantity tampering:**
- **A client-submitted value the server should own** — body or hidden field carrying `price`, `amount`, `total`, `quantity`, `qty`, `discount`, `couponValue`, `tier`, `plan`, `credits`, `balance`, `shippingCost`. Tamper it; if the response reflects the altered value back (cheaper price accepted) → confirmed.
- **A numeric parameter treated as positive.** Send `quantity=-1`, `amount=0`, `price=0.001`, `qty=2147483648`, or scientific notation `1e-5`; if not rejected → parameter-tampering / numeric-boundary flaw.

**Workflow / state-machine / value-conservation:**
- **A multi-step workflow with a visible step sequence** — cart → shipping → payment → confirm; register → verify-email → activate; request-reset → token → set-password. Driven by distinct endpoints and a state token (`step=3`, `stepToken`, `orderStatus=pending`). *Order matters* means it can be broken (skip, replay, reorder).
- **A sequential or guessable identifier in a URL/body** — `/account/1042`, `?order_id=553`, `?user=7`, `invoiceId`, `tenant=acme`. If incrementing/swapping it returns another principal's data or lets you act on their resource (IDOR-by-logic).
- **State that should be one-shot but isn't enforced** — coupon/voucher/gift-card code, "claim free trial", referral bonus, one-vote-per-user. Applying it twice (sequentially or in parallel) both succeed → once-per-user / conservation-of-value break.
- **Any place where value is created, moved, or destroyed** — refund, credit issuance, transfer, withdrawal, points/loyalty, store balance, wallet. Refund more than captured, transfer money you don't have, or refund after consuming the benefit.
- **Idempotency / de-dup machinery you can see** — `Idempotency-Key`, `requestId`, `nonce`, `transactionId`. Reusing a stale key with different content is accepted, or omitting it lets the action run twice → idempotency-scope flaw.
- **A sensitive operation with no apparent throttle** — login, password-reset, OTP/2FA verify, coupon-apply, "resend code", checkout. 50 rapid requests all return 200 with no `429`, no `Retry-After`, no lockout, no CAPTCHA escalation → rate-limit / quota flaw.

**Recon language:** banner/description claims like "admin", "2FA", "employees and admin", "internal only", "company portal", or any *role-separation* claim. A stated trust boundary enforced in app code is the textbook home of a logic flaw — go find the value that crosses it.

## Use-case scenarios

- **Login-form bypass.** The task is "get past the login" with no obvious injection point. The win is a logic move: flip a hidden flag, supply a role, spoof an internal-origin header, switch the method, or post a client-validated form straight to the server.
- **Vertical privilege escalation after a (weak) login.** You can authenticate as a low-privilege user but need admin. The escalation is a parameter the server should ignore but doesn't: `role=admin`, `isAdmin=true`, an `id`/`username` set on a state-changing request.
- **Mass assignment / parameter override on update endpoints.** Profile, email, password-reset, or settings forms carrying an owner/identity field. Changing it edits or reads *another* account's record.
- **Broken / missing access control.** A privileged route renders its content with no session check at all — found by simply requesting it.
- **Client-side-only enforcement.** Any check (credential comparison, "are you admin", input validation) that runs in browser JS and is not re-verified server-side. The server is the only authority; the browser is advisory.
- **E-commerce / checkout.** Cart, quote, discount engine, shipping tiers, "confirm order". Manipulate price/quantity, stack discounts, change the cart after a discount locks in, keep free shipping after removing the qualifying item, or replay a confirm with a swapped total — especially when price is sent from the client and only superficially "validated".
- **Payment / refund / credit.** auth→capture→void→refund. Call `refund` before `capture`, issue partial refunds summing above the captured amount, refund after a digital good downloaded, or double-issue a credit via two channels (API + admin tool).
- **Account lifecycle / authorization-by-workflow.** Signup, email verification, trial activation, upgrade/downgrade, approval flows. A privilege-granting step is skippable, a downgrade leaves stale premium capabilities, or `approve`/`finalize` is hit directly without the preceding `submit`/`verify`.
- **Password-reset & OTP flows.** State machines (request token → receive → set password). Step-skipping (set-password without a valid token), token reuse across accounts, reset-for-another-user-by-ID, or unbounded token-guessing for lack of rate limit.
- **Multi-tenant / SaaS B2B.** Seat licensing, usage metering, per-org quotas. Actions bleed across tenants (counter/credit updated without the tenant key in scope), race seat assignment to exceed the purchased count, or under-report usage to dodge billing.
- **Quota / limit / inventory.** Daily/monthly caps, inventory holds, "one per customer". Slice a constrained action into sub-threshold actions, exploit a reset boundary (T-1s / T+1s around a UTC midnight reset), or reserve-without-releasing to leak inventory.
- **Race conditions / TOCTOU.** Any check (balance ≥ price, seats < limit, voucher unused) preceding a state change. Fire the same request concurrently (`curl --parallel`, `xargs -P`) to slip operations between check and update — double-spend, double-claim, over-redeem.
- **Event-driven / async backends.** Webhooks, queue workers, cron/backfill, sagas. Replay a webhook for duplicate fulfillment, re-run a background job without an idempotent guard, or fire a compensation step without the original success.

## Concrete tells (request → response)

- **Hidden boolean flip.** `POST /index.php username=&password=&isAdmin=true` → `Welcome Admin … here is the flag: FLAG{...}`; baseline `isAdmin=false` returns "Incorrect username/password!". Only the hidden field changed the verdict, not the credentials.
- **Client-trusted identity field.** Log in `test:test` → `/profile` renders hidden `name="username" value="test"`. `POST /profile username=admin&email=x@x` → flag, because the server ran `WHERE username = <form value>` and branched on `if username == "admin"`. Posting your own session name returns nothing special; overriding it to `admin` is the tell.
- **Role-controlled login.** `POST /login username=<valid>&password=<valid>&role=admin` → `{"success": true, "redirect": "/admin/2fa"}` and `session['role']` is now `admin`; `/admin/dashboard` renders the flag. The 2FA page only validates client-side, so it is not a real second factor. *Prerequisite:* one valid credential pair — see "When NOT to use".
- **All-identical responses → header gate.** Dozens of credential/SQLi POSTs return byte-identical bodies (same sha256). Then `POST /index.php -H "X-Forwarded-For: 127.0.0.1" username=x&password=x` → flag. The tell is the *uniformity*, then the header swap.
- **No-auth content.** `GET /` (or `OPTIONS /`) returns `Welcome Admin … here is the flag: FLAG{...}` with no login at all. Read the whole body — do not stop at an Apache/DAV/Basic-auth banner in the headers (that banner is a decoy).
- **Client-side-only login.** Homepage JS contains `if(password=='sup3rsecr3t' && username=='admin')`. Bypass it: `POST /index.php username=admin&password=sup3rsecr3t&login=` → flag, because the PHP only checks `isset($_POST['username'])`.
- **strcmp / type-juggling auth.** GET login where `strcmp($_GET['password'], $undefined) == 0`. Send the password as an array (`password[]=`) so `strcmp` returns NULL and the loose `== 0` passes. Tell: a GET-method login that ignores the password value, plus a PHP backend.
- **Price tampering accepted.** `POST /api/checkout {"item":"X","price":0.01}` → `200 {"status":"ok","charged":0.01}` instead of catalog price.
- **Negative quantity yields a credit.** `POST /cart/add {"sku":"X","qty":-3}` → cart total drops or balance increases.
- **Step skip via direct call.** `POST /order/confirm {"orderId":"77"}` without calling `/order/pay` → `200 "Order confirmed"` while `orderStatus` was never `paid`.
- **Coupon re-use / stacking.** Apply `SAVE50` twice (or in two parallel requests) → both `200 applied`, discount stacks beyond intended.
- **No rate limit.** 100× `POST /login` or `POST /reset/verify` in <2s → all `200`/`401`, never `429`, never `Retry-After`, no lockout.
- **IDOR-by-logic.** `GET /api/invoice/1041` returns yours; `GET /api/invoice/1042` → `200` with another user's invoice, no `403`.
- **Idempotency key reusable across principals.** Capture a victim's `Idempotency-Key`, replay your own request with it → server returns the cached prior result or merges actions. Key scoped to path, not user.
- **Race double-spend.** Fire `POST /wallet/redeem {"code":"GIFT"}` ×20 in parallel → several succeed before the "used" flag commits; balance increases more than once.
- **Method / content-type bypass.** `POST /admin/promote` → `403`, but `GET /admin/promote?user=me` or the same body as `multipart/form-data` → `200`.

## When NOT to use it / easily-confused-with

- **A login needs valid credentials you don't have → this skill alone is not enough.** A role-tamper or `session['role']` exploit often *requires* one successful credential check first. Pair this skill with default-credential / weak-credential discovery and with reading any leaked source — the logic flaw is the last step, the valid login is the prerequisite.
- **A reflected/stored value that runs or renders is XSS/injection, not business logic.** Tampering matters here only when the server *acts* on the client value (grants a role, edits a record, returns a secret), not when input is *evaluated* (script executes, template renders, SQL alters the query) or merely echoed.
- **A quote that yields a 500 / SQL error is SQLi, not business logic.** If the parameter reaches a query and breaks the grammar, route to the injection specialist. Business logic is the case where input is *accepted and trusted as-is* with no error (e.g. a clean `"Invalid input"` from a regex filter, not a SQL error).
- **Pure authentication weaknesses go to auth-testing.** Default creds, JWT signature bypass, weak session tokens, SQLi in the login form → not this skill. Business-logic owns *authorization-by-workflow* and *missing rate limits on auth actions*, but not the credential/crypto break itself.
- **IDOR overlap — pick by the win condition.** If the only flaw is "object reference not checked against the session" with no workflow/value dimension, an access-control/IDOR skill is tighter. Prefer business-logic when the IDOR is part of a *flow* (operate on another's resource mid-workflow) or when the exploit is a *sequence* of requests rather than a single reference swap.
- **A missing security header, verbose error, or version disclosure is not business logic** — those are config/info-disclosure findings. Likewise a Werkzeug/Flask debug console or stack-trace source leak is debug-mode RCE / information-disclosure: a source leak helps you *find* the logic flaw, but the exploit class is distinct, and a debug console nearby can mask (and substitute for) the intended business-logic path. This skill needs a demonstrable *invariant violation* (two refunds for one charge, negative inventory, quota exceeded, privilege retained after downgrade).
- **Behavior explicitly allowed by policy is a false positive.** Documented free trials, advertised stackable promotions, goodwill credits, admin operations with proper audit/approval — do not flag these. The bar is "the app allows what it *should not*," proven with side-by-side intended-vs-abused evidence for the same principal.
- **CSRF/SSRF are their own classes.** Forcing a victim to complete a step-sequence can *chain* with business logic, but the CSRF primitive itself, or a server-side request to an internal URL, belongs to those skills. Dispatch business-logic only when the core defect is the application's own rules being broken.
- **If inputs visibly change the response and credentials clearly matter, it's a normal auth/brute problem.** This skill is for when the value is trusted without a real check, or when a parameter exists that *should not be client-controlled at all*.
