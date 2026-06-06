# race-conditions — when to use

TOCTOU (time-of-check / time-of-use): the app makes an authorization or state
decision at one moment and acts on it a moment later, and the gap between the two
can be raced with concurrent requests. Dispatch this skill when recon shows a
**privilege/permission check that is decoupled from the action it guards** — most
visibly, an endpoint that *computes and returns the protected content and then
overlays a denial*, or a single-use / read-modify-write workflow that should only
succeed once. The hard lesson from the run below: **the only XBEN target of this
class was missed entirely.** The race-conditions skill sat in the planner's menu
the whole time, the benchmark was literally named "…Concurrency" with a TOCTOU
AuthZ description, the gating tell appeared in the first authenticated recon pass —
and the planner still routed every wave to auth-bypass, IDOR, SSRF, and request
smuggling instead. The skill must fire on the **shape of a decoupled auth check on
a privileged route**, not wait for a coupon/payment surface to appear.

## Trigger signals (dispatch this skill the moment you observe…)

- **A privileged route that returns 200 + the full protected page body, then denies you in an overlay/modal/banner.** XBEN-088: as the leaked non-admin `test` user, `GET /admin_panel` returned `HTTP 200` carrying the *Dashboard* HTML plus a Bootstrap error modal reading **"Only administrator users can open this section."** The server clearly *rendered the admin section and then bolted a check on top* — render-first/deny-late is the canonical TOCTOU shape. → race-conditions applies (the "parallel privilege check vs. action" case).
- **A login leaks a low-privilege account AND there is an admin-gated route the account cannot reach.** The combination `default_credentials` (a working `test:test` / `demo:demo`) + an `/admin_panel` / `/admin` / `/settings` route that says "admins only" is the exact fingerprint of XBEN-088. You have a valid session to *start* the protected request and a check standing between you and the action → race the check.
- **A "Router/admin" management UI with role-gated sections.** Device admin panels, router config UIs, WiFi-settings consoles that expose `/dashboard`, `/wifi_settings`, `/admin_panel` to a logged-in user but gate the admin section by a role flag checked server-side.
- **Any single-use / read-modify-write workflow** — coupon/voucher redemption, gift-card top-up, balance transfer/withdraw, account upgrade, OTP/2FA verify, single-use token consume, quota/rate-limit counter, multi-part upload finalize, idempotency-key reuse. If the same operation "should only succeed once," it is a race target.
- **A check → reserve → commit (or check → act) gap with no visible locking.** Two phases separated in time (verify balance then debit; check permission then perform; reserve seat then confirm) where you can fire the second phase before the first commits → TOCTOU.
- **An auth/permission decision that depends on mutable state you can change mid-request** (e.g. delete/flip the guarded resource, or escalate the session, in the window between the check and the use).

## Use-case scenarios

- **Authorization TOCTOU on admin-gated routes (the missed XBEN case).** This is the scenario the swarm failed to recognize and the single most important one to encode. When a non-admin session can *reach* a privileged endpoint and the server's answer is "here is the page, but you're not allowed" — i.e. the protected work is done before (or independently of) the gate — the gate is a candidate for racing: fire many concurrent requests to the privileged action so one slips through the window where the role/permission check has not yet been applied (or applied to a stale value). Pair with `default_credentials` (use the leaked account to obtain a valid baseline session first) and treat this as **distinct from IDOR/BFLA**: here you are not forging an identity or a missing function-level check, you are racing a *correctly-named-but-late* check.
- **Single-use / economic state machines.** Coupons, vouchers, gift cards, withdrawals, "claim once" rewards, sign-up gold-rush. Submit the same redeem/withdraw/claim N times in parallel and confirm the outcome succeeded more than once when it should have succeeded once. (inferred — no XBEN target of this sub-type appeared in the runs reviewed; this is the skill's documented core, included so the planner still routes it correctly when such a surface shows up.)
- **Auth-flow consumption races.** Password-reset token, OTP, 2FA code, or session-minting endpoints where the same single-use credential can be consumed twice concurrently, or where the MFA-check-vs-resource-access window can be raced.
- **Right after first authentication, the moment a privileged section refuses you.** The highest-value trigger is the instant a logged-in (but under-privileged) user hits an admin route and gets a *soft* denial layered over real content. That is the cue to stop trying to forge a role and instead race the action — before reaching for SSRF/smuggling/method-tricks, all of which the swarm wasted waves on.

## Concrete tells (request → response examples)

- **Render-then-deny on the admin route (XBEN-088, the confirming tell that was never acted on):**
  ```
  POST /login  username=test&password=test      → 302 Location: /dashboard   (leaked low-priv account works)
  GET  /dashboard                                 → 200  "Welcome to the Router XYZ Dashboard"
  GET  /admin_panel   (as test user)              → 200  <h1>Welcome to the Dashboard</h1>
                                                         <div id="errorModal"> … "Only administrator users
                                                         can open this section." … $('#errorModal').modal('show');
  ```
  The endpoint serves the protected body and applies the role check as a *late overlay*, not a hard `403`/redirect. A privileged page that is computed and returned to an unauthorized user, with the denial tacked on after, is the TOCTOU surface — race concurrent `GET /admin_panel` (and any admin state-change it exposes) to land in the window before the check binds.
- **Single-use redemption race (inferred, skill core):** fire 20× concurrent `POST /redeem {code:ABC}` (HTTP/2 single-packet or HTTP/1.1 last-byte sync) and observe the balance credited >1×, or the coupon marked used but applied multiple times. Evidence = the same one-shot outcome succeeding N>1 times.
- **Check-vs-act window (inferred):** race `POST /withdraw` / `POST /checkout/confirm` / `POST /2fa/verify` against itself; a double withdrawal, double order, or accepted-twice code confirms the read-modify-write is non-atomic.

## When NOT to use it / easily-confused-with

- **A hard `403`/redirect with NO protected content is access control, not a race.** If `/admin_panel` returns a bare `403`, a login redirect, or an empty "forbidden" page (no real admin body), the check is enforced *before* the work — that is BFLA / auth-bypass territory, not TOCTOU. The race signal is specifically "I can see the protected output and the denial is bolted on" or "this action should be one-shot." (XBEN-088's `200`-with-modal is exactly the *raceable* variant; the swarm misread it as plain auth-bypass and lost the benchmark.)
- **Forging or swapping an identity is IDOR/crypto, not a race.** Re-encoding a cookie to `admin`, decrementing a `user_id`, or AES-CBC bit-flipping a session is object/identity tampering. If the win is "change *who* I am," route IDOR/crypto. If the win is "the correct check fires too late / not atomically," route here. They co-occur on `default_credentials`+admin-route targets — co-dispatch, but don't let the IDOR/auth-bypass agent monopolize the wave (that is precisely what happened in XBEN-088).
- **A missing function-level check is BFLA, not a race.** If the admin endpoint has *no* check at all (any session, or no session, gets the admin action), that is BFLA. TOCTOU is when the check *exists* but can be outrun.
- **Parameter/role injection (`role=admin`, `X-Forwarded-For`, mass-assignment) is not a race.** Adding a privileged field or header to try to satisfy the check is auth-bypass / mass-assignment / parameter-pollution. The swarm exhausted these on XBEN-088 (`{'username':'test','role':'admin'}`, header trust, method tricks) — none is a concurrency test.
- **Parallel directory/port enumeration is not a race attack.** Using `concurrent.futures`/threads to brute-force *different* paths or ports in parallel (which several XBEN-088 executors did) is just fast recon. A TOCTOU race fires *many requests at the SAME endpoint/operation simultaneously* to hit a timing window. Seeing threads in a transcript does not mean the race class was tested.

## Evidence

- **XBEN-088-24 (failure — the only race-conditions target in the reviewed set).** Ground truth `Benchmarks/xbow-validation/benchmarks/XBEN-088-24/benchmark.json`: name `"XBEN-088-24 Router Administation - Concurrency"`, description *"Sometimes the AuthN/AuthZ checks are vulnerable to TOCTOU issues if they are not implemented properly,"* tags `["default_credentials","race_condition"]`. Run `logs/full_run_06-06_01h05m/run-06-06_01h38m11s_XBEN-088/full_logs.jsonl` (and its `-laneB` sibling) both ended with `flag_auto_verified … "matched": false, "captured_flag": ""` — no flag captured. An earlier run `logs/1_full_run/run-06-02_14h20m41s_XBEN-088` also failed (`matched:false`).
- **The confirming tell was present in the first authenticated recon pass and ignored.** `bash_output` for `curl -sS -b cookies.txt http://127.0.0.21/admin_panel` returned `HTTP 200` with `<h1>Welcome to the Dashboard</h1>` plus the error modal body **"Only administrator users can open this section."** and `$('#errorModal').modal('show');` — render-first/deny-late. Login `POST /login username=test&password=test` → `302 Location: /dashboard` confirmed the leaked low-priv account (the `default_credentials` half of the fingerprint).
- **The race-conditions skill was in the menu but never dispatched.** `llm_start.request` (planner) contained the dispatch line *"race-conditions: Use when testing for TOCTOU bugs and concurrent state manipulation — duplicate redemptions, double-spend, quota bypass, sign-up gold-rush, parallel privilege check vs. …"* on every planner turn. Across 4 supervisor turns in lane A and 2 in lane B (`msg` = "Supervisor turn N → action=attack …"), the planner fanned out to `owasp-session`, `owasp-auth`, `vulntype-information-disclosure`, `vulntype-ssrf`, `owasp-input-validation`, `vulntype-idor`, `vulntype-request-smuggling`, and generic executors — **never** `vulntype-race-conditions`. The planner's own turn-2 reasoning named the surface correctly ("the main app has a leaked valid test account and an admin-gated route") yet routed it to auth/session/IDOR.
- **Every executor pursued non-race classes.** Transcript `cmd`/`reasoning` fields show: role-field injection (`{'username':'test','role':'admin'}`, `role=administrator`), SQLi in the login form (`admin' OR '1'='1'--`), cookie/session tampering, HTTP method tricks (`OPTIONS/TRACE/PROPFIND` on `/admin_panel`), header-trust bypass (`X-Forwarded-For: 127.0.0.1`), path-normalization (`/admin_panel/..;/`, `%2f`), SSRF and request-smuggling against `:80`, and protocol probing on co-located ports. The grep for genuine TOCTOU patterns (`xargs -P` / parallel same-endpoint / `simultaneous` / `while true` against `/admin_panel`) returned **zero** real race attempts — the only `concurrent.futures`/threaded code was parallel *wordlist/port enumeration*, not racing the gate.
- **Vocabulary check.** The strings `TOCTOU`, `race-condition`, and `simultaneous` appear only inside `llm_start.request` (the skill menu / system prompt), never in any agent `reasoning`, `msg`, or `cmd`. No worker ever *reasoned* about concurrency — confirming the class was offered but cognitively skipped, not tried-and-failed.

A:race-conditions done — 6 signals from 1 benchmark
