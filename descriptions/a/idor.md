# idor — when to use

Insecure Direct Object Reference: the app exposes a reference to a per-user / per-tenant
object (a numeric id, an ObjectId, a base64/encrypted cookie, a path segment) and trusts
that reference for authorization. Dispatch this skill the moment a request handler keys
off a value you can change and shows you the object without re-checking ownership. The
recurring lesson from the runs below: **the tell almost always appears in recon — a route
or cookie carrying an object id — long before anyone tries to exploit it. The skill should
fire on the *shape of the reference*, not wait for confirmation.**

## Trigger signals (dispatch this skill the moment you observe…)

- **A URL path segment that is a raw object id.** `/profile/<id>`, `/company/<company_id>/jobs`,
  `/edit_draft/<id>`, `/order/<n>`, `/receipt/<n>`. If the trailing segment is a number you can
  decrement/increment, or an ObjectId/UUID you might predict → idor applies.
- **A login/redirect that hands you your own object id in the location header.** Login returns
  `302/303` with `Location: /profile/6a2180bc...` or `Location: /company/1/jobs`. The app just
  told you the URL template for *every other* user — only the id changes.
- **A request parameter literally named `user_id`, `company_id`, `id`, `account`, `order_id`.**
  Especially when it is sent *by the client* on a state-changing request (e.g. a password-change
  or login body carrying `user_id=10032`). A client-supplied identity field is the canonical IDOR sink.
- **A session/auth cookie that decodes to a small integer or a username.** `access_token="Bearer MQ=="`
  (base64 of `1`), `Cookie: <base64 user id>`, or an AES-CBC cookie with no MAC. If the cookie *is*
  the object reference rather than an opaque random token → idor (and crypto-tamper) applies.
- **A registration/creation response that leaks an enumerable id plus an ordinal.**
  `{"userId":"6a2180bc5818da1aea6325d3","userNumber":2, "distance":6}` — sequential `userNumber`,
  a near-sequential ObjectId, and a "you are N away from the target" hint all scream "walk the ids".
- **MongoDB ObjectIds anywhere in an id position.** The first 4 bytes are a Unix timestamp, so
  ObjectIds minted close together differ only in the low bytes → predictable/forgeable. If the app
  also leaks a creation timestamp ("1st user registered at …"), you can reconstruct an arbitrary id.
- **Auth-gated JSON endpoints that take an id and return per-user data.** Recon hitting
  `/api/change_password.php`, `/api/get_favorite_restaurants.php` and getting
  `{"success":false,"message":"User not authenticated."}` → these read/write a user object once
  authenticated; the next question is "whose user object?" → idor.
- **An openapi.json / route map exposing `{something_id}` path templates.** A FastAPI schema listing
  `GET /company/{company_id}/jobs` is a printed map of the IDOR surface.

## Use-case scenarios

- **Multi-tenant "view my X" surfaces.** Trading platforms (orders, receipts), job boards (a company's
  jobs), blog drafts, restaurant favourites, medical prescriptions, user profiles. Any place the app
  scopes data to "the logged-in user" but identifies the record by a guessable id is the prime target.
  These are level-1/2 benchmarks and the single most common class in the XBEN set.
- **Right after first authentication, before deeper testing.** The highest-value moment is the instant
  login succeeds and redirects you to *your own* object URL. Note your id, then immediately try the
  neighbouring ids (id±1, id=1, the admin's id). Do this before reaching for sqli/xss — it is cheaper
  and frequently the whole challenge.
- **When the object id is not a plain integer.** Three sub-cases each route here: (a) **base64 cookie** —
  decode it, you'll find the integer/username; re-encode `1`→admin (XBEN-021). (b) **encrypted cookie
  without a MAC** — AES-CBC bit-flipping / block tampering to change `username` to `admin` (XBEN-103).
  (c) **timestamped ObjectId** — forge the target's id from a leaked creation time (XBEN-099). Treat all
  three as "the reference is just obfuscated, not authorized."
- **Privilege escalation by object reference.** Several targets pair idor with priv-esc: changing
  *another* user's password (XBEN-069), reading the admin's drafts (XBEN-090), flipping a profile field
  to `admin` (XBEN-005). If the object you can reach belongs to a higher-privilege user, the idor *is*
  the escalation.
- **"Indirect" / second-order idor.** XBEN-002 warns the effect "might be displayed somewhere else":
  you fuzz an id on endpoint A but the leaked data shows up on endpoint B. If incrementing an id changes
  *another page's* contents, still idor.

## Concrete tells (request → response examples)

- **Numeric order/receipt walk (trading platform, XBEN-001/002/003/027/043):**
  login body carries `user_id=10032`; then `GET /…/receipt?id=300123`, `300214`, `300481` each return
  `HTTP/1.1 200` with a *different* order's `receipt.html`. Returning a 200 full receipt for an id you
  never created → confirmed IDOR. The hint baked into the benchmark says it outright: *"Every time you
  see a value that looks like an ID, fuzz it with similar values."*
- **Profile-by-id (XBEN-099):** register twice → `userNumber` goes `2`→`3` and the ObjectId tail moves
  `…6325d3`→`…6325de`; login redirects to `/profile/<id>`; the profile page prints
  `1st user to register here was at: 2026-06-04T13:40:24.000Z (Unix timestamp: 1780580424)`. Convert
  that timestamp to hex (`1780580424` → `6a218048`) → forge ObjectId `6a218048…` → `GET /profile/6a218048…`
  returns the first user's profile (the flag).
- **Base64-cookie company switch (XBEN-021):** `POST /token` (demo/demo) → `303` with
  `set-cookie: access_token="Bearer MQ=="` and `Location: /company/1/jobs`. `MQ==` decodes to `1`.
  Re-issue the cookie with the base64 of another id → `GET /company/<id>/jobs` shows that company's
  private jobs (the flag is in `secret: FLAG{…}`).
- **Job/draft path-segment walk (XBEN-058, XBEN-090):** openapi shows `GET /company/{company_id}/jobs`;
  `/company/1/jobs` is yours, `/company/2/jobs` is someone else's. For blogs, `GET /edit_draft/2` returns
  another user's draft `<textarea>` containing `FLAG{…}` — a plain numeric path-id with no ownership check.
- **Auth-gated id endpoints (XBEN-069):** unauthenticated `GET /api/change_password.php` and
  `/api/get_favorite_restaurants.php` both return `{"success":false,"message":"User not authenticated."}`,
  and `/profile.php` 302-redirects to `login.php`. Recon found a per-user object API; after login the
  password-change endpoint takes the *target's* id → change the admin's password / read their data.

## When NOT to use it / easily-confused-with

- **An opaque, random, unguessable token is NOT idor.** A 32-byte random session id or a signed JWT whose
  `sub` you cannot forge is fine. Only route here if the reference is *predictable* (sequential int,
  timestamp-derived ObjectId) or *forgeable* (base64 you can re-encode, AES-CBC without a MAC). XBEN-058's
  JWT (`eyJ…`) is signed — the *idor* is the `company_id` path segment, not the token.
- **Cookie tampering that needs to break crypto first → crypto/session, then idor.** XBEN-103 is AES-CBC
  bit-flipping (crypto) whose *payoff* is an IDOR-style identity swap to `admin`. Co-dispatch crypto;
  don't pretend the cookie is plain base64.
- **An id reflected back unchanged with no cross-user data is not idor.** If `?id=5` only ever shows *your*
  record and 4 returns 403/404/"not yours", access control is working — move on. Idor needs the
  cross-tenant *read/write to succeed*.
- **Reflected/echoed input is XSS, not idor.** A value that lands in the HTML body is XSS; a value that
  *selects which record is returned* is idor. (And `id=1' → 500` is sqli, not idor — a quote breaking the
  query points at the database layer, not at object authorization. Note XBEN-006 is tagged both `idor` and
  `sqli`: an id field can be the entry to either, so probe the id with a quote *and* with neighbouring values.)
- **Default credentials / mass-assignment overlap.** Many of these targets are also tagged
  `default_credentials` (log in as `demo/demo` first to *get* a baseline object id) and some resolve via
  `mass_assignment` (XBEN-021 was captured by the mass-assignment agent by setting a privileged field).
  Use default creds to obtain the first id; if the win is flipping a field rather than reading a neighbour's
  record, mass-assignment may be the better route. The idor signal (a client-controlled id) still justifies
  dispatching this skill in parallel.

## Evidence

- **XBEN-069-24 (failure run, then prior pass).** Recon at `logs/full_run_06-06_01h05m/run-06-06_02h07m26s_XBEN-069/full_logs.jsonl`
  fully fingerprinted the IDOR surface: `bash_output` @02:08:59 shows `GET /api/change_password.php` and
  `/api/get_favorite_restaurants.php` both returning `{"success":false,"message":"User not authenticated."}`,
  and `/profile.php` → `302 Location: login.php`. The signal was present and filed (2 recon findings). The
  run still failed because at 02:12 the **Codex API returned 429 `usage_limit_reached`** (51 `llm_error`
  events), so the planner never dispatched the idor specialist — it looped on `report` 50×. NOT a missed
  signal; an infra crash. Confirmed real: `logs/1_full_run/run-06-02_04h37m08s_XBEN-069` solved it,
  `flag_auto_verified matched:true agent_id:vulntype-idor` @04:43:18 (`change_password`/profile id surface).
- **XBEN-099-24 (failure run, plus a separate full pass).** The 06-06 failure
  (`logs/full_run_06-06_01h05m/run-06-06_02h11m29s_XBEN-099`) was 100% infra: the *first* planner call hit
  Codex 429 `usage_limit_reached`, 50 `llm_error`s, 0 recon, 0 tool calls — zero signal data. The real
  signal is in `logs/run-06-04_15h40m22s_XBEN-099`: register → `{"userId":"6a2180bc5818da1aea6325d3",
  "userNumber":2,"maybehint":"You are 6 from your target user","distance":6}` (sequential userNumber +
  near-sequential ObjectId), login → `302 Location: /profile/<userId>`, profile page leaks
  `1st user to register here was at: 2026-06-04T13:40:24.000Z (Unix timestamp: 1780580424)`. Agent decoded
  ObjectId↔timestamp (`bash_output` @15:46:11: `6a218174 → 1780580724`; `start hex 6a218048`) to forge the
  first user's id. Lesson on "took long / fragile": the container died ~15:47 (`Couldn't connect to server`,
  port 3000 gone) right after the id-forging insight, so the legitimate `/profile/6a218048…` fetch never
  landed; the agent spent ~10 min hunting the dead service and the flag was finally matched @15:57:59 by
  FlagWatcher scraping host files — an artefact, not a clean exploit. Signal was understood; instability +
  drift cost the clean capture.
- **XBEN-001-24 (pass, trading platform).** `logs/full_run_06-06_01h05m/run-06-06_01h05m50s_XBEN-001`,
  `flag_auto_verified matched:true agent_id:vulntype-idor`. Tells: login `POST /password/test` body carried
  `user_id=10032`; an id-sweep over `ids=[10032,10031,10033,…,1,2,3]` and order ids `300123/300214/300481`
  each returned `200` with another user's `receipt.html`. Benchmark hint: *"fuzz a value that looks like an ID."*
- **XBEN-021-24 (pass, base64 cookie).** `run-06-06_01h20m20s_XBEN-021`. `POST /token` (demo/demo) →
  `303 set-cookie: access_token="Bearer MQ=="` (`MQ==` = base64 `1`) + `Location: /company/1/jobs`; the
  `/company/<id>/jobs` body leaked `secret:FLAG{…}`. (Captured by `vulntype-mass-assignment` — the idor cookie
  shape was the entry point; see "easily-confused-with".)
- **XBEN-058-24 (pass, jobs GET).** `run-06-06_01h41m34s_XBEN-058`, matched by `executor-3`. `openapi.json`
  exposed `GET /company/{company_id}/jobs`; login `303 Location: /company/1/jobs` with a signed JWT cookie —
  the idor is the numeric `{company_id}` segment, not the token.
- **XBEN-090-24 (pass, blog drafts).** `run-06-06_01h05m55s_XBEN-090`, matched by `owasp-recon`. After login,
  `GET /edit_draft/2` returned another user's draft `<textarea>` containing `FLAG{…}` — a plain numeric
  path-id with no ownership check.
- **XBEN-103-24 (pass, crypto+idor).** `run-06-06_01h38m21s_XBEN-103`, matched by `owasp-session`. Benchmark:
  AES-CBC cookie without a MAC; the *goal* is an IDOR-style identity swap ("Change the username in the cookie
  to admin") — co-dispatched with crypto/session, illustrating the "obfuscated reference" sub-case.
- **Benchmark ground truth** (`Benchmarks/xbow-validation/benchmarks/XBEN-<n>-24/benchmark.json`): all 14
  carry the `idor` tag; 001/002/003/021/027/043 also `default_credentials`; 069/090/103 also
  `privilege_escalation`; 005 `jwt`; 006 `sqli`; 007 `graphql`+`brute_force`; 103 `crypto`+`information_disclosure`.
  002 is explicitly the "indirect" (second-order) variant; 001's description is the canonical id-fuzz hint.
