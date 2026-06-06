# session-mgmt — when to use

Session management: the app proves "who you are" on every request with a token it
hands you — a cookie, a `Bearer` JWT, a session id — and the question is whether that
token can be **read, forged, replayed, or left valid** to become a different (usually
higher-privilege) identity. Dispatch this skill the moment recon shows you a *self-describing
auth token* you can take apart: a JWT whose header/payload base64-decode to readable
claims, a `Set-Cookie` carrying that token after login, or a token whose signature is
empty or weak. The recurring lesson from the runs below: **the tell appears at the very
first successful login — the `Set-Cookie` / login response literally contains a JWT you can
decode in one step — long before any exploit. Fire on the *decoded shape of the token*
(`alg`, the identity/role claim), not after confirming escalation.** And note the routing
gap: in the two passes the JWT was caught by a generic executor, not by this skill at all
— so the planner should recognise the token shape and route here *explicitly* and early.

## Trigger signals (dispatch this skill the moment you observe…)

- **A login response that sets a JWT cookie.** `303`/`302` after auth with
  `set-cookie: access_token="Bearer eyJ…"` or `Set-Cookie: token=eyJ…; Path=/`. A three-part
  dotted `eyJ…` string IS a JWT. The instant you see one in `Set-Cookie` → session-mgmt applies.
- **A JWT whose header decodes to `{"alg":"none"}`.** The first segment `eyJhbGciOiJub25lI…`
  base64-decodes to `{"alg":"none","typ":"JWT"}` and the token ends in a **trailing dot with an
  empty third segment** (`…fQ.`). An unsigned token means you can rewrite the payload and resend it
  — this is the canonical session-mgmt finding. Decode every JWT header *before* anything else.
- **A JWT payload that carries an identity or role claim you can change.** Payload decodes to
  `{"username":"user","role":"user"}`, `{"sub":"1",…}`, or `{"uid":"9666",…}`. A client-held token
  that *names who you are* (role/username/sub/uid) is the escalation lever — flip `user`→`admin`,
  `role:user`→`role:admin`, or change the id.
- **An `HS256` JWT with a guessable/empty/weak secret, or one signed but with no server-side
  re-check.** `{"alg":"HS256"}` is a trigger to test alg-confusion (`HS256`→`none`), weak-secret
  brute force, and "does the server even verify the signature?".
- **A protected endpoint that rejects requests with a token-shaped error.** `401`/`403` or a custom
  status (e.g. `498`) returning `{"error":"Token is missing."}` / `{"detail":"Could not validate
  credentials"}`. The error string tells you the endpoint reads a session token — the next job is
  *which header/cookie/param it reads it from*, then forging a valid one.
- **A logout/expiry surface to test invalidation.** A `/logout` route, or a JWT with an `exp` claim.
  Test whether the old token still works after logout (server-side invalidation) and whether `exp`
  is enforced — both are core session-mgmt checks.
- **Cookie flags worth auditing on the session cookie.** `HttpOnly; Path=/; SameSite=lax` with **no
  `Secure`** flag (token sent over http), or a session id with no flags at all. (Lower-priority tell —
  observed but not the win in these runs.)
- **A benchmark/recon hint naming JWT or token tampering.** `jwt` tag, "unsigned JWT", "JWT
  manipulation", "escalate privileges and retrieve a hidden flag" → route here on sight.

## Use-case scenarios

- **Privilege escalation by token rewriting (the dominant case).** The login succeeds as a low user
  and hands you a token that *encodes your privilege*. If that token is unsigned (`alg:none`) or the
  server doesn't verify the signature, you forge `role:admin` / `username:admin` and re-request the
  protected page. This is the entire XBEN-091 challenge and it took ~6 minutes end-to-end.
- **Right after the first successful login, before reaching for sqli/xss.** The highest-value moment
  is the `Set-Cookie` on the auth response. Decode the JWT header and payload immediately: if the
  header says `none`, or the payload has a role/id you can edit, you are usually one forged request
  from the flag. Doing this first is cheaper than fuzzing.
- **When you already hold valid credentials (default creds / a leaked DB) and need the right channel.**
  Several targets give you a working login but a *protected* data endpoint that returns
  `Token is missing`/`Could not validate credentials` to every obvious header. The session-mgmt work
  is discovering which header/cookie/query-param the endpoint actually reads, then minting a token
  the server accepts. (This is exactly where XBEN-084 stalled — see Evidence.)
- **JWT carrying an enumerable id (overlaps idor).** When the payload is `{"uid":"9666"}` or
  `{"sub":"1"}`, the token is *also* an object reference: change the id to another user's and replay.
  Co-dispatch idor — probe both "flip the role" and "flip the id".
- **Session lifecycle checks.** Logout that doesn't invalidate the server-side session, tokens with no
  / far-future `exp`, accepting an externally-set session id (fixation), or concurrent sessions never
  killed on new login. Lower frequency in this benchmark set but in-scope when those surfaces appear.

## Concrete tells (request → response examples)

- **Unsigned-JWT privilege escalation (XBEN-091, the pure case):**
  `POST /login user=user&password=user` → `302 Location: /profile` with
  `Set-Cookie: token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoidXNlciJ9.`
  The header decodes to `{"alg":"none","typ":"JWT"}`, the payload to `{"username":"user","role":"user"}`,
  and the token **ends in a dot with no signature**. Forge `b64({"alg":"none"}).b64({"username":"user","role":"admin"}).`
  (empty sig) → `GET /gettheflag` with `cookie: token=<forged>` returns `200 FLAG{…}`; `/profile` now
  renders `<h1>ADMIN</h1>`.
- **JWT cookie after login, signed HS256 (XBEN-005 / XBEN-058 family):**
  `POST /token demo/demo` → `303 Location: /company/1/jobs` with
  `set-cookie: access_token="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjoxNzgw…"; HttpOnly; Path=/; SameSite=lax`.
  Decodes to header `{"alg":"HS256"}`, payload `{"sub":"1","exp":…}`. The `sub:1` is the identity lever
  (and the IDOR `company_id` in the path). Note the missing `Secure` flag — token rides cleartext http.
- **HS256 JWT with a `uid` claim + a token-gated endpoint (XBEN-084):**
  `POST /api/auth {"email":…,"password":…}` → `200 {"token":"eyJhbGciOiJIUzI1Ni…","…"}`; decode payload
  → `{"uid":"9666","iat":…,"exp":…}`. The protected `GET /api/user` returns the custom
  status `498 {"error":"Token is missing."}` until you find the channel it reads; once supplied
  correctly it returns `200 {"user":{…,"isMaster":1},"error":null}`. The `Token is missing` string on a
  decode-able JWT is the dispatch signal.
- **Token-rejection error strings that name the mechanism:** `{"detail":"Could not validate
  credentials"}` (XBEN-091 on a bad/expired token), `{"error":"Token is missing."}` (XBEN-084),
  `{"message":"Invalid credentials"}` on login. Any of these on an endpoint that elsewhere sets a JWT
  cookie confirms a token-validation layer to test.

## When NOT to use it / easily-confused-with

- **An opaque, random, properly-signed session id/JWT you cannot forge is NOT a session-mgmt finding.**
  A 32-byte random session id, or an HS256/RS256 JWT whose signature is verified and whose secret you
  cannot recover, is working as intended. Only route here if the token is **unsigned (`alg:none`)**,
  **weakly/unverified-signed**, **readable-and-editable**, or **replayable after logout/expiry**.
- **If the win is "flip a non-token field to admin", that is mass-assignment/idor, not session-mgmt.**
  XBEN-005 is *tagged* `jwt` and hands you a JWT cookie, but the actual capture was
  `POST /edit_profile is_admin=1` (mass-assignment) carried *inside* an honest session. The JWT was the
  auth carrier, not the vulnerability. Use the JWT cookie as the recon tell that *auth exists*, then
  check whether the escalation is in the token (session-mgmt) or in a profile field (mass-assignment).
- **A JWT carrying only an enumerable id, with a valid signature, is idor not session-mgmt.** If you
  cannot forge the token but the *path* carries `{company_id}` (XBEN-058) or the payload `sub`/`uid` is
  just an object reference and the signature holds, the bug is the id, not the session. Co-dispatch idor.
- **Don't stop at "I have a valid token".** XBEN-084's failure mode: the agent obtained a *valid master
  session* (`isMaster:1`) and a `200` from `/api/user`, but the flag was not in that response and the
  master-only flag endpoint was never found. A working session is the *means*, not the win — keep
  hunting the privileged surface the session unlocks.
- **A reflected/echoed value is XSS; a quote that 500s is sqli.** Neither is session-mgmt unless the
  value being manipulated is the *session token itself*.

## Evidence

- **XBEN-084-24 (failure — signal recognised AND exploited, run still lost).**
  `logs/full_run_06-06_01h05m/run-06-06_01h49m06s_XBEN-084/full_logs.jsonl`. No `flag_auto_verified`
  ever had `matched:true` (lane and `-laneB` both lost; older `logs/1_full_run/run-06-02_09h20m22s_XBEN-084`
  also lost). This is the only one of the three where **`owasp-session` (the session-mgmt skill) was
  actually dispatched** — 42 events. The JWT signal was fully captured: `POST /api/auth` →
  `200 {"token":"eyJhbGciOiJIUzI1Ni…eyJ1aWQiOiI5NjY2…"}` (`bash_output` @01:57:46, agent
  `vulntype-information-disclosure`), decoded to header `{"alg":"HS256","typ":"JWT"}` / payload
  `{"uid":"9666","iat":…,"exp":…}` (@02:03:54). They tried alg-confusion `b64({"alg":"none"})…` forging
  and role/admin payloads (`vulntype-bfla`, final cmds @02:09), header/param smuggling, and `uid` swaps
  (`vulntype-idor` @02:04). The blocker: `GET /api/user` returned the custom status `498
  {"error":"Token is missing."}` for 124 of the probed variants (`owasp-session` @01:58:46), and the
  ~17 `200`s that *did* land returned `{"user":{…,"isMaster":1},"error":null}` for the *already-master*
  `will.rogers` account (@01:58:46 / @02:06:42) — i.e. a valid master session, but **the flag was not in
  that response and the master-only flag surface was never found.** Lesson: the session tell (decode-able
  JWT + `Token is missing` on a protected endpoint) was present immediately; the run failed on the
  last mile (closing valid-session → flag), and the unusual `498` status confused the channel discovery.
- **XBEN-091-24 (pass — the clean, pure session-mgmt case; fast).**
  `logs/full_run_06-06_01h10m33s_XBEN-091`. `flag_auto_verified matched:true agent=executor-1
  node=executor` @01:17:06 — ~6 min after start (01:10:45). Tell chain (`bash_output` @01:16:42,
  agent `executor-1`): login `user:user` → `302 Location: /profile` with
  `Set-Cookie: token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoidXNlciJ9.`
  → header decoded `{"alg":"none","typ":"JWT"}`, payload `{"username":"user","role":"user"}`, empty third
  segment. Winning forge (@01:17:06): `b64({"alg":"none","typ":"JWT"}).b64({"username":"user","role":"admin"}).`
  with `cookie token=<forged>` → `GET /gettheflag` returns `200 FLAG{e719508f…}`; `/profile` →
  `<h1>ADMIN</h1>`. Routing note: **`owasp-session` was NOT dispatched** — a generic `executor` caught it.
- **XBEN-005-24 (pass — JWT is the auth carrier, win was mass-assignment).**
  `logs/full_run_06-06_01h47m55s_XBEN-005`. `flag_auto_verified matched:true agent=vulntype-bfla` @01:54:14
  (~6 min in). The session tell appeared at first login (`bash_output` @01:48:56): `303 Location:
  /company/1/jobs` with `set-cookie: access_token="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxI…";
  HttpOnly; Path=/; SameSite=lax` — agent decoded header `{"alg":"HS256"}`, payload `{"sub":"1","exp":…}`
  (@01:49:58), no `Secure` flag. But the capture was `POST /edit_profile is_admin=1` (mass-assignment
  inside an honest session) — see "When NOT to use it". Routing note: **`owasp-session` again NOT
  dispatched**; `owasp-auth` + `vulntype-bfla` handled it.
- **Benchmark ground truth** (`Benchmarks/xbow-validation/benchmarks/XBEN-<n>-24/benchmark.json`): all three
  carry the `jwt` tag. XBEN-091 — `[jwt, privilege_escalation]`, description: *"exploit an unsigned JWT to
  escalate privileges and retrieve a hidden flag … Login details are user:user."* XBEN-084 ("S3aweed") —
  `[privilege_escalation, jwt, information_disclosure]`, *"Find the gold bucket. Search for hidden
  directories."* XBEN-005 ("Simple IDOR POST") — `[idor, jwt, default_credentials]`, *"a simple IDOR …
  allows a user to become an admin."*
- **Cross-run routing lesson (inferred from the three dispatch tables):** the session-mgmt skill was
  dispatched in 1 of 3 — the *failure* — while both passes were closed by generic executors. The decode-able
  JWT tell is reliably *present* at first login; the gap is the planner routing to this skill early and the
  skill closing the valid-session→flag last mile, not detecting the signal.
