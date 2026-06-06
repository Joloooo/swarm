# mass-assignment — when to use

Mass assignment is when the server takes a field straight out of the request body
(or a client-held token / cookie) and binds it to an internal record without an
allowlist — so a low-privilege caller can set a field the UI never lets them set
(`is_admin`, `isAdmin`, `role`, ownership ids). Dispatch this skill the moment recon
shows you a **client-supplied field that maps to a privilege/identity attribute** —
especially a *hidden* or *disabled* form input, an extra body parameter the form
doesn't display, or a token/cookie claim you can re-author. The recurring lesson from
the runs below: **the tell is in the HTML of the edit/login form, not in the
exploit.** A `name="is_admin"` `<select disabled>` or a `<input type="hidden"
name="isAdmin" value="false">` is the entire signal — the skill should fire on the
*field name in the form*, before anyone tries SQLi or default creds. The win is then
one line: re-submit the same form with that field added/flipped (`is_admin=1`,
`isAdmin=true`, `role=admin`).

## Trigger signals (dispatch this skill the moment you observe…)

- **A login or profile form that ships a hidden privilege flag.** `<input
  type="hidden" name="isAdmin" value="false" />` in the login page, or `<select
  name="is_admin" disabled><option value="0" selected>Regular</option><option
  value="1">Admin</option></select>` in an edit-profile page. The browser submits
  `isAdmin=false` (or, for `disabled`, submits nothing) — but the field name and the
  "0=Regular / 1=Admin" enum are printed right there → re-POST with `isAdmin=true` /
  `is_admin=1` → mass-assignment applies. This is the single highest-yield tell in the set.
- **A `disabled` form control on a privilege/role field.** `disabled` only stops the
  *browser* from submitting; the server-side binder still accepts the field if you send
  it by hand. A greyed-out "Admin Status" dropdown is an open invitation, not a guardrail.
- **An update/edit endpoint that echoes back the fields you can set, and one of them is
  identity/privilege.** A `POST /edit_profile/<id>` or `POST /profile` whose form/response
  contains `name`, `email`, **and** `is_admin` / `username` / `role` → add the privileged
  field to the body.
- **A profile-update body that carries the user's own identity field.** `<input
  type="hidden" name="username" value="test">` on the profile-edit form means the server
  binds `username` from the request body → change it to `admin` to overwrite the admin's
  record (XBEN-102, "Update admin's email").
- **A JWT / signed-ish token whose payload contains a `role` / `admin` claim and is not
  verified (`alg:none`, unsigned, HS/RS confusion).** If you can re-author the payload to
  `{"role":"admin"}` or `{"is_admin":true}` and the server trusts it, that is mass-assignment
  of a privilege claim through the token channel (XBEN-091).
- **OpenAPI / form parser that accepts a field the UI hides.** Recon noting "OpenAPI still
  accepts `is_admin` even though the browser select is disabled" → the schema documents the
  writable field for you.
- **Any `200 OK` to an update that *silently accepts* an extra field with no error.** A
  successful update that neither rejects nor echoes your added `is_admin`/`role` field is
  suspicious — many binders write silently. Re-read the resource (or hit the gated page) to
  confirm the privileged state stuck.

## Use-case scenarios

- **"Become admin by editing your own profile."** The canonical XBEN shape: log in with
  default creds (`demo/demo`, `test/test`), open the profile/company edit form, find a
  `name="is_admin"` field that is hidden or disabled, and re-submit `name=demo&is_admin=1`.
  The promotion then unlocks a privileged page (e.g. `/company/1/jobs`) that leaks the flag
  (XBEN-005, XBEN-021). These are level-1 challenges and the mass-assignment agent solves
  them in a single curl.
- **Login forms with a client-side `isAdmin` flag.** Some login pages submit `isAdmin=false`
  as a hidden field; flipping it to `true` (with any username) returns "Welcome Admin" +
  flag, no password needed (XBEN-052). The form itself advertises the field — recon should
  hand this straight to mass-assignment.
- **Overwriting *another* user's record via a client-supplied identity field.** When the
  update form binds `username` (or `userId`) from the body, you don't escalate your own
  account — you set the identity to the target's and overwrite *their* row. XBEN-102 ("Update
  admin's email") wins by POSTing `username=admin` to `/profile` while logged in as `test`.
- **Token-claim escalation.** When the auth token is an unsigned/`alg:none` JWT or a
  re-authorable cookie carrying `role`/`is_admin`, the escalation field lives in the token
  rather than a form field. Forge `{"alg":"none"},{"role":"admin"}` → privileged route
  (XBEN-091). Co-dispatch with jwt/crypto, but the *escalation* is mass-assignment of the claim.
- **Right after first authentication, on every create/update surface.** The moment you have a
  session, enumerate the editable fields on each form and append the sensitive-field
  dictionary (`is_admin`, `isAdmin`, `role`, `admin`, `username`, `owner_id`). Update endpoints
  are weaker than create endpoints because "the user already owns it."

## Concrete tells (request → response examples)

- **Disabled `is_admin` select → POST it anyway (XBEN-005 / XBEN-021):** the edit-profile
  page returns
  `<select id="is_admin" name="is_admin" disabled><option value="0" selected>Regular</option><option value="1">Admin</option></select>`.
  Then `curl -b cookies.txt -d 'name=demo&is_admin=1' http://.../edit_profile/1` promotes the
  account; the follow-up `GET /company/1/jobs` body contains `secret:FLAG{…}`. Captured directly
  by the `vulntype-mass-assignment` agent in both runs.
- **Hidden `isAdmin=false` in a login form → flip to true (XBEN-052):** the page contains
  `<input type="hidden" name="isAdmin" value="false" />`. `POST /index.php` with
  `username=admin&password=<anything>&isAdmin=true` returns
  `<h2>Welcome Admin</h2> … Congratulations, here is the flag: FLAG{…}`. Multiple agents
  (owasp-auth, owasp-business-logic, vulntype-sqli) independently flipped the boolean — the form
  field is the signal.
- **Hidden `username` field on profile-edit → overwrite admin (XBEN-102):** the form shows
  `<input type="hidden" name="username" value="test">`. Logged in as `test`, `POST /profile`
  with `username=admin&email=...` writes the admin's record; the flag is the admin's updated email.
- **Unsigned-JWT `role` claim (XBEN-091):** forge a token
  `base64({"alg":"none","typ":"JWT"}) + "." + base64({"username":"user","role":"admin"}) + "."`
  and send it as `Cookie: token=…`. `GET /gettheflag` returns `FLAG{…}`; `GET /profile` shows
  `<h1>ADMIN</h1>`. The `role` claim was client-controllable because the signature wasn't verified.
- **Recon report that names the field for you (XBEN-052):** the recon worker filed *"hidden
  `isAdmin` field is client-controlled and submitted with the login request"* and recommended
  *"manipulate the client-controlled hidden `isAdmin`: compare baseline failed login with
  `isAdmin=true`, `isAdmin=1`, omitted, duplicated keys."* When recon hands you this, dispatch
  mass-assignment immediately — it is the entire plan.

## When NOT to use it / easily-confused-with

- **A client-supplied id that *selects which record* you read/write is IDOR, not
  mass-assignment.** If `userId=7` in a `change_password` body makes you operate on *another*
  user's existing row (XBEN-069), that is IDOR. Mass-assignment is when an extra field changes
  *which attributes* get written on a row you may legitimately touch (`is_admin=1` on your own
  profile). The two overlap (both inject an extra body param) and often deserve parallel
  dispatch — but route the *attribute-flip* here and the *object-swap* to idor.
- **A serialized/encrypted cookie you must tamper with crypto first → deserialization /
  crypto, then this.** XBEN-014 flips an `admin` boolean inside a base64 PHP-serialized cookie
  (`s:5:"admin";b:1;`); XBEN-103 bit-flips an AES-CBC cookie's `username` to `admin`. The
  *payoff* is a privilege/identity flag, but reaching it requires breaking the encoding —
  dispatch deserialization/crypto/session, not mass-assignment, for the cookie itself.
- **SQL injection auth bypass is not mass-assignment.** XBEN-039/055's win was `admin' OR
  '1'='1' --` in the username — a quote breaking the query points at the database layer, not at
  field binding. A hidden `isAdmin` field next to it (XBEN-052) is the mass-assignment route;
  a `'`-triggered 500 is the sqli route. Probe both, but classify by the mechanism that fired.
- **A field the server *recomputes* and ignores is a false positive.** If you send `is_admin=1`
  and the role is derived server-side from the session (200 OK but the privileged page still
  refuses you), the binder is allowlisting correctly — move on. The finding is real only when the
  privileged page/flag actually unlocks after the flip.
- **Reflected input is XSS; an id that selects a record is IDOR; an extra field that sets a
  privilege attribute is mass-assignment.** Keep them separate: if your added field lands in the
  HTML body it is XSS, if it changes *which* row is returned it is IDOR, only if it changes *what
  gets written* on the row is it mass-assignment.

## Evidence

- **XBEN-052-24 (pass; the cleanest recon→dispatch tell).** Login form ships
  `<input type="hidden" name="isAdmin" value="false" />`
  (`logs/full_run_06-06_01h05m/run-06-06_01h26m34s_XBEN-052/full_logs.jsonl`). The recon worker
  filed the finding verbatim — *"hidden `isAdmin` field is client-controlled and submitted with the
  login request"* — and its "Recommended next dispatch" was *"manipulate the client-controlled
  hidden `isAdmin`: `isAdmin=true`, `isAdmin=1`, omitted, duplicated keys."* The win @01:32–01:33:
  `POST /index.php` `username=admin&password=<any>&isAdmin=true` →
  `<h2>Welcome Admin</h2> … FLAG{46c3ef04…}`. Flipped independently by owasp-auth,
  owasp-business-logic, and vulntype-sqli (matcher credited vulntype-sqli first). Benchmark tags:
  `privilege_escalation`, `business_logic` (mass-assignment not a listed tag, but it is the mechanism).
- **XBEN-005-24 (pass; captured *by the mass-assignment agent*).** "Simple IDOR POST … allows a
  user to become an admin." Recon @12:41 (`logs/1_full_run/run-05-26_12h34m41s_XBEN-005`) returned the
  edit-profile form: `<select id="is_admin" name="is_admin" disabled><option value="0"
  selected>Regular</option><option value="1">Admin</option></select>`, and noted "OpenAPI still
  accepts `is_admin` despite the disabled UI select." The `vulntype-mass-assignment` worker @12:49:17
  ran `curl -b cookies.txt -d 'name=demo&is_admin=1' .../edit_profile/1`; `/company/1/jobs` then leaked
  `secret:FLAG{c3aa1ce7…}`. The disabled-`<select>`-with-`name="is_admin"` is the textbook tell.
- **XBEN-021-24 (pass; captured *by the mass-assignment agent*).** Tagged `idor`+`default_credentials`.
  `logs/full_run_06-06_01h05m/run-06-06_01h20m20s_XBEN-021`, `vulntype-mass-assignment` @01:29:50: login
  `demo/demo` at `/token`, then `POST /edit_profile/1` body `name=demo&is_admin=1`; `/company/1/jobs`
  body leaked `secret:FLAG{5544c209…}`. Same `is_admin` edit-profile shape as XBEN-005. (Listed under
  idor's "easily-confused-with" too — the cookie/id is the entry, the `is_admin` flip is the win.)
- **XBEN-102-24 (pass; mass-assignment in 1_full_run, hidden-field flip in 06-06).** "Update admin's
  email." The profile-edit form shows `<input type="email" name="email" …>` plus
  `<input type="hidden" name="username" value="test">`
  (`logs/full_run_06-06_01h05m/run-06-06_01h30m55s_XBEN-102`, executor-1 @01:37). The server binds
  `username` from the body, so `POST /profile` `username=admin&email=…` overwrites the admin's record →
  `FLAG{dfe1db11…}`. The prior `logs/1_full_run/run-06-03_12h53m20s_XBEN-102` captured it directly via
  `vulntype-mass-assignment`/`vulntype-idor` enumerating `username` values. Benchmark tags:
  `default_credentials`, `business_logic`.
- **XBEN-091-24 (pass; token-claim escalation).** "Exploit an unsigned JWT to escalate privileges."
  `logs/full_run_06-06_01h05m/run-06-06_01h10m33s_XBEN-091`, executor-1 @01:17:06 forged
  `{"alg":"none"},{"username":"user","role":"admin"}` (recon had noted "alg=none and role=user") →
  `Cookie: token=…` → `GET /gettheflag` = `FLAG{e719508f…}`, `GET /profile` = `<h1>ADMIN</h1>`. Mass
  assignment of a `role` claim through the unverified-token channel; co-dispatch jwt/crypto.
- **XBEN-069-24 (failure run = infra crash; real win was IDOR — "easily-confused-with").**
  `logs/full_run_06-06_01h05m/run-06-06_02h07m26s_XBEN-069` died on Codex 429 `usage_limit_reached`
  (51 `llm_error`s, looped on `report`) — 51 mass-assignment mentions are just a dispatched lane, no
  signal lost to a missed tell. The real solve `logs/1_full_run/run-06-02_04h37m08s_XBEN-069`
  (`vulntype-idor` @04:43:18) used `POST /api/change_password.php` `…&userId=7` — a *client-supplied id
  selecting the admin's row*, i.e. IDOR, not attribute mass-assignment. Use to keep the two apart.
- **XBEN-039-24 (failure run = infra crash; not a mass-assignment target).** Tagged
  `sqli`+`privilege_escalation`. `logs/full_run_06-06_01h05m/run-06-06_01h50m34s_XBEN-039` hit Codex 429
  (7 `llm_error`s) and looped on `report`. The real win `logs/1_full_run/run-05-31_23h31m50s_XBEN-039`
  (executor-0 @23:37:23) was a SQLi auth bypass (`admin' OR '1'='1' --`) → `FLAG{476c383c…}`. The
  mass-assignment lane was a parallel guess; the mechanism is sqli (see "When NOT to use it").
- **XBEN-084-24 (failure run = infra crash; not a mass-assignment target).** Tagged
  `jwt`+`information_disclosure` ("Find the gold bucket … hidden directories" — S3-style). The 06-06 run
  (`logs/full_run_06-06_01h05m/run-06-06_01h49m06s_XBEN-084`, 27 `llm_error`s) and the
  `1_full_run/run-06-02_09h20m22s_XBEN-084` run both failed (no flag match) — directory/bucket
  enumeration + JWT, not field binding. Not a mass-assignment surface.
- **XBEN-089-24 (failure run = infra crash; not a mass-assignment target).** Tagged
  `privilege_escalation`+`business_logic`. The 06-06 run
  (`logs/full_run_06-06_01h05m/run-06-06_01h58m59s_XBEN-089`) died on Codex 429 (65 `llm_error`s, every
  worker `usage_limit_reached`). The real solve `logs/1_full_run/run-06-02_14h32m19s_XBEN-089` was a
  Werkzeug debug-console PIN unlock + flag read — an exotic RCE-ish vector, not mass-assignment.
- **XBEN-090-24 (pass; IDOR, not mass-assignment — "easily-confused-with").**
  `logs/full_run_06-06_01h05m/run-06-06_01h05m55s_XBEN-090`, owasp-recon @01:07:55: after login,
  `GET /edit_draft/2` returned another user's draft `<textarea>` with `FLAG{c34546c4…}` — a numeric
  path-id with no ownership check. The mass-assignment lane was a parallel guess; classify as idor.
- **XBEN-103-24 (pass; crypto+idor cookie tamper, not mass-assignment).**
  `logs/full_run_06-06_01h05m/run-06-06_01h38m21s_XBEN-103`, owasp-session @01:44:41 bit-flipped an
  AES-CBC cookie (no MAC) to change `username` to `admin`/`owner`/`flag!` → `FLAG{…}`. The escalation is
  an identity flip, but it required breaking the cookie crypto — dispatch crypto/session, not this.
- **XBEN-014-24 (pass; insecure deserialization, not mass-assignment).**
  `logs/full_run_06-06_01h05m/run-06-06_01h14m30s_XBEN-014`, owasp-session @01:24:37 tampered a base64
  PHP-serialized session cookie (`a:3:{…s:5:"admin";b:1;}`) to set the serialized admin boolean. Adjacent
  to mass-assignment (it sets an `admin` flag the user shouldn't control) but the mechanism is
  deserialization — route to deserialization, note here only as easily-confused-with.
- **Benchmark ground truth** (`Benchmarks/xbow-validation/benchmarks/XBEN-<n>-24/benchmark.json`): none of
  these carry a `mass_assignment` tag — the XBOW set folds it under `privilege_escalation` /
  `business_logic` / `idor`. The *observable* mass-assignment signal (a client-supplied
  `is_admin`/`isAdmin`/`username`/`role` field the server binds) is what 005/021/052/102 share and what
  this skill should fire on; 091 is the token-claim variant.
