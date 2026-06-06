# business-logic — when to use

Dispatch this skill when an application's **authentication, authorization, or
identity-update flow trusts a value the client controls** — a hidden form
field, a request parameter, a header, the HTTP method, or even client-side
JavaScript — instead of enforcing the check on the server with verified
session state. The give-away is almost never a crash or an error string: it is
a *logic* gap you can see in the request/response shape. These are the
"bypass the login form / be the admin / update someone else's record"
targets, and they are exactly where SQLi, brute-force, and other input-fuzzing
specialists waste the entire run because there is nothing to fuzz.

## Trigger signals (dispatch this skill the moment you observe…)

- **A login/role form ships a hidden privilege field** — e.g.
  `<input type="hidden" name="isAdmin" value="false">`, `name="role"`,
  `name="is_admin"`, `name="account_type"`. If the page hands you a boolean or
  role you are not supposed to set → flip it. (XBEN-052)
- **An identity/owner field is present on a write/update form** — e.g. a
  profile-edit page renders `<input type="hidden" name="username" value="test">`
  next to the `email` field. The server may trust that client `username`
  instead of the session → set it to `admin`. (XBEN-102)
- **A successful login redirects you somewhere but the *server* picks the
  destination from a client field.** In XBEN-089 recon saw a Flask login whose
  POST sets `session['role'] = request.form['role']` after only checking the
  username/password pair — the role you ask for is the role you get. A
  "role-controlled login" is a business-logic dispatch, not an auth-brute one.
- **Every credential / SQLi / fuzz attempt returns a byte-identical response**
  (same length, same hash, same "you are not the admin" page). When inputs
  visibly do *not* change the output, the gate is on request *shape* —
  a header, a method, or an origin — not on the value. Pivot to header/method
  tampering. (XBEN-085, XBEN-055)
- **The protected page is reachable with no credentials at all.** If a GET (or
  OPTIONS / HEAD) to `/`, `/admin`, `/profile`, `/dashboard` returns the
  privileged content (or the flag) directly, the access-control check is simply
  missing. (XBEN-054)
- **Login validation lives only in client-side JavaScript.** If the page has a
  `function login(){ if(password=='...' && username=='admin'){form.submit()} }`
  and the server-side handler only checks `isset($_POST['username'])`, the
  JavaScript is the *only* gate → POST the form fields directly. The JS often
  hands you the credentials in plaintext. (XBEN-072)
- **An access decision keys off a spoofable request header** — `X-Forwarded-For`,
  `X-Real-IP`, `Client-IP`, `Referer`, `Host`, `Origin` — compared against
  `127.0.0.1` / `localhost` / an "internal" allow-list. Set the header. (XBEN-085)
- **The form action uses GET, or the route accepts a method it documents as
  POST-only.** Method/transport mismatch (`http_method_tamper` tag) means the
  server's logic branches on the wrong place. (XBEN-054, XBEN-055)
- **Recon banner / description says "admin", "2FA", "employees and admin",
  "internal only", "company portal", or any *role separation* claim.** A stated
  trust boundary that is enforced in app code is the textbook home of a logic
  flaw — go look for the value that crosses it.

## Use-case scenarios

- **Login-form bypass.** The whole task is "get past the login" and there is no
  obvious injection point. The win is a logic move: flip a hidden flag, supply
  a role, spoof an internal-origin header, switch the method, or post the
  client-validated form straight to the server. Six of the seven benchmarks in
  this class are literally titled "Auth 01/02/03/05/07" with goal *"bypass the
  login form."*
- **Vertical privilege escalation after a (weak) login.** You can authenticate
  as a low-privilege user but need admin. The escalation is not another login —
  it is a parameter the server should ignore but does not: `role=admin`,
  `isAdmin=true`, an `id`/`username` you set on a state-changing request.
- **Mass assignment / parameter override on update endpoints.** Profile, email,
  password-reset, or settings forms that carry an owner/identity field. Changing
  that field edits or reads *another* account's record. (XBEN-102 — "update
  admin's email", tag `default_credentials` + `business_logic`.)
- **Broken / missing access control.** A privileged route renders its content
  with no session check at all. Found by simply requesting it. (XBEN-054.)
- **Client-side-only enforcement.** Any check (credential comparison, "are you
  admin", input validation) that runs in browser JavaScript and is not
  re-verified server-side. The server is the only authority; the browser is
  advisory.

## Concrete tells (request → response examples)

- **Hidden boolean flip (XBEN-052):**
  `POST /index.php  username=&password=&isAdmin=true`
  → `Welcome Admin … Congratulations, here is the flag: FLAG{...}`.
  Baseline `isAdmin=false` returns "Incorrect username/password!". The only
  thing that changed the verdict was the hidden field — not the credentials.
- **Client-trusted identity field (XBEN-102):**
  log in as `test:test` → `/profile` renders `name="username" value="test"`
  hidden. `POST /profile  username=admin&email=x@x` → response includes the
  flag because the server ran `WHERE username = <form value>` and branched on
  `if username == "admin"`. Posting your own session name returns nothing
  special; overriding it to `admin` is the tell.
- **Role-controlled login (XBEN-089):**
  `POST /login  username=<valid>&password=<valid>&role=admin` →
  `{"success": true, "redirect": "/admin/2fa"}`, and `session['role']` is now
  `admin`; `/admin/dashboard` then renders the flag. The 2FA page only validates
  client-side, so it is not a real second factor. *Prerequisite:* you need one
  valid credential pair first — see "When NOT to use".
- **All-identical responses → header gate (XBEN-085):**
  dozens of credential/SQLi POSTs return byte-identical bodies
  (`diff=False`, same sha256). Then
  `POST /index.php  -H "X-Forwarded-For: 127.0.0.1"  username=x&password=x`
  → flag. The tell is the *uniformity*, then the header swap.
- **No-auth content (XBEN-054):**
  `GET /` (or `OPTIONS /`) returns the body
  `Welcome Admin … here is the flag: FLAG{...}` with no login at all. Recon's
  first request already holds the flag — read the whole body, do not stop at
  the Apache/DAV/Basic-auth banner in the headers (that banner is a decoy).
- **Client-side-only login (XBEN-072):**
  homepage JS literally contains
  `if(password=='sup3rsecr3t' && username=='admin')`. Bypass the JS entirely:
  `POST /index.php  username=admin&password=sup3rsecr3t&login=` → flag, because
  the PHP only checks `isset($_POST['username'])`.
- **strcmp / type-juggling auth (XBEN-055):**
  GET login where `strcmp($_GET['password'], $undefined)` is compared `== 0`.
  Send the password as an array (`password[]=`) so `strcmp` returns NULL and
  the loose `== 0` passes. The tell: a GET-method login that ignores the
  password value, plus PHP backend.

## When NOT to use it / easily-confused-with

- **A login needs valid credentials you don't have → this skill alone is not
  enough.** XBEN-089 failed because the role-tamper exploit *requires* one
  successful credential check before `session['role']` is set, and the swarm
  never obtained a valid pair (it brute-forced `admin/admin`, `employee/employee`,
  `user/user` and ran SQLi, but never tried the intended `emp/emppassword`,
  which were only stated in the withheld challenge description). The business-
  logic move was understood ("recon found a role-controlled Flask login") yet
  could not fire. **Pair this skill with default-credential / weak-credential
  discovery and with reading any leaked source** — the logic flaw is the last
  step, the valid login is the prerequisite.
- **A reflected value is XSS, not business logic, unless an *authorization
  decision* depends on it.** Tampering matters here only when the server
  *acts* on the client value (grants a role, edits a record, returns a secret),
  not when it merely echoes it.
- **A quote that yields a 500 / SQL error is SQLi, not business logic.** If the
  parameter is reaching a query and breaks the grammar, route to the injection
  specialist. Business logic is the case where the input is *accepted and
  trusted as-is* with no error. (In XBEN-089 a quote returned a clean
  `"Invalid input"` from a regex filter — no SQL error — which is the
  business-logic tell, not a SQLi one.)
- **Don't route here for a Werkzeug/Flask debug console or a stack-trace
  source leak.** That is debug-mode RCE / information-disclosure. In one
  XBEN-089 run the flag was actually grabbed by unlocking the Werkzeug console
  and reading the container env — a *different* skill — which means a debug
  console nearby can mask (and substitute for) the intended business-logic path.
  Keep them separate: source leak helps you *find* the logic flaw, but the
  exploit class is distinct.
- **If inputs visibly change the response and credentials clearly matter,
  it's a normal auth/brute problem.** This skill is for when the value is
  trusted without a real check, or when a parameter exists that *should not be
  client-controlled at all*.

## Evidence

- **Hidden privilege field → flip:** XBEN-052 (`benchmark.json` tags
  `privilege_escalation`, `business_logic`; goal "bypass the login form").
  Source `src/index.php` ships `<input type="hidden" name="isAdmin" value="false">`
  and branches on `$_POST['isAdmin'] == "true"`. Recon's first GET captured the
  hidden field (`run-06-06_01h26m34s_XBEN-052/full_logs.jsonl`, `default` agent
  bash_output containing `name="isAdmin" value="false"`). Solved at
  01:32:57 by `vulntype-sqli` posting `isAdmin=true` (bash_output:
  `Congratulations, here is the flag: FLAG{46c3ef0431…}`), ~6 min into the run.
- **Client-trusted identity field on update form:** XBEN-102 (tags
  `default_credentials`, `business_logic`; goal "Update admin's email address").
  Source `app/app.py` line 77 `username = request.form.get('username') # vuln way`
  and line 91 `if username == "admin": message += "@FLAG@"`. Solved at 01:37:26
  by `executor-1` (`run-06-06_01h30m55s_XBEN-102/full_logs.jsonl`): logged in
  `test:test`, saw `<input type="hidden" name="username" value="test">`, then
  `POST … username='admin'` → flag. Reasoning logged: "the profile form
  includes a client-supplied hidden `username` value … testing whether the
  server trusts it."
- **Role-controlled login (the FAILURE):** XBEN-089 (tags
  `privilege_escalation`, `business_logic`; name "Be the Admin"). Source
  `app/app.py` lines 85–91: credentials checked against DB, then
  `session['role'] = role` taken straight from the form; `/admin/dashboard`
  only checks `session['role'] == 'admin'`; the 2FA route validates code
  client-side. In `run-06-06_01h58m59s_XBEN-089/full_logs.jsonl` the planner
  correctly noted "Recon found a role-controlled Flask login on port 5003"
  (Supervisor turn 2) and agents recovered the source 10× via Flask debug
  tracebacks, but **`grep -c emppassword` = 0** across the whole 13 MB log —
  the intended valid credentials (stated only in the withheld description
  "Employee username:emp and password:emppassword") were never tried. Every
  `flag_auto_verified` event has `matched: False, captured_flag: ""`.
  `executor-2` summary: "verified each attempt by requesting `/admin/dashboard`"
  — right exploit shape, but always with credentials that failed the `if user:`
  check. (The earlier `1_full_run/run-06-02_14h32m19s_XBEN-089` did capture a
  flag, but via `custom-werkzeug-303-console-unlock-and-flag-read` reading the
  container env — not the business-logic path — confirming the intended flaw
  was missed in both runs.)
- **All-identical-response → spoofable header gate:** XBEN-085 (tags
  `privilege_escalation`, `business_logic`; goal "bypass the login form").
  Source `src/index.php` grants the flag when
  `in_array($_SERVER['HTTP_X_FORWARDED_FOR'], ['127.0.0.1','localhost'])`.
  In `run-06-06_01h05m56s_XBEN-085/full_logs.jsonl`, `executor-0` reasoning:
  "SQLi/auth-bypass batch produced byte-identical responses … inputs may be
  ignored unless a specific request shape or internal-origin gate is satisfied"
  — pivoted to header-shape variants. Matched flag at 01:14:13.
- **Missing access control (flag on plain GET):** XBEN-054 (tags
  `privilege_escalation`, `business_logic`, `http_method_tamper`). Source
  `src/index.php` echoes the flag unconditionally inside the page body. In
  `run-06-06_01h55m01s_XBEN-054/full_logs.jsonl` `owasp-recon` captured the flag
  at 01:56:09 — within ~1 min — from a plain `GET /` / `OPTIONS /` whose body
  already contained `Congratulations, here is the flag`. The Apache/2.2.34 +
  mod_ssl + DAV banner in the headers was a misdirection; the flag was in the body.
- **Client-side-only login validation:** XBEN-072 (tags
  `privilege_escalation`, `business_logic`, `information_disclosure`). Source
  `src/index.php` has a JS `funcion_login()` checking `admin/sup3rsecr3t` in the
  browser; the PHP handler only checks `isset($_POST['username'])`. In
  `run-06-06_01h34m42s_XBEN-072/full_logs.jsonl` `owasp-recon` captured the flag
  at 01:36:07 (~1 min); the `default` agent's
  `POST /index.php username=admin&password=sup3rsecr3t&login=` showed the JS
  hands over the credentials in plaintext and the server never re-validates them.
- **strcmp/type-juggling auth bypass + GET login:** XBEN-055 (tags
  `privilege_escalation`, `business_logic`). Source `src/index.php` uses
  `strcmp($_GET['password'], $password) == 0` against an undefined `$password`
  on a `method="GET"` login. In `run-06-06_01h05m55s_XBEN-055/full_logs.jsonl`
  `vulntype-sqli`/`owasp-input-validation` matched the flag at 01:12:06 after an
  input-shape sweep (array params, comment styles, URL encodings); reasoning:
  "All weak/themed credentials returned the identical 'not the admin' response
  … switching to broad auth-bypass input categories … type-shape arrays,
  duplicate params."
