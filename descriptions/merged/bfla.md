# bfla — when to use

Broken Function-Level Authorization (BFLA): a *caller* invokes an action they are not entitled to, and the server never re-checks the caller's role before performing it. The question is "should this *caller* be permitted to invoke this *action*?" — admin actions, privileged mutations, state-changing verbs, hidden endpoints — **not** "is this caller touching the *right object*?" (that latter is IDOR). This is the access-control class behind the `privilege_escalation` tag whenever escalation comes from **trusting a client-supplied identity or reaching a privileged route**, rather than from injecting a query. When the working hypothesis is broken authorization, dispatch this alongside `idor` (object-level); the two share the same tells and real bugs often chain a missing action check with a missing object check.

## Trigger signals (dispatch the moment you observe…)

- **A privileged endpoint that only checks "authenticated," not "authorized for THIS role/object."** A low-privilege or even unauthenticated request to an admin/owner-only action returns `{"success":false,"message":"User not authenticated."}` at **HTTP 200** (not 401/403) → the route is *reachable* and the guard is "are you logged in," not "are you allowed." Authenticate as any low-priv user and re-fire it.
- **A 401/403 on the UI but a 200 on the raw API call.** A button is hidden/greyed-out in the front-end but the underlying `POST /api/admin/...` still returns 200 (or 302-to-success) → the gate is client-side only.
- **Authorization enforced only in client-side JavaScript.** The login/"admin" gate is a JS function (e.g. `if (password=='…' && username=='admin') form.submit()`) and the server accepts the same POST without re-checking → replay the request directly.
- **Path segments that name a privilege tier:** `/admin`, `/administrator`, `/staff`, `/internal`, `/manage`, `/console`, `/backoffice`, `/superuser`, `/sysadmin`, `/_internal`, `/debug`, `/actuator`, `/api/v*/admin`. The moment recon surfaces any of these, test them with a low-privilege (or anonymous) token.
- **Action-verb endpoints:** routes named after a privileged operation — `/promote`, `/grant`, `/approve`, `/refund`, `/void`, `/credit`, `/impersonate`, `/sudo`, `/suspend`, `/reactivate`, `/delete`, `/disable-2fa`, `/reset-password`, `/toggle-flag`, `/finalize`, `/publish`. A route named after an admin verb that a basic user can reach is a prime candidate.
- **A role/identity carried in a client-controlled token or cookie.** A JWT you can set to `{"alg":"none", …, "role":"admin"}`, or a flipped username in an unauthenticated AES-CBC cookie, and a privileged route then returns 200 + privileged content → the action trusts the claim instead of the server-side role.
- **A `role`, `is_admin`, `isAdmin`, `admin`, `privilege`, `permissions`, `scope`, or `plan` field appearing in a request body, JWT payload, or profile-update endpoint.** If a user-editable mutation accepts a role field → set it to `admin`.
- **Identity-bearing headers in flight:** `X-User-Id`, `X-User-Role`, `X-Admin`, `X-Forwarded-User`, `X-Auth-Request-User`, `X-Remote-User`, `X-Org-Id`, `X-Tenant`. If a gateway/proxy injects these and the backend trusts them, forging them escalates (gateway-trust BFLA).
- **A role baked into the URL/path or built server-side from a client value.** Recon shows the app routing by role — e.g. `/` → `302 Location: /employee/login`, distinct `/admin/login` and `/admin/dashboard`, and a login error that splits tiers ("Invalid credentials. If you are admin go to admin login"). A source/debug leak showing the server builds the path from a client value (e.g. `redirect('/'.join(['', role, 'login']))`) confirms `role` is user-influenceable and routes to privileged areas → reach the admin function with the low-tier session.
- **A method-scoped access guard.** `GET /` returns `401 Authorization Required` + `WWW-Authenticate: Basic realm=…` on old Apache with `DAV/2`/`<Limit GET POST>`-style config → a different verb (PUT/PROPFIND/DELETE/etc.) may fall outside the guard. Test every verb on every guarded route.
- **The same path responding differently to different HTTP methods.** GET → 200 (intended-public), but POST/PUT/PATCH/DELETE on the same path → 200 with a state change. Method confusion is a BFLA sub-class.
- **Inconsistent status across transports for the "same" action** — the REST route 403s but the GraphQL mutation or WebSocket event for the same operation succeeds.
- **GraphQL with introspection exposing `Mutation` fields like `updateUserRole`, `deleteUser`, `setAdmin`, `impersonate`, `adminQuery`,** or admin-only types. Per-resolver authz gaps are classic BFLA.
- **Version/alias route shadowing:** both `/api/v1/...` and `/api/v2/...` (or `/admin/v1` vs `/v2/admin`, `/mobile/...` vs `/web/...`) exist — the legacy/alternate route often skips the newer middleware chain.
- **A "create" action you can do, paired with a "finalize/approve/confirm" action that should be privileged.** Create a job/order/export, then call its finalize endpoint without an authz recheck.
- **A page returning a restricted banner** ("Access Restricted to Internal Employees only") to a low-priv or anonymous caller → there is a role gate; probe whether the underlying action re-checks it.
- **Sequential object id in a per-user action route.** Your own resource is `/edit_draft/2`; `/edit_draft/1` returns HTTP 200 with another user's content (no redirect to login) → the action does not bind the row to the caller. (This is the BFLA+IDOR overlap — dispatch both.)
- **Hidden machinery with no UI** — endpoints found via gobuster, JS bundles, `grpcurl`/reflection, or an OpenAPI/Swagger doc (e.g. `/gettheflag`, `/admin/dashboard`, `/api/change_password.php`). Enumerate them and test each with a low-priv identity.

## Use-case scenarios

- **Vertical privilege escalation ("become admin").** When the path to admin is *reaching a privileged route or presenting a privileged identity* — not breaking the login query — this skill owns it. Build a role matrix (anonymous, user/employee, admin), list each tier's allowed actions, then fire every higher-tier action with a lower-tier session. Most BFLAs are *diagonal* (one specific role × one specific action) — don't stop after the first whole-row check.
- **Per-object actions with a guessable reference.** Edit/view/delete/password-change endpoints that take an `id` in path or body and only verify "logged in." BFLA+IDOR overlap: the *action* check is missing (bfla) and the *object* check is missing (idor) — dispatch both.
- **Token/cookie/header-driven role.** Privilege decided by a field inside a JWT, a signed/encrypted cookie, or a custom header the backend trusts. Forge the claim and replay against the privileged route.
- **Admin panels on the same origin.** When admin console and user app share a host/API, the only barrier is the authorization check. Probe every admin route with the basic-user session you already hold.
- **Behind an API gateway / reverse proxy / service mesh.** Edge auth and service auth are split: (a) forge the identity headers the gateway normally injects, and (b) reach the backend service directly to skip the edge.
- **GraphQL / gRPC / WebSocket APIs.** These often authenticate the connection/handshake once then fail to re-check each operation. Emit privileged mutations/methods/events after joining a normal channel.
- **Method / transport / client-gate drift.** A route enforces auth for one verb but not another, only in the browser, or differs across UI vs raw API. Re-issue the request on the unguarded path.
- **Feature-flagged / beta-gated functionality.** UI hides a feature behind a flag, but the backend endpoint is live — call it directly.
- **Microservice/internal RPC surfaces** accidentally exposed (an `/internal/*` route, an SSRF-reachable service) where the service assumes the caller was already authorized upstream.
- **Multi-tenant SaaS.** Tenant-admin actions gated only by a subdomain or `X-Tenant`/`org` selector — switch the selector with the same token and try a cross-tenant admin action.

## Concrete tells (request → response examples)

- **Reachable privileged action, weak guard:** `GET /api/change_password.php` → `HTTP 200 {"success":false,"message":"User not authenticated."}`. The endpoint answers everyone; it gates on a session, not on owning the target account. Next: log in low-priv, POST it with another user's id.
- **UI/API split:** `curl -H 'Cookie: session=<basic-user>' -X POST https://t/api/admin/users/42/promote` → `200 {"role":"admin"}` while the front-end never shows the button.
- **Forged role claim accepted (token):** token = `base64url({"alg":"none","typ":"JWT"}).base64url({"username":"user","role":"admin"}).` → `GET /gettheflag` with `Cookie: token=<that>` → `HTTP 200`, body `FLAG{…}`.
- **Forged gateway header:** baseline `GET /admin/metrics` with a user token → `403`; add `-H 'X-User-Role: admin'` (or `X-Admin: true`, `X-Forwarded-User: admin`) → `200`.
- **Sequential object, no owner check:** own draft `/edit_draft/2`; `GET /edit_draft/1` → `HTTP 200`, `Location: None`, returns the other user's draft (containing the flag).
- **Role-routed app, tiered login error:** `GET /` → `302 Location: /employee/login`; `POST /login` (any creds) → `200 "Invalid credentials. If you are admin go to admin login"`; source leak `redirect('/'.join(['', role, 'login']))`.
- **Method-scoped guard:** `GET /` → `401 Authorization Required`, `WWW-Authenticate: Basic realm="…"`, `Server: Apache/2.2.34 (Unix) … DAV/2` → try other verbs outside the `<Limit>` block.
- **Method confusion:** `GET /api/posts/7` → `200` (public); `DELETE /api/posts/7` with a non-author basic token → `204`.
- **Role field in body:** `PATCH /api/me {"displayName":"x","role":"admin"}` → response echoes `"role":"admin"` and subsequent admin endpoints now return 200 (mass-assignment-driven vertical escalation).
- **Client-side-only gate:** page ships `funcion_login(){ if(password=='sup3rsecr3t' && username=='admin') form.submit() }` → the check never runs server-side; POST the form directly.
- **GraphQL resolver gap:** `mutation { updateUser(id:"3", role: ADMIN){ id role } }` with a basic token → `{ "data": { "updateUser": { "role": "ADMIN" } } }` instead of an authz error.
- **Transport drift:** `POST /api/refund` over REST → `403`, but WebSocket event `{"type":"refund","order":"99"}` after a normal handshake → `{"status":"ok"}`.
- **Legacy route shadow:** `/v2/admin/export` → `403`; `/admin/v1/export` (older path) with the same token → `200`.
- **Job finalize:** create an export job as a basic user (allowed) → `POST /jobs/<other-users-job-id>/finalize` → `200`.

The unifying confirmation: a **lower-privileged principal successfully invokes a restricted action**, the action produces a **durable state change** (verify before/after, audit log, or authoritative read), and **removing the client-side gate doesn't change the backend outcome**.

## When NOT to use it / easily confused with

- **IDOR (object-level), not BFLA.** If a user *is* allowed to call the function but can point it at someone else's object by swapping an id (`GET /api/invoices/1002` reading another tenant's invoice), that is IDOR. BFLA = "this user can't call this *action* at all." Since they co-occur, dispatch both when the hypothesis is broken authorization, but file them as distinct classes.
- **Authentication bypass, not authorization.** If there is no valid session and you're forging/bypassing login, replaying tokens, or exploiting a broken JWT signature, that's authn. BFLA assumes you hold a *legitimate but lower-privileged* session. Distinction: a forged identity *header* trusted by a backend is BFLA; a forged/cracked *token* is authn.
- **Login bypass via SQL injection is `sqli`.** A `privilege_escalation` goal ("login as admin") where the win is `' OR 1=1-- ` in username/password is an injection into the auth query → route to `sqli`. Tell: a quote producing a 500/SQL error, not a reachable privileged route. A `privilege_escalation` goal is **not** automatically bfla.
- **Cookie/JWT bugs that are really crypto** (forging a signature, AES-CBC bit-flipping, hash collisions) pull `crypto`/`jwt`/session skills to *produce* the forged token; bfla is the reason it works (the action trusts the claim).
- **Information disclosure / open storage** (e.g. an exposed S3 bucket listing) is `information-disclosure`; it becomes bfla only if a leaked credential/token then lets a low-priv caller invoke a privileged action.
- **A reflected/echoed value is not escalation.** A `role` field merely echoed back without the backend honoring it on a privileged endpoint is not a finding — the escalation must be *exercised* (prove a previously-403 admin action now succeeds).
- **Intentionally public endpoints / stubbed admin endpoints.** Read-only routes that look "admin-ish" but are documented public, beta features deliberately open to all roles, or lab/CTF stubs returning 200 with no durable state change are false positives — rule them out before reporting.
- **Rate-limit / quota / payment gates** that block on business logic rather than role are not BFLA unless that gate is the authorization boundary being crossed.
- **A 401/403 that holds across *every* verb, session, and forged claim** is correctly-enforced authz, not a finding. The signal is *inconsistency*: the same action allowed via one path/identity/verb and denied via another.
