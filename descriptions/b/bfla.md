# bfla — when to use

Broken Function-Level Authorization is about **whether a given role is allowed to call a function at all** — admin actions, privileged mutations, state-changing verbs, hidden endpoints. Dispatch this skill when the question is "should this *caller* be permitted to invoke this *action*?", not "is this caller touching the *right object*?" (that latter question is IDOR).

## Trigger signals (dispatch this skill the moment you observe…)

- **A 401/403 on the UI but a 200 on the raw API call.** If a button is hidden/greyed-out in the front-end but the underlying `POST /api/admin/...` still returns 200 (or 302-to-success), the gate is client-side only → BFLA.
- **Path segments that name a privilege tier:** `/admin`, `/administrator`, `/staff`, `/internal`, `/manage`, `/console`, `/backoffice`, `/superuser`, `/sysadmin`, `/_internal`, `/debug`, `/actuator`, `/api/v*/admin`. The moment recon surfaces any of these, test them with a *low-privilege* (or anonymous) token.
- **Action-verb endpoints:** routes whose name is a privileged operation — `/promote`, `/grant`, `/approve`, `/refund`, `/void`, `/credit`, `/impersonate`, `/sudo`, `/suspend`, `/reactivate`, `/delete`, `/disable-2fa`, `/reset-password`, `/toggle-flag`, `/finalize`, `/publish`. A route literally named after an admin verb that a basic user can reach is a prime BFLA candidate.
- **A `role`, `is_admin`, `isAdmin`, `admin`, `privilege`, `permissions`, `scope`, or `plan` field appearing in a request body, JWT payload, or profile-update endpoint.** If a user-editable mutation accepts a role field → try setting it to `admin`.
- **Identity-bearing headers in flight:** `X-User-Id`, `X-User-Role`, `X-Admin`, `X-Forwarded-User`, `X-Auth-Request-User`, `X-Remote-User`, `X-Org-Id`, `X-Tenant`. If the app sits behind a gateway/proxy that injects these and the backend trusts them, forging them escalates → BFLA via gateway trust.
- **The same path responding differently to different HTTP methods.** GET → 200, but POST/PUT/PATCH/DELETE on the same path → 200 with a state change while only GET was "intended" to be public. Method-confusion is a BFLA sub-class.
- **Inconsistent status codes across transports for the "same" action** — the REST route 403s but the GraphQL mutation or WebSocket event for the same operation succeeds.
- **GraphQL with introspection enabled exposing `Mutation` fields like `updateUserRole`, `deleteUser`, `setAdmin`, `impersonate`, `adminQuery`,** or admin-only types. Per-resolver authz gaps are classic BFLA.
- **Version/alias route shadowing:** both `/api/v1/...` and `/api/v2/...` (or `/admin/v1` vs `/v2/admin`, or `/mobile/...` vs `/web/...`) exist. The legacy/alternate route often skips the newer middleware chain.
- **A "create" action you can do, paired with a "finalize/approve/confirm" action that is supposed to be privileged.** If you can create a job/order/export and then call its finalize endpoint without an authz recheck → BFLA in the batch/job path.
- **`grpcurl`/reflection or an OpenAPI/Swagger doc revealing methods/endpoints with no corresponding UI.** Hidden machinery you can call = candidate.

## Use-case scenarios

- **Multi-role apps.** Any target that has more than one user tier (anonymous → registered → paying → staff → admin) is fertile ground. Build the actor×action matrix and test every higher-privilege action with every lower-privilege token. Most BFLAs are *diagonal* — one specific role × one specific action — so don't stop after the first whole-row check.
- **Admin panels reachable on the same origin.** When the admin console and the user app share a host/API, the only thing standing between a normal user and the admin functions is the authorization check. Probe every admin route with the basic-user session you already hold.
- **Behind an API gateway / reverse proxy / service mesh.** When edge auth and service auth are split, test (a) forging the identity headers the gateway normally injects, and (b) reaching the backend service directly to skip the edge entirely. This is the gateway-vs-service mismatch.
- **GraphQL / gRPC / WebSocket APIs.** These often authenticate the connection/handshake once and then fail to re-check each operation. Emit privileged mutations/methods/events after joining a normal channel.
- **Feature-flagged / beta-gated functionality.** UI hides a feature behind a flag, but the backend endpoint is live. Call it directly.
- **Microservice/internal RPC surfaces** exposed accidentally (an `/internal/*` route, an SSRF-reachable service) where the service assumes the caller was already authorized upstream.
- **Multi-tenant SaaS.** Tenant-admin actions gated only by a subdomain or `X-Tenant`/`org` selector — switch the selector with the same token and try a cross-tenant admin action.

## Concrete tells (request → response examples)

- **UI/API split:**
  `curl -H 'Cookie: session=<basic-user>' -X POST https://t/api/admin/users/42/promote` → `200 {"role":"admin"}` while the front-end never shows the button → BFLA confirmed.
- **Forged gateway header:**
  Baseline `GET /admin/metrics` with a user token → `403`. Add `-H 'X-User-Role: admin'` (or `X-Admin: true`, `X-Forwarded-User: admin`) → `200` → backend trusts edge-injected identity → BFLA.
- **Method confusion:**
  `GET /api/posts/7` → `200` (public). `DELETE /api/posts/7` with a non-author basic token → `204` → state-changing verb missing the role check.
- **Role field in body:**
  `PATCH /api/me {"displayName":"x","role":"admin"}` → response echoes `"role":"admin"` and subsequent admin endpoints now return 200 → mass-assignment-driven vertical escalation.
- **GraphQL resolver gap:**
  `mutation { updateUser(id:"3", role: ADMIN){ id role } }` sent with a basic token → returns `{ "data": { "updateUser": { "role": "ADMIN" } } }` instead of an authorization error → per-field authz missing.
- **Transport drift:**
  `POST /api/refund` over REST → `403`, but the WebSocket event `{"type":"refund","order":"99"}` after a normal handshake → `{"status":"ok"}` → per-message authz not enforced.
- **Legacy route shadow:**
  `/v2/admin/export` → `403`; `/admin/v1/export` (older path) with the same token → `200` → alternate route skips the new middleware.
- **Job finalize:**
  Create an export job as a basic user (allowed) → then `POST /jobs/<other-users-job-id>/finalize` → `200` → finalize path doesn't re-check the actor.

The unifying confirmation: a **lower-privileged principal successfully invokes a restricted action**, the action produces a **durable state change** (verify before/after, audit log, or authoritative read), and **removing the client-side gate doesn't change the backend outcome**.

## When NOT to use it / easily-confused-with

- **IDOR (object-level), not BFLA.** If a user *is* allowed to call the function but can point it at *someone else's object* by swapping an id (`GET /api/invoices/1002` reading another tenant's invoice), that is IDOR. BFLA is "this user can't call this function at all." When the hypothesis is broken authorization, dispatch **both** `bfla` and `idor` — many real bugs chain a missing action check with a missing object check — but file them as distinct classes; don't conflate.
- **Authentication bypass, not authorization.** If there is *no* valid session at all and you're forging/bypassing login, replaying tokens, or exploiting a broken JWT signature, that's an authn problem; BFLA assumes you hold a *legitimate but lower-privileged* session and are reaching past its permitted actions. (A forged identity *header* trusted by a backend is BFLA; a forged/cracked *token* is authn.)
- **A reflected/echoed value is not escalation.** A `role` field merely echoed back in a response without the backend honoring it on a privileged endpoint is not a finding. The escalation must be *exercised* — prove a previously-403 admin action now succeeds.
- **Intentionally public endpoints.** Read-only routes that look "admin-ish" but are documented as public, or beta features deliberately open to all roles, are false positives. Rule them out before reporting.
- **Stubbed/simulated admin endpoints with no side effects** (common in lab/CTF builds) — a 200 with no durable state change isn't a real BFLA.
- **Rate-limit / quota / payment gates** that block on business logic rather than role are not BFLA unless the gate is the *authorization* boundary being crossed.

Return: B:bfla done

