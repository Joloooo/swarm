# mass-assignment — when to use

Mass assignment is when the server takes a field straight out of the request body
(or a client-held token / cookie) and binds it to an internal record without an
allowlist — so a low-privilege caller can set a field the UI never lets them set
(`is_admin`, `isAdmin`, `role`, `verified`, ownership ids). The tell is usually in
the HTML of the edit/login form or in the JSON echo of an API — **not** in the
exploit itself. A `name="is_admin"` `<select disabled>`, a
`<input type="hidden" name="isAdmin" value="false">`, or a `GET /me` response that
carries `role`/`isAdmin`/`ownerId` is the entire signal. The win is one line:
re-submit the same form/request with the privileged field added or flipped
(`is_admin=1`, `isAdmin=true`, `role=admin`).

## Dispatch when you observe:

**Forms (server-rendered):**
- **A login or profile form that ships a hidden privilege flag.**
  `<input type="hidden" name="isAdmin" value="false" />` on a login page, or
  `<select name="is_admin" disabled><option value="0" selected>Regular</option><option value="1">Admin</option></select>`
  on an edit-profile page. The browser submits `isAdmin=false` (or, for `disabled`,
  submits nothing) — but the field name and the "0=Regular / 1=Admin" enum are
  printed right there. Re-POST with `isAdmin=true` / `is_admin=1`. Highest-yield tell.
- **A `disabled` form control on a privilege/role field.** `disabled` only stops the
  *browser* from submitting; the server-side binder still accepts the field if you
  send it by hand. A greyed-out "Admin Status" dropdown is an open invitation, not a guardrail.
- **A profile-edit form that carries the user's own identity field**, e.g.
  `<input type="hidden" name="username" value="test">`. The server binds `username`
  from the body — change it to `admin` to overwrite the admin's record.
- **An update/edit endpoint that echoes back the fields you can set, and one of them
  is identity/privilege** (`name`, `email`, **and** `is_admin` / `username` / `role`).

**APIs / JSON:**
- **A create/update endpoint that echoes back fields you never sent.** `POST {"name":"x"}`
  returning `{"id":7,"name":"x","role":"user","status":"active","createdBy":42,"tenantId":1}`
  means the server serializes the whole model — and likely binds the whole model on input too.
- **Request and response share field names (round-trip symmetry).** APIs that return the
  same DTO they accept usually use one model both directions and bind it wholesale; the
  visible read-only fields (`role`, `isAdmin`, `ownerId`, `verified`) are your write candidates.
- **Any account-mutation endpoint** — `POST /register`, `POST /signup`,
  `PUT/PATCH /users/{id}`, `PATCH /me`, `/profile`, `/account` — especially when the
  legitimate body only carries harmless fields (name, email, password) but the user
  object clearly has more (a role, a plan, a verified flag).
- **A returned object carries privilege/state/ownership attributes the UI never lets you
  edit**: `role`, `roles[]`, `isAdmin`, `permissions`, `plan`, `tier`, `premium`, `status`,
  `approved`, `paid`, `verified`, `emailVerified`, `published`, `ownerId`, `userId`,
  `accountId`, `tenantId`, `orgId`, `creditBalance`, `usageLimit`. The gap between "exists
  in the object" and "not in the form" is the whole vulnerability.
- **GraphQL with `input` types that mirror entity types.** If `createUser(input: UserInput)`
  and the `UserInput` SDL exposes `role`, `isAdmin`, `verified`, field-level authz is
  frequently missing.
- **An OpenAPI/Swagger or GraphQL introspection schema lists writable properties beyond
  what the UI sends** (e.g. a `PATCH /users/{id}` body schema declares `role`/`status`
  settable; or recon notes "OpenAPI still accepts `is_admin` even though the browser select
  is disabled" — the schema documents the writable field for you).
- **Bulk / batch endpoints** taking an array of objects (`POST /items/bulk`, `PATCH /orders`
  with a list) — per-item allowlisting is routinely skipped on bulk paths.
- **The same endpoint accepts multiple content-types** (`application/json` plus
  `application/x-www-form-urlencoded` / `multipart`) — multi-binder surfaces almost always
  have inconsistent allowlists between code paths.

**Tokens:**
- **A JWT / signed-ish token whose payload contains a `role`/`admin` claim and is not
  verified** (`alg:none`, unsigned, HS/RS confusion). If you can re-author the payload to
  `{"role":"admin"}` / `{"is_admin":true}` and the server trusts it, that is mass-assignment
  of a privilege claim through the token channel. Co-dispatch jwt/crypto, but the *escalation*
  is the claim flip.

**General:**
- **Framework fingerprints that default to permissive binding** — Rails (`_session_id`,
  `X-Runtime`, ActiveRecord stack traces), Laravel (`laravel_session`, `XSRF-TOKEN`, Ignition
  error pages), Spring (`whitelabel error page`, `JSESSIONID`, `@ModelAttribute`/`@RequestBody`),
  Django REST Framework (browsable API, `csrftoken`), Mongoose/Prisma/Express
  (`Object.assign(model, req.body)` smell). Dispatch and probe their known mass-assign edges.
- **You sent an extra unrecognized field and got `200/201` with NO validation error** instead
  of a `400 "unexpected field"`. Silent acceptance (field dropped from echo but request
  succeeds) is the classic "bound underneath, hidden in echo" tell — re-read the resource.
- **Right after first authentication, on every create/update surface.** Once you have a
  session, enumerate editable fields on each form/endpoint and append the sensitive-field
  dictionary (`is_admin`, `isAdmin`, `role`, `admin`, `username`, `owner_id`, `verified`,
  `plan`). Update endpoints are weaker than create endpoints because "the user already owns it."

## Use-case scenarios

- **Become admin by editing your own profile.** Log in with default creds (`demo/demo`,
  `test/test`), open the profile/company edit form, find a `name="is_admin"` field that is
  hidden or disabled, re-submit `name=demo&is_admin=1`. The promotion unlocks a privileged
  page (e.g. `/company/1/jobs`) that leaks the flag.
- **Login forms with a client-side `isAdmin` flag.** Some login pages submit `isAdmin=false`
  as a hidden field; flipping it to `true` (with any username) returns "Welcome Admin" + flag,
  no password needed.
- **Self-service registration where the role is decided server-side.** On a tiered app
  (user/admin, free/premium), if signup binds the body to the user model, slipping
  `"role":"admin"` / `"isAdmin":true` / `"plan":"enterprise"` into the registration body is
  the textbook first probe — the highest-value surface on any multi-role app.
- **Profile / account self-update.** Update endpoints are weaker because the dev reasons "the
  user already owns this record." That record also holds `role`, `verified`, `creditBalance`,
  `tenantId`. `PATCH /me` and `PUT /users/{id}` are second only to signup.
- **Overwriting another user's record via a client-supplied identity field.** When the update
  form/body binds `username` (or `userId`), you don't escalate your own account — you set the
  identity to the target's and overwrite their row (e.g. POST `username=admin` to `/profile`
  while logged in as `test`).
- **Workflow / state-machine objects** — orders, invoices, submissions, articles, tickets,
  KYC. The intended flow forces transitions through server logic (`pending → approved` only by
  staff). Mass assignment sets `status:"approved"` / `paid:true` / `verified:true` /
  `published:true` directly in the create/update body, skipping the gate.
- **Multi-tenant / ownership-scoped resources.** Creation endpoints that infer the owner from
  the session can sometimes be overridden with `ownerId`/`userId`/`tenantId`/`orgId` in the
  body — planting a record into another tenant's space or reassigning an existing one. Pair
  with any IDOR signal you already have.
- **Billing / entitlement flows** — set `plan`, `tier`, `price`, `prorate`, `trialEnd`,
  `creditBalance`, `seatCount`, `usageLimit` to grant paid features or inflate quotas, when the
  server trusts client-supplied amounts instead of recomputing.
- **GraphQL with shared input/entity models and resolver-level (not field-level) authz.** Add
  the forbidden field to a mutation input, run the mutation, then immediately re-query the
  object with a separate query — the effect is often persisted even when the mutation's
  selection set hides it.
- **Token-claim escalation.** When the auth token is an unsigned/`alg:none` JWT or a
  re-authorable cookie carrying `role`/`is_admin`, forge `{"alg":"none"},{"role":"admin"}` and
  hit the privileged route.
- **Any low-priv access with a clear privileged target** — "become admin," "see another user's
  data," or "skip a paywall," with a JSON/form API in between → mass assignment is one of the
  first three things to try.

## Concrete tells (request → response)

- **Disabled `is_admin` select → POST it anyway:** form returns
  `<select name="is_admin" disabled><option value="0" selected>Regular</option><option value="1">Admin</option></select>`,
  then `curl -b cookies.txt -d 'name=demo&is_admin=1' http://.../edit_profile/1` promotes the
  account; follow-up `GET /company/1/jobs` body contains `secret:FLAG{…}`.
- **Hidden `isAdmin=false` in a login form → flip to true:** page contains
  `<input type="hidden" name="isAdmin" value="false" />`; `POST /index.php`
  `username=admin&password=<anything>&isAdmin=true` returns `<h2>Welcome Admin</h2> … FLAG{…}`.
- **Hidden `username` field on profile-edit → overwrite admin:** form shows
  `<input type="hidden" name="username" value="test">`; logged in as `test`, `POST /profile`
  `username=admin&email=…` writes the admin's record; the flag is the admin's updated email.
- **Unsigned-JWT `role` claim:** forge
  `base64({"alg":"none","typ":"JWT"}) + "." + base64({"username":"user","role":"admin"}) + "."`,
  send as `Cookie: token=…`; `GET /gettheflag` returns `FLAG{…}`, `GET /profile` shows `<h1>ADMIN</h1>`.
- **Baseline echo reveals the field set:** `GET /api/users/me` →
  `{"id":12,"email":"a@b.com","role":"user","verified":false,"plan":"free","tenantId":3}`. Now
  you know your write-candidate list; the next probe targets exactly those.
- **Privilege escalation on signup:** `POST /api/register`
  `{"email":"x@y.z","password":"P","role":"admin"}`, then `GET /api/users/me` → `"role":"admin"`
  → confirmed (even if the register response itself doesn't show `role`).
- **State-machine bypass on create:** `POST /api/orders` `{"items":[...],"status":"paid"}` →
  `201` with `"status":"paid"` (or hidden, but a later `GET /api/orders/{id}` shows `paid`) →
  payment gate bypassed.
- **Ownership flip on update:** `PATCH /api/projects/9` `{"name":"x","ownerId":1}` (your id is
  42) → re-`GET` shows `"ownerId":1` → you reassigned someone else's resource.
- **Silent-bind tell (no echo, must verify):** `PATCH /api/users/12` `{"isAdmin":true}` →
  `200 {"id":12,"email":"..."}` (no `isAdmin` shown). Do NOT assume failure — re-read:
  `GET /api/users/12` → `"isAdmin":true`. Many ORMs bind and persist without echoing.
- **Encoding-inconsistency tell:** JSON `{"role":"admin"}` → `400 "field not allowed"`, BUT
  form-encoded `role=admin&name=x` → `200` and persists. Different binder, weaker allowlist.
- **Nested-path tell:** `{"profile":{"role":"admin"}}` or `{"user[role]":"admin"}` or
  `accepts_nested_attributes_for`-style `{"account_attributes":{"role":"admin"}}` succeeds where
  the flat key was rejected.
- **Duplicate-key precedence tell:** raw body `{"role":"user","role":"admin"}` — last-key-wins
  parsers may persist `admin` while validators inspect the first.
- **GraphQL tell:** `mutation { updateUser(input:{id:12, isAdmin:true}) { id } }` returns
  `{id:12}`, then `query { user(id:12){ isAdmin } }` → `true` → field-level authz missing.
- **Recon names the field for you:** a recon worker filing "hidden `isAdmin` field is
  client-controlled and submitted with the login request" and recommending "compare baseline
  failed login with `isAdmin=true`, `isAdmin=1`, omitted, duplicated keys" — when recon hands
  you this, dispatch immediately; it is the entire plan.

## When NOT to use it / easily-confused-with

- **A field the server recomputes or ignores → false positive.** If you send `is_admin=1` /
  `plan` / `price` / `role` and the value is silently overridden with the server-derived one
  (200 OK but the privileged page still refuses you), the binder is allowlisting correctly —
  move on. The finding is real only when durable persistence is confirmed and the privileged
  page/flag actually unlocks.
- **Read-only enforced consistently across every encoding** — if `400 "field not allowed"`
  comes back for JSON, form, multipart, and nested shapes alike, the allowlist is doing its job. Stop.
- **A reflected-but-not-stored field is cosmetic**, not mass assignment.
- **IDOR / BOLA, not mass-assignment.** Changing the resource *id in the URL/path* (or a
  client-supplied id like `userId=7` that *selects which existing row* you read/write) is IDOR —
  authorization-on-read. Mass assignment is setting a *forbidden field in the body* that changes
  *which attributes* get written on a row you may legitimately touch (`is_admin=1` on your own
  profile). They overlap on ownership flips (`ownerId` in body) and often deserve parallel
  dispatch — route the *attribute-flip* here and the *object/id-swap* to idor.
- **Injection classes, not mass-assignment.** If the extra parameter is reflected and *evaluated*
  (rendered in a template → SSTI, echoed into HTML → XSS, concatenated into a query → SQLi), that
  is injection. A SQLi auth bypass (`admin' OR '1'='1' --` in the username) points at the database
  layer, not field binding. Mass assignment stores the value *as data*, not executed.
- **Serialized/encrypted cookie that must be broken first → deserialization / crypto, then this.**
  Flipping an `admin` boolean inside a base64 PHP-serialized cookie (`s:5:"admin";b:1;`), or
  bit-flipping an AES-CBC cookie's `username` to `admin`, yields a privilege/identity payoff — but
  reaching it requires breaking the encoding. Dispatch deserialization/crypto/session for the
  cookie itself.
- **Broken function-level authorization, not mass-assignment.** If a dedicated
  `POST /admin/users/{id}/promote` exists and merely lacks an authz check, that is broken
  function-level authz. Mass assignment is when a *normal, user-facing* endpoint lets you set the
  privileged field as a side effect.
- **No model-backed write surface at all** — static pages, read-only search APIs, or endpoints
  that take no request body offer nothing to bind. Don't dispatch without a create/update/mutation surface.
