# mass-assignment — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A create/update endpoint that echoes back fields you never sent.** If you `POST {"name":"x"}` and the response contains `{"id":7,"name":"x","role":"user","status":"active","createdBy":42,"tenantId":1,...}`, the server is serializing the whole model — and is a prime candidate for binding the whole model on input too → dispatch.
- **Request body and response body have the same field names (round-trip symmetry).** APIs that return the same DTO they accept usually use one model for both directions and bind it wholesale. The visible read-only fields (`role`, `isAdmin`, `ownerId`, `verified`) are your candidate write list → dispatch.
- **Any account-mutation endpoint** — `POST /register`, `POST /signup`, `PUT/PATCH /users/{id}`, `PATCH /me`, `/profile`, `/account` — especially when the legitimate body only contains harmless fields (name, email, password) but the user object clearly has more (a role, a plan, a verified flag) → dispatch.
- **A returned object carries privilege/state/ownership attributes the UI never lets you edit** — `role`, `roles[]`, `isAdmin`, `permissions`, `plan`, `tier`, `premium`, `status`, `approved`, `paid`, `verified`, `emailVerified`, `published`, `ownerId`, `userId`, `accountId`, `tenantId`, `orgId`, `creditBalance`, `usageLimit`. The gap between "exists in the object" and "not in the form" is the whole vulnerability → dispatch.
- **GraphQL with `input` types that mirror entity types.** If `createUser(input: UserInput)` and the `UserInput` SDL exposes `role`, `isAdmin`, `verified` etc., field-level authz is frequently missing → dispatch.
- **An OpenAPI/Swagger or GraphQL introspection schema lists writable properties beyond what the UI sends** (e.g. a `PATCH /users/{id}` body schema declares `role` and `status` as settable) → dispatch.
- **Framework fingerprints that default to permissive binding.** Headers/cookies/errors that reveal Rails (`_session_id`, `X-Runtime`, ActiveRecord stack traces), Laravel (`laravel_session`, `XSRF-TOKEN`, Ignition error pages), Spring (`whitelabel error page`, `JSESSIONID`, `@ModelAttribute`/`@RequestBody`), Django REST Framework (browsable API, `csrftoken`), Mongoose/Prisma/Express (Node + JSON, `Object.assign(model, req.body)` smell) → dispatch and probe their known mass-assign edges.
- **You sent an extra unrecognized field and got `200/201` with NO validation error** rather than a `400 "unexpected field"`. Silent acceptance (the field is dropped from the response but the request still succeeds) is the classic "bound underneath, hidden in echo" tell → dispatch and re-read the resource.
- **The same endpoint accepts multiple content-types** (`application/json` and `application/x-www-form-urlencoded`/`multipart`). Multi-binder surfaces almost always have inconsistent allowlists between code paths → dispatch.
- **Bulk / batch endpoints** that take an array of objects (`POST /items/bulk`, `PATCH /orders` with a list). Per-item allowlisting is routinely skipped on bulk paths → dispatch.

## Use-case scenarios

- **Self-service registration where the role is decided server-side.** The app has tiered users (user/admin, free/premium). If signup binds the body to the user model, slipping `"role":"admin"` or `"isAdmin":true` or `"plan":"enterprise"` into the registration body is the textbook first probe. This is the highest-value surface on any multi-role app.
- **Profile / account self-update.** Update endpoints are weaker than create endpoints because the developer reasons "the user already owns this record, so it's safe." That same record holds `role`, `verified`, `creditBalance`, `tenantId` — which the user must NOT set. `PATCH /me` and `PUT /users/{id}` are second only to signup.
- **Workflow / state-machine objects** — orders, invoices, submissions, articles, tickets, KYC records. The intended flow forces transitions through server logic (`pending → approved` only by staff). Mass assignment lets you set `status:"approved"` / `paid:true` / `verified:true` / `published:true` directly in the create or update body, skipping the gate.
- **Multi-tenant / ownership-scoped resources.** Resource-creation endpoints that infer the owner from the session can sometimes be overridden with `ownerId`/`userId`/`tenantId`/`orgId` in the body — letting you plant a record into another tenant's space or reassign an existing one. Pair with any IDOR signal you already have.
- **GraphQL APIs with shared input/entity models and resolver-level (not field-level) authz.** Add the forbidden field to a mutation input, run the mutation, then immediately re-query the object with a separate query — the effect is often persisted even when the mutation's selection set hides it.
- **Billing / entitlement flows** — set `plan`, `tier`, `price`, `prorate`, `trialEnd`, `creditBalance`, `seatCount`, `usageLimit` to grant yourself paid features or inflate quotas, when the server trusts client-supplied amounts instead of recomputing.
- **Apps where you have low-priv access and a clear privileged target.** Whenever the goal is "become admin," "see another user's data," or "skip a paywall," and there is a JSON/form API in between — mass assignment is one of the first three things to try.

## Concrete tells (request → response examples)

- **Baseline echo reveals the field set:**
  - `GET /api/users/me` → `{"id":12,"email":"a@b.com","role":"user","verified":false,"plan":"free","tenantId":3}`
  - Now you know your write-candidate list. The next probe targets exactly those.

- **Privilege escalation on signup:**
  - `POST /api/register` `{"email":"x@y.z","password":"P","role":"admin"}`
  - Then `GET /api/users/me` → `"role":"admin"` → confirmed. (Even if the register response itself doesn't show `role`.)

- **State-machine bypass on create:**
  - `POST /api/orders` `{"items":[...],"status":"paid"}` → `201` with `"status":"paid"` (or status hidden but a later `GET /api/orders/{id}` shows `paid`) → confirmed bypass of the payment gate.

- **Ownership flip on update:**
  - `PATCH /api/projects/9` `{"name":"x","ownerId":1}` (your id is 42) → re-`GET` shows `"ownerId":1` → you reassigned someone else's resource (or planted yours into their scope).

- **Silent-bind tell (no echo, must verify):**
  - `PATCH /api/users/12` `{"isAdmin":true}` → `200 {"id":12,"email":"..."}` (no `isAdmin` field shown). Do NOT assume failure — re-read: `GET /api/users/12` → `"isAdmin":true`. Many ORMs bind and persist without echoing.

- **Encoding-inconsistency tell:**
  - JSON `{"role":"admin"}` → `400 "field not allowed"`, BUT form-encoded `role=admin&name=x` → `200` and persists. Different binder, weaker allowlist.

- **Nested-path tell:**
  - `{"profile":{"role":"admin"}}` or `{"user[role]":"admin"}` or `accepts_nested_attributes_for`-style `{"account_attributes":{"role":"admin"}}` succeeds where the flat key was rejected.

- **Duplicate-key precedence tell:**
  - Raw body `{"role":"user","role":"admin"}` — last-key-wins parsers may persist `admin` while validators inspect the first.

- **GraphQL tell:**
  - `mutation { updateUser(input:{id:12, isAdmin:true}) { id } }` returns `{id:12}`, then `query { user(id:12){ isAdmin } }` → `true` → field-level authz missing on the input type.

## When NOT to use it / easily-confused-with

- **Server ignores or recomputes the field → not a finding (and don't keep this skill on it).** If `plan`/`price`/`role` is derived server-side and your injected value is silently overridden with the correct one, it's a false positive. Confirm durable persistence, not just a 200.
- **Read-only enforced consistently across every encoding** — if `400 "field not allowed"` comes back for JSON, form, multipart, and nested shapes alike, the allowlist is doing its job. Stop.
- **The injected value only changes the UI/response shape with no persisted effect** — a reflected-but-not-stored field is cosmetic, not mass assignment.
- **Confused with IDOR/BOLA:** changing the resource *id in the URL/path* to access another object is IDOR — that is authorization-on-read. Mass assignment is about setting a *forbidden field in the body*. They overlap on ownership flips (`ownerId` in body) but route to the right skill: URL-id tampering → IDOR; body-field smuggling → here.
- **Confused with parameter pollution / general injection:** if the extra parameter is reflected and *evaluated* (rendered in a template → SSTI, echoed into HTML → XSS, concatenated into a query → SQLi), that is an injection class, not mass assignment. Mass assignment is specifically *unauthorized binding of a trusted attribute into a persisted model* — the value is stored as-data, not executed.
- **Confused with privilege escalation via broken access control on a dedicated admin endpoint:** if a `POST /admin/users/{id}/promote` exists and is simply missing an authz check, that is broken function-level authorization, not mass assignment. Mass assignment is when a *normal, user-facing* endpoint lets you set the privileged field as a side effect.
- **No model-backed write surface at all** — purely static pages, read-only search APIs, or endpoints that take no request body offer nothing to bind. Don't dispatch here without a create/update/mutation surface.

B:mass-assignment done

