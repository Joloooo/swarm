# idor — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A user-controlled identifier in a URL path or query that maps to a stored record** — `/account/4012`, `/api/orders/88231`, `?invoice_id=506`, `/profile?uid=17`. If the value looks like a database row, dispatch this skill to swap it.
- **Sequential or low-entropy numeric IDs** — you see `id=1003` and the next request after creating an object gives `id=1004`. Predictable increments are the single strongest tell that object-level checks are the only thing standing between you and other rows.
- **The same resource returns 200 with full content when you change only the ID, with no re-auth** — you flip `userId=100` to `userId=101` while keeping your own session/token, and you get back data that isn't yours.
- **A leaked-but-unguessable ID actually works** — a UUID/ULID/slug you harvested from a list, search, export, email, or JS bundle returns 200 when fetched directly under your own session. Unpredictable ≠ protected.
- **Status differential between "your" object and a "foreign" object** — your ID gives `200`, a neighbouring ID gives `403`/`404` but a *different* neighbouring ID gives `200` again. Inconsistent enforcement across the ID space screams missing per-row authorization.
- **Object references inside JSON bodies / form fields the UI doesn't expose** — `{"ownerId":...}`, `{"account_id":...}`, `{"tenantId":...}`, `parentId`, `projectId`, `subscriptionId` sitting in PUT/PATCH/POST payloads.
- **Tenant/org scoping carried in a header or path the client sets** — `X-Tenant-ID`, `X-Organization-Id`, `X-User-Id`, org subdomain, `/org/{slug}/...`. If the client supplies the scope, you can probably change it.
- **GraphQL with `node(id:)` / `user(id:)` field arguments, or Relay `base64("Type:rawId")` global IDs** — decode, increment rawId, re-encode, refetch. Resolver-level auth is commonly missing.
- **Batch / bulk endpoints** — `POST /bulk-delete {"ids":[...]}`, multi-record imports. Validators frequently check only the first element; slip a foreign ID into the middle of the array.
- **Job/export/report handles** — `export/{jobId}/download`, `reports/{taskId}`, `/files/{key}`. These are often fetched by ID with no ownership binding.
- **A list/search/export endpoint that returns IDs belonging to other principals** — even before exploitation, that is your ID corpus and a direct lead into this skill.

## Use-case scenarios

- **Authenticated multi-account apps** where each user owns records (orders, messages, invoices, documents, profiles). The classic surface: you have one valid session and an object reference, you want to read or mutate someone else's object. This is the core IDOR/BOLA case and the right move whenever the target requires login and exposes per-record endpoints.
- **REST / JSON APIs with CRUD-shaped routes** — `GET/PUT/PATCH/DELETE /api/<resource>/{id}`. Test every verb, not just GET: a PATCH that silently rewrites `/owner_id` or `/role` on someone else's record is a high-impact write-side IDOR even when reads are locked down.
- **Multi-tenant / B2B SaaS** — workspaces, organizations, projects. Cross-tenant access is the most severe form (CRITICAL): mix the org of your token with a resource ID from another org and watch whether isolation holds. Aggregated admin/analytics/rollup views are prime targets.
- **GraphQL backends** — per-root auth that doesn't repeat at field/edge resolvers, alias batching to pull many users' nodes in one request, persisted queries that skip later hardening, introspection exposing every `id`-argument type.
- **Microservice/gateway architectures** — token confusion (a JWT minted for service A accepted by service B with no `aud` check), gateway-injected identity headers (`X-User-Id`) the backend trusts blindly, async workers that re-process without re-authorizing.
- **File / object storage** — direct object keys, weakly scoped S3/GCS signed URLs, share tokens reusable across tenants. Try key-prefix swaps and replaying another tenant's share token.
- **Mass-assignment-adjacent surfaces** — when a create/update accepts a JSON body, the same skill covers injecting privileged or foreign-owned fields (`role`, `is_admin`, `owner_id`) the UI never shows.

## Concrete tells (request → response examples)

- **Horizontal read:**
  `GET /api/users/1001/profile` (your account, session cookie A) → `200 {"email":"you@x.com"}`.
  `GET /api/users/1002/profile` (same cookie A) → `200 {"email":"victim@x.com"}` ← **confirmed IDOR**. The win is content that isn't yours returned under your own session.

- **Vertical / privileged variant:**
  `GET /api/users/myinfo` ignores any `id`, but `GET /api/admins/myinfo?id=1002` returns the target → the admin/parallel endpoint accepts a parameter the user endpoint dropped.

- **Write-side (silent mutation):**
  `PATCH /api/orders/501 {"status":"refunded"}` with cookie A, where order 501 belongs to user B → `200 {"status":"refunded"}` and a follow-up GET confirms the change → missing object-level check on the write path.

- **Leaked-UUID binding test:**
  list endpoint returns `{"id":"a3f2-...-9c","name":"Other Co"}`. `GET /api/documents/a3f2-...-9c` under your session → `200` with the document body → unpredictability gave a false sense of security; binding is absent.

- **Status differential (blind / masked content):**
  `HEAD /api/files/9000` → `404`; `HEAD /api/files/9001` → `200` with an `ETag` and `Content-Length`, while you only own `9001`'s neighbours → existence side-channel even when bodies are redacted.

- **Tenant boundary:**
  `GET /api/reports/77 -H "X-Tenant-ID: 42"` (your tenant) → `200`; change to `-H "X-Tenant-ID: 43"` keeping the same token → `200` with tenant 43's data → cross-tenant CRITICAL.

- **GraphQL Relay:**
  decode `node(id:"VXNlcjo0NTY=")` → `User:456`, re-encode `User:457` → `node(id:"VXNlcjo0NTc=")` returns `{email, billing{last4}}` for user 457.

## When NOT to use it / easily-confused-with

- **The identifier is reflected into the page/response but not used to look up a record** → that is likely **XSS** (if rendered) or path/parameter handling, not IDOR. IDOR requires the ID to dereference a *stored object on the server*.
- **The ID feeds a backend resource fetch the server controls (URL, host, file path the app reads)** → that's **SSRF** or **path traversal / LFI**, not IDOR. IDOR is about *which authorized object you get*, not about making the server reach a new location. (A traversal segment used purely to confuse the auth router, e.g. `delete/MY_ID/../VICTIM_ID`, is still IDOR; reading arbitrary server files via `../../etc/passwd` is traversal.)
- **The endpoint is genuinely public/anonymous by design** (public profiles, published blog posts, shared marketing assets) → returning another ID's content is expected, not a vulnerability. Rule this out before reporting.
- **The action requires no specific object — it's a privileged *function* the role shouldn't be able to call at all** (`POST /admin/wipe-db`, `GET /admin/all-users` with no per-record id) → that is **function-level authorization (BFLA)**, dispatch `bfla`. Many real bugs need both, so pair them when the hypothesis is "broken authorization"; but a pure missing-action-gate with no object reference is not this skill alone.
- **Changing the ID returns a uniform `403`/`404`/empty across the whole ID space, including IDs you know exist** → access control is holding; do not keep hammering as IDOR. Move on or pivot to auth-bypass / token-tampering classes.
- **The "other" data is the same idempotent public metadata for everyone** (e.g. a currency lookup, a feature-flag list) → no sensitive cross-account exposure, false positive.
- **You have no session and the target is single-user or fully anonymous** → IDOR generally needs at least one valid principal (ideally two) to demonstrate owner-vs-non-owner; with zero accounts and no leaked IDs there's nothing to bind against.

B:idor done

