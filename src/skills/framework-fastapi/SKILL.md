---
name: framework-fastapi
description: Use when the target is a FastAPI / Starlette application — Python ASGI stack with dependency injection, Pydantic validation, and async middleware. Covers FastAPI-specific attack surface (`Depends` vs `Security` scope confusion, OpenAPI / `/docs` / `/redoc` exposure, Pydantic `extra="allow"` mass-assignment, alias and union-type validation bypass, middleware ordering gaps, ProxyHeadersMiddleware / TrustedHostMiddleware misuse, mounted sub-apps that bypass global middleware, WebSocket / SSE auth drift, BackgroundTasks queueing, Jinja2Templates SSTI). Reference-only knowledge that vulnerability-class skills consult when reconnaissance fingerprints FastAPI.
---

# FastAPI

Stack-specific testing knowledge for FastAPI / Starlette
applications.

This skill is **reference-only** — it has no `agent_id`. The
planner and active vulnerability-class agents consult it when
reconnaissance fingerprints FastAPI / Starlette in the response
stack (typical signals: `server: uvicorn`, `/docs`, `/redoc`,
`/openapi.json`, Pydantic-style 422 validation errors).

## Attack Surface

**Core components**:
- ASGI middlewares — CORS, TrustedHost, ProxyHeaders, Session,
  exception handlers, lifespan events.
- Routers and sub-apps — `APIRouter` prefixes / tags, mounted apps
  (StaticFiles, admin), `include_router`, versioned paths.
- Dependency injection — `Depends`, `Security`,
  `OAuth2PasswordBearer`, `HTTPBearer`, scopes.

**Data handling**:
- Pydantic models — v1 / v2, unions / `Annotated`, custom
  validators, extra-fields policy, coercion.
- File operations — `UploadFile`, `File`, `FileResponse`,
  `StaticFiles` mounts.
- Templates — `Jinja2Templates` rendering.

**Channels**:
- HTTP (sync / async), WebSocket, SSE / `StreamingResponse`.
- `BackgroundTasks` and task queues.

**Deployment**: Uvicorn / Gunicorn, reverse proxies / CDN, TLS
termination, header trust.

## High-value targets

- `/openapi.json`, `/docs`, `/redoc` in production — full
  attack-surface map, securitySchemes, server URLs.
- Auth flows — token endpoints, session / cookie bridges, OAuth
  device / PKCE.
- Admin / staff routers, feature-flagged routes,
  `include_in_schema=False` endpoints.
- File upload / download, import / export / report endpoints,
  signed-URL generators.
- WebSocket endpoints — notifications, admin channels, commands.
- Background-job endpoints — `/jobs/{id}`, `/tasks/{id}/result`.
- Mounted subapps — admin UI, storage browsers, metrics / health.

## Reconnaissance

### OpenAPI mining
```
GET /openapi.json
GET /docs
GET /redoc
GET /api/openapi.json
GET /internal/openapi.json
```

Extract — paths, parameters, securitySchemes, scopes, servers.
Endpoints with `include_in_schema=False` won't appear; fuzz based
on discovered prefixes and common admin / debug names.

### Dependency mapping

For each route, identify:
- Router-level dependencies (applied to all routes).
- Route-level dependencies (per endpoint).
- Which dependencies enforce auth vs. just parse input.

## Vulnerability classes

### Authentication & authorization

**Dependency-injection gaps**:
- Routes missing security dependencies present on other routes.
- `Depends` used instead of `Security` — ignores scope
  enforcement.
- Token presence treated as authentication without signature
  verification.
- `OAuth2PasswordBearer` only yields a token string — verify
  routes don't treat presence as auth.

**JWT misuse**:
- Decode without verify — test unsigned tokens, attacker-signed
  tokens.
- Algorithm confusion — HS256 / RS256 cross-use if not pinned.
- `kid` header injection for custom key-lookup paths.
- Missing issuer / audience validation, cross-service token
  reuse.

**Session weaknesses**:
- `SessionMiddleware` with weak `secret_key`.
- Session fixation via predictable signing.
- Cookie-based auth without CSRF protection.

**OAuth / OIDC** — device / PKCE flows must enforce strict PKCE
S256 and `state` / `nonce`.

### Access control

**IDOR via dependencies**:
- Object IDs in path / query not validated against caller.
- Tenant headers trusted without binding to authenticated user.
- `BackgroundTasks` acting on IDs without re-validating ownership
  at execution time.
- Export / import pipelines with IDOR and cross-tenant leaks.

**Scope bypass**:
- Minimal scope satisfaction — any valid token accepted.
- Router vs. route scope enforcement inconsistency.

### Input handling

**Pydantic exploitation**:
- Type coercion — strings to ints / bools, empty strings to
  `None`, truthiness edge cases.
- Extra fields — `extra = "allow"` permits injecting control
  fields (`role`, `ownerId`, `scope`).
- Union types and `Annotated` — craft shapes hitting unintended
  validation branches.

**Content-type switching**:
```
application/json ↔ application/x-www-form-urlencoded ↔ multipart/form-data
```
Different content-types hit different validators or code paths
(parser differentials).

**Parameter manipulation**:
- Case variations in header / cookie names.
- Duplicate parameters exploiting DI precedence.
- Method override via `X-HTTP-Method-Override` (upstream respects,
  app doesn't).

### CORS & CSRF
- Overly broad `allow_origin_regex`.
- Origin reflection without validation.
- Credentialed requests with permissive origins.
- Verify preflight vs. actual-request deltas.
- FastAPI / Starlette has **no built-in CSRF** — cookie-based auth
  without origin validation is a common gap.
- Missing `SameSite` attribute.

### Proxy & host trust
- `ProxyHeadersMiddleware` without network boundary — spoof
  `X-Forwarded-For` / `Proto` to influence auth / IP gating.
- Absent `TrustedHostMiddleware` — Host-header poisoning in
  password-reset links and absolute-URL generation.
- Cache-key confusion — missing `Vary` on `Authorization` /
  `Cookie` / tenant.

### Server-side vulnerabilities

**Template injection (Jinja2)**:
```python
{{7*7}}  # arithmetic confirmation
{{cycler.__init__.__globals__['os'].popen('id').read()}}  # RCE
```
Check autoescape settings and custom filters / globals.

**SSRF**:
- User-supplied URLs in imports, previews, webhook validation.
- Test loopback, RFC1918, IPv6, redirects, DNS rebinding, header
  control.
- Library behavior — `httpx` / `requests`: redirect policy,
  header forwarding, protocol support.
- Protocol smuggling — `file://`, `ftp://`, gopher-like shims if
  custom clients.

**File upload**:
- Path traversal in `UploadFile.filename` with control characters.
- Missing storage-root enforcement, symlink following.
- Vary filename encodings, dot segments, NUL-like bytes.
- Verify storage paths and served URLs.

### WebSocket security
- Missing per-connection authentication.
- Cross-origin WebSocket without origin validation.
- Topic / channel IDOR — subscribing to other users' channels.
- Authorization only at handshake, not per-message.

### Mounted sub-apps

Sub-apps at `/admin`, `/static`, `/metrics` may bypass global
middlewares. Verify auth-enforcement parity across all mounts.

### Alternative stacks
- GraphQL (Strawberry / Graphene) mounted — validate
  resolver-level authorization, IDOR on node / global IDs.
- SQLModel / SQLAlchemy present — probe for raw-query usage and
  row-level authorization gaps.

## Bypass techniques

- Content-type switching to traverse alternate validators.
- Parameter duplication and case variants exploiting DI
  precedence.
- Method confusion via proxies (`X-HTTP-Method-Override`).
- Race windows around dependency-validated state transitions —
  issue token then mutate with parallel requests.

## Workflow

1. **Enumerate** — fetch OpenAPI, diff with 404-fuzzing for hidden
   endpoints.
2. **Matrix testing** — test each route across unauth / user /
   admin × HTTP / WebSocket × JSON / form / multipart.
3. **Dependency analysis** — map which dependencies enforce auth
   vs. parse input.
4. **Cross-environment** — compare dev / stage / prod for
   middleware and docs-exposure differences.
5. **Channel consistency** — verify same authorization on HTTP and
   WebSocket for equivalent operations.

## Validation requirements

- Side-by-side requests showing unauthorized access (owner vs.
  non-owner, cross-tenant).
- Cross-channel proof — HTTP and WebSocket for the same rule.
- Header / proxy manipulation showing altered outcomes (Host /
  XFF / CORS).
- Minimal payloads for template injection, SSRF, token misuse with
  safe / OAST oracles.
- Document exact dependency paths (router-level, route-level)
  that missed enforcement.
