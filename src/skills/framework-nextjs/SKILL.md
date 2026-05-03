---
name: framework-nextjs
description: Use when the target is a Next.js application — React-based full-stack framework with Pages Router and App Router, Server Actions, React Server Components (RSC), Edge runtime vs. Node runtime, and middleware-based auth. Covers Next.js-specific attack surface (auth drift between Edge and Node runtimes, middleware bypass via path normalization and `x-middleware-subrequest` header, cache-boundary failures with personalized content in shared cache, RSC flight-data over-disclosure, Server Action authorization gaps and IDOR via action payloads, `next/image` optimizer SSRF via lax `remotePatterns`, NextAuth `callbackUrl` open redirect, ISR / on-demand revalidation abuse, draft / preview mode secret leaks, `__NEXT_DATA__` over-fetching). Reference-only knowledge that vulnerability-class skills consult when reconnaissance fingerprints Next.js.
---

# Next.js

Stack-specific testing knowledge for Next.js applications.

This skill is **reference-only** — it has no `agent_id`. The
planner and active vulnerability-class agents consult it when
reconnaissance fingerprints Next.js (typical signals:
`x-powered-by: Next.js`, `/_next/*` static asset paths, RSC
`?_rsc=` query parameters, `x-nextjs-cache` response headers,
`__NEXT_DATA__` JSON islands).

## Attack Surface

**Routers**:
- App Router (`app/`) and Pages Router (`pages/`) often coexist.
- Route Handlers (`app/api/**`) and API routes (`pages/api/**`).
- Middleware — `middleware.ts` at project root.

**Runtimes**:
- Node.js (full API access).
- Edge (V8 isolates, restricted APIs).

**Rendering & caching**:
- SSR, SSG, ISR, on-demand revalidation.
- RSC (React Server Components) with fetch cache.
- Draft / preview mode.

**Data paths**:
- Server Components, Client Components.
- Server Actions (streamed POST with `Next-Action` header).
- `getServerSideProps`, `getStaticProps`.

**Integrations**:
- NextAuth.js (callbacks, CSRF, callbackUrl).
- `next/image` optimization and remote loaders.

## High-value targets

- Middleware-protected routes (auth, geo, A/B).
- Admin / staff paths, draft / preview content, on-demand
  revalidate endpoints.
- RSC payloads and flight data, streamed responses.
- Image optimizer and custom loaders, `remotePatterns` /
  `domains`.
- NextAuth callbacks (`/api/auth/callback/*`), sign-in providers.
- Edge-only features (bot protection, IP gates) and their Node
  equivalents.

## Reconnaissance

### Route discovery
```javascript
// Browser console — list all routes
console.log(__BUILD_MANIFEST.sortedPages.join('\n'))

// Inspect server-fetched data
JSON.parse(document.getElementById('__NEXT_DATA__').textContent).props.pageProps

// List public environment variables
Object.keys(process.env).filter(k => k.startsWith('NEXT_PUBLIC_'))
```

### Build artifacts
```
GET /_next/static/<buildId>/_buildManifest.js
GET /_next/static/<buildId>/_ssgManifest.js
GET /_next/static/chunks/pages/
GET /_next/static/chunks/app/
```
Chunk filenames map to routes (e.g., `admin.js` → `/admin`).

### Source maps
Check `/_next/static/` for exposed `.map` files revealing route
structure, server-action IDs, and internal functions.

### Client bundle mining
Search `main-*.js` for `pathname:`, `href:`, `__next_route__`,
`serverActions`, API endpoints. Grep for `API_KEY`, `SECRET`,
`TOKEN`, `PASSWORD` to find leaked credentials.

### Server-Action discovery
Inspect Network tab for POST requests with `Next-Action` header.
Extract action IDs from response streams and hydration data.

### Additional leakage
- `/sitemap.xml`, `/robots.txt`, `/sitemap-*.xml` for unintended
  admin / internal / preview paths.
- Client bundles / env for secret paths and preview / admin flags
  (many teams hide routes via UI only).

## Vulnerability classes

### Middleware bypass

**Known techniques**:
- `x-middleware-subrequest` header crafting (CVE-2025-29927 class
  bypass).
- `x-nextjs-data` probing.
- Look for 307 + `x-middleware-rewrite` / `x-nextjs-redirect`
  headers.

**Path normalization**:
```
/api/users
/api/users/
/api//users
/api/./users
```
Middleware may normalize differently than route handlers. Test
double slashes, trailing slashes, dot segments.

**Parameter pollution**:
```
?id=1&id=2
?filter[]=a&filter[]=b
```
Middleware checks first value, handler uses last or array.

### Server Actions
- Invoke actions outside the UI flow with alternate
  content-types.
- Authorization assumed from client state rather than enforced
  server-side.
- IDOR via object references in action payloads.
- Map action IDs from source maps to discover hidden actions.

### RSC & caching

**Cache-boundary failures**:
- User-bound data cached without identity keys (ETag /
  `Set-Cookie` unaware).
- Personalized content served from shared cache / CDN.
- Missing `no-store` on sensitive fetches.

**Flight-data leakage**: inspect streamed RSC payloads for
serialized sensitive fields in props.

**ISR issues**:
- Stale-while-revalidate responses containing user-specific or
  tenant-dependent data.
- Weak secrets in on-demand revalidation endpoint URLs.
- Referer-disclosed tokens or unvalidated hosts triggering
  `revalidatePath` / `revalidateTag`.
- Header-smuggling or method variations to trigger revalidation.

### Authentication

**NextAuth pitfalls**:
- Missing or relaxed `state` / `nonce` / PKCE per provider
  (login CSRF, token mix-up).
- Open redirect in `callbackUrl` or mis-scoped allowed hosts.
- JWT audience / issuer not enforced across routes.
- Cross-service token reuse.
- Session hijacking by forcing callbacks.

**Session boundaries**:
- Different auth enforcement between App Router and Pages
  Router.
- API routes vs. Route Handlers authorization inconsistency.

### Data exposure

**`__NEXT_DATA__` over-fetching**:
Server-fetched data passed to client but not rendered:
- Full user objects when only username is needed.
- Internal IDs, tokens, admin-only fields.
- ORM select-all patterns exposing entire records.
- API responses forwarded without sanitization (metadata,
  cursors, debug info).

**Environment-dependent exposure**:
- Staging / dev accidentally exposes more fields than production.
- Inconsistent serialization logic across environments.

**Props inspection**:
```javascript
// Check for sensitive data in page props
JSON.parse(document.getElementById('__NEXT_DATA__').textContent).props
```
Look for `_metadata`, `_internal`, `__typename` (GraphQL),
nested sensitive objects.

### Image-optimizer SSRF

**Remote patterns**:
- Broad `images.domains` / `remotePatterns` in `next.config.js`.
- Test internal hosts, IPv4 / IPv6 variants, DNS rebinding.

**Custom loaders**:
- Protocol smuggling via redirect chains.
- Cache poisoning via URL-normalization differences affecting
  other users.

### Runtime divergence

**Edge vs. Node**:
- Defenses relying on Node-only modules skipped on Edge.
- Header trust differs (`x-forwarded-*` handling).
- Same route may behave differently across runtimes.

### Client-side

**XSS vectors**:
- `dangerouslySetInnerHTML`.
- Markdown renderers.
- User-controlled `href` / `src` attributes.
- Validate CSP / Trusted Types coverage for SSR / CSR /
  hydration.

**Hydration mismatches**: server vs. client render differences
can enable gadget-based XSS.

### Draft / preview mode
- Secret URLs / cookies enabling preview.
- Preview secrets leaked in client bundles / env.
- Setting preview cookies from subdomains or via open redirects.

## Bypass techniques

- Content-type switching — `application/json` ↔
  `multipart/form-data` ↔ `application/x-www-form-urlencoded`.
- Method override — `_method`, `X-HTTP-Method-Override`, GET on
  endpoints accepting writes.
- Case / param aliasing and query duplication affecting
  middleware vs. handler parsing.
- Cache-key confusion at CDN / proxy (lack of `Vary` on auth
  cookies / headers).

## Workflow

1. **Enumerate** — use `__BUILD_MANIFEST`, source maps, build
   artifacts, sitemap / robots to map all routes.
2. **Runtime matrix** — test each route under Edge and Node
   runtimes.
3. **Role matrix** — test as unauth / user / admin across SSR,
   API routes, Route Handlers, Server Actions.
4. **Cache probing** — verify caching respects identity (strip
   cookies, alter Vary headers, check ETags).
5. **Middleware validation** — test path variants and header
   manipulation for bypass.
6. **Cross-router** — compare authorization between App Router
   and Pages Router paths.

## Validation requirements

- Side-by-side requests showing cross-user / tenant access.
- Cache-boundary-failure proof (response diffs, ETag collisions).
- Server-action invocation outside UI with insufficient auth.
- Middleware bypass with explicit headers showing protected-
  content access.
- Runtime-parity checks (Edge vs. Node inconsistent
  enforcement).
- Discovered routes verified as deployed (200 / 403) — not just
  build artifacts (404).
- Leaked credentials tested with minimal read-only calls; filter
  placeholders.
- `__NEXT_DATA__` exposure — verify cross-user (User A's props
  shouldn't contain User B's PII); confirm exposed fields not in
  DOM.
- Path-normalization bypasses — show differential responses
  (403 vs. 200); redirects don't count.
