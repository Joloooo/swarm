# information-disclosure — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A stack trace, exception page, or traceback in any response body.** If you see Python `Traceback (most recent call last)`, a Java `java.lang.NullPointerException ... at com.app...`, a PHP `Fatal error: ... in /var/www/...`, a .NET yellow-screen-of-death, or a Ruby/Rails error page → dispatch. The app is leaking source paths, framework, and internals.
- **A framework debug page rendered to an unauthenticated client.** Werkzeug interactive debugger ("Werkzeug Debugger", `__debugger__` query param, the "console" PIN prompt), Django `DEBUG=True` page (yellow/orange settings dump with `Request information`, `Settings` table), Laravel Ignition/Whoops error page, Symfony profiler toolbar → dispatch immediately.
- **Verbose / structured error contracts on bad input.** If a malformed request (broken JSON, wrong type, out-of-range value, invalid UUID) returns a 400/422/500 that names internal classes, DB columns, ORM entities, or query fragments → dispatch.
- **SQL error fragments in the body.** `You have an error in your SQL syntax`, `ORA-00933`, `PG::SyntaxError`, `Unclosed quotation mark`, leaked table/column names → dispatch (note: this can ALSO be SQLi — see "easily confused" below).
- **A static-artifact path returns 200 instead of 404.** `/.git/HEAD`, `/.git/config`, `/.env`, `/.svn/entries`, `/composer.json`, `/package.json`, `/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/actuator`, `/actuator/env`, `/debug/pprof/`, `/server-status`, `/metrics`, `/phpinfo.php` → dispatch. A 200 (or even a 403 that proves the file exists) on any of these is the strongest single tell.
- **A `.map` source map served alongside any JS bundle.** If `app.<hash>.js.map` returns 200, or a `//# sourceMappingURL=` comment points to a reachable file → dispatch.
- **Directory listing / autoindex.** Apache "Index of /", nginx autoindex, a folder URL returning an HTML file table → dispatch.
- **Fingerprinting headers.** `Server: Apache/2.4.49`, `X-Powered-By: PHP/7.1.3`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `Via`, `X-Backend`, debug/trace headers (`X-Debug-*`, `X-Request-Id`, `Server-Timing` with internal timings) → dispatch (version → CVE chain).
- **GraphQL introspection or field-suggestion errors.** A `/graphql` endpoint that answers `__schema { types { name } }`, or returns `Did you mean "secretField"?` on a typo → dispatch.
- **Embedded data in HTML/JS.** `__NEXT_DATA__`, `window.__INITIAL_STATE__`, inline JSON with internal IDs/flags/emails, `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*` values that look like secrets → dispatch.
- **Differential responses across identity.** Same resource URL returns different status / Content-Length / ETag / `Last-Modified` for owner vs. non-owner vs. anonymous → dispatch (existence oracle; adjacent to IDOR).
- **Cache headers that ignore auth.** A response with `Cache-Control: public` / a CDN `X-Cache: HIT` / `Age:` header on a page that contains user-specific content → dispatch (cache-key confusion).
- **Permissive CORS.** `Access-Control-Allow-Origin: *` (or reflecting an arbitrary `Origin`) together with `Access-Control-Allow-Credentials: true`, or `Access-Control-Expose-Headers` leaking sensitive headers → dispatch.
- **Backup / temp file naming patterns resolve.** `index.php.bak`, `config.php~`, `.index.php.swp`, `app.zip`, `db.sql`, `*.old`, `*.orig` returning content → dispatch.

## Use-case scenarios

- **Opening recon on any unfamiliar target.** Before crafting payloads, this skill is the cheapest, highest-yield first move: a header sweep + a short artifact wordlist (`.git`, `.env`, source maps, swagger, actuator) often hands you secrets, the framework, and the exact version with zero exploitation. Dispatch it early on *every* engagement.
- **You have an error somewhere but no clear injection.** When inputs cause 500s or noisy errors but you can't yet confirm a sink (SQLi, command injection), use this skill to read the error channel itself for filesystem layout, DB schema, framework version, and internal hosts — that intel directs the next, more targeted attack.
- **A SPA / JS-heavy frontend.** Modern React/Vue/Next/Angular apps ship large bundles. Source maps, embedded build-time env vars, and prefetched JSON (`__NEXT_DATA__`) routinely leak API routes, internal IDs, feature flags, and occasionally credentials. This skill is the right tool to mine the client bundle.
- **A JSON/GraphQL/gRPC API with no human UI.** API-only surfaces frequently leave introspection, OpenAPI docs, or reflection on, and return overly detailed error objects. Dispatch this skill to enumerate the hidden/privileged operations the docs reveal.
- **You suspect tech-stack-specific dev tooling left in prod.** Spring `/actuator/*`, Go `/debug/pprof`, Laravel Telescope, Django debug, Rails console, Prometheus `/metrics`, exposed Kibana/Grafana/Jaeger — when fingerprints point at one of these stacks, this skill chases the matching diagnostic endpoint.
- **You need a version number to pivot to a known CVE.** When the goal is "what exactly is running here", this skill's header/error/bundle sweep produces the precise component+version you map to an exploit.
- **Multi-channel apps (REST + GraphQL + WebSocket + SSR/CSR).** Use this skill to compare hardening across channels — a field hidden in the HTML page is often present in the JSON API or GraphQL schema.

## Concrete tells (request → response examples)

- **`.git` exposure:**
  `GET /.git/HEAD` → `200 OK`, body `ref: refs/heads/main`. Confirms a dumpable repo → reconstruct source + secrets.
- **`.env` exposure:**
  `GET /.env` → `200 OK`, body containing `APP_KEY=`, `DB_PASSWORD=`, `AWS_SECRET_ACCESS_KEY=`. Critical finding.
- **Source map:**
  `GET /static/js/main.4f2a.js.map` → `200 OK`, JSON with `"sources":["webpack:///src/api/admin.ts", ...]`. Reveals original source and hidden endpoints.
- **Werkzeug debug:**
  `GET /nonexistent` → `500`, body contains `Werkzeug Debugger`, a `Traceback`, and a `console` link with `__debugger__=yes`.
- **Django DEBUG:**
  `GET /?x[]=1` (or any 500-trigger) → page titled `... DjangoError`, showing `Request Method`, `Django Version`, `Settings` dump with `SECRET_KEY` partially visible, full traceback with `/app/...` paths.
- **Malformed JSON to an API:**
  `POST /api/users` with body `{` → `500`, body `{"error":"Unexpected token in JSON","stack":"at JSON.parse ... /srv/app/routes/users.js:42"}`.
- **Type mismatch:**
  `GET /api/item?id=abc` (expects int) → `500`, body naming the ORM entity / column, e.g. `invalid input syntax for type integer: "abc"` plus `SELECT ... FROM items WHERE id = $1`.
- **Spring actuator:**
  `GET /actuator/env` → `200`, JSON dumping `spring.datasource.password`, environment variables, system properties.
- **GraphQL introspection:**
  `POST /graphql` body `{"query":"{__schema{types{name}}}"}` → `200`, full type list including `User`, `AdminMutation`, etc.
- **Existence oracle via conditional request:**
  `GET /api/orders/1001` as anon → `401`; `GET /api/orders/999999` as anon → `404`. The differing status reveals which IDs exist.
- **Cache-key confusion:**
  Request `/dashboard` as user A, observe `X-Cache: HIT` and user A's name in the body when requested unauthenticated, or as user B → cross-user content served from cache.
- **Verb probing:**
  `OPTIONS /` → `Allow: GET, POST, TRACE, PROPFIND`; `TRACE /` echoing the request → diagnostic verbs enabled.
- **Backup file:**
  `GET /config.php.bak` → `200`, raw PHP source with DB credentials (not executed because of the `.bak` extension).

## When NOT to use it / easily-confused-with

- **A SQL error you intend to *exploit*, not just read, is SQL injection — not this skill.** If the error fragment is the doorway to extracting data via crafted queries (`' OR 1=1--`, UNION, boolean/time-based), route to the SQL-injection skill. This skill only *harvests* the leaked schema/version as intelligence; it does not drive the injection.
- **A value reflected verbatim in the HTML is XSS, not information disclosure** — and if that reflected value is *evaluated* (`{{7*7}}` → `49`), it is SSTI. Information-disclosure uses `{{7*7}}`/`${7*7}` only to *fingerprint* the template engine via the error/echo, not to achieve code execution. The moment evaluation or script execution is the goal, route elsewhere.
- **Reading another user's record by changing an ID is IDOR/access-control, not this skill.** Differential oracles here only *infer existence/state* from status/length/ETag differences. If you can actually retrieve the foreign object's full contents through a missing authorization check, that is the IDOR/broken-access-control skill's job.
- **Fetching arbitrary files via `../` or a `file=` parameter is LFI/path-traversal, not this skill.** This skill discovers *intentionally-reachable* artifacts at fixed paths (`/.git`, `/.env`). Once you're manipulating a path parameter to traverse the filesystem, that's the traversal/LFI skill (information-disclosure *feeds* it by leaking the filesystem layout, then hands off).
- **Making the server fetch an internal URL leaked from metadata is SSRF, not this skill.** Disclosed internal hosts/IPs are intel; turning them into a server-side request is the SSRF skill.
- **Don't dispatch on a bare, generic banner with no chain.** `Server: nginx` (no version), a stock 404 page, or intentional public API docs with no hidden/privileged operations are not findings — they're low/no-impact noise. Require either a precise vulnerable version, sensitive data, or a hidden surface before treating it as actionable.
- **Predictable sequential IDs alone are not a leak.** A visible counter is only in scope when the enumerated resource carries business-sensitive data or crosses a tenant/identity boundary.

B:information-disclosure done

