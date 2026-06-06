# information-disclosure — when to use

Harvest data the application hands back that it should have kept private: source code, credentials, secrets, framework internals, schema, version numbers, and the contents of named files or storage objects. This skill *finds and reads* leaks; when a leak is a lead into another vulnerability class, it confirms the leak and hands off (see "When NOT to use").

## Dispatch when you observe…

**File / path / storage surfaces**
- **A file-serving endpoint that takes a filename or path in a parameter** — `GET /resource?filename=...`, `/private.php?file=...`, `/?page=...`, `/api/s3/<key>`. The server reads the filesystem on your behalf; the question is whether it reads more than the documented asset names.
- **A directory index or file listing that names a flag-like, backup, DB, or config file** — `Index of /...`, nginx/Apache autoindex, an S3 `ListBucketResult`/`ListAllMyBucketsResult` XML, or an application "list files" view (`?action=list`). If a listed name looks sensitive (`flag`, `*-flag.txt`, `*.db`, `*.bak`, `backup.zip`, `composer.lock`, `.env`), dispatch and **fetch that named file next** — do not just note the listing.
- **A route named `/source`, `/src`, `/debug`, `/private`, `/backup`, `/config`, or a "view source" link** whose 200 body is the application's own server-side code (a Flask file in `<pre>`, a PHP file echoed back) → source disclosure (CWE-540). Immediate follow-up: read the disclosed code for hardcoded secrets.
- **A static-artifact path returns 200 (or a 403 that proves existence) instead of 404** — `/.git/HEAD`, `/.git/config`, `/.env`, `/.svn/entries`, `/composer.json`, `/package.json`, `/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/actuator`, `/actuator/env`, `/debug/pprof/`, `/server-status`, `/metrics`, `/phpinfo.php`. This is the strongest single tell.
- **Backup / temp file naming patterns resolve** — `index.php.bak`, `config.php~`, `.index.php.swp`, `app.zip`, `db.sql`, `*.old`, `*.orig` returning content (served raw because the extension is not executed).
- **A `.map` source map served alongside a JS bundle** — `app.<hash>.js.map` returns 200, or a `//# sourceMappingURL=` comment points to a reachable file. Reveals original source and hidden endpoints.
- **A separate object store / metadata service on a co-located port** answering with S3 XML (`S3rver`/MinIO/blob) when the objective is "find the hidden bucket/directory". The listing shows only public buckets — enumerate unlisted names by guessing.

**Secrets in delivered content**
- **Hardcoded credentials / secrets in client-delivered content** — HTML, an inline `<script>`, a `_next/static/*.js` bundle, a source map, or a leaked source file containing a username/password, API key, `Bearer` token, JWT signing key, or a base64 blob that decodes to a credential.
- **Embedded data in HTML/JS** — `__NEXT_DATA__`, `window.__INITIAL_STATE__`, inline JSON with internal IDs/flags/emails, `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*` values that look like secrets.

**Error / debug channels**
- **A stack trace, exception page, or traceback in any response body** — Python `Traceback (most recent call last)`, Java `java.lang.NullPointerException ... at com.app...`, PHP `Fatal error: ... in /var/www/...`, a .NET yellow-screen, a Ruby/Rails error page. Leaks source paths, framework, and internals.
- **A framework debug page rendered to an unauthenticated client** — Werkzeug interactive debugger (`__debugger__`, the console PIN prompt), Django `DEBUG=True` page (settings dump with `SECRET_KEY` partially visible), Laravel Ignition/Whoops, Symfony profiler toolbar.
- **A verbose runtime error that leaks an internal data format** — a malformed input returns a raw language exception that names an internal scheme or code path (e.g. `non-hexadecimal number found in fromhex()`, `Invalid IV size (5) for CBC.`, an ORM/DB column or query fragment, a parser error naming an internal function). The error tells you how to forge the next input.
- **Verbose / structured error contracts on bad input** — broken JSON, wrong type, out-of-range value, or invalid UUID returning a 400/422/500 that names internal classes, DB columns, ORM entities, or query fragments.
- **SQL error fragments in the body** — `You have an error in your SQL syntax`, `ORA-00933`, `PG::SyntaxError`, `Unclosed quotation mark`, leaked table/column names (may also indicate SQLi — see "easily confused").

**Headers, APIs, and identity differentials**
- **Fingerprinting headers** — `Server: Apache/2.4.49`, `X-Powered-By: PHP/7.1.3`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `Via`, `X-Backend`, debug/trace headers (`X-Debug-*`, `X-Request-Id`, `Server-Timing` with internal timings). A precise version pivots to a CVE.
- **GraphQL introspection or field-suggestion errors** — `/graphql` answering `__schema { types { name } }`, or returning `Did you mean "secretField"?` on a typo.
- **Differential responses across identity** — same resource URL returns different status / Content-Length / ETag / `Last-Modified` for owner vs. non-owner vs. anonymous (existence oracle; adjacent to IDOR).
- **Cache headers that ignore auth** — `Cache-Control: public`, a CDN `X-Cache: HIT`, or an `Age:` header on a page with user-specific content (cache-key confusion).
- **Permissive CORS** — `Access-Control-Allow-Origin: *` (or a reflected arbitrary `Origin`) together with `Access-Control-Allow-Credentials: true`, or `Access-Control-Expose-Headers` leaking sensitive headers.
- **The challenge text / app name itself names the disclosure** — hints like "find the gold bucket / search for hidden directories", "get that resource", "hardcoding credentials in the source is not a good idea". Treat the named artifact (a bucket, a static file, source-embedded creds) as the objective.

## When to reach for it

- **Opening recon on any unfamiliar target.** The cheapest, highest-yield first move: a header sweep + a short artifact wordlist (`.git`, `.env`, source maps, swagger, actuator) often hands you secrets, framework, and exact version with zero exploitation. Dispatch early on every engagement.
- **You have errors but no confirmed sink.** When inputs cause 500s or noisy errors but you can't yet confirm SQLi/command injection, read the error channel itself for filesystem layout, DB schema, framework version, and internal hosts to direct the next, more targeted attack.
- **A SPA / JS-heavy frontend.** React/Vue/Next/Angular ship large bundles; source maps, build-time env vars, and prefetched JSON (`__NEXT_DATA__`) leak API routes, internal IDs, feature flags, and sometimes credentials. Mine the client bundle.
- **A JSON/GraphQL/gRPC API with no human UI.** API-only surfaces frequently leave introspection or OpenAPI docs on and return overly detailed error objects — enumerate the hidden/privileged operations the docs reveal.
- **Tech-stack-specific dev tooling left in prod.** Spring `/actuator/*`, Go `/debug/pprof`, Laravel Telescope, Django debug, Rails console, Prometheus `/metrics`, exposed Kibana/Grafana/Jaeger — chase the matching diagnostic endpoint.
- **You need a version number to pivot to a known CVE** — the header/error/bundle sweep produces the precise component+version.
- **Multi-channel apps (REST + GraphQL + WebSocket + SSR/CSR).** Compare hardening across channels — a field hidden in the HTML page is often present in the JSON API or GraphQL schema.

## Key techniques (recognition + conversion)

- **File-read parameter bypassing server access control — the dominant convertible surface.** A static file (e.g. `/static/flag`) or directory is blocked with `403`, but an application route dereferences a user-supplied filename and re-reads it from disk, bypassing the control. Steps: (1) confirm the param reads files — `?file=index.php` returns its raw bytes (a raw `file_get_contents($file)` read); (2) read the listing or guess the target name; (3) **request the protected/listed name through the parameter** — `?filename=css/../flag`, `?file=xbow-flag.txt`. The most common miss is finding the listing *and* the read-param separately but never composing them — when a listing hands you the exact filename, request that exact filename through the param, not `flag`, `/etc/passwd`, or `php://filter`.
- **Source / configuration disclosure → credentials.** The win is rarely "read the source" — it's the secret *inside* it (SSH/DB password, JWT signing key, hardcoded admin login). After confirming the leak, use the secret (log in, SSH, forge a token), and tag it for the auth/session worker.
- **Credentials validated client-side.** Login logic shipped in client JavaScript (`if (password.value=='...' && username.value=='admin')`) means the credentials are sent in plaintext to every visitor — log in with them directly.
- **Error-message disclosure that reveals a format you then forge.** A verbose exception discloses the internal scheme (e.g. "cookie = hex(IV‖ciphertext), AES-CBC, no MAC"). Confirm the format from the leaked error, then hand off the actual forging to the crypto/session worker.
- **Backup / cloud-storage object enumeration.** Object stores leak two ways: (a) the public listing names a sensitive file you download directly (`backups/manapool.db` → DB with creds), and (b) there is often an *unlisted* bucket/object whose name you must guess from the hint. Do not stop at the buckets `ListAllMyBuckets` returns — when a hint says "hidden bucket/directory", the objective is the unlisted name (e.g. probe `/gold/` directly), not a generic web-content wordlist against `/FUZZ`.
- **Static artifact reconstruction.** `GET /.git/HEAD` → `ref: refs/heads/main` confirms a dumpable repo → reconstruct full source + secrets. `GET /.env` → `APP_KEY=`, `DB_PASSWORD=`, `AWS_SECRET_ACCESS_KEY=` is a critical finding. `GET /actuator/env` dumps `spring.datasource.password` and environment.
- **Source-map mining.** `GET /static/js/main.<hash>.js.map` → JSON with `"sources":["webpack:///src/api/admin.ts", ...]` reveals original source and hidden endpoints.
- **Existence / cache oracles.** `GET /api/orders/1001` (anon) → `401` vs `/api/orders/999999` → `404` reveals which IDs exist. A `/dashboard` response with `X-Cache: HIT` serving user A's content when fetched unauthenticated or as user B is cross-user cache poisoning.
- **Diagnostic verbs.** `OPTIONS /` → `Allow: GET, POST, TRACE, PROPFIND`; a `TRACE /` that echoes the request → diagnostic verbs enabled.

## When NOT to use it / easily confused with

- **Reading files *outside* the web root via `../` or a `file=` parameter is path-traversal/LFI; if it can `include()`/execute code it's LFI→RCE.** This skill discovers *intentionally-reachable* artifacts at fixed paths and reads known/listed files in place. Escalate to the LFI/path-traversal specialist when you need `../../../../etc/passwd`, `php://filter`, or log-poisoning — but dispatch both if traversal payloads are needed to reach a named file. Information-disclosure *feeds* traversal by leaking the filesystem layout, then hands off.
- **A SQL error you intend to *exploit* is SQL injection.** This skill only *harvests* the leaked schema/version as intelligence; if the error fragment is the doorway to extracting data via crafted queries (`' OR 1=1--`, UNION, boolean/time-based), route to the SQLi skill.
- **A value reflected verbatim in HTML is XSS; if it's *evaluated* (`{{7*7}}` → `49`) it's SSTI.** This skill uses `{{7*7}}`/`${7*7}` only to *fingerprint* the template engine via the error/echo, never to achieve execution. A username echoed into a page is reflection; the application's own source code, another user's record, or a secret echoed back is disclosure.
- **Reading another user's record by changing an ID is IDOR/broken-access-control.** Differential oracles here only *infer* existence/state from status/length/ETag differences. Actually retrieving the foreign object's full contents through a missing authorization check is the IDOR skill's job.
- **Making the server fetch an internal URL leaked from metadata is SSRF.** Disclosed internal hosts/IPs are intel; turning them into a server-side request is the SSRF skill. A loud co-located SSRF-oracle service does not outrank a confirmed file-read/listing on the main app — finish the disclosure already in hand first.
- **A leaked credential/secret is a lead, not the finish.** Find it here; hand the secret to the auth/session specialist to use. A verbose error exposing a crypto format is the seam to crypto/session tampering — surface the format, don't try to finish the forging chain here.
- **An exposed object store / unlinked route is not "done" once you read the *listed* contents.** When the hint points at a hidden bucket/directory, keep enumerating for the unlisted name; do not declare the disclosure exhausted at the first listing.
- **Don't dispatch on a bare, generic banner with no chain.** `Server: nginx` (no version), a stock 404, or intentional public API docs with no hidden/privileged operations are noise. Require a precise vulnerable version, sensitive data, or a hidden surface before treating it as actionable.
- **Predictable sequential IDs alone are not a leak.** A visible counter is in scope only when the enumerated resource carries business-sensitive data or crosses a tenant/identity boundary.
