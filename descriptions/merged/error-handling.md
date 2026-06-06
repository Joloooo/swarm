# error-handling — when to use

Targets information disclosure: stack traces, debug pages, version/path leaks, and exposed config/VCS/backup artifacts. Run it early as a fingerprinting pass on every target — what it harvests (stack, framework version, internal paths, DB driver, web root, secrets) makes every later attack (SQLi, deserialization, LFI, auth bypass) more precise.

## Dispatch when:
- A response contains a raw stack trace or exception class: `Traceback (most recent call last)`, `java.lang.NullPointerException`, `System.NullReferenceException`, Laravel `Whoops! There was an error`, `ActionController::RoutingError`, `org.springframework...`.
- A `500 Internal Server Error` returns a verbose body rather than a generic branded page (debug mode likely on).
- A debug exception page is shown: `debug=true`, `APP_DEBUG=true`, `display_errors=On`, or a Django `DEBUG=True` yellow page.
- Recon shows version-leaking headers: `Server: Apache/2.4.41 (Ubuntu)`, `X-Powered-By: PHP/7.4.3`, `X-AspNet-Version: 4.0.30319`, `X-Generator`, `X-Runtime`, `Via:`. Low severity alone, but a clear tell to run a full enumeration pass.
- Filesystem paths appear in output: `/var/www/html/...`, `C:\inetpub\wwwroot\...`, `/home/user/app/...` (path disclosure).
- A probe for a disclosure artifact returns 200 (or 403 with content): `/.git/HEAD`, `/.env`, `/.svn/entries`, `/server-status`, `/actuator`, `/phpinfo.php`, `/info.php`.
- A param expecting an integer/UUID, when sent a string/array/null, returns a different error than a clean validation message — the type mismatch is reaching the framework layer; probe for the leaked trace.
- Default/sample install pages appear: Apache "It works!", nginx welcome, Tomcat manager, IIS default, phpMyAdmin login, "Welcome to Laravel".
- A `404` for one path differs from another (custom vs. framework default), or `OPTIONS`/`TRACE`/`PUT` return `Allow:` headers or echo the request (loose unexpected-method handling).
- Backup/editor artifacts resolve: `index.php.bak`, `config.php~`, `app.js.map`, `.DS_Store`, `web.config.old`, `.swp` (source disclosure).

## Key techniques:
- **Probe disclosure artifacts directly.** `GET /.git/HEAD` → `200` `ref: refs/heads/master` means the whole repo is recoverable (High). `GET /.env` → `200` with `APP_KEY=`, `DB_PASSWORD=` leaks environment secrets (High/Critical). `GET /index.php.bak` or `/config.php~` → `200` returning raw, unexecuted PHP source leaks credentials (High). `GET /app.js.map` → `200` source map recovers original client source, comments, and internal API routes (Medium).
- **Hit management/status endpoints.** `GET /actuator` or `/actuator/env` → JSON listing Spring Boot endpoints / `{"propertySources": [...]}` exposes config and secrets (High).
- **Force type-mismatch errors.** Send a string/array to an integer param, e.g. `GET /item?id=abc` or `GET /item?id[]=1` → `500` with `Traceback ... sqlalchemy.exc.ProgrammingError` gives an unhandled exception plus DB driver fingerprint (High).
- **Force a framework-specific error to fingerprint a clean stack.** When headers strip `X-Powered-By`, the error page identifies the stack: Django yellow page vs. Flask Werkzeug debugger vs. Symfony profiler. A default 404 also fingerprints (Werkzeug, Express `Cannot GET /...`, Django debug 404 listing URL patterns) and in debug mode dumps the route map (Medium).
- **Break the parser.** Malformed/oversized JSON to a JSON API → parser exception with class name and line number reveals backend language and parser, sometimes a full trace (Medium/High).
- **Enumerate version/method surface.** Read `Server`, `X-Powered-By`, `X-AspNet-Version` headers for exact stack version (Low alone, but routes other skills). `OPTIONS /` → `Allow: GET, POST, PUT, DELETE, TRACE` exposes the method surface; follow with `TRACE` to test Cross-Site Tracing / request echo.
- **Feed leaks downstream.** A leaked DB hostname + driver tells the SQLi tester the dialect; a leaked absolute web root tells the LFI/upload tester where to write; a `.git` directory lets you reconstruct source and read secrets. Run this before those skills so they aren't guessing.

## When NOT to use / easily confused with:
- **Reflected input is not disclosure.** Malformed input echoed verbatim into HTML is an XSS/reflection lead → XSS skill. This skill cares about *internal* details an error leaks (traces, paths, versions), not whether input bounced back.
- **SQL error tied to your input is injection.** `you have an error in your SQL syntax near '...'` triggered by a `'` is an active SQLi finding → SQLi skill. Use error-handling only to *fingerprint* the DB; exploitation belongs elsewhere.
- **A clean, generic error page is a negative result.** A `500` with a branded "Something went wrong", no stack/path/version, consistent across inputs, means error handling is correct. Record it and move on.
- **Auth/authz failures are not this skill.** A `401`/`403` on a protected resource is access control → auth/IDOR skills, unless the response *body* leaks a trace or path.
- **A verbose 404 wordlist hit is not content discovery.** Generic directory brute-forcing for app features is recon/enumeration; this skill targets *disclosure artifacts* (`.git`, `.env`, `.bak`, debug/status endpoints) and *forced errors*.
- **Open redirect / SSRF error noise.** A failing redirect or external fetch is not disclosure unless the error body leaks internals → otherwise route to the redirect/SSRF skills.
