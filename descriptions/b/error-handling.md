# error-handling — when to use

## Trigger signals (dispatch this skill the moment you observe…)
- If you see a raw stack trace, exception class, or framework error page in ANY response (e.g. `Traceback (most recent call last)`, `java.lang.NullPointerException`, `System.NullReferenceException`, `Whoops! There was an error` from Laravel, `ActionController::RoutingError`, `org.springframework...`) → this skill applies. The app is leaking internals through errors.
- If you see a `500 Internal Server Error` that returns a verbose body (not a generic branded page) → probe it harder; debug mode is likely on.
- If you see a `debug=true`, `APP_DEBUG=true`, `display_errors=On`, or Django `DEBUG=True` style yellow exception page → dispatch immediately.
- If you see version-leaking headers in recon: `Server: Apache/2.4.41 (Ubuntu)`, `X-Powered-By: PHP/7.4.3`, `X-AspNet-Version: 4.0.30319`, `X-Generator`, `X-Runtime`, `Via:` → low-severity but a clear tell this skill should run a full enumeration pass.
- If you see file system paths in any output (`/var/www/html/...`, `C:\inetpub\wwwroot\...`, `/home/user/app/...`) → path disclosure; this skill applies.
- If you see a 200 (or 403 with content) on probes like `/.git/HEAD`, `/.env`, `/.svn/entries`, `/server-status`, `/actuator`, `/phpinfo.php`, `/info.php` → dispatch.
- If a parameter that expects an integer/UUID, when sent a string/array/null, returns a different error than a clean validation message → the type-mismatch is reaching the framework layer, not the validation layer. Probe for the leaked trace.
- If you see default/sample install pages: Apache "It works!", nginx welcome page, Tomcat manager, IIS default, phpMyAdmin login, "Welcome to Laravel" → misconfiguration footprint; enumerate further.
- If a `404` page for one path differs from another (custom vs. framework default), or if `OPTIONS`/`TRACE`/`PUT` return `Allow:` headers or echo the request → unexpected-method handling is loose; this skill applies.
- If you see backup/editor artifacts succeed: `index.php.bak`, `config.php~`, `app.js.map`, `.DS_Store`, `web.config.old`, `.swp` → source disclosure.

## Use-case scenarios
- **After initial recon, on every target.** Information disclosure is the cheapest, highest-value reconnaissance multiplier. Before deep-diving any specific vuln class, this skill harvests the technology stack, framework versions, internal paths, and config that make every later attack (SQLi, deserialization, LFI, auth bypass) more precise. Dispatch it early as a fingerprinting pass.
- **When error pages are verbose or inconsistent.** If you've noticed the app fails loudly — different inputs producing different error formats, or a single malformed request dumping a trace — this skill systematically forces and catalogs those errors across endpoints and parameters.
- **When recon headers already hint at a leaky stack.** A target advertising its exact framework/version in headers is usually leaking elsewhere too (verbose 500s, debug routes, exposed `.env`). Use this skill to confirm and enumerate.
- **On apps that look freshly deployed or default-configured.** Default install pages, demo content, or `/admin` with sample creds signal a hardening gap. This skill checks for the full family of misconfiguration artifacts: VCS dirs, env files, actuator/status endpoints, source maps, backups.
- **As a precursor to chained exploitation.** A leaked DB hostname + driver from a stack trace tells the SQLi tester which dialect to target. A leaked absolute web root tells the LFI/upload tester where to write. A `.git` directory means you can reconstruct source and read secrets. Run this first so downstream skills aren't guessing.
- **When you need to confirm framework identity that headers hide.** Some apps strip `X-Powered-By`. Forcing a framework-specific error (Django yellow page vs. Flask Werkzeug debugger vs. Symfony profiler) fingerprints the stack even when headers are clean.

## Concrete tells (request → response examples)
- Probe: `GET /.git/HEAD` → Response: `200 OK` body `ref: refs/heads/master` → `.git` exposed; whole repo is recoverable. **High.**
- Probe: `GET /.env` → Response: `200 OK` with `APP_KEY=...`, `DB_PASSWORD=...` → environment secrets leaked. **High/Critical.**
- Probe: send a string to an integer param, e.g. `GET /item?id=abc` or `GET /item?id[]=1` → Response: `500` with `Traceback (most recent call last): ... sqlalchemy.exc.ProgrammingError` → unhandled exception + DB driver fingerprint. **High.**
- Probe: `GET /actuator` or `GET /actuator/env` → Response: JSON listing Spring Boot endpoints / `{"propertySources": [...]}` with config and secrets → exposed management interface. **High.**
- Probe: `curl -v https://target/` → Response headers `Server: Microsoft-IIS/10.0`, `X-Powered-By: ASP.NET`, `X-AspNet-Version: 4.0.30319` → exact stack version. **Low** on its own, but routes other skills.
- Probe: `OPTIONS /` → Response: `Allow: GET, POST, PUT, DELETE, TRACE` → broad method surface; follow with `TRACE` to test Cross-Site Tracing / request echo.
- Probe: `GET /index.php.bak` or `GET /config.php~` → Response: `200 OK` returning raw PHP source (not executed) → source/credential disclosure. **High.**
- Probe: `GET /app.js.map` → Response: `200 OK` JSON source map → original client source + comments + internal API routes recovered. **Medium.**
- Probe: `GET /nonexistent-xyz` → Response: default framework 404 (e.g. Werkzeug, Express `Cannot GET /nonexistent-xyz`, Django debug 404 listing URL patterns) → framework + (in debug) route map disclosed. **Medium.**
- Probe: malformed JSON / oversized body to a JSON API → Response: parser exception with class name and line number → backend language + parser fingerprint, sometimes full trace. **Medium/High.**

## When NOT to use it / easily-confused-with
- **A reflected error string is not injection.** If a malformed input is echoed back verbatim into HTML, that's a potential XSS/reflection lead, not information disclosure — route to the XSS skill. This skill cares about the *internal* details an error leaks (traces, paths, versions), not whether your input bounced back.
- **If an error reveals SQL syntax tied to YOUR input** (e.g. `you have an error in your SQL syntax near '...'` triggered by a `'`), that's an active SQL injection finding — hand off to the SQLi skill. Use error-handling only to *fingerprint* the DB; exploitation belongs elsewhere.
- **A clean, generic error page is a negative result.** `500` returning a branded "Something went wrong" with no stack, no path, no version, and consistent across inputs means error handling is done right. Don't keep grinding — record it and move on.
- **Auth/authz failures are not this skill.** A `401`/`403` on a protected resource is access control to test with the auth/IDOR skills, unless the *body* of that response leaks a trace or path.
- **Don't confuse a verbose 404 wordlist hit with content discovery.** Generic directory brute-forcing for app functionality is recon/enumeration; this skill specifically targets *disclosure artifacts* (`.git`, `.env`, `.bak`, debug/status endpoints) and *forced errors*. If you're hunting for hidden app features, that's a different move.
- **Open redirect / SSRF error noise.** A redirect or external fetch failing is not information disclosure unless the resulting error body leaks internals — otherwise route to the redirect/SSRF skills.
