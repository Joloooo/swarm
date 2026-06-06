# fuzzing — when to use

Fuzzing *discovers* hidden input surface — paths, parameters, vhosts, leaked files. It does not exploit what it finds: a discovered path/param is a lead to hand off, not a finding.

## Dispatch when:

- **Recon returned very little surface on a clearly real app.** A handful of routes (one login page, a brochure homepage, an API with two endpoints) on an obviously substantial server means the rest is hidden, not absent.
- **A nearly-empty target leaves downstream skills nothing to work with.** When sqli/xss/idor/ssrf/lfi have no inputs, the bottleneck is discovery, not exploitation. Fuzzing manufactures the inputs they need: a found `id` to test for IDOR, a `/upload` for file upload, a `?url=` for SSRF.
- **`robots.txt` / `sitemap.xml` lists or hints at paths you can't reach by browsing** (`Disallow: /admin`, `/backup/`, `/api/internal`). Disallow lines are a curated list of "things they don't want found" → fuzz those prefixes and their neighbours.
- **Framework / server fingerprints in headers or error pages** tell you which short, high-hit-rate wordlist to run:
  - `Server: Apache-Coyote` / `JSESSIONID` / `X-Powered-By: Servlet` → Tomcat `/manager/html`, `/actuator/{env,heapdump,mappings}` (Spring Boot).
  - `X-Powered-By: PHP` → `.php` / `.phps` / `.bak`.
  - `Set-Cookie: laravel_session` / `connect.sid` → matching tech wordlist.
  - WordPress → `/wp-admin`, `/wp-json`, `/xmlrpc.php`. Jolokia → `/console`.
- **An application-rendered 404** (styled "Page not found", SPA shell, framework default) rather than a bare web-server 404 → a router/front controller handles unknown paths, so you must calibrate and diff to separate real routes from the catch-all.
- **Sequential / guessable identifiers** (`?id=42`, `/user/1001`, `?file=report.pdf`) → the app likely accepts more parameters than the UI sends; run parameter discovery (Arjun / x8) on that endpoint.
- **You have one endpoint and need its full parameter contract.** A documented `POST /api/login` taking `{user,pass}` may silently accept `role`, `is_admin`, `redirect`, `next`, `debug`. Run parameter discovery (`arjun -m POST -m JSON`) on every input-taking endpoint.
- **Behaviour changes on an unexpected parameter** — `?debug=1`, `?admin=true`, `?format=json` flips the response. Any sign hidden flags exist → fuzz the parameter namespace.
- **A bare IP, wildcard cert, or `Host`-based vhost setup.** TLS cert SANs listing several names, different responses for different `Host:` headers, or an IP with no name → fuzz vhosts and enumerate subdomains (brute + crt.sh + subfinder). Dev/staging/internal vhosts on a shared host routinely lack the WAF and auth that protect production.
- **The visible app is gated but ungated siblings are likely.** Strong WAF/login wall on the front door → fuzz for side doors (staging/dev/admin vhosts).
- **Directory-listing or partial path leaks** seed a custom wordlist: a `Location:` redirect to `/app/v2/`, a JS bundle referencing `/api/v3/internal/...`, a comment mentioning `/old/`, a stack trace with a filesystem path → fuzz around those tokens.
- **Backup / source-control tells**: a `.DS_Store`, a stray `.bak`, an `ETag` that looks like a git hash → sweep extensions (`.bak .old .swp ~ .zip .tar.gz`) and VCS dirs (`.git/ .svn/`). Worth a pass on any app that looks hand-deployed rather than containerized.
- **Auth/router boundary mapping.** Sweeping a path set and distinguishing `401` (needs login) from `403` (logged in but forbidden) reveals where the authorization boundary actually sits — useful before an auth-bypass or IDOR attempt.

## Recognition tells (request → response):

- **Calibration confirms a router/catch-all:** `GET /zzz-random-nonexistent-abc123` → `200 OK` with a full HTML page (SPA shell or styled 404) instead of a tiny bare server-level 404. Everything is handled by a front controller → fuzz with `-ac` / response diffing to find real routes.
- **Hidden path lead:** `GET /admin` → `302`, `Location: /login`, while `GET /random` → `200` SPA shell. A redirect *only* for `/admin` proves it's a real, gated route — a confirmed hit to pivot on.
- **Tech-default path hit:** `GET /actuator/env` → `200`, `application/json`, body with `"systemProperties"` / `"propertySources"` → Spring Boot Actuator env dump (actual secrets-bearing content, not just a 200) → keep enumerating `/actuator/*`.
- **Source-control leak:** `GET /.git/HEAD` → `200`, body `ref: refs/heads/main` → real git tree exposed; pivot to dumping it. A `200` with an HTML body is a false positive — the body must be the literal git ref.
- **Hidden parameter (response-diff):** baseline `GET /api/user` → `200`, 412 bytes; `GET /api/user?debug=1` → `200`, 1840 bytes with a stack trace, or `GET /api/user?id=2` → a *different* user. A behavioural delta from a candidate param (caught by Arjun/x8 diffing, even with no reflection) confirms an undocumented input.
- **Vhost split:** `GET / Host: target.com` → `200` marketing site, 30 KB; `GET / Host: dev.target.com` (same IP) → `200` login portal, 4 KB, `X-Powered-By: Express` → a different app on the same server, found purely by changing `Host:`.
- **Backup leak:** `GET /config.php` → `200` empty (PHP executed); `GET /config.php.bak` → `200`, `text/plain`, body with `$db_password = "..."` → source served verbatim because the `.bak` extension isn't routed through the interpreter.

## When NOT to use / easily confused with:

- **You already have the input; you need to test it.** If recon already surfaced the parameter or endpoint, route to the matching exploitation skill (sqli, xss, ssrf, lfi, idor, auth). Fuzzing finds surface; it does not break it.
- **A value reflects into the page → XSS/SSTI/injection, not fuzzing.** Note reflection as a pivot signal, but confirming/exploiting it (especially reflected-vs-evaluated for SSTI) belongs to the XSS/SSTI skill.
- **Confirmed login form, credential attack is the goal.** Fuzzing finds the login *endpoint*; password attacks, default creds, and auth-bypass logic are the auth skill's job. Find the form, then hand off.
- **A true SPA catch-all** (every path → identical `index.html`, identical size). Blind path fuzzing yields soft-404 noise. The real surface is the backend API the SPA calls — pull endpoints from the JS bundles and fuzz *parameters* on those instead of brute-forcing front-end routes.
- **Tiny, fully-enumerated target.** A single-page form whose whole contract is visible needs no wordlist — test the one input directly. Fuzzing a 3-route app burns budget for no signal.
- **Hard rate-limit / aggressive WAF that bans on volume.** Early `429` / `503` / sudden `403` / CAPTCHA means blind high-thread fuzzing will get you blocked and poison the engagement. Drop to a tiny tech-targeted list at a crawl rate, or pivot to quieter discovery (passive subdomain sources, cert transparency).
- **Confused with directory traversal / LFI:** finding `?file=` is fuzzing; making `?file=../../etc/passwd` work is the LFI skill.
