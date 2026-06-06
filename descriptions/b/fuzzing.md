# fuzzing — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **The crawler found very little surface.** If recon returned only a handful of routes (a single login page, a brochure homepage, an API with two documented endpoints) but the server is clearly a real application → dispatch fuzzing. Small visible surface on a big app means the rest is hidden, not absent.
- **A `robots.txt` / `sitemap.xml` that lists or hints at paths you can't reach by browsing** (e.g. `Disallow: /admin`, `Disallow: /backup/`, `Disallow: /api/internal`). Disallow lines are a curated list of "things they don't want you to find" → fuzz those prefixes and their neighbours.
- **Framework / server fingerprints in headers or error pages.** `Server: Apache-Coyote`/`X-Powered-By: Servlet` → fuzz `/actuator`, `/manager`, Tomcat paths. `X-Powered-By: PHP` → fuzz `.php`/`.phps`/`.bak`. `Set-Cookie: laravel_session` / `JSESSIONID` / `connect.sid` → pick the matching tech wordlist. A recognizable stack tells you which short, high-hit-rate list to run.
- **A 404 page that is clearly application-rendered** (a styled "Page not found", an SPA shell, a framework default) rather than the bare web-server 404 → there is a router in front, so unknown paths get *handled*. This is exactly when you need calibration + diffing to separate real routes from the catch-all → fuzzing.
- **Sequential / guessable identifiers in URLs or params** (`?id=42`, `/user/1001`, `?file=report.pdf`) → the app probably accepts more parameters than the UI sends; run parameter discovery (Arjun/x8) on that endpoint.
- **An endpoint whose behaviour changes based on a parameter you didn't expect** — e.g. adding `?debug=1`, `?admin=true`, `?format=json` flips the response. Any sign that hidden flags exist → fuzz the parameter namespace.
- **A bare IP, a wildcard cert, or a `Host`-based vhost setup.** If TLS cert SANs list several names, or the server answers differently for different `Host:` headers, or you only have an IP with no name → fuzz vhosts and enumerate subdomains.
- **Directory-listing or partial path leaks**: a `Location:` redirect to `/app/v2/`, a JS bundle that references `/api/v3/internal/...`, a comment mentioning `/old/`, a stack trace with a filesystem path → seed a custom wordlist from those tokens and fuzz around them.
- **Backup / source-control tells**: a `.DS_Store`, a stray `.bak` you stumbled on, an `ETag` that looks like a git hash → sweep extensions (`.bak .old .swp ~ .zip .tar.gz`) and VCS dirs (`.git/ .svn/`).
- **The visible app is gated but you suspect ungated siblings** — e.g. the main site has a WAF/login wall, but staging/dev/admin vhosts on the same IP usually don't. Strong WAF on the front door → fuzz for the side doors.

## Use-case scenarios

- **Early-stage black-box recon on an unfamiliar target.** This is the bread-and-butter use. After a passive crawl, the navigable UI is almost always a fraction of the real input surface. Fuzzing is the highest-leverage move to expand the map: hidden admin panels, debug consoles, legacy endpoints, undocumented API versions, staging vhosts. Dispatch it before committing to any single vulnerability hunt, because the path/param you discover often *is* the thing that's exploitable.
- **A nearly-empty target where nothing else has anything to work with.** If the SQLi/XSS/IDOR skills have no inputs to test, the bottleneck is *discovery*, not exploitation. Fuzzing manufactures the inputs the downstream skills need (a found `id` param to test for IDOR, a found `/upload` to test for file upload, a found `?url=` to test for SSRF).
- **You found one endpoint and need its full parameter set.** A documented `POST /api/login` taking `{user,pass}` may also silently accept `role`, `is_admin`, `redirect`, `next`, `debug`. Parameter discovery (Arjun `-m POST -m JSON`) on every input-taking endpoint is the right call whenever you've located an endpoint but not its full contract.
- **Tech stack is identified and has well-known hidden paths.** Spring Boot → `/actuator/{env,heapdump,mappings}`. WordPress → `/wp-admin`, `/wp-json`, `/xmlrpc.php`. Tomcat → `/manager/html`. Jolokia → `/console`. The moment you fingerprint such a stack, a *tech-targeted* fuzz is high-value and cheap.
- **Vhost / subdomain expansion on a shared host.** One IP frequently serves many apps differentiated only by `Host:`. Dev/staging/internal vhosts routinely lack the WAF and auth that protect production. When you have an IP plus any naming hint, fuzz `Host:` values and enumerate subdomains (brute + crt.sh + subfinder).
- **Backup / source-leak hunting.** When a path is known (`/login`, `/config`), re-fuzz it with backup and editor-swap extensions — leaked source or `.git/` is a direct credential/secret pivot. Worth a pass on any app that looks hand-deployed rather than containerized.
- **Auth/router boundary mapping.** Distinguishing `401` (needs login) from `403` (logged in but forbidden) across a path sweep reveals where the authorization boundary actually sits — useful before an auth-bypass or IDOR attempt.

## Concrete tells (request → response examples)

- **Calibration confirms a router/catch-all is present:**
  `GET /zzz-random-nonexistent-abc123` → `200 OK`, full HTML page (the SPA shell or a styled 404). The web-server-level 404 would be a tiny bare page. A 200 (or styled-404) on garbage means everything is handled by a front controller → you *must* fuzz with `-ac`/diffing to find the real routes, and that's precisely this skill's job.
- **Hidden path lead:**
  `GET /admin` → `302 Found`, `Location: /login` (vs `GET /random` → `200` SPA shell). A redirect *only* for `/admin` proves `/admin` is a real, recognized route the app gates — a confirmed hit to pivot on.
- **Tech-default path hit:**
  `GET /actuator/env` → `200`, `Content-Type: application/json`, body containing `"systemProperties"` / `"propertySources"` → Spring Boot Actuator env dump (not just a 200 — actual secrets-bearing content). Strong signal to keep enumerating `/actuator/*`.
- **Source-control leak:**
  `GET /.git/HEAD` → `200`, body `ref: refs/heads/main` → real git tree exposed; pivot to dumping it. (A `200` with an HTML body is a false positive — the body must be the literal git ref.)
- **Hidden parameter (response-diff):**
  Baseline `GET /api/user` → `200`, 412 bytes. `GET /api/user?debug=1` → `200`, 1840 bytes with stack trace, OR `GET /api/user?id=2` → returns a *different* user. A behavioural delta from injecting a candidate param (caught by Arjun/x8 diffing, even with no reflection) confirms an undocumented input.
- **Vhost split:**
  `GET / Host: target.com` → `200` marketing site, 30 KB. `GET / Host: dev.target.com` (same IP) → `200` login portal, 4 KB, `X-Powered-By: Express` → a *different app* on the same server, found purely by changing `Host:`.
- **Backup leak:**
  `GET /config.php` → `200` empty (PHP executed). `GET /config.php.bak` → `200`, `Content-Type: text/plain`, body containing `$db_password = "..."` → source served verbatim because the `.bak` extension isn't routed through the interpreter.

## When NOT to use it / easily-confused-with

- **You already have the input; you need to test it, not find more.** If recon/crawl already surfaced the parameter or endpoint and you're trying to break it, route to the matching exploitation skill (sqli, xss, ssrf, lfi, idor, auth) — not fuzzing. Fuzzing *finds* surface; it does not exploit it. A discovered path is a lead, not a finding.
- **A value reflects into the page → that's XSS/SSTI/injection territory, not fuzzing.** Fuzzing notes reflection as a *pivot signal*, but confirming and exploiting the reflection (especially distinguishing reflected-vs-evaluated for SSTI) belongs to the XSS/SSTI skill.
- **You have a confirmed login form and credentials/brute-force is the goal.** Fuzzing discovers the login *endpoint*; password attacks, default creds, and auth-bypass logic are the auth skill's job. Use fuzzing only to find the form, then hand off.
- **The whole app is a true SPA catch-all (every path → identical `index.html`, identical size).** Blind path fuzzing here mostly yields soft-404 noise. The real surface is the backend API the SPA calls — pull endpoints from the JS bundles and fuzz *parameters* on those, rather than brute-forcing front-end routes.
- **Tiny, fully-enumerated target.** A single-page form whose entire contract is already visible doesn't need a wordlist; jump straight to testing the one input. Fuzzing a 3-route app for hidden paths burns budget for no signal.
- **Hard rate-limit / aggressive WAF that bans on volume.** If early probes return `429`/`503`/sudden `403`/CAPTCHA, blind high-thread fuzzing will get you blocked and poison the engagement. Either drop to a tiny tech-targeted list at a crawl rate, or pivot to a quieter discovery path (passive subdomain sources, cert transparency) — don't hammer.
- **Confused with directory traversal / LFI:** finding `?file=` is fuzzing; making `?file=../../etc/passwd` work is the LFI skill. The discovery of the parameter and the exploitation of it are two different skills.
