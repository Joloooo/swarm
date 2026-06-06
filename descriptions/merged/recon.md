# recon — when to use

Application-layer reconnaissance: read a running web app to learn its server, framework, language, and CMS; enumerate its routes; and map the inputs a user can drive. This is the breadth pass that produces a surface map the planner uses to route specialists. It runs alongside (not instead of) the network/port pass.

## Dispatch when:

- **You have a bare target and nothing else** — a URL, hostname, or IP with no map of what runs there yet. If the surface is unknown, recon applies by definition and is always the correct first move.
- **The HTTP root responds at all** — any `200`, a `301/302` to a login or app path, `401/403`, or even a `404` from a real server (not connection-refused). There is a web service to fingerprint and enumerate.
- **A response carries a technology tell** in headers you have not catalogued: `Server: Apache/2.4.x`, `Server: nginx`, `X-Powered-By: PHP/7.x`, `X-Powered-By: Express`, `X-AspNet-Version`, `X-Drupal-Cache`, `X-Generator: Drupal`, `Link: <…/wp-json/>`, or a framework session cookie (`PHPSESSID`, `JSESSIONID`, `connect.sid`, `laravel_session`, `csrftoken` for Django). Fingerprint the stack so the right specialist gets dispatched.
- **The homepage HTML reveals input vectors you have not enumerated**: `<form action=… method=POST>`, hidden inputs, `fetch('/api/…')` / `axios` calls in inline or bundled JS, `<meta name="generator" content="WordPress 6.x">`, or asset paths like `/wp-content/`, `/sites/default/files/`, `/_next/static/`, `/static/admin/`. Map the forms, parameters, and routes.
- **You suspect pages you have not seen** — a thin landing page, an SPA shell, a redirect to `/login`, or a directory returning `403` (exists but forbidden). Directory and file brute-forcing is warranted.
- **The target is a real FQDN** (not `localhost`, not a raw IP). Subdomain and passive-dataset enumeration (Certificate Transparency, passive DNS) becomes available and cheap.
- **A scan or crawl just changed the picture** — a new vhost, a new port hosting a second web app, or a newly discovered subdomain. Re-run recon scoped to the newly found surface before sending in specialists; the map is never "done" the moment the topology grows.
- **A robots.txt, sitemap.xml, .well-known, or HTML comment names a path you have not visited.** These are free leads to hidden surface — enumerate them.

## Recognition tells (request → response):

- **Header probe pins the stack.** `curl -sI http://target/` returns `Server: Apache/2.4.49 (Unix)`, `X-Powered-By: PHP/7.1.33`, `Set-Cookie: PHPSESSID=…` → a PHP/Apache app. File the exact version (it may be a known-vulnerable build), map routes, then hand off.
- **Generator/asset tells reveal a CMS.** `GET /` body contains `<meta name="generator" content="WordPress 6.4.2">` or links to `/wp-content/themes/…` and `/wp-json/` → WordPress. Enumerate plugins/themes and the `/wp-admin` login as input surface.
- **403 on a directory means it exists but is protected.** `GET /admin/` → `403 Forbidden` (not `404`) → the path is real; note it as high-priority surface and enumerate siblings (`/admin/login`, `/admin/config`).
- **JS reveals an API the HTML hides.** Homepage is an empty `<div id="root">`, but the bundle contains `fetch("/api/v1/users?id=1")` → record the `/api/v1/users` endpoint and the `id` parameter shape. Use a rendering fallback for SPAs whose interesting endpoints live in JS bundles, not raw HTML.
- **A redirect names the front door.** `GET /` → `302 Location: /login.php` → a PHP auth surface; map the login form's field names (`username`, `password`, CSRF token) for the auth and injection specialists.
- **robots.txt leaks structure.** `GET /robots.txt` → `Disallow: /backup/`, `Disallow: /internal-api/` → free leads; enumerate both.
- **Forbidden-but-listed VCS or dotfile.** `GET /.git/HEAD` → `200` with `ref: refs/heads/master` → exposed source repo; file it as a finding and flag for retrieval by a specialist.

## Key techniques:

- Probe headers and cookies to fingerprint server, language, framework, and CMS.
- Read the homepage HTML first; extract forms, hidden inputs, parameters, and inline/bundled JS `fetch`/XHR calls. For SPAs, render or parse the JS bundles to surface `/api/…` routes and parameter shapes.
- Directory and file brute-force to find hidden surface: login portals, `/admin`, `/phpmyadmin`, `.git/`, `.env`, backups (`*.bak`, `*.old`, `*.zip`), and dev/staging leftovers. A `403` marks an existing protected path worth enumerating around.
- Mine robots.txt, sitemap.xml, `.well-known`, and HTML comments for named paths.
- For a real FQDN, enumerate subdomains via Certificate Transparency and passive DNS.
- Produce a surface map specific enough to route the next specialist: a `?id=` parameter on a PHP page → SQLi/IDOR; a file-upload form → upload-handling specialist; a `url=` parameter fetching remote content → SSRF.

## When NOT to use it / easily confused with:

- **Not for grinding a single endpoint.** Once a form/parameter/route is *located*, recon's job for that vector is done — hand off. Firing injection strings, path-traversal sequences, or auth-bypass attempts against one endpoint is specialist work. recon maps breadth; specialists drill depth.
- **Not the network/port pass.** Open-port discovery, service-version scanning, and non-HTTP service identification belong to the parallel ports lane (nmap). recon is the web/app layer only.
- **A reflected value is not yet a vuln.** A parameter echoed in the response is a surface tell to *record*. It becomes XSS only in an unescaped HTML/JS context, SQLi only if it reaches a query, SSTI only if it is *evaluated* (`{{7*7}}`→`49`), LFI only if used as a file path. recon notes and routes the reflective parameter; it does not adjudicate the class.
- **A known-vulnerable version string is a finding, not an exploit.** File `Server: Apache/2.4.49` and move on — exploiting the CVE is a specialist's job.
- **Not for credential or business-logic attacks.** recon maps and notes the login form; brute-forcing, default-credential testing, and logic-flaw chaining are downstream.
- **Don't confuse a proxy/view with the real target.** If a single `/api/…` proxy or admin route looks like "the whole objective," note it as high-priority surface and keep mapping — the thing it fronts often lives on another port or route.
