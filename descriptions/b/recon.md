# recon — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **You have a bare target and nothing else** — a URL, hostname, or IP with no map of what runs there yet → recon is always the correct first move. If the surface is unknown, this skill applies by definition.
- **The HTTP root responds at all** — any `200`, `301/302` to a login or app path, `401/403`, even a `404` from a real server (not connection-refused) → there is a web service to fingerprint and enumerate.
- **A response carries a technology tell** in headers you have not yet catalogued: `Server: Apache/2.4.x`, `Server: nginx`, `X-Powered-By: PHP/7.x`, `X-Powered-By: Express`, `X-AspNet-Version`, `Set-Cookie: PHPSESSID=`, `Set-Cookie: JSESSIONID=`, `Set-Cookie: connect.sid=`, `Set-Cookie: laravel_session=`, `Set-Cookie: csrftoken=` (Django), `X-Drupal-Cache`, `X-Generator: Drupal`, `Link: <…/wp-json/>` → fingerprint the stack so the right specialist gets dispatched.
- **The homepage HTML reveals input vectors you have not enumerated**: `<form action=… method=POST>`, hidden inputs, `fetch('/api/…')` / `axios` calls in inline or bundled JS, `<meta name="generator" content="WordPress 6.x">`, asset paths like `/wp-content/`, `/sites/default/files/`, `/_next/static/`, `/static/admin/` → map the forms, parameters, and routes.
- **You suspect there are pages you have not seen** — a thin landing page, an SPA shell, a redirect to `/login`, or a directory that returns `403` (exists but forbidden) → directory and file brute-forcing is warranted.
- **The target is a real FQDN** (not `localhost`, not a raw IP) → subdomain and passive-dataset enumeration (Certificate Transparency, passive DNS) becomes available and cheap.
- **A scan or crawl just changed the picture** — a new vhost, a new port hosting a second web app, a newly discovered subdomain → re-run recon scoped to the newly found surface before sending in specialists.
- **A robots.txt, sitemap.xml, .well-known, or comment in the HTML names a path you have not visited** → enumerate it; these are free leads to hidden surface.

## Use-case scenarios

- **Cold start on any engagement.** You are handed a target with zero prior knowledge. Before any injection, auth-bypass, or IDOR work can be meaningful, someone has to learn what server, framework, language, and CMS are in play, which routes exist, and which inputs the user can drive. recon is that first pass. Dispatching a SQLi or XSS specialist before recon is premature — they have nothing to aim at.
- **The web half of a parallel recon split.** This skill is specifically the *application-layer* reconnaissance lane, meant to run alongside a network/port pass. While the port scan finds open services, recon reads the running web app: homepage HTML first, then directory enumeration, technology fingerprinting, and input-surface mapping. Use it whenever the web tier specifically needs to be understood, independent of what the port scan turns up.
- **Re-orienting after the surface expands.** Mid-engagement you discover a new subdomain, a second app on another path, or a virtual host. Treat that as a fresh unknown surface and recon it before grinding. The map is never "done" the moment the topology grows.
- **Mapping an SPA or JS-heavy app.** When the landing page is a near-empty shell that renders client-side, the interesting endpoints live in the JavaScript bundles and `fetch`/XHR calls, not in the raw HTML. recon (with a rendering fallback) is the right tool to pull those `/api/…` routes and parameter shapes into the open.
- **Finding the hidden admin/backup/config surface.** Login portals, `/admin`, `/phpmyadmin`, `.git/`, `.env`, backup files (`*.bak`, `*.old`, `*.zip`), and dev/staging leftovers are classic recon discoveries that hand a clear target to the specialists. Directory brute-forcing belongs here.
- **Deciding which specialist to dispatch next.** The entire value of recon is producing a surface map clear enough that the planner can route correctly: "there is a `?id=` parameter on a PHP page" → SQLi/IDOR; "there is a file-upload form" → upload-handling specialist; "there is a `url=` parameter that fetches remote content" → SSRF. Without recon, routing is guesswork.

## Concrete tells (request → response examples)

- **Header probe pins the stack:**
  `curl -sI http://target/` →
  ```
  HTTP/1.1 200 OK
  Server: Apache/2.4.49 (Unix)
  X-Powered-By: PHP/7.1.33
  Set-Cookie: PHPSESSID=…; path=/
  ```
  → PHP/Apache app; the exact Apache version is itself worth filing (known-vulnerable). Map routes, then hand off.

- **Generator/asset tells reveal a CMS:**
  `GET /` body contains `<meta name="generator" content="WordPress 6.4.2">` or links to `/wp-content/themes/…` and `/wp-json/` → WordPress. Enumerate plugins/themes and the `/wp-admin` login as input surface.

- **A 403 on a directory means it exists but is protected:**
  `GET /admin/` → `403 Forbidden` (not `404`) → the path is real; note it as a high-priority surface and let gobuster enumerate siblings (`/admin/login`, `/admin/config`).

- **JS reveals an API the HTML hides:**
  Homepage is an empty `<div id="root">`, but the bundle contains `fetch("/api/v1/users?id=1")` → record the `/api/v1/users` endpoint and the `id` parameter shape. These are the inputs the next specialist will exercise.

- **A redirect names the app's front door:**
  `GET /` → `302 Location: /login.php` → a PHP auth surface; map the login form's field names (`username`, `password`, CSRF token) for the auth and injection specialists.

- **robots.txt leaks structure:**
  `GET /robots.txt` → `Disallow: /backup/` and `Disallow: /internal-api/` → free leads; enumerate both.

- **Forbidden-but-listed VCS or dotfile:**
  `GET /.git/HEAD` → `200` with `ref: refs/heads/master` → exposed source repo; file it as a finding and flag for retrieval by a specialist.

## When NOT to use it / easily-confused-with

- **Not for grinding a single endpoint.** The moment you have *located* a form/parameter/route, recon's job is done for that vector — stop and hand off. Firing injection strings, path-traversal sequences, or auth-bypass attempts against one endpoint is the specialist's work, not recon's. recon maps breadth; specialists drill depth.
- **Not the network/port pass.** Open-port discovery, service-version scanning, and non-HTTP service identification belong to the parallel `recon-ports` lane (nmap). recon is the web/app layer only. If the question is "what TCP services are listening", that is the other pass.
- **A *reflected* value is not automatically anything yet.** Seeing a parameter echoed in the response is a surface tell to *record* — it becomes XSS only if it lands in an HTML/JS context unescaped, SQLi only if it reaches a query, SSTI only if it is *evaluated* (`{{7*7}}`→`49`), and LFI only if it is used as a file path. recon notes the reflective parameter and routes it; it does not adjudicate the vuln class.
- **A known-vulnerable version string is a finding, but exploitation isn't recon.** recon should file `Server: Apache/2.4.49` (path-traversal CVE) as a finding and move on — actually exploiting the CVE is a specialist's job.
- **Not for deep credential or business-logic attacks.** Recon maps the login form and notes it; brute-forcing, default-credential testing, and logic-flaw chaining are downstream. Don't route those here.
- **Don't confuse a proxy/view with the real target.** If a single `/api/…` proxy or admin route looks like "the whole objective", note it as high-priority surface and keep mapping — the thing it fronts often lives on another port or route. Fixating on the visible endpoint instead of finding what's behind it wastes the pass.
