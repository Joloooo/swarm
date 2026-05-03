---
name: mitigations
description: Cross-cutting reference for common defensive mitigations — input validation, output encoding, parameterized queries, CSP, Trusted Types, SameSite cookies, CSRF tokens, rate limiting, WAF deployment, sandboxing, RBAC / ABAC, audit logging — what each prevents and the typical bypass classes. Used by attack skills to recognize when a target has a particular mitigation in place and pivot accordingly. Reference-only — not dispatched as an attack agent.
---

# Mitigations Reference

Defensive controls deployed by web targets. Attack agents consult this catalogue to (a) recognize which mitigation is in place from observable signals, (b) understand the threat class it blocks, and (c) pivot to a bypass class or a different vector. This is reference material — never dispatched as an agent. Other skills cite it.

A mitigation does not equal immunity. Most have well-known bypass classes; weakness is usually misconfiguration, partial coverage, or a stale ruleset. The catalogue below is organised by control family.

## Mitigation catalogue

### Input validation & sanitisation

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| Allowlist input validation | Reject anything not matching a strict regex / type / range | Injection of unexpected payloads, oversized input, type confusion | Encoding tricks (URL, Unicode, double-encode), parser differentials, fields validated server-side but rendered raw client-side |
| Denylist filtering | Strip / reject known-bad tokens (`<script`, `UNION`, `../`) | Naive payload variants | Case variation, comment injection (`UN/**/ION`), nested tags (`<scr<script>ipt>`), null byte, alternate keywords (`SLEEP` vs `BENCHMARK`), polyglot |
| HTML sanitiser (DOMPurify, OWASP Java HTML Sanitizer) | Parse → allowlist tags/attrs → reserialise | Stored / reflected XSS in HTML sinks | Mutation XSS (mXSS), namespace confusion (SVG/MathML), parser desync between sanitiser and browser, stale library version |
| Parameterised queries / prepared statements | DB driver binds params separately from SQL text | SQL injection via string concatenation | Second-order injection (data stored unsafely, used unsafely later), dynamic identifiers (table/column names) still concatenated, ORM raw-query escape hatches |
| Stored procedure / ORM | Abstracts SQL behind typed API | Most direct SQLi | `exec`, `raw`, `where(stringFragment)` escape hatches; SQL inside the stored proc itself |
| Output encoding (context-aware) | Encode per sink: HTML, attribute, JS, URL, CSS | Reflected XSS | Wrong context applied (HTML-encode in JS sink), template auto-escape disabled (`\| safe`, `dangerouslySetInnerHTML`), DOM XSS sinks bypass server encoding entirely |
| Path canonicalisation | Resolve `..`, symlinks, encoding before access check | Path traversal, LFI | Double-decode (`..%252f`), Unicode (`..`), TOCTOU between canonicalise and open, OS-specific separators (`\` on Windows) |
| File-upload type/extension allowlist | Whitelist MIME, extension, magic bytes | Webshell upload, polyglot payload | Double-extension (`shell.jpg.php`), null-byte truncation (legacy), MIME-sniff vs declared, content-type set client-side, `.htaccess` upload, Apache mod_mime parsing of multi-extension |
| Schema validation (JSON Schema, OpenAPI, protobuf) | Reject body not matching schema | Type juggling, prototype pollution via unexpected keys | `additionalProperties: true` default, `oneOf` ambiguity, deeply-nested DoS, schema validated but raw object passed to ORM |
| Server-side length limits | Cap request / field size | Buffer attacks, regex-DoS, oversized log writes | Limit applied at proxy but not app, gzip-bomb body, multipart per-part limit missing |

### Browser-enforced controls

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| Content Security Policy (CSP) | Response header restricts script/style/connect/frame sources | Inline XSS, exfil to attacker domain | `unsafe-inline`, `unsafe-eval`, wildcard (`*`), allowlisted CDN with JSONP/Angular/AMD, `data:` in `script-src`, dangling-markup, base-tag injection, missing `frame-ancestors` |
| Trusted Types | Forces sink assignments to go through a typed policy | DOM XSS in `innerHTML`, `eval`, `setTimeout(string)` | Policy with bypassable rules, `default` policy that returns input unchanged, sinks not covered (CSS, SVG), report-only mode |
| SameSite cookies (`Lax` / `Strict`) | Browser strips cookie on cross-site request | CSRF on state-changing endpoints | Top-level GET still sends Lax cookies; `<form method=POST>` after navigation; subdomain takeover; `SameSite=None; Secure` reverts to old behaviour; missing on legacy browsers |
| `HttpOnly` cookie | JS cannot read cookie via `document.cookie` | Session theft via XSS | XS-Leaks (timing, length); ServiceWorker; XSS still allows in-session requests |
| `Secure` cookie | Browser only sends over HTTPS | Cookie capture on plaintext | Mixed-content path; downgrade attack on first navigation if no HSTS preload |
| HSTS (+ preload) | Force HTTPS, refuse cert errors | TLS strip, MITM cert swap | Not preloaded → first-visit window; subdomain not covered (no `includeSubDomains`); user already trusted bad cert |
| CORS (allowlisted origins, no wildcard with creds) | Browser blocks cross-origin reads | Cross-origin data theft | Reflective `Access-Control-Allow-Origin`, null-origin allowed, regex bug (`evil-victim.com`), preflight cached, `Access-Control-Allow-Credentials: true` with wildcard |
| X-Frame-Options / `frame-ancestors` | Block embedding in iframe | Clickjacking | Missing on a sibling page; only set by reverse proxy, app sometimes serves direct |
| Subresource Integrity (SRI) | `integrity=sha384-…` on script tags | Compromised CDN serving altered JS | Missing on dynamic loaders, CDN ships unhashed bundle, `crossorigin` misconfig disables enforcement |
| Permissions-Policy / Feature-Policy | Disable browser features (camera, geolocation, payments) per origin | Abuse of powerful APIs from injected JS | Header missing, allow-list includes attacker iframe origin, policy not propagated through redirect chain |
| `Sec-Fetch-*` server-side checks | Inspect `Sec-Fetch-Site/Mode/Dest` to reject cross-site state-changing requests | CSRF, drive-by request | Header forwarded by proxy and trusted blindly, legacy browser does not send headers → fall-back-allow |

### Anti-CSRF

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| Synchroniser token (per-session / per-request) | Server-issued nonce echoed in form / header | Forged state-changing requests | Token leaked via referrer/XSS, token not validated on subset of endpoints, same token for all users, validated only when present |
| Double-submit cookie | Token in cookie + header, server compares | CSRF without server state | Cookie-set on subdomain attacker controls; `httpOnly`-less cookie read by XSS |
| Origin / Referer check | Reject if `Origin` header not in allowlist | CSRF | Header stripped by privacy tooling → server falls back to allow; null origin (sandboxed iframe, `data:`); regex bug |

### Network / infrastructure

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| Rate limiting (per-IP / per-user / per-endpoint) | Reject after N reqs / window | Brute force, credential stuffing, scraping | Rotate IP (proxy pool, X-Forwarded-For if trusted blindly), distribute across accounts, race-condition window, parallelise within burst budget, sub-resource endpoints unprotected |
| Account lockout | Disable account after N failed logins | Online password brute force | User enumeration via lockout response, denial-of-service by lockout, password-spray (one pw across many users) |
| WAF (Cloudflare, AWS WAF, ModSecurity / OWASP CRS) | Signature + scoring on req body, headers, URL | Common SQLi/XSS/RCE payloads | Encoding mutations, payload chunking via parser differential, HTTP request smuggling past WAF, IP origin direct (bypass CDN), oversized body skipped, JSON vs form parser mismatch, time-based blind variants below scoring threshold |
| IP allowlist / VPN-only admin | Network ACL on admin endpoints | Direct admin access from internet | SSRF pivoting from a public app server in the allowlist, DNS rebinding, internal service exposed via misconfigured proxy |
| TLS / mTLS | Cert-based client auth | Unauthenticated access to backend | Stolen cert / key, mTLS terminated at proxy that forwards plaintext, downgrade if server allows fallback |
| Bot management (Turnstile, hCaptcha, reCAPTCHA, device fingerprint) | Score-based challenge on suspicious traffic | Credential stuffing, content scraping | Solver services, residential-proxy + headless-browser stack, replay valid token across many requests, target unprotected JSON endpoint behind same auth |
| Geo / ASN blocking | Drop traffic from listed regions / ASNs | Region-targeted abuse | Residential-proxy in allowed region, Tor exits, mobile carrier ASN treated as benign |

### Authentication & session

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| MFA / TOTP / WebAuthn | Second factor on login | Pure password compromise | MFA fatigue / push bombing, SIM swap on SMS-OTP, phishing proxy (evilginx) for TOTP, recovery flow weaker than primary, session-cookie theft post-MFA |
| Session expiry + rotation on privilege change | Invalidate or rotate session ID on login / role change | Session fixation, stale-token reuse | Token never rotated, parallel sessions allowed, refresh token long-lived and unrevocable |
| Password policy + breach-list check | Reject weak / pwned passwords | Trivial brute force | Common-but-not-pwned passwords, predictable seasonal patterns, user reuses across sites |
| OAuth / OIDC with PKCE | Code-flow with verifier | Auth-code interception | `state` not validated (CSRF on login), open redirect on `redirect_uri`, implicit-flow legacy endpoints, mix-up attack across IdPs |
| Device-binding / risk-based step-up | Re-prompt MFA on new device or anomalous location | Pure cookie theft | Cookie + device-fingerprint replayed together, stolen refresh token still valid, risk engine tunable threshold |
| Sign-out revokes refresh tokens | Server-side revoke on logout | Stolen-token reuse after logout | Soft-logout that only clears cookie, refresh-token DB not consulted on access-token issue |

### Authorisation

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| RBAC (role-based) | Each user has roles; endpoint requires role | Vertical privilege escalation | Missing check on a single endpoint (BOLA-adjacent), client-side-only enforcement, role assigned via tamperable JWT claim |
| ABAC (attribute-based) / policy engine (OPA, Cedar) | Decision against attribute predicates | Complex auth logic drift | Policy bug (default-allow on unknown action), attribute spoofable from request, cache stale after revoke |
| IDOR protection (object-scoped queries) | `WHERE owner_id = current_user` in every query | BOLA / IDOR | One handler missing the scope, indirect access via batch endpoint, GraphQL field-level missed, predictable IDs make discovery trivial |
| Scope checks on tokens (OAuth scopes) | Token grants only listed scopes | Over-privileged token misuse | Scope checked at token issue but not per-request, scope-elevation via refresh-token reuse |

### Sandboxing & isolation

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| Iframe sandbox (`sandbox` attribute) | Restrict scripts/forms/popups in untrusted frame | Embedded-content takeover | `allow-same-origin` + `allow-scripts` together = full bypass; postMessage handler trusts origin loosely |
| Server-side template sandbox (Jinja `SandboxedEnvironment`, Twig sandbox) | Block dangerous attribute access in template | SSTI → RCE | Known sandbox-escape gadget chains (`__class__.__mro__`, `_self.env`), version-specific gaps, unsandboxed includes |
| Container / OS sandbox (seccomp, AppArmor) on render workers | Restrict syscalls | Sandbox escape from RCE | Allowed syscall chain (`io_uring`, `userfaultfd`), kernel CVE, mount/`/proc` leak, capabilities not dropped |
| SSRF allowlist + metadata-IP block (169.254.169.254, link-local, loopback, RFC1918) | Reject outbound to internal ranges | Cloud-metadata theft, internal pivot | DNS rebinding, redirect chain to internal IP, `0.0.0.0` / IPv6 / decimal / hex IP encodings, alternate metadata host (GCP `metadata.google.internal`) |
| `noopener` / `noreferrer` on `target=_blank` | Strip `window.opener` | Tabnabbing | Dynamically-set `window.open` without flag |

### Logging & detection

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| Audit log (auth events, admin actions, data export) | Append-only event stream | Undetected breach | Logs writable by app role → wipeable post-RCE, sensitive params logged in plaintext (token leak), retention too short |
| Anomaly detection / SIEM rules | Baseline + rule-based alerts | Slow data exfil, account takeover | Low-and-slow under threshold, behaviour from legitimate-looking IP, alert fatigue / muted rule |
| Honeytokens / canaries | Fake credentials / files trigger alert on use | Detect post-compromise lateral movement | Skilled attacker recognises canary by structure / domain / path |
| Request ID / correlation ID propagation | Each request gets traceable ID across services | Forensic gaps | None directly bypassable, but predictable IDs leak request volume; verbose error pages echo internal IDs |
| Error sanitisation | Generic 500 page; stack traces only in internal logs | Info-leak via stack trace | Debug mode left on in staging, error page differs in length / Content-Length leaking branch taken, Werkzeug / Whoops debug console exposed |

### Cryptography & data-at-rest

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| Password hashing (Argon2id, bcrypt, scrypt) | One-way hash with per-user salt + cost | Offline cracking after DB dump | Low cost factor, missing salt, fast hash (MD5/SHA1), GPU/ASIC for bcrypt, stolen pepper key |
| Encryption-at-rest (TDE, KMS-wrapped) | DB / disk encrypted at the storage layer | Disk-level theft | App role still reads decrypted; key stored next to ciphertext; backup unencrypted |
| JWT signing (RS256/EdDSA) + `kid` allowlist | Verify token signature with public key | Forged tokens | `alg: none` accepted, HS256 confusion using public key as HMAC secret, weak HS256 secret, `kid` parameter SQLi/path-traversal, expired-but-not-validated `exp` |
| HMAC-signed URLs / tokens (S3 pre-signed, image-resize CDN) | Server signs URL params, client cannot tamper | Parameter tampering on signed resource URL | Signature covers only subset of params, expiry too long, key reused across tenants, length-extension on broken HMAC |

### Supply chain & build

| Control | Mechanism | Prevents | Bypass classes |
|---|---|---|---|
| Lockfile + integrity hashes (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) | Pin transitive versions with hashes | Dependency-confusion swap | Lockfile not committed, `--frozen-lockfile` not enforced in CI, internal scope unreserved on public registry |
| SBOM + CVE scanning (Snyk, Dependabot, `npm audit`) | Inventory + alert on vulnerable deps | Known-CVE exploitation | Scanner stale, false-negative on transitive, severity bucket ignored, scanner only scans prod manifest not dev |
| Signed container images (cosign / Notary) | Verify image signature at deploy | Tampered image in registry | Verification only at admission controller, sidecar pulled unsigned, base image trust transitively assumed |

## Recognition signals

How an attack agent infers a mitigation is in place from observable behaviour. Most signals come from response headers, error pages, or response timing.

| Signal | Likely mitigation |
|---|---|
| `Content-Security-Policy` header on HTML responses | CSP — read directives, look for `unsafe-inline`, `unsafe-eval`, wildcards, missing `frame-ancestors` |
| `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` | Security-headers baseline (often via reverse proxy) |
| `Set-Cookie` with `HttpOnly; Secure; SameSite=Lax\|Strict` | Cookie hardening — HttpOnly blocks JS read, SameSite blocks most CSRF |
| `Server: cloudflare`, `cf-ray`, `__cfduid`, `cf-cache-status` | Cloudflare WAF/CDN front |
| `x-amz-cf-id`, `x-cache: Hit from cloudfront` | AWS CloudFront (often + AWS WAF) |
| `x-sucuri-id`, `x-akamai-*`, `x-iinfo` (Imperva) | Other WAFs |
| 403 with body containing "Request blocked", "Access denied", challenge page, captcha | WAF block — fingerprint vendor from page text |
| 429 + `Retry-After` header | Rate limit — note window and per-IP vs per-user |
| Login response always identical timing for valid/invalid user | User-enumeration mitigation (constant-time compare or unified error) |
| Password reset says "if account exists, email sent" regardless of input | Username enumeration mitigation |
| Hidden form field `csrf_token`, `_token`, `authenticity_token`, or `X-CSRF-Token` header on AJAX | CSRF synchroniser token |
| `Origin` / `Referer` validated (request without them rejected) | Origin-check CSRF defence |
| Captcha on form (hCaptcha, reCAPTCHA, Turnstile) | Bot mitigation, often layered with rate limit |
| Server returns parameter-sanitised echo (`<` becomes `&lt;` in reflection) | Output encoding active — try DOM-XSS sinks instead |
| SQL error messages absent on injection probe; only generic 500 | Error suppression, possibly parameterised queries |
| `WWW-Authenticate: Bearer realm="…", error="invalid_token"` | OAuth bearer auth, possibly with scope enforcement |
| Identical 404 for `/admin` and `/admin-this-does-not-exist` | Admin path possibly behind allowlist; no leak via differential response |
| JS bundle imports DOMPurify / sanitize-html | Client-side sanitiser — try mXSS / version-specific bypass |
| `Sec-Fetch-Site`, `Sec-Fetch-Mode` checked server-side (rejecting cross-site) | Modern fetch-metadata defence |
| Response sets `Trusted-Types: …` or `Content-Security-Policy: require-trusted-types-for 'script'` | Trusted Types enforced — DOM-XSS dramatically harder |

## Rules

- Treat the catalogue as a checklist for response-fingerprinting, not as a list of "things to attack". Mitigations themselves are not the target.
- When recon notes a mitigation, the next attack skill must pick a bypass class from the relevant row, not blindly retry the default payload.
- Absence of a header is itself a signal — note it in findings; a missing `X-Frame-Options` opens clickjacking even on a hardened app.
- WAF presence is a soft block, not a hard one. Always try at least one encoding-mutation payload and one chunked / smuggled variant before concluding the endpoint is safe.
- Rate-limit hits (429) are recon data: they reveal that the endpoint is monitored. Slow down, do not abandon — switch to a parallelisable variant or a different endpoint of the same flow.
- Constant-time / unified error responses on auth flows mean username enumeration via this endpoint is closed; pivot to other oracles (password reset, registration uniqueness check, OAuth social-login probe).
- Never assume a sanitiser is current. Note the library + version when fingerprintable (script tag URL, source map, bundle comment) and check against the known-bypass list for that exact version.
- A mitigation listed as "in place" in one response is only proven for that one endpoint. Probe sibling endpoints — coverage gaps are the most common real-world weakness.
- Do not trust client-side enforcement. Anything enforced only in JS (form validation, role gating, rate limiting) is bypassable by replaying the raw request.
- When two mitigations layer (e.g. CSP + Trusted Types, or WAF + parameterised queries), the realistic path is usually a logic / authorisation flaw, not a payload bypass — pivot to BOLA / business-logic skills.
- Findings must record both the mitigation observed and the bypass class attempted, so the report can show defence-in-depth coverage gaps.
