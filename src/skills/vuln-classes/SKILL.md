---
name: vuln-classes
description: Cross-cutting catalogue of web-pentest vulnerability classes — symptom-to-class mapping, OWASP Top 10 alignment, CWE references, and pointers to the specific SwarmAttacker skill that handles each class (sqli, xss, ssrf, idor, bfla, rce, xxe, csrf, lfi, ssti, deserialization, mass-assignment, race-conditions, request-smuggling, parameter-pollution, etc.). Used by the planner to identify which skill to dispatch when given a fuzzy finding description. Reference-only — not dispatched as an attack agent.
---

This skill is a **reference catalogue**, not an attack agent. It is loaded by
the planner (or by other skills consulting "what class is this finding?")
when a recon worker reports an observation that does not yet name a class —
e.g. "the `id` parameter reflects in HTML", "the server fetches a URL the
user supplies", "the API returns another tenant's record". Map the symptom
to the class column, then dispatch the SwarmAttacker skill in the right-most
column.

The catalogue covers the web-app classes SwarmAttacker actually handles.
Memory-corruption classes (UAF, heap overflow, format string, type
confusion) are out of scope — SwarmAttacker is a black-box web pentester,
not an exploit-dev framework.

## Class catalogue

| Symptom (what recon saw) | Class | Primary CWE | SwarmAttacker skill |
|--------------------------|-------|-------------|---------------------|
| `id`, `q`, `search` reflected in body unchanged | Reflected XSS | CWE-79 | `xss` |
| User input rendered later in another user's page | Stored XSS | CWE-79 | `xss` |
| URL fragment / `location.hash` ends up in `innerHTML` / `document.write` | DOM XSS | CWE-79 | `xss` |
| Quote in parameter triggers SQL error / 500 / behavioural delta | Error-based SQLi | CWE-89 | `sqli` |
| `' AND 1=1` vs `' AND 1=2` give different responses | Boolean blind SQLi | CWE-89 | `sqli` |
| `SLEEP(5)` / `pg_sleep(5)` measurably delays response | Time-based SQLi | CWE-89 | `sqli` |
| Param taken into a `find_one`, `aggregate`, `$where` Mongo call | NoSQL injection | CWE-943 | `sqli` (NoSQL section) |
| Endpoint fetches a URL we control (webhook, image proxy, RSS, PDF render) | SSRF | CWE-918 | `ssrf` |
| SSRF that reaches cloud metadata (`169.254.169.254`) | SSRF → cloud creds | CWE-918 | `chain-ssrf-to-rce` |
| Numeric / UUID resource ID in URL or body, swap → other user's data | IDOR | CWE-639 | `idor` |
| `/admin/*` returns 200 for a normal user (no role check) | BFLA / vertical priv-esc | CWE-285 | `bfla` |
| `?role=admin` or hidden `is_admin` field accepted in POST/PUT | Mass assignment | CWE-915 | `mass-assignment` |
| `..%2F..%2Fetc/passwd` / `?file=../../../` returns file contents | Path traversal / LFI | CWE-22 / CWE-98 | `lfi` |
| Uploaded `.php` / `.jsp` / `.aspx` lands in webroot and executes | Unrestricted file upload → RCE | CWE-434 | `insecure-file-uploads` |
| Template syntax `{{7*7}}` returns `49`, `${7*7}` returns `49` | SSTI | CWE-1336 / CWE-94 | `ssti` |
| Backticks / `;id` / `|whoami` injected into shell via app | OS command injection | CWE-78 | `rce` |
| `java.io.ObjectInputStream`, pickled blobs, `__proto__`, YAML tags accepted | Insecure deserialization | CWE-502 | `rce` |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` returns the file | XXE | CWE-611 | `xxe` |
| State-changing POST works with no CSRF token / no Origin check | CSRF | CWE-352 | `csrf` |
| `Host:` header reflected in password-reset link / cache key | Host header injection | CWE-20 | `csrf` (request-smuggling neighbour) |
| Front/back-end disagree on `Content-Length` vs `Transfer-Encoding` | HTTP request smuggling | CWE-444 | `request-builder` (manual) |
| `?a=1&a=2` collapses or splits differently across hops | HTTP parameter pollution | CWE-235 | `request-builder` (manual) |
| `Location: /redirect?url=https://evil` follows arbitrary host | Open redirect | CWE-601 | `open-redirect` |
| `*.staging.target.com` CNAMEs to an unclaimed S3 / GitHub Pages | Subdomain takeover | CWE-1395 | `subdomain-takeover` |
| Same endpoint hit N× concurrently mints N coupons / N transfers | Race condition | CWE-362 | `race-conditions` |
| Login with `' OR 1=1--`, weak lockout, password reset via Q&A | Auth bypass | CWE-287 / CWE-307 | `auth-testing` |
| Session ID predictable / not rotated on login / leaked in URL | Session-mgmt flaw | CWE-384 / CWE-598 | `session-mgmt` |
| `eyJ...` JWT with `alg:none`, weak HS256 secret, `kid` injection | JWT forgery | CWE-345 | `auth-testing` |
| `/api/v1/.git/config`, `.env`, `Dockerfile`, `swagger.json` reachable | Information disclosure | CWE-200 / CWE-538 | `information-disclosure` |
| Stack trace, framework banner, full SQL dumped on error | Verbose errors | CWE-209 | `error-handling` |
| TLS 1.0, RC4, expired cert, mixed content, predictable token | Crypto misuse | CWE-327 / CWE-330 | `crypto` |
| Workflow can be re-ordered (skip payment, replay step) | Business-logic flaw | CWE-840 | `business-logic` |
| Upper- vs lower-case path bypasses auth / case in email validation | Input-validation bypass | CWE-20 | `input-validation` |
| `Cache-Control: public` on per-user response, victim's data served from cache | Web cache deception / poisoning | CWE-525 | `information-disclosure` |
| `<form action="javascript:...">` accepted, `javascript:` URL in profile field | JS-URL injection | CWE-79 | `xss` |
| `Content-Type: text/xml` body parsed even on JSON endpoint | Content-type confusion | CWE-436 | `xxe` |
| Reset-token brute-forceable / token reuse / token in URL referer-leak | Broken password reset | CWE-640 | `auth-testing` |
| `?next=//evil.com` after login redirects off-site | Open redirect via auth flow | CWE-601 | `open-redirect` |
| `Origin: null` accepted by `Access-Control-Allow-Origin` reflection | CORS misconfiguration | CWE-942 | `csrf` |
| `WebSocket` upgrade with no origin check, cross-site WS hijack | CSWSH | CWE-346 | `csrf` |
| GraphQL `__schema` introspection enabled in prod, batched query DoS | GraphQL misconfiguration | CWE-200 | `information-disclosure` |
| Long-running endpoint not rate-limited, single IP can exhaust workers | App-layer DoS | CWE-770 | `business-logic` |

## OWASP Top 10 alignment

The catalogue maps to OWASP Top 10 (2021) as follows. When the planner needs
to report against Top-10 categories, route by class first, then bucket here.

| OWASP Top 10 (2021) | Classes covered above |
|---------------------|----------------------|
| A01 — Broken Access Control | IDOR, BFLA, mass assignment, path traversal, CSRF |
| A02 — Cryptographic Failures | Crypto misuse, JWT forgery, session leakage |
| A03 — Injection | SQLi, NoSQLi, command injection, SSTI, XSS, XXE |
| A04 — Insecure Design | Business-logic flaws, race conditions |
| A05 — Security Misconfiguration | Verbose errors, exposed `.git`/`.env`, default creds |
| A06 — Vulnerable / Outdated Components | (out of scope: dependency-side) |
| A07 — Identification & Auth Failures | Auth bypass, weak session mgmt, JWT issues |
| A08 — Software & Data Integrity Failures | Insecure deserialization, unsigned updates |
| A09 — Security Logging & Monitoring Failures | (out of scope: defender-side) |
| A10 — SSRF | SSRF, SSRF→cloud-metadata chain |

OWASP API Top 10 mostly overlaps; the API-specific ones map as:
`API1 → idor`, `API3 → bfla`, `API6 → mass-assignment`, `API8 →
information-disclosure`, `API10 → ssrf`.

## Class hierarchy (tie-breakers)

When a symptom legitimately matches two rows, prefer the row higher in the
following list. The order is: cheaper-to-confirm first, higher-impact
first, more-specific first.

1. `information-disclosure` — exposed `.git` / `.env` / Swagger is a single
   GET, confirms instantly, and often hands you creds for everything else.
2. `idor` / `bfla` — flip an ID, change a session cookie. One request each.
3. `sqli` (error-based) → `sqli` (boolean) → `sqli` (time-based). Cheaper
   oracles first.
4. `ssrf` — one outbound DNS lookup confirms it. Pair with
   `chain-ssrf-to-rce` only after baseline SSRF is proven.
5. `xss` — reflected before stored before DOM. Reflected has the cheapest
   sentinel oracle (single token round-trip).
6. `rce` (command-injection) → `ssti` → `rce` (deserialization). Try shell
   metacharacters before template syntax before crafted serialised blobs.
7. Everything else — by class catalogue order.

## Rules

- **Reference only.** Do not call this skill as an attack agent. It has no
  `agent_id`, no `tools`, no `max_tool_calls`. Other skills *consult* it.
- **One class per finding.** When a symptom plausibly fits two classes (e.g.
  "user input ends up in a system call" → command-injection vs SSTI),
  dispatch the cheaper / more specific skill first. Only escalate if the
  first skill returns negative.
- **Class names are stable.** Use exactly the skill names in the right-most
  column when writing into `state.findings.skill` so the planner can
  correlate runs.
- **CWE is the lingua franca.** When emitting a finding to the report, fill
  the CWE column from this table verbatim. Do not invent new CWE numbers.
- **Out of scope here:** memory-corruption classes (stack/heap overflow,
  UAF, type confusion, format string, integer overflow). Those belong to
  binary exploit-dev tooling, not SwarmAttacker. If a recon worker reports
  a binary-side finding (rare for web targets — only via file-upload of a
  native binary), record it but do not dispatch.
- **Out of scope, social:** phishing, OSINT, password-cracking off-target.
  SwarmAttacker stays inside the HTTP boundary of the target.
- **When in doubt, prefer `request-builder`.** If recon's symptom doesn't
  match any row above, the input/output transformation is itself the
  signal. Hand it to `request-builder` for one more probing input rather
  than guess a class.
- **Update protocol.** When a new class is added to SwarmAttacker (new
  skill folder under `src/skills/`), append a row here. The planner reads
  this table; an unmapped skill is invisible to it.
- **Symptoms drift.** WAFs and frameworks change response shapes. Treat
  the "Symptom" column as a starting hypothesis, not a certainty —
  always confirm via the dedicated skill's own oracle (e.g. `sqli`'s
  boolean-vs-time differential, `xss`'s reflected-token sentinel,
  `ssrf`'s out-of-band callback) before writing the finding.
- **Compound findings.** A single endpoint can host two classes (e.g. an
  IDOR-vulnerable admin route is also missing a CSRF token). Emit one
  finding per class, not one combined "everything is broken" finding —
  the report aggregates per CWE and combined findings get lost.
- **Framework hints sharpen the prior.** Recon's `framework-fastapi`,
  `framework-nestjs`, `framework-nextjs` skills tag the stack. Use that
  to bias which class to try first: FastAPI/Pydantic → mass-assignment
  is rarer (Pydantic strict by default) but SSRF in webhook handlers is
  common; Express/NestJS → mass-assignment via `req.body` spread is
  classic; Next.js → SSRF in `next/image` `?url=` is well-known.
- **Black-box only.** This catalogue is for symptoms an unauthenticated
  or low-priv attacker can observe through HTTP. Source-code-only flaws
  (timing side channels in cryptographic primitives, supply-chain
  typosquatting, build-time RCE) are excluded — SwarmAttacker has no
  source-code access.
- **One-line finding template.** When a dispatched skill confirms a
  class, write back into state as: `class=<column-3-class-name>`,
  `cwe=<column-3-CWE>`, `skill=<column-4-skill-name>`,
  `endpoint=<url>`, `evidence=<short string>`. Keep the schema flat; the
  reporter joins on `class`.
