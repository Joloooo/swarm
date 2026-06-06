# parameter-pollution — when to use

This skill owns **request-shape manipulation that defeats an access or filter check**. Its core is HTTP Parameter Pollution (duplicate query/body/header params, scalar-vs-array shape confusion, JSON duplicate keys, and parser-precedence differentials between a WAF/gateway and the app). It is also the right route for the sibling case of **HTTP method / verb tampering**, where the security check is bound to one request verb (usually `GET`) and the app serves the protected content under a different verb.

The whole class fires on a *discrepancy between request shapes* — not on a confirmed bypass. The moment two ways of asking for the same thing produce different answers (different verb, duplicated param, array vs scalar), dispatch.

## Dispatch when:

**Method / verb tampering**
- A resource returns `401`/`403` to `GET` but `200` to a different HTTP method. `GET /` → `401 Authorization Required` with `WWW-Authenticate: Basic realm="..."`, yet `OPTIONS /` (or `HEAD` / `POST` / `PUT` / `DELETE` / `TRACE` / a made-up verb like `FOO`) returns the real page body. The auth check is wired to the verb. The status flip on the *same URL* under a *different method* is the confirmation.
- Recon reports "every path returns the same `401`" with a uniform body length (e.g. gobuster aborts: *"the server returns a status code that matches the provided options for non existing urls … 401 (Length: 401)"*). A blanket filter on one verb is the prime verb-tamper candidate. Probe alternate methods immediately rather than pivoting to brute force or gobuster-with-auth.
- A login / auth gate framed as "bypass the login form" that looks monolithic — Basic auth, a single login POST — with no creds path, no leaked id to walk, and no injectable field on the GET surface. Test whether the gate is shape-bound (verb, duplicate param, array vs scalar) before assuming sqli or brute force.
- An old/permissive server banner fronts the gate: `Server: Apache/2.2.x (Unix) … DAV/2`, IIS with WebDAV, etc. Legacy/DAV configs frequently scope an `<Limit GET POST>` / `<LimitExcept>` directive to named methods only, leaving every other verb unprotected — the textbook method-tamper misconfiguration, often the directive written backwards.
- A generic scanner (e.g. nikto) returns protected content the GET-based crawl never saw. nikto issues non-GET methods as part of its checks; if it surfaces a `200` page the crawl missed, that is the same verb-tamper signal.

**HTTP Parameter Pollution**
- A duplicated parameter changes the outcome. `?id=1&id=2` returns a different status/body/record than either single value alone — that delta is the whole bug.
- Two values come back joined: `?p=A&p=B` echoes `A,B` (comma-joined) → a concatenating stack (ASP.NET/IIS, Perl CGI); concatenation lets you split a payload across the comma.
- A perimeter and an origin clearly disagree. Anything fingerprinting a WAF/CDN/API-gateway in front of an app (`Server: cloudflare`, `cf-ray`, `x-amzn-RequestId`, `x-amz-apigw-id`, `Via:`, `X-Kong-*`, an NGINX/ALB banner) combined with a separate backend framework. Two parsers in the path is the precondition for a precedence split.
- A `403`/`406` WAF block on a single-value payload (`?q=<script>`, `?q=' OR 1=1`) at an endpoint that otherwise reflects/uses `q`. Retry the payload as the *second* of a duplicate pair (`?q=safe&q=<payload>`); if the block disappears, it is a pollution-driven filter bypass.
- An authorization check and the business logic look like separate layers (gateway authorizes the request shape, backend fetches the object). Probe `?id=<yours>&id=<target>` for a gateway-vs-backend IDOR.
- A parameter accepts both scalar and array notation: `role=user` works and `role[]=user`, `p[0]=`, `p[k]=`, or nested `user[role]=` is *also* accepted or changes type/behavior → shape-confusion surface.
- Duplicate JSON keys are tolerated: raw body `{"role":"user","role":"admin"}` (built as a literal string, not via a serializer) returns `200` and acts on one of them → JSON last-wins/first-wins differential.
- Trust-bearing headers can be set twice: two `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Original-URL`, or `Host` headers change a trust/routing/ACL behavior.
- A `/graphql` endpoint with rate limiting or per-operation quotas: aliased duplicate operations (`a: login(...) b: login(...)`) or batch arrays in one POST multiply the effect past a per-request limiter.
- An allowlist-validated URL/redirect parameter: duplicate `url=`, `redirect_uri=`, `next=`, `return=` where the first is allowlisted and the second is your choice → SSRF / open-redirect / OAuth augmentation via validate-first / use-last.
- Duplicate `Content-Length` / `Transfer-Encoding` headers are not rejected → request-smuggling-flavored pollution (front-end and back-end pick different framing headers).

## Key use cases:

- **Login-bypass / "get past the auth gate" challenges where the gate is monolithic.** Basic-auth wall or single login form, no creds, no leaked id, no injectable GET field. Cheapest high-value first move: replay the request as `OPTIONS`, `HEAD`, `POST`, `PUT`, `DELETE`, `TRACE`, and a nonsense method, and watch for a status drop from `401`/`403` to `200`. The protected content (and, in CTF/benchmark targets, the flag) is often served verbatim under the unguarded verb.
- **Legacy Apache / IIS / nginx fronting protected content.** Method-scoped auth directives are commonly written backwards; verb tampering is the canonical exploit.
- **Anything behind a WAF/CDN/gateway with a real backend.** The bread-and-butter case: two or more parsers in the request path that can be made to disagree about which copy of a parameter wins. The more layers (CDN → WAF → API gateway → framework router → ORM), the more likely a differential exists.
- **An endpoint where a single-value injection is blocked but the parameter is clearly used.** Before concluding the input is sanitized, rule out that the WAF only inspects the *first* occurrence — pollution is the cheapest WAF-bypass to try.
- **Authorization at a different layer than the data fetch.** AWS API Gateway → Lambda, Kong → upstream, auth proxy → app: the edge authorizes the id you own; the backend reads a different copy and fetches someone else's object. Pollution-chained IDOR.
- **Forms with hidden/protected fields (mass assignment).** A whitelist runs on the first copy but the framework deserializes the *last* copy into the model — append `is_admin=true`, `role=admin`, `balance=99999` as duplicates/extra keys.
- **Fingerprinting the stack when banners are stripped.** A single `?p=A&p=B` probe and observing which value wins (first / last / concatenated / array) is a reliable framework fingerprint even when `Server`/`X-Powered-By` are hidden. Use as a recon multiplier, not only as an exploit.
- **CSRF / OAuth / SAML flows with duplicated control parameters.** `token=valid&token=fake`, duplicate `state`/`client_id`/`redirect_uri` — validate-first / consume-last lets the security-critical value differ from the acted-on value.
- **GraphQL behind a rate limiter.** Per-operation throttles and coupon/credit/login limits are often enforced per HTTP request, so N aliased identical operations in one request multiply the effect.

## Concrete tells (request → response):

**Verb tampering**
- `curl -v http://target/` → `401 Authorization Required`, `WWW-Authenticate: Basic realm="..."`, legacy `Server` banner; then `curl -i -X OPTIONS http://target/` → `200` with the full HTML page (often containing the protected body / flag inline). No further exploitation needed once the body comes back.

**HPP precedence behaviors** (also doubles as a fingerprint)
- **Last-wins** (PHP/Apache, Django, Rails, Express-`qs`): `?p=A&p=B` → acts on **B**; `?p=B&p=A` → acts on **A**. Winner follows position, not value.
- **First-wins** (Flask, Spring `@RequestParam`, JSP/Tomcat, Go `c.Query`, Cloudflare/API-GW rule eval): `?p=A&p=B` → acts on **A**.
- **Concatenation** (ASP.NET/IIS, Perl CGI): `?p=A&p=B` → literal `A,B` in the response. Split a payload across the comma to dodge a contiguous-string WAF rule.

**Exploitation patterns**
- **WAF-vs-app split:** `?q=<script>alert(1)</script>` → `403`; `?q=harmless&q=<script>alert(1)</script>` → `200` and the script lands. WAF inspected the first copy; the app used the last.
- **Gateway-vs-backend IDOR:** `GET /api/account?id=<your-id>&id=<victim-id>` → `200` returning the **victim's** record while the edge ACL passed on your own id.
- **JSON duplicate-key differential:** `POST {"role":"user","role":"admin"}` (raw string) → `200`, account now `admin` (last-wins), vs. `400 duplicate key` (parser rejects → no bug), vs. acted-on `user` (first-wins).
- **Array/shape confusion:** `role=user` normal; `role[]=user&role[]=admin` → privilege change, type error, or a stack trace revealing the binder. Any *change* between scalar and array form is the tell.
- **Header pollution:** two `X-Forwarded-For` headers (`1.2.3.4` and `127.0.0.1`) → an internal-only feature unlocks, or rate-limit/ACL keys off the wrong address.
- **Parameter cloaking:** `?par%61m=evil` (decodes to `param`) or `?PARAM=evil` bypasses a WAF rule keyed on literal lowercase `param` while the backend still binds it.

## When NOT to use / easily confused with:

- **No second parser in the path.** A lone app server (no WAF/CDN/gateway) with a consistent winner across every layer has no differential — the framework's documented precedence alone is not a vulnerability. Don't dispatch just because you can name the precedence.
- **The duplicate request errors out.** Strict binders (Spring strict mode, Hapi/Joi rejecting duplicates) or a JSON parser returning `400 duplicate key` give an error, not a split — false positive, move on.
- **The CDN collapses duplicates before the origin.** If the edge strips or merges the second copy so both values arrive identical, there is nothing to exploit. Confirm the second copy actually *reaches* the app.
- **A guessable object id in URL/cookie is IDOR, not this.** `GET /profile/6` showing another user's data by changing the id is `idor` — the reference is the bug. This skill is for when *no* id is exposed and the gate itself is shape-bound. Pollution-IDOR specifically requires the gateway-authorizes-one / backend-reads-another split.
- **A monolithic auth gate bypassed with stolen/forged credentials or a logic flaw is `auth-testing` / `business-logic`.** Route here only when the bypass comes from *changing the request shape* (verb, duplicated/array param), not from guessing creds, replaying a token, or abusing a multi-step flow.
- **A reflected/executed single value is the injection class itself** (`xss` / `ssti` / `sqli` / `ssrf`), not pollution. Pollution is only the *delivery trick* that gets a blocked payload past a filter — route here only when the duplicate/shape is what you are testing, then hand the landed payload to the matching injection skill. A WAF block you defeat by encoding/casing of one copy alone is generic injection evasion, not HPP.
- **Mass assignment via an unrelated extra field.** If you can just *add* `is_admin=true` once (no duplication, no precedence trick) and it sticks, that is over-posting → mass-assignment skill. Pollution is when the duplicate-and-precedence mechanic is what defeats the whitelist.
- **Response deltas from caching, load balancing, or A/B tests.** A different body on the duplicated request can be a cache or canary, not a parser split. Pair every probe with a single-value baseline and confirm the only changed variable is the duplicate/shape.
- **Don't over-fire on every `401`.** A `401` genuinely enforced on all verbs is not method-tamper — move on to credential/token testing. The trigger is the *discrepancy* between verbs, not the `401` itself.
