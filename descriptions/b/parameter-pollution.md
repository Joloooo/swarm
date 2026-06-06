# parameter-pollution — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A duplicated parameter changes the outcome.** If you send the same key twice (`?id=1&id=2`) and the response differs from either single value alone — different status, different body, a different record returned — → this skill applies. That delta is the whole bug.
- **Two values come back joined.** If `?p=A&p=B` echoes `A,B` (comma-joined) anywhere in the response → you are on an ASP.NET/IIS or Perl-CGI-style concatenating stack; concatenation is a classic pollution primitive (smuggle a payload across the comma).
- **A perimeter and an origin clearly disagree.** Anything that fingerprints a WAF/CDN/API-gateway in front of an app — `Server: cloudflare`, `cf-ray`, `x-amzn-RequestId`, `x-amz-apigw-id`, `Via:`, `X-Kong-*`, an NGINX/ALB banner — combined with a separate backend framework → dispatch. Two parsers in the path is the precondition for a precedence split.
- **A 403/406 WAF block on a payload you believe should land.** If a single-value injection probe (`?q=<script>` , `?q=' OR 1=1`) gets blocked but the endpoint otherwise reflects/uses `q` → try the same payload as the *second* of a duplicate pair (`?q=safe&q=<payload>`). If the block disappears and the payload reaches the app → pollution-driven filter bypass; this skill owns that move.
- **An authorization check and the business logic look like separate layers.** Gateway-authorized request shapes (`Authorization:` validated at the edge, object id in the query) → probe `?id=<yours>&id=<target>` for an IDOR via gateway-vs-backend split.
- **A parameter accepts both scalar and array notation.** If `role=user` works and `role[]=user` *also* works (or changes the type/behavior), or `p[0]=`, `p[k]=`, nested `user[role]=` are accepted → shape-confusion surface; dispatch.
- **Duplicate JSON keys are tolerated.** POST a literal body `{"role":"user","role":"admin"}` (built as a raw string, not via a serializer). If it returns 200 and acts on *one* of them → last-wins/first-wins JSON differential; this skill applies.
- **Trust-bearing headers can be set twice.** Sending two `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Original-URL`, or `Host` headers and seeing a trust/routing/ACL behavior change → header pollution surface.
- **A `/graphql` endpoint with rate limiting or per-operation quotas.** Aliased duplicate operations (`a: login(...) b: login(...)`) or batch arrays in one POST → alias/batch pollution to defeat the per-request limiter; dispatch here.
- **An allowlist-validated URL/redirect parameter.** Duplicate `url=`, `redirect_uri=`, `next=`, `return=` where the first is allowlisted and the second is attacker-chosen → SSRF/open-redirect/OAuth augmentation via validate-first-use-last.
- **Duplicate `Content-Length` / `Transfer-Encoding` headers are not rejected.** Front-end and back-end picking different framing headers → request-smuggling-flavored pollution.

## Use-case scenarios

- **Anything sitting behind a WAF/CDN/gateway with a real backend behind it.** This is the bread-and-butter case. The skill's value is precisely when there are *two or more parsers in the request path* and you can make them disagree about which copy of a parameter wins. The more layers (CDN → WAF → API gateway → framework router → ORM), the more likely a differential exists.
- **An endpoint where a single-value injection is blocked but the parameter is clearly used.** Before concluding the input is sanitized, you must rule out that the WAF only inspects the *first* occurrence. Pollution is the cheapest WAF-bypass to try, so route here early when a signature-based block stands between you and an otherwise-confirmed sink.
- **Authorization that happens at a different layer than the data fetch.** AWS API Gateway → Lambda, Kong → upstream, an auth proxy → app. The edge authorizes the id you own; the backend reads a different copy and fetches someone else's object. Classic pollution-chained IDOR.
- **Forms with hidden/protected fields (mass assignment).** When a form whitelists fields but the framework deserializes the *last* copy into the model after the whitelist ran on the first — append `is_admin=true`, `role=admin`, `balance=99999` as duplicates/extra keys.
- **Identifying the stack when banners are stripped.** A single `?p=A&p=B` probe and observing which value wins (first / last / concatenated / array) is a reliable framework fingerprint even when `Server`/`X-Powered-By` are hidden. Use this skill as a recon multiplier, not only as an exploit.
- **CSRF / OAuth / SAML flows with duplicated control parameters.** `token=valid&token=fake`, duplicate `state`/`client_id`/`redirect_uri` — validate-first-consume-last lets the security-critical value differ from the acted-on value.
- **GraphQL behind a rate limiter.** Per-operation throttles and coupon/credit/login limits are often enforced per HTTP request, so N aliased identical operations in one request multiply the effect.

## Concrete tells (request → response examples)

- **Last-wins (PHP/Apache, Django, Rails, Express-`qs`):**
  `GET /?p=A&p=B` → response reflects/acts on **B**.
  `GET /?p=B&p=A` → reflects/acts on **A**. The "winner" follows position, not value.
- **First-wins (Flask, Spring `@RequestParam`, JSP/Tomcat, Go `c.Query`, Cloudflare/API-GW rule eval):**
  `GET /?p=A&p=B` → reflects/acts on **A**.
- **Concatenation (ASP.NET/IIS, Perl CGI):**
  `GET /?p=A&p=B` → response contains literal `A,B`. (Lets you split a payload across the comma to dodge a contiguous-string WAF rule.)
- **WAF-vs-app split, confirmed:**
  `GET /?q=<script>alert(1)</script>` → `403 Forbidden` (WAF block).
  `GET /?q=harmless&q=<script>alert(1)</script>` → `200` and the script lands in the reflected page. WAF inspected the first copy; the app used the last. This is the confirming pattern.
- **Gateway-vs-backend IDOR:**
  `GET /api/account?id=<your-id>&id=<victim-id>` → `200` returning the **victim's** record while the edge ACL passed on your own id.
- **JSON duplicate-key differential:**
  `POST {"role":"user","role":"admin"}` (raw string) → `200`, account now `admin` (parser last-wins), vs. a `400 duplicate key` (parser rejects → no bug) vs. acted-on `user` (first-wins).
- **Array/shape confusion:**
  `role=user` → normal; `role[]=user&role[]=admin` → privilege change, type error, or a stack trace revealing the binder. Any *change* between scalar and array form is the tell.
- **Header pollution:**
  Two `X-Forwarded-For: 1.2.3.4` and `X-Forwarded-For: 127.0.0.1` headers → an internal-only feature unlocks or rate-limit/ACL keys off the wrong address.
- **Parameter cloaking:**
  `?par%61m=evil` (decodes to `param`) or `?PARAM=evil` bypassing a WAF rule keyed on literal lowercase `param`, while the backend still binds it.

## When NOT to use it / easily-confused-with

- **No second parser in the path.** A lone app server with no WAF/CDN/gateway and a consistent winner across every layer has *no differential* — the framework's documented behavior alone is not a vulnerability. Don't dispatch just because you can name the framework's precedence.
- **The duplicate request errors out.** Strict binders (Spring strict mode, Hapi/Joi rejecting duplicates) or a JSON parser returning `400 duplicate key` give you an error, not a split. That is a false positive, not this skill's win condition — move on.
- **The CDN collapses duplicates before the origin.** If the edge strips or merges the second copy so both values arrive identical, there is nothing to exploit. Confirm the second copy actually *reaches* the app.
- **A reflected payload that lands is XSS/SQLi/SSRF, not "pollution."** If a single-value payload already executes, the relevant skill is the injection class itself. Pollution is only the *delivery trick* that gets a blocked payload past a filter — route here only when the bypass mechanism (the duplicate) is the thing you're testing, then hand the landed payload to the matching injection skill.
- **A plain IDOR with one id.** If changing a single `id=` to another value returns someone else's data with no edge/backend disagreement, that's straight IDOR/BOLA, not pollution. Pollution-IDOR specifically requires the *gateway-authorizes-one / backend-reads-another* split.
- **Response deltas from caching, load balancing, or A/B tests.** A different body on the duplicated request can be a cache or canary, not a parser split. Rule this out by pairing every probe with a single-value baseline and confirming the only changed variable is the duplicate/shape.
- **Mass assignment via an entirely unrelated extra field.** If you can just *add* `is_admin=true` once (no duplication, no precedence trick) and it sticks, that's an over-posting/mass-assignment bug to route to the mass-assignment skill; pollution is when the *duplicate-and-precedence* mechanic is what defeats the whitelist.
