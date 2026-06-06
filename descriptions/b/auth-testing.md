# auth-testing — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A login form exists.** Any `POST` endpoint that takes a username/email + password pair and returns a session — `/login`, `/signin`, `/auth`, `/admin`, `/wp-login.php`, `/user/login`, `/account/login`. The presence of a credential form is the single strongest trigger.
- **A `Set-Cookie` carrying a session identifier** — `session=`, `sessionid=`, `JSESSIONID=`, `PHPSESSID=`, `connect.sid=`, `laravel_session=`, `auth_token=`. Especially if it lacks `HttpOnly`, `Secure`, or `SameSite`, or if the value looks short/sequential/guessable rather than high-entropy.
- **A JWT anywhere in the traffic.** A token starting with `eyJ` (base64 of `{"`) in an `Authorization: Bearer` header, a cookie, a `?token=`/`?access_token=`/`?jwt=` query string, `localStorage`, or a response body. Decode the header — if you see `"alg":"RS256"`, `"alg":"HS256"`, `"kid":...`, `"jku":...`, `"x5u":...`, or `"jwk":...`, this skill applies immediately.
- **OIDC / OAuth2 discovery documents** — `/.well-known/openid-configuration`, `/oauth2/.well-known/...`, `/jwks.json`, or any of `/authorize`, `/token`, `/introspect`, `/revoke`, `/callback`, `/logout` with `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `code_challenge` parameters.
- **`401 Unauthorized` or `403 Forbidden` guarding content** that becomes `200 OK` once a cookie/header is present → there is an auth layer worth probing for bypass.
- **A `WWW-Authenticate` header** (`Basic`, `Bearer`, `Digest`, `Negotiate`) → an authentication scheme to attack directly.
- **Login responses that differ between "user not found" and "wrong password"** (different status, body length, wording, or response time) → username enumeration oracle, the first step of credential attacks.
- **No lockout / no rate-limit observed** after several failed logins (no `429`, no CAPTCHA appears, no "account locked" message) → brute-force resistance is absent, dispatch to confirm.
- **Default-looking admin panels** — router/printer/IoT/CMS/database admin UIs (phpMyAdmin, Jenkins, Grafana, Tomcat manager, Kibana) → test default credentials.
- **A password-reset, email-change, 2FA-enrollment, "remember me", or impersonation/"login as" flow** is discovered in the crawl.
- **An `id`/`user`/`role`/`isAdmin` field inside a signed-or-unsigned token or hidden form field** → claim/parameter tampering candidate.

## Use-case scenarios

- **Black-box recon just surfaced a login page and nothing else is obviously exploitable yet.** Authentication is the front door; test default creds → enumeration → brute-force resistance → SQLi-in-login bypass → session handling, in that cost order.
- **You hold a valid low-privilege account** (or can register one) and want to escalate. This skill covers IDOR-in-sessions, role-claim tampering, access-vs-ID-token confusion, and forced browsing to admin-only routes past the auth check.
- **The target is API-first / microservice / mobile-backend and issues JWTs.** Run the full JWT mutation matrix: `alg:none`, RS256→HS256 confusion (public key as HMAC secret), `kid` path-traversal/injection, `jku`/`x5u`/`jwk` header pointing at attacker-hosted keys, `crit` header abuse, and claim edits (`aud`/`iss`/`exp`/`scope`) to see what the server actually enforces vs. assumes.
- **An OAuth2/OIDC handshake is in play.** Test `redirect_uri` allowlisting (exact-match vs. prefix/wildcard/open-redirect), PKCE downgrade (`plain` or absent `code_verifier`), missing/predictable `state`/`nonce` (login CSRF, code injection), token-endpoint cross-tenant redemption, and SSRF via `redirect_uri`/JWKS fetch.
- **Multiple credential formats are accepted** (cookie + bearer, API key + JWT, SAML + JWT). Test which path validates weakest — submit each credential on the wrong channel.
- **Logout/session-lifecycle review** — confirm tokens are actually invalidated server-side after logout, refresh tokens rotate and detect reuse, and sessions don't survive password change.

## Concrete tells (request → response examples)

- **Username enumeration:**
  - `POST /login {user:alice,pass:x}` → `"Invalid password"` vs. `POST /login {user:zzzz,pass:x}` → `"No such user"`. Different messages, or a measurable response-time delta (bcrypt runs only for real users) → enumeration confirmed.
- **No brute-force protection:**
  - 20 rapid bad logins → all return the same `200`/`401` with no `429`, no CAPTCHA, no `Retry-After`, no lockout message → form is brute-forceable (use a tiny top-100 wordlist first).
- **SQLi auth bypass:**
  - `POST /login {user:admin' -- ,pass:anything}` or `{user:admin' OR '1'='1,pass:x}` → redirect to dashboard / `Set-Cookie` for an authenticated session, or a `500` SQL error string (`You have an error in your SQL syntax`, `ORA-`, `psql:`) → SQLi in the auth query.
- **JWT `alg:none`:**
  - Take `eyJhbGciOiJSUzI1NiIs...`, re-encode the header as `{"alg":"none"}`, edit `sub`/`role`, drop the signature (keep the trailing dot) → if the protected endpoint returns `200` with the elevated identity, signature verification is off. Try `None`/`NONE`/`nOnE` casing too.
- **RS256→HS256 confusion:**
  - Re-sign the token with `HS256` using the server's RSA *public* key as the HMAC secret → `200` means the algorithm isn't pinned.
- **Claim trust:**
  - Decode token, flip `"role":"user"` → `"admin"` or `"aud":"service-a"` → `"service-b"`, re-sign (or don't, if sig is unchecked), replay → if it's honoured, claims are trusted without re-derivation / audience isn't enforced.
- **Session fixation:**
  - Set a known `SESSIONID` before login → if the same ID is still valid *after* authentication (not rotated), fixation is possible.
- **Cookie flags:**
  - `Set-Cookie: session=...; path=/` with no `HttpOnly; Secure; SameSite` → flag as weak session handling.
- **Token in URL:**
  - Crawl/recon shows `https://app/cb?access_token=eyJ...` → token leaks via logs, `Referer`, and history; grep recon for `eyJ` in URLs.

## When NOT to use it / easily-confused-with

- **A value is merely *reflected* in the response → that's XSS/SSTI/reflection, not auth.** Auth-testing is about credential/session/token *validation*, not output handling. Only route here if the reflected thing is a token or controls an identity claim.
- **An object reference like `/api/orders/123` that returns another user's data with a valid session → that's IDOR / broken object-level authorization (access-control skill), not authentication.** Authentication = "are you who you say you are"; authorization = "are you allowed to do this." Route to access-control unless the bypass is achieved by forging/tampering the *token or session* itself (then it's auth).
- **SQL injection on a non-login parameter (search, filter, product id) → that's the SQLi skill.** Only the *login form's* injection used to bypass authentication belongs here.
- **SSRF reached via a generic fetch/url parameter → SSRF skill.** It only belongs to auth when the SSRF is via a JWKS/`jku`/`x5u` key-fetch or OIDC `redirect_uri`.
- **Open redirect on a generic `?next=`/`?url=` param → redirect skill**, unless it is an OAuth `redirect_uri` used to capture an auth code.
- **A static site, brochureware, or a target with no login, no cookie-based session, and no bearer token in any traffic → no auth surface; do not dispatch.**
- **A token that is correctly rejected** when you tamper with `alg`/`aud`/`iss` (strict enforcement, JWKS pinning, short-lived rotating tokens) → that's the expected secure behaviour, not a finding; don't keep grinding it.
