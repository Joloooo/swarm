# auth-testing — when to use

Owns the **authentication** half (obtain a valid session) and the **privilege-boundary** half (is identity/role enforced server-side or trusted from a cookie/claim?). The recurring shape: a leaked or default credential gets you a session, and the flag lives behind an `/admin` or owner-only view. The most common failure is under-weighting an obvious login gate or leaked credential and chasing exotic vulns or unknown TCP services instead. **Dispatch the moment a credential or a login/token boundary appears — not several rounds later.**

## Dispatch when:

- **A credential is leaked in page source or an HTML comment** — e.g. `<!-- test:test -->`, `<!-- TODO: Delete the testing account (test:test). -->` in the homepage or `/login` body. Log in with those creds *first* to reach the authenticated surface.
- **Hardcoded credentials in exposed source** — a route like `/source` returns application code containing a username/password or SSH key (recon flags `[HIGH] category=auth`). Reuse them against the app *and* any co-located service (e.g. SSH on :22).
- **A login form exists** — any `POST` taking username/email + password and returning a session: `/login`, `/signin`, `/auth`, `/admin`, `/wp-login.php`, `/user/login`, `/account/login`. A credential form is the single strongest trigger.
- **The app redirects an unauthenticated request to `/login`** (`HTTP/1.1 302` → `Location: /login`), and other paths also bounce there → everything of value sits behind auth; treat login as the mandatory first gate.
- **A `WWW-Authenticate` header** (`Basic`, `Bearer`, `Digest`, `Negotiate`) or a bare `401 Unauthorized` / `403 Forbidden` guarding content that becomes `200 OK` once a cookie/header is present → an auth scheme/layer to attack. HTTP Basic in front of an admin/router panel → test default creds and bypasses on that realm.
- **Demo / default credentials are advertised or accepted** — `user:user`, `test:test`, FastAPI demo creds, a docs page naming a test account, or default admin panels (router/printer/IoT/CMS/DB UIs: phpMyAdmin, Jenkins, Grafana, Tomcat manager, Kibana). If recon says creds authenticate and redirect to `/profile`/`/dashboard`, login is solved → pivot immediately to privilege escalation.
- **A `Set-Cookie` carrying a session identifier** — `session=`, `sessionid=`, `JSESSIONID=`, `PHPSESSID=`, `connect.sid=`, `laravel_session=`, `auth_token=`. Especially if it lacks `HttpOnly`/`Secure`/`SameSite`, or the value looks short/sequential/guessable, or base64-decodes to JSON / an integer id / `user_id` / `sub` → test token tampering, fixation, and id replay.
- **A JWT anywhere in traffic** — a token starting with `eyJ` in `Authorization: Bearer`, a cookie, a `?token=`/`?access_token=`/`?jwt=` query string, `localStorage`, or a response body. Decode the header: `"alg":"none"`, `"alg":"RS256"`, `"alg":"HS256"`, `"kid"`, `"jku"`, `"x5u"`, `"jwk"`, or a payload carrying `sub=1`/`role`/`is_admin` → run the JWT mutation matrix.
- **OIDC / OAuth2 discovery or endpoints** — `/.well-known/openid-configuration`, `/oauth2/.well-known/...`, `/jwks.json`, or `/authorize`, `/token`, `/introspect`, `/revoke`, `/callback`, `/logout` carrying `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `code_challenge`.
- **A disclosed password *hash* plus a PHP backend** — a hash beginning `0e…` with `X-Powered-By: PHP/5.x` → test loose-comparison (`==`) type-juggling magic-hash bypass (this is an auth bypass, not brute force).
- **Login responses differ between "user not found" and "wrong password"** (status, body length, wording, or response-time delta — bcrypt runs only for real users) → username-enumeration oracle, the first step of credential attacks.
- **No lockout / no rate-limit** after several failed logins (no `429`, no `Retry-After`, no CAPTCHA, no "account locked") → brute-force resistance absent; confirm.
- **An admin-only route alongside valid non-admin credentials** — an `/admin`-gated boundary while you hold a low-privilege session → test the privilege boundary (claim/cookie edit, forced browsing, token swap).
- **An `id`/`user`/`role`/`isAdmin` field inside a token or hidden form field** → claim/parameter tampering candidate.
- **A password-reset, email-change, 2FA-enrollment, "remember me", or impersonation/"login as" flow** is found in the crawl.

## Key techniques:

- **Login is often the prerequisite for another vuln class.** When recon surfaces both a login gate *and* an injection/template hint, dispatch auth-testing in parallel so the SSTI/LFI/XXE/IDOR specialist isn't probing a 302-to-login wall — hand them an authenticated session.
- **Default/leaked-credential reuse:** try advertised/demo creds and any leaked pair first; reuse discovered creds (SSH keys, passwords) across the app and every co-located service.
- **SQLi auth bypass:** `POST /login {user:admin' -- ,pass:x}` or `{user:admin' OR '1'='1,pass:x}` → an authenticated `Set-Cookie`/dashboard redirect, or a SQL error string (`You have an error in your SQL syntax`, `ORA-`, `psql:`) confirms injection in the auth query.
- **JWT mutation matrix:** forge `alg:none` (re-encode header `{"alg":"none"}`, edit `sub`/`role`/`username`, drop the signature but keep the trailing dot; try `None`/`NONE`/`nOnE` casing); RS256→HS256 confusion (re-sign with HS256 using the server's RSA *public* key as the HMAC secret); `kid` path-traversal/injection; `jku`/`x5u`/`jwk` header pointing at an attacker-hosted key; `crit` header abuse; and claim edits (`role`, `aud`, `iss`, `exp`, `scope`) to see what the server enforces vs. assumes.
- **Session attacks:** increment/replace a decodable id and replay; session fixation — set a known `SESSIONID` before login, and if the same id is valid *after* auth (not rotated), fixation works; flag cookies missing `HttpOnly`/`Secure`/`SameSite`; flag tokens leaked in URLs (`?access_token=eyJ...` leaks via logs/`Referer`/history — grep recon for `eyJ` in URLs).
- **PHP magic-hash type juggling:** with a disclosed `0e…` hash, submit another all-digit `0e…` string as the password → loose `==` compares both as float `0`, granting access.
- **OAuth2/OIDC:** test `redirect_uri` allowlisting (exact-match vs. prefix/wildcard/open-redirect), PKCE downgrade (`plain` or absent `code_verifier`), missing/predictable `state`/`nonce` (login CSRF, code injection), token-endpoint cross-tenant redemption, and SSRF via `redirect_uri`/JWKS fetch.
- **Multiple credential formats** (cookie + bearer, API key + JWT, SAML + JWT): submit each credential on the wrong channel to find which path validates weakest.
- **Logout/lifecycle review:** confirm tokens are actually invalidated server-side after logout, refresh tokens rotate and detect reuse, and sessions don't survive a password change.
- **Cost order for a bare login page:** default creds → enumeration → brute-force resistance → SQLi-in-login bypass → session handling.

## When NOT to use it / easily confused with:

- **A leaked/default credential is the *door*, not the *flag*.** Once you hold a valid session, hand off and stop grinding the login form: SSTI sink behind login → **ssti**; "update admin's email" / business rule after login → **business-logic**; a guessable numeric id in an authenticated response → **idor** (and **bfla** for function-level access).
- **An admin boundary you can't beat by forging/tampering the token is not always auth.** If token manipulation doesn't move the boundary, route the privilege escalation elsewhere — the auth layer may be a decoy over an HTTP **request-smuggling**/desync or a TOCTOU **race-condition** on the authz check.
- **An object reference like `/api/orders/123` returning another user's data with a valid session → IDOR / broken object-level authorization (access-control), not authentication.** Authentication = "are you who you say you are"; authorization = "are you allowed to do this." Route here only if the bypass is achieved by forging/tampering the *token or session* itself.
- **SQLi in the login form is shared territory.** Try the bypass here; escalate to **sqli** if the error proves a genuinely injectable parameter rather than just a login bypass. SQLi on a non-login parameter (search, filter, product id) → **sqli**.
- **A plain decodable cookie is session-mgmt / IDOR, not JWT.** Reserve the `alg:none`/`kid`/`jku` matrix for values that decode to a JWT header (`alg`/`typ`); don't run it on a bare `user_id` token.
- **A value merely *reflected* in the response → XSS/SSTI/reflection**, unless the reflected thing is a token or controls an identity claim.
- **SSRF via a generic fetch/url param → ssrf**, unless via a JWKS/`jku`/`x5u` key-fetch or OIDC `redirect_uri`. **Open redirect on a generic `?next=`/`?url=` → redirect skill**, unless it's an OAuth `redirect_uri` used to capture an auth code.
- **A token correctly rejected** when you tamper with `alg`/`aud`/`iss` (strict enforcement, JWKS pinning, short-lived rotating tokens) is expected secure behaviour, not a finding — stop grinding it.
- **A static site / brochureware with no login, no cookie session, and no bearer token in any traffic → no auth surface; do not dispatch.**
- **Co-located unknown TCP services are not an auth signal** and are a known distraction; do not let their presence deprioritise the login gate.
