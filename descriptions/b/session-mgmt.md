# session-mgmt — when to use

## Trigger signals (dispatch this skill the moment you observe…)
- If you see a `Set-Cookie` header on any response → inspect its attributes for missing `HttpOnly`, `Secure`, or `SameSite` flags. A login response that sets a session cookie without these flags is the canonical entry point for this skill.
- If you see a cookie name that looks like a session identifier (`session`, `sessionid`, `sid`, `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `connect.sid`, `laravel_session`, `_session_id`, `auth`, `token`) → dispatch to analyze its randomness, length, and flag hygiene.
- If you see a value that decodes as a JWT (three Base64URL segments separated by dots, first segment decodes to `{"alg":...,"typ":"JWT"}`) used as a session/auth token in a cookie or `Authorization: Bearer` header → this skill covers capturing and reasoning about it (predictability, `alg`, claims, expiry).
- If you see a session identifier carried in a URL query string or path (`?sid=...`, `;jsessionid=...`, `?PHPSESSID=...`) → strong fixation/hijacking candidate; URL-borne session IDs leak via Referer, logs, and history.
- If you see the same session token value returned across multiple fresh logins or across different users → predictable/non-rotating token; dispatch.
- If you see session tokens that are short, sequential, time-based, or have low entropy (e.g. incrementing integers, MD5 of a username, timestamps) → predictability finding; dispatch.
- If you see that a session cookie value you set yourself BEFORE authenticating is still valid AFTER you authenticate (the app did not issue a fresh ID at the privilege boundary) → session fixation; dispatch.
- If you see that after hitting a logout endpoint the previously captured cookie still grants access to authenticated pages → broken logout / no server-side invalidation; dispatch.
- If you see state-changing POST/PUT/DELETE requests (password change, email change, fund transfer, role change, add-to-cart-checkout) that succeed with NO anti-CSRF token, NO `SameSite` cookie, and NO custom header requirement → CSRF; dispatch.
- If you see a form WITHOUT a hidden `csrf_token` / `authenticity_token` / `__RequestVerificationToken` field, or a token that never changes / is shared across users / is not validated server-side → CSRF; dispatch.
- If you see the same auth cookie accepted on multiple simultaneous sessions with no invalidation of the older one → concurrent-session weakness; dispatch.
- If you see auth state transmitted over plain `http://` (session cookie sent without `Secure` over cleartext) → hijacking exposure; dispatch.

## Use-case scenarios
- **Right after a successful login.** The single highest-value moment for this skill is the authentication transition. Capture the `Set-Cookie` from the login response, then compare it to the pre-login cookie. This one comparison answers fixation (did the ID change?), hijacking (are the flags set?), and token-quality (is the value random?) at once.
- **Any application with a login form, registration, or "remember me" feature.** Session management is only meaningful where authentication exists. If the target establishes any notion of a logged-in user, this skill is the systematic way to attack the session lifecycle: issuance → use → rotation → expiry → destruction.
- **Multi-step authenticated workflows** (banking, admin panels, shopping carts, account settings). These have the sensitive state-changing actions where CSRF matters most, and where hijacking a session yields the biggest payoff.
- **APIs and SPAs using bearer tokens / JWTs.** When the front end stores a token and replays it on each request, this skill reasons about token entropy, expiry handling, whether logout revokes the token server-side, and whether the token can be set/fixed by an attacker.
- **Targets where authorization bugs were already found.** If you can become another user, the next question is "can I stay them / impersonate them persistently?" — session fixation and hijacking are the persistence mechanism, so this skill pairs naturally after an auth bypass.
- **When you need a CSRF assessment.** Any time the planner identifies a sensitive action driven purely by an ambient session cookie, route here to test for missing anti-CSRF protection.

## Concrete tells (request → response examples)
- Cookie flag audit:
  - Probe: `curl -v -d 'user=admin&pass=admin' http://target/login`
  - Confirming response: `Set-Cookie: session=eyJ...; Path=/` with NO `HttpOnly`, NO `Secure`, NO `SameSite` → flag-hygiene findings, hijacking exposure.
- Token randomness:
  - Probe: log in three times, capture three cookies. `curl -c c1.txt ...`, `curl -c c2.txt ...`, `curl -c c3.txt ...`
  - Confirming pattern: values like `session=1001`, `session=1002`, `session=1003`, or three identical values → predictable / non-rotating session ID.
- Session fixation:
  - Probe: `curl -b 'PHPSESSID=attackerchosen123' -d 'user=x&pass=y' -c after.txt http://target/login` then `curl -b 'PHPSESSID=attackerchosen123' http://target/account`
  - Confirming pattern: `/account` returns the authenticated page using `attackerchosen123` (the ID was accepted and never regenerated) → fixation.
- Logout invalidation:
  - Probe: capture cookie, `curl -b cookie http://target/logout`, then `curl -b cookie http://target/account`
  - Confirming pattern: `/account` still returns `200` authenticated content with the same cookie → logout does not destroy the server-side session.
- CSRF:
  - Probe: `curl -b session=<valid> -d 'newemail=evil@x.com' http://target/account/email` from a context with no token and no Origin/Referer the server checks
  - Confirming pattern: `200`/`302` "email updated" with no token required → state change succeeds purely on the ambient cookie → CSRF.
- JWT capture:
  - Probe: decode the cookie/bearer value. `echo <segment> | base64 -d`
  - Confirming pattern: header `{"alg":"HS256"...}` and a body of claims used as the session → analyze entropy, expiry, and whether logout revokes it.

## When NOT to use it / easily-confused-with
- A reflected or stored user value that ends up in HTML/JS is **XSS**, not session management — even though stealing a cookie is the eventual goal. Use this skill only for how the session token itself is issued, protected, and destroyed; route the injection that steals it to XSS.
- Being able to read or change ANOTHER user's data by tampering with an ID in a request is **IDOR / broken object-level authorization**, not session management. This skill is about the session token, not about object references.
- A login form that accepts weak/guessable credentials, or has no lockout, is **authentication / brute-force / credential** territory, not session management. The crossover point is only the token issued after auth.
- A predictable numeric identifier in a URL is IDOR unless that identifier IS the session/auth token. Confirm the value actually authenticates a session before routing here.
- A JWT with a signature-bypass (`alg:none`, weak HS256 secret, `kid` injection) is primarily a **JWT/auth-token attack**; this skill captures and characterizes the token and flags predictability/lifecycle issues, but deep crypto/signature forgery belongs to the dedicated JWT/auth skill if one exists.
- Missing `Secure`/`HttpOnly` on a NON-session cookie (e.g. a UI preference, analytics, or CSRF cookie that carries no auth state) is low/no impact — do not over-report; the flags matter because they protect a *session* token.
- Pure transport issues (TLS config, HSTS) live with TLS/transport testing; this skill only cares about cleartext transmission insofar as it exposes the session cookie.

B:session-mgmt done
