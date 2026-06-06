# csrf — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A `Set-Cookie` for the session that carries no `SameSite` attribute at all** → browsers default to `Lax`, but legacy clients and top-level GET navigations still ship it. If you see `Set-Cookie: session=...; HttpOnly; Secure` with `SameSite` absent → CSRF surface is live, dispatch.
- **`Set-Cookie: ...; SameSite=None; Secure`** → the site deliberately allows the cookie on cross-site sub-requests. This is the single loudest CSRF tell. Any state-change endpoint behind that cookie is exploitable unless a token saves it.
- **Authentication is cookie/session based, NOT a bearer token in an `Authorization` header** → CSRF only works against ambient credentials. If the app drives auth via cookies → applies. If every request needs a manually-attached `Authorization: Bearer ...` or custom header that JS reads from non-cookie storage → it does not (see "When NOT to use").
- **A state-changing endpoint (POST/PUT/PATCH/DELETE) that returns 2xx with no hidden `_csrf` / `csrf_token` / `authenticity_token` field in the rendering form, and no `X-CSRF-Token` request header** → no token mechanism present, dispatch.
- **You strip the anti-CSRF token (or send it empty/blank) and the request still returns 200/302 with the action applied** → token is decorative, not enforced. Confirmed CSRF.
- **You replay one user's CSRF token inside a second user's session and it is accepted** → token not bound to session. Dispatch and exploit.
- **A GET request mutates state** (e.g. `GET /account/delete?id=5`, `GET /logout`, `GET /transfer?to=x&amt=100` returns 200/302 and the side-effect occurs) → top-level navigation CSRF, the easiest variant. Even `SameSite=Lax` does not protect GET.
- **The endpoint expects JSON but also accepts `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain` bodies** → preflightless delivery is possible; no CORS preflight stands between an attacker page and the action. Strong tell.
- **A `_method=DELETE` / `_method=PUT` form field or `X-HTTP-Method-Override` header is honored** → method-override lets a simple POST reach a verb whose token check may be absent.
- **CORS reflects the request Origin and sets `Access-Control-Allow-Credentials: true`** → not a CSRF fix; it turns CSRF into authenticated cross-origin reads. Both classes apply; dispatch CSRF for the write side.
- **The server accepts a request with `Origin: null` or a missing/forged `Referer` on a state change** → origin enforcement is broken; sandboxed iframes and `data:`/`about:blank` produce exactly this.
- **GraphQL `/graphql` endpoint answers mutations over `GET ?query=mutation{...}`, or accepts persisted-query hashes / batched arrays via simple content-types** → GraphQL CSRF, dispatch.
- **A WebSocket handshake (`Upgrade: websocket`) succeeds cross-origin and the server does not validate the `Origin` header at handshake** → WebSocket CSRF.

## Use-case scenarios

- **Cookie-session web apps with sensitive state changes.** The bread-and-butter target: classic server-rendered apps (Rails, Django, PHP, Express+cookie-session, Spring) where the browser auto-attaches the session cookie. Any time you have authenticated and can reach an action that changes the account, this skill is the right move to ask "could a malicious page trigger this without the user's intent?"
- **Account-security and money-movement flows specifically.** Email change, password change (especially when it does not require the current password), phone/2FA enable-disable, API-key/PAT generation, payment and subscription changes, account deletion, OAuth connect/disconnect, account linking. These are the highest-yield endpoints — test them first.
- **Login and logout endpoints.** Logout CSRF is a nuisance vector, but **login CSRF** is the underrated one: if `POST /login` has no token, an attacker can silently log a victim into the *attacker's* account, then harvest whatever the victim subsequently does (search history, saved payment, uploaded files) under attacker control.
- **APIs that "feel safe" because they take JSON.** Many teams assume "we only accept `Content-Type: application/json`, so CORS preflight protects us." Dispatch here to test whether the parser also coerces form-encoded or `text/plain` bodies into the same handler, defeating the preflight assumption.
- **Endpoints reachable by more than one HTTP verb.** Whenever recon shows the same path responding to both POST and GET (or PUT), this skill's method-confusion matrix is exactly the tool — the alternate verb frequently bypasses the token check that the primary verb enforces.
- **GraphQL and WebSocket surfaces behind cookie auth.** Both are routinely deployed assuming SOP protects them and both are routinely missing the one control (GET-disabled / Origin-checked handshake) that actually would.
- **Hybrid mobile/WebView and back-office/staff tools.** Embedded WebViews auto-send cookies on deep links; internal admin panels often expose destructive actions as plain GET/POST links with no token because "it's internal."

## Concrete tells (request → response examples)

- **Missing-token acceptance.** Capture a legitimate state change, drop the token field, replay:
  ```
  POST /settings/email HTTP/1.1
  Cookie: session=<victim>
  Content-Type: application/x-www-form-urlencoded

  email=attacker@evil.com
  ```
  → `HTTP/1.1 302 Found` / `200 OK` and the email is changed = **CSRF confirmed** (no enforced token).

- **Cross-session token replay.** Take user B's `authenticity_token`, splice it into user A's session request → if accepted (200/302, action applied), the token is not session-bound = vulnerable.

- **GET-driven state change.**
  ```
  GET /account/api-keys/new HTTP/1.1
  Cookie: session=<victim>
  ```
  → `200 OK` with `{"new_key":"sk_live_..."}` = top-level-navigation CSRF; an `<img src=...>` or auto-redirect on an attacker page triggers it.

- **Preflightless JSON.** Endpoint normally takes `application/json`. Resend the same body as:
  ```
  POST /api/transfer HTTP/1.1
  Content-Type: text/plain
  Cookie: session=<victim>

  {"to":"attacker","amount":1000}
  ```
  → if `200 OK` and the transfer posts, no preflight ever fires for `text/plain`, so an off-site `fetch`/form can deliver it = **CSRF on a "JSON-only" API**.

- **Origin not enforced.** Replay any successful state change with `Origin: https://evil.example` (and/or no `Referer`). → `200 OK` action-applied means the server never checks origin; combined with a sent cookie, that is a clean finding.

- **SameSite=Lax + GET confirmation step.** Cookie is `SameSite=Lax`; the dangerous action's final step is a `GET /confirm-delete?token=...` link. Top-level navigation to that URL still carries the Lax cookie → action fires. Lax is not a cure when GET mutates.

- **Method override.**
  ```
  POST /users/42 HTTP/1.1
  Content-Type: application/x-www-form-urlencoded
  Cookie: session=<victim>

  _method=DELETE
  ```
  → `204`/`302` and user 42 is deleted = override honored, token path likely bypassed.

- **GraphQL over GET.**
  ```
  GET /graphql?query=mutation{deleteAccount}
  Cookie: session=<victim>
  ```
  → `200 {"data":{"deleteAccount":true}}` = GraphQL CSRF.

## When NOT to use it / easily-confused-with

- **Bearer-token / header-only auth = not CSRF.** If the app authenticates exclusively with a token that JavaScript must read from `localStorage`/`sessionStorage` and attach as `Authorization: Bearer` or a custom header, a cross-origin page cannot forge it (it is not ambient). Pure SPA-with-bearer designs are out of scope — don't dispatch unless cookies are *also* in play (hybrid apps).
- **`SameSite=Strict` on the session cookie + no simple-request side-channel + no HTTP auth = effectively protected.** The cookie simply isn't sent cross-site. Confirm Strict is on the *session/auth* cookie (not some unrelated analytics cookie) before dismissing, but if so, deprioritize.
- **Read-only / idempotent endpoints are not the target.** CSRF needs a *state change*. A GET that only returns data and a malicious page cannot read (no permissive CORS) is not CSRF. If the issue is that an attacker can *read* cross-origin authenticated data, that is a **CORS misconfiguration / data-exfiltration** finding, not CSRF — route accordingly.
- **The action requires a value the attacker cannot know or guess** (e.g. password change that demands the *current* password, or a server-issued one-time confirmation code that isn't itself CSRF-deliverable) → the request can be forged but cannot succeed; treat as not-exploitable rather than a finding.
- **Token present AND enforced AND origin-checked consistently across every verb/content-type** → after running the full matrix, if removal/replay/method-swap/content-type-switch all fail and Origin/Referer are required, log it as a ruled-out false positive, not a finding.
- **Don't confuse with XSS or SSRF.** If an attacker injects script that runs *in the victim's own origin* and fires requests with the real token, that is **XSS** (the same-origin script legitimately has the token) — CSRF is specifically the *cross-origin, no-token* case. If the server itself makes a request to an attacker-chosen URL, that is **SSRF**, unrelated.
- **Clickjacking is adjacent, not the same.** If the missing control is `X-Frame-Options`/`frame-ancestors` and the exploit needs the victim to *click*, that is clickjacking; CSRF needs no interaction beyond visiting (though the two chain well).

B:csrf done

