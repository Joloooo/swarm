# csrf

Cross-Site Request Forgery: forcing an authenticated victim's browser to issue a state-changing request the victim did not intend, by riding on the ambient session cookie the browser auto-attaches.

## Dispatch when

Cookie/session-based auth (the prerequisite — CSRF only works against ambient credentials), combined with any of:

- **Session `Set-Cookie` carries no `SameSite` attribute** → browsers default to `Lax`, but legacy clients and top-level GET navigations still ship the cookie. `Set-Cookie: session=...; HttpOnly; Secure` with `SameSite` absent → surface is live.
- **`Set-Cookie: ...; SameSite=None; Secure`** → the site deliberately allows the cookie on cross-site sub-requests. The loudest CSRF tell; any state-change endpoint behind that cookie is exploitable unless a token saves it.
- **A state-changing endpoint (POST/PUT/PATCH/DELETE) returns 2xx with no hidden `_csrf` / `csrf_token` / `authenticity_token` field in the rendering form and no `X-CSRF-Token` request header** → no token mechanism present.
- **Stripping the anti-CSRF token (or sending it empty/blank) still returns 200/302 with the action applied** → token is decorative, not enforced. Confirmed.
- **One user's CSRF token is accepted inside a second user's session** → token not bound to session.
- **A GET request mutates state** (e.g. `GET /account/delete?id=5`, `GET /logout`, `GET /transfer?to=x&amt=100` succeeds and the side-effect occurs) → top-level-navigation CSRF, the easiest variant. Even `SameSite=Lax` does not protect GET.
- **An endpoint that expects JSON also accepts `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain` bodies** → preflightless delivery is possible; no CORS preflight stands between an attacker page and the action.
- **A `_method=DELETE` / `_method=PUT` form field or `X-HTTP-Method-Override` header is honored** → method-override lets a simple POST reach a verb whose token check may be absent.
- **CORS reflects the request Origin with `Access-Control-Allow-Credentials: true`** → not a CSRF fix; turns CSRF into authenticated cross-origin reads. Dispatch CSRF for the write side.
- **The server accepts a state change with `Origin: null` or a missing/forged `Referer`** → origin enforcement is broken; sandboxed iframes and `data:`/`about:blank` produce exactly this.
- **GraphQL `/graphql` answers mutations over `GET ?query=mutation{...}`, or accepts persisted-query hashes / batched arrays via simple content-types** → GraphQL CSRF.
- **A WebSocket handshake (`Upgrade: websocket`) succeeds cross-origin without `Origin` validation at handshake** → WebSocket CSRF.

## High-yield targets (test these first)

- **Account-security and money-movement flows:** email change, password change (especially when it does not require the current password), phone/2FA enable-disable, API-key/PAT generation, payment and subscription changes, account deletion, OAuth connect/disconnect, account linking.
- **Login and logout endpoints.** Logout CSRF is a nuisance vector; **login CSRF** is the underrated one — if `POST /login` has no token, an attacker can silently log a victim into the *attacker's* account and harvest whatever the victim then does (search history, saved payment, uploaded files) under attacker control.
- **APIs that "feel safe" because they take JSON** — test whether the parser also coerces form-encoded or `text/plain` bodies into the same handler, defeating the assumed preflight protection.
- **Endpoints reachable by more than one HTTP verb** — the alternate verb frequently bypasses the token check the primary verb enforces.
- **GraphQL and WebSocket surfaces behind cookie auth** — routinely missing the one control (GET-disabled / Origin-checked handshake) that would protect them.
- **Hybrid mobile/WebView and back-office/staff tools** — embedded WebViews auto-send cookies on deep links; internal admin panels often expose destructive actions as token-less GET/POST links.

## Concrete tells (request → response)

- **Missing-token acceptance.** Capture a legitimate state change, drop the token field, replay:
  ```
  POST /settings/email HTTP/1.1
  Cookie: session=<victim>
  Content-Type: application/x-www-form-urlencoded

  email=attacker@evil.com
  ```
  → `302 Found` / `200 OK` and email changed = CSRF confirmed (no enforced token).

- **Cross-session token replay.** Splice user B's `authenticity_token` into user A's session request → if accepted (200/302, action applied), the token is not session-bound.

- **GET-driven state change.**
  ```
  GET /account/api-keys/new HTTP/1.1
  Cookie: session=<victim>
  ```
  → `200 OK` with `{"new_key":"sk_live_..."}` = top-level-navigation CSRF; an `<img src=...>` or auto-redirect on an attacker page triggers it.

- **Preflightless JSON.** Resend a normally-`application/json` body as `text/plain`:
  ```
  POST /api/transfer HTTP/1.1
  Content-Type: text/plain
  Cookie: session=<victim>

  {"to":"attacker","amount":1000}
  ```
  → if `200 OK` and the transfer posts, no preflight ever fires for `text/plain`, so an off-site `fetch`/form can deliver it.

- **Origin not enforced.** Replay a successful state change with `Origin: https://evil.example` and/or no `Referer` → `200 OK` action-applied means the server never checks origin.

- **SameSite=Lax + GET confirmation step.** Cookie is `SameSite=Lax`; the dangerous action's final step is a `GET /confirm-delete?token=...` link. Top-level navigation still carries the Lax cookie → action fires. Lax is not a cure when GET mutates.

- **Method override.**
  ```
  POST /users/42 HTTP/1.1
  Content-Type: application/x-www-form-urlencoded
  Cookie: session=<victim>

  _method=DELETE
  ```
  → `204`/`302` and user 42 deleted = override honored, token path likely bypassed.

- **GraphQL over GET.**
  ```
  GET /graphql?query=mutation{deleteAccount}
  Cookie: session=<victim>
  ```
  → `200 {"data":{"deleteAccount":true}}` = GraphQL CSRF.

## Key techniques

- Run the full bypass matrix on each candidate: token removal, blank token, cross-session token replay, method-override (`_method` / `X-HTTP-Method-Override`), content-type switch to a simple/preflightless type, GET-instead-of-POST, and Origin/Referer stripping or forging.
- For destructive actions gated behind a final GET confirmation step, deliver via top-level navigation (`<img>`, redirect, link) — even `SameSite=Lax` cookies ride along.
- For login CSRF, forge `POST /login` with attacker credentials to silently authenticate the victim as the attacker.

## When NOT to use / easily confused with

- **Bearer-token / header-only auth = not CSRF.** If auth is exclusively a token JS reads from `localStorage`/`sessionStorage` and attaches as `Authorization: Bearer` or a custom header, a cross-origin page cannot forge it (not ambient). Pure SPA-with-bearer is out of scope unless cookies are *also* in play (hybrid apps).
- **`SameSite=Strict` on the session/auth cookie + no simple-request side-channel + no HTTP auth = effectively protected.** Confirm Strict is on the *session/auth* cookie (not an unrelated analytics cookie) before dismissing, then deprioritize.
- **Read-only / idempotent endpoints are not the target.** CSRF needs a *state change*. If an attacker can *read* cross-origin authenticated data, that is a **CORS misconfiguration / data-exfiltration** finding, not CSRF.
- **The action requires a value the attacker cannot know or guess** (current password, server-issued one-time confirmation code not itself CSRF-deliverable) → forgeable but cannot succeed; treat as not-exploitable, not a finding.
- **Token present AND enforced AND origin-checked consistently across every verb/content-type** → if the full matrix all fails and Origin/Referer are required, log as a ruled-out false positive.
- **Not XSS.** Script running *in the victim's own origin* that fires requests with the real token is XSS (the same-origin script legitimately holds the token); CSRF is specifically the *cross-origin, no-token* case.
- **Not SSRF.** A request the *server* makes to an attacker-chosen URL is SSRF, unrelated.
- **Not clickjacking.** If the missing control is `X-Frame-Options` / `frame-ancestors` and the exploit needs the victim to *click*, that is clickjacking; CSRF needs no interaction beyond visiting (the two chain well).
