# Client-Side Path Traversal (CSPT) — Open WHEN: the app's front-end JavaScript builds a same-origin `fetch`/XHR/`axios` URL by concatenating a user-controlled value into the request PATH (not the host), and you want to retarget that request into a CSRF or XSS primitive

CSPT (a.k.a. "on-site request forgery") is a **client-side** bug — nothing
on the server reads a file. The browser makes a same-origin request whose
path you partly control; injecting `../` walks that path onto a different
endpoint. Because the request stays in-origin, the browser auto-sends
cookies and the front end adds its own CSRF token / auth header, so the
retargeted call is fully authenticated. This is why CSPT defeats
`SameSite=Lax` and classic anti-CSRF tokens.

## Spotting the sink (read the front-end JS)

Look for a value taken from `location.search` / hash / a path segment /
DOM input that is concatenated into a request path **without**
`encodeURIComponent`:

```js
const id = new URLSearchParams(location.search).get('newsitemid');
fetch('/newsitems/' + id)            // id = "../admin/deleteUser/42" → /admin/deleteUser/42
fetch(`/api/v4/items/${id}`)          // template-literal join, same problem
axios.get('/profile/' + userInput)
```

If the value is run through `encodeURIComponent` first, `../` becomes
`..%2F` and usually will not traverse — that is the standard fix. A
half-fix (encoding only some chars, or stripping `../` once) is bypassable.

## CSPT → CSRF (the common, higher-impact case)

You cannot control the request **body**, only the **path and method** the
front end already uses. So hunt for a state-changing sink that acts on path
+ method alone: cache-invalidate, cancel/revoke, toggle-flag, accept/reject,
delete-by-id. Then craft input so the traversal lands on it.

CSPT2CSRF vs classic CSRF:

| Property                       | Classic CSRF | CSPT2CSRF |
|--------------------------------|--------------|-----------|
| Control request body           | yes          | no        |
| Works past an anti-CSRF token  | no           | yes (FE adds it) |
| Works past `SameSite=Lax`      | no           | yes       |
| GET/PUT/PATCH/DELETE sinks     | no           | yes       |
| 1-click                        | no           | yes       |

Real CVEs / examples (study the path-walk, not the host):

```
# Mattermost POST sink (CVE-2023-45316)
/<team>/channels/channelname?telem_action=x&forceRHSOpen&telem_run_id=../../../../../../api/v4/caches/invalidate

# erasec.be invite flow — cancel a card via the invite GET call
/signup/invite?email=foo%40bar.com&inviteCode=123456789/../../../cards/<uuid>/cancel?a=

# Grafana JSON API plugin (CVE-2023-5123), Mattermost GET sink (CVE-2023-6458),
# 1-click CSPT2CSRF in Rocket.Chat
```

Method matters: the front end decides GET vs POST vs DELETE for that fetch.
You can only reach sinks reachable with **that** verb. Map each
controllable fetch to its method first, then pick a same-method sink.

## CSPT → XSS

Walk the fetched URL onto an endpoint whose response the page then injects
unsafely (e.g. a `.js`/JSON route with a reflected text-injection param).
The retargeted response body lands in a sink that executes it.

```
# page at /static/cms/news.html fetches /newsitems/<newsitemid> and reflects it;
# /pricing/default.js has a reflected `cb` param → walk onto it
?newsitemid=../pricing/default.js?cb=alert(document.domain)//
```

## Bypassing encoding / WAF on the client (Matan Berson levels)

CSPT lives across **encoding layers** — the value may be decoded once by
the framework router, again by the browser. Match the number of `../`
encodings to how many decode passes happen before the path is used:

```
../            # no encoding survives if FE encodes once
..%2f          # single-encoded slash, decoded once downstream
%2e%2e%2f      # dot+slash encoded
..%252f        # double-encoded for a two-pass decode
```

Also try a trailing `?` or `#` (as in `default.js?cb=...//`) to truncate
the rest of the original path the FE appends after your value.

## Validation

A CSPT finding is real only when:
1. You show the exact front-end code (or network trace) where user input
   joins into a same-origin fetch path unencoded.
2. You demonstrate the retargeted request actually fires same-origin with
   the session cookie / CSRF token attached (browser devtools network tab).
3. For CSPT2CSRF: the retargeted call produces a real state change at the
   new endpoint. For CSPT2XSS: script executes in the page origin.
4. Report the source (the controllable fetch), the sink (the endpoint the
   `../` lands on), the method, and the full one-click URL.

## Tools

- doyensec **CSPTBurpExtension** — find/exploit CSPT in Burp.
- doyensec **CSPTPlayground** — local lab to practice source→sink mapping.
- Read the bundled/minified JS by hand: grep it for `fetch(`, `axios`,
  `XMLHttpRequest`, and string concatenation into a `/`-prefixed path.
