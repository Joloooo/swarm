# Client-side desync (CSD) chain — Open WHEN: the target has no shared front-end but a POST-ignoring endpoint, or you want a browser-triggered desync that works cross-origin

Client-side desync (CSD) is the browser-powered branch of request
smuggling (James Kettle, "Browser-Powered Desync Attacks"). It does NOT
need a front-end/back-end split or a pooled connection between two
servers. It works against a single server because the desynced connection
is the **victim's own browser-to-server keep-alive socket**. The smuggled
request is planted by JavaScript a victim loads cross-origin, so the
victim's browser sends it with the victim's cookies.

## Precondition: find a POST-ignoring endpoint

CSD needs a path where the server reads the request line and headers but
**discards the body** of a POST — it answers as if the body were a fresh
request on the same socket. Common offenders:

- Static-file handlers that accept POST but serve the file regardless.
- Redirect handlers (`/redirect`, `/`, marketing links) returning 301/302.
- SPA catch-all routes and 404 handlers that don't read the body.
- Some serverless / edge function gateways.

Server-side this is the same mechanism as the **CL.0** variant in the body
(front-end sends `Content-Length` bytes, back-end ignores the body). CSD
just delivers it from a browser instead of a raw socket.

## Detection — confirm the body is treated as a second request

1. Open a keep-alive connection to the target with a raw client.
2. Send a POST whose body is a complete second request to a path that
   answers distinctly (e.g. `GET /404page`), then read responses.

```
POST / HTTP/1.1
Host: target.example
Content-Length: 38
Connection: keep-alive

GET /404page HTTP/1.1
X: Y
```

If you receive **two** responses (the POST's, then the 404 for
`/404page`), the body was parsed as a second request — the connection is
desync-capable. Toggle it off by shrinking `Content-Length` to swallow the
smuggled bytes; the second response must disappear. That causal toggle is
the confirmation.

## Browser delivery — the redirect/CORS catch trick

The cleanest browser primitive plants the smuggled bytes, then forces the
victim's browser to **reuse the same poisoned socket** for a follow-up
navigation. A redirect endpoint plus a CORS error gives that reuse for
free: the redirect is blocked by `mode: 'cors'`, the `catch` runs, and the
follow-up `location =` navigation rides the already-desynced connection.

```javascript
fetch('https://target.example/redirect', {
  method: 'POST',
  body: `HEAD /404/ HTTP/1.1\r\nHost: target.example\r\n\r\n` +
        `GET /x?x=<script>alert(document.domain)</script> HTTP/1.1\r\nX: Y`,
  credentials: 'include',
  mode: 'cors'            // forces a CORS error so .catch fires
}).catch(() => {
  location = 'https://target.example/'   // reuses the poisoned socket
})
```

Why it lands: the server processes the `HEAD /404/` smuggled into the POST
body, then the `GET /x?x=<script>…`, then the browser's real follow-up
`GET /`. The browser sent only one navigation, so it pairs the response
to the smuggled `HEAD` with its own request and reads the later responses
(including the reflected `<script>`) as the body — executing the script
in the target's origin on the victim's authenticated session.

## Impact patterns

- **Reflected JavaScript execution (XSS without a stored sink)** — smuggle
  a `GET` to any endpoint that reflects a query parameter; the reflected
  markup runs in the victim's session as shown above. Turns a
  body-ignoring redirect into reflected XSS even when the app has no
  obvious injection point.
- **Capture victim credentials into a readable store** — smuggle a request
  that causes the victim's next (credentialed) request to be stored
  somewhere you can read it back (a "save my request" debug endpoint, a
  logging sink, a comment field).
- **Force the victim to reach an internal path** — make the victim's
  browser deliver a request to a path you cannot reach directly (internal
  admin, SSRF-style internal vhost via a smuggled `Host`), which also
  shifts attribution to the victim.

## Operational notes

- Body bytes must use literal `\r\n` (`\r\n` in the JS string), not `\n`.
- `credentials: 'include'` is required so the smuggled follow-up carries
  the victim's cookies.
- Connection reuse is the fragile part: HTTP/2 to the target usually
  prevents reuse, so CSD typically needs the victim's browser to speak
  HTTP/1.1 to the origin. Confirm the origin offers HTTP/1.1.
- Scope discipline (body Rules apply): a CSD PoC inherently runs in a real
  victim's browser. Demonstrate with a benign marker (`alert(document.domain)`
  or a unique cache marker), never capture real third-party credentials
  outside engagement scope.
