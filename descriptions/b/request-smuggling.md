# request-smuggling — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A multi-tier HTTP path is fingerprinted.** If recon shows ANY edge layer in front of the origin — `Server: cloudflare` + `CF-Ray:`, `Via: 1.1 varnish`, `X-Cache:`/`X-Cache-Hits:`, `X-Amz-Cf-Id:`/`X-Amz-Cf-Pop:`, `X-Served-By:` (Fastly), `X-Akamai-*`, `Server: AkamaiGHost`, `X-Azure-Ref:`, `X-Iinfo:` (Imperva), an `ALB`/`awselb` cookie, or a generic `Server: nginx` reverse-proxy banner that differs from the app's own error pages → there are two parsers on the wire → this skill applies.
- **The same target exposes two different "personalities."** If the 404/500 error page style, `Date` header skew, or `Server` banner changes between paths (one path looks like Nginx, another leaks gunicorn/Werkzeug/Tomcat) → front-end and back-end are distinct → candidate for desync.
- **Connection reuse is confirmed.** If responses carry `Connection: keep-alive` (HTTP/1.1) and the front-end pools/reuses TCP/TLS to origin → the prerequisite for one user's bytes leaking into another's request stream exists.
- **HTTP/2 to client, HTTP/1.1 to origin.** If `curl --http2 -v` negotiates `h2` at the edge but downstream behaviour smells like HTTP/1.1 (textual `Content-Length` quirks, `Transfer-Encoding` round-tripping) → HTTP/2 downgrade smuggling applies. This is the single most fertile modern variant.
- **A POST endpoint accepts an arbitrary body and does NOT auto-redirect.** `/login`, `/search`, `/api/*`, `/comment`, `/graphql` returning 200/4xx (not a 301/302 that discards the body) → you have a usable injection surface for CL.TE/TE.CL probes.
- **Timing tell:** if a crafted CL.TE/TE.CL probe makes the *next* request on the SAME kept-alive connection hang for ~the back-end header timeout (Nginx default 60 s, others 30 s) while a control request on a fresh connection returns instantly → strong desync signal.
- **Differential tell:** if sending a probe + a normal follow-up request, the *follow-up* comes back with the response to a request you never sent (e.g. a 405 for a `GPOST` method, or a 301 to a path you smuggled) → confirmed parser disagreement.
- **Header-handling oddities in recon:** the server tolerates `Transfer-Encoding` with weird whitespace, duplicate `Content-Length`, or both `CL` and `TE` present without a 400 → the parsers are lenient and likely disagree.
- **`h2c` is reachable:** an `Upgrade: h2c` / `HTTP2-Settings:` request earns a `101 Switching Protocols` from the back-end through the proxy → h2c tunnel/upgrade-smuggling path is open.
- **Internal-only paths return 403/401 at the edge but the app clearly hosts them** (`/admin`, `/metrics`, `/actuator`, `/debug`) → smuggling to bypass first-request edge filtering is the right lever.

## Use-case scenarios

- **CDN / WAF in front of an origin.** Cloudflare, Akamai, Fastly, CloudFront, Azure Front Door, Imperva. These edges accept HTTP/2 from clients and downgrade to HTTP/1.1 on the back link, and they cache by URL — the perfect setup for HTTP/2 downgrade desync and front-end cache poisoning. Whenever recon names one of these edges AND the origin is a separate server, this skill is the move.
- **Reverse proxy in front of an app server.** Nginx, HAProxy, Varnish, Apache `mod_proxy`, Traefik, Envoy fronting Node/Express, gunicorn/uvicorn (Python), Go, .NET, Tomcat/Jetty/Undertow (Java). The classic CL.TE / TE.CL / TE.TE matrix lives here — each proxy/app pairing mishandles `Transfer-Encoding` obfuscation differently.
- **Load balancers and API gateways.** AWS ALB/NLB, GCP HTTPS LB, F5 BIG-IP, NetScaler, Kong, AWS API Gateway. Each has its own `TE`/`CL` quirks; serverless gateways frequently drop request bodies (CL.0).
- **Service meshes / sidecars.** Istio (Envoy), Linkerd, Consul Connect — the mTLS-sidecar-to-app-port translation re-parses HTTP and introduces inconsistencies; h2c between sidecar and app is common.
- **Defeating edge-only access control.** When `/admin`, `/internal`, `/metrics`, or `/actuator/*` are blocked at the proxy but the app serves them, a smuggled second request slips past the first-request-only filter and reaches the back-end unfiltered.
- **Bypassing a WAF that inspects only the first request on a connection.** Smuggle the malicious request as the "second" one so it never passes through the WAF's view.
- **As an SSRF pivot / host-whitelist bypass.** Smuggle a `Host: internal.service` line to reach internal vhosts the front-end would otherwise reject.

## Concrete tells (request → response examples)

- **Timing oracle (TE.CL imbalance).** Send on a keep-alive connection:
  ```http
  POST / HTTP/1.1
  Host: target
  Transfer-Encoding: chunked
  Content-Length: 4

  1
  A
  X
  ```
  → If the *connection* then hangs for tens of seconds (back-end waiting for bytes the front-end already consumed) while a fresh connection is instant → desync. Reverse the headers (CL big / TE) to test CL.TE.

- **Differential / confirmation oracle.** On one connection, send a CL.TE probe whose smuggled prefix is `GPOST / HTTP/1.1`, immediately followed by a normal `POST / HTTP/1.1`:
  ```http
  POST / HTTP/1.1
  Host: target
  Content-Length: 6
  Transfer-Encoding: chunked

  0

  G
  ```
  → If the *second* (normal) request comes back **405 Method Not Allowed** (from the smuggled `GPOST`) instead of the expected 200 → confirmed CL.TE. The effect must vanish when you remove the `0\r\n\r\n` terminator — that toggle proves causality.

- **HTTP/2 downgrade with duplicate CL.** Send over h2 two `content-length` headers (`0` then `50`) with a smuggled `GET /admin HTTP/1.1` in the body. → If `/admin` content or its distinct status appears in a follow-up response → downgrade desync confirmed. Inline `\r\n` injected into an h2 header value that surfaces as a new HTTP/1.1 header on the origin is the same tell.

- **CL.0 against a body-dropping back-end.** `POST` with a real `Content-Length` whose body is `GET /admin HTTP/1.1...`; if the back-end ignores POST bodies, the next request it reads is your smuggled `GET`. → A follow-up request returning the `/admin` page → CL.0.

- **h2c upgrade.** `GET / HTTP/1.1` + `Connection: Upgrade, HTTP2-Settings` + `Upgrade: h2c` + `HTTP2-Settings: ...` → a **101 Switching Protocols** that the proxy forwards → you can tunnel raw HTTP/2 past the edge.

- **TE.TE obfuscation sweep.** Vary one byte at a time: `Transfer-Encoding : chunked` (space before colon), `Transfer-Encoding:\tchunked` (tab), leading-space header, `Transfer-Encoding: xchunked`, `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`. → Exactly one obfuscation that flips behaviour identifies which parser ignores `TE`.

## When NOT to use it / easily-confused-with

- **Single-server target with no front-end.** If recon shows one server, no CDN/proxy headers, no connection reuse to a distinct origin → there is no parser seam → request smuggling cannot exist. Do not dispatch.
- **A 502/504 is not automatically a desync.** Back-end overload, idle-timeout resets, and DNS/TLS/network jitter all mimic the timing oracle. Confirm on a warm connection and rule these out before claiming smuggling.
- **Differential responses from rate limiting or first-request WAF inspection** look like desync but are per-IP/per-request artifacts — not a parser disagreement.
- **Round-robin / AnyIP routing** makes results irreproducible; a "hit" that doesn't replay on a single sticky front-end IP is noise, not a finding.
- **Not the right skill for header *injection* into a single server's own response** (that's CRLF / response-splitting / header injection against ONE parser). Request smuggling specifically needs TWO parsers disagreeing about message *framing*.
- **Not SSRF, cache-deception, or open-redirect by themselves.** Those become relevant only *as the impact* once a desync is already confirmed — if there's no front/back parser split, route to the dedicated SSRF/cache/redirect skill instead.
- **An HTTP/2-only end-to-end path** (no downgrade to HTTP/1.1 anywhere) sharply limits classic CL/TE smuggling; if you cannot establish that the edge downgrades to HTTP/1.1 on the origin link, lower this skill's priority.
