# request-smuggling — when to use

HTTP request smuggling exploits a disagreement between two HTTP parsers — a front-end (CDN/WAF/reverse proxy/load balancer) and a back-end origin — about where one request ends and the next begins. The precondition is two parsers on the wire plus connection reuse; you do NOT need a visible vulnerable parameter first. The presence of the proxy chain IS the use case.

## Dispatch when

- **A multi-tier HTTP path is fingerprinted.** Any edge layer in front of the origin disclosed by recon headers:
  - Proxy/LB chain: `Via: haproxy (2.0.5)`, `Via: 1.1 varnish`, `X-Upstream-Proxy:`, any `Via:` / `X-*-Proxy:` header.
  - Cache: `X-Cache:`, `X-Cache-Hits:`, `X-Served-By:` (Fastly).
  - CDN: `Server: cloudflare` + `CF-Ray:`, `X-Amz-Cf-Id:`/`X-Amz-Cf-Pop:` (CloudFront), `X-Akamai-*` / `Server: AkamaiGHost`, `X-Azure-Ref:` (Azure Front Door), `X-Iinfo:` (Imperva), an `ALB`/`awselb` cookie.
  - A generic `Server: nginx` reverse-proxy banner that differs from the app's own error pages.
- **Two or more distinct server fingerprints on the same target.** Front edge advertises one server (e.g. `Server: Apache/2.4.67 (Debian)`) while responses also expose a different downstream agent (HAProxy, mitmproxy, gunicorn/uvicorn, Werkzeug/Flask, Tomcat). The 404/500 error-page style, `Date` header skew, or `Server` banner changing between paths means front-end and back-end are distinct parsers that can disagree on framing. This mismatch is the single strongest tell.
- **An old/pinned proxy version that predates desync hardening.** HAProxy `2.0.x`, old Nginx, Apache `mod_proxy`, or any "outdated proxy" fingerprint → escalate the proxy from a version-disclosure note to the primary input surface. "Complicated stacks with outdated proxies" is the classic HRS setup.
- **HTTP/2 to client, HTTP/1.1 to origin.** `curl --http2 -v` negotiates `h2` at the edge but downstream behaviour smells like HTTP/1.1 (textual `Content-Length` quirks, `Transfer-Encoding` round-tripping) → HTTP/2 downgrade smuggling. The single most fertile modern variant.
- **Connection reuse is confirmed.** Responses carry `Connection: keep-alive` (HTTP/1.1) and the front-end pools/reuses TCP/TLS to origin → the prerequisite for one user's bytes leaking into the next request stream.
- **A POST endpoint accepts an arbitrary body and does NOT auto-redirect.** `/login`, `/search`, `/api/*`, `/comment`, `/graphql` returning 200/4xx (not a 301/302 that discards the body) → usable injection surface for CL.TE/TE.CL probes.
- **Header-handling oddities in recon.** Server tolerates `Transfer-Encoding` with weird whitespace, duplicate `Content-Length`, or both `CL` and `TE` present without a 400 → lenient parsers that likely disagree.
- **`h2c` is reachable.** An `Upgrade: h2c` / `HTTP2-Settings:` request earns a `101 Switching Protocols` from the back-end through the proxy → h2c tunnel/upgrade-smuggling path is open.
- **An internal/private virtual host or path leaked.** `Host: internal.router`, `internal.*`, `*.local`, RFC-1918 upstream IPs, or an internal path disclosed via a debug endpoint → an internal-only back-end reachable only *through* the proxy. Smuggling is how to reach it; routing/Host-header tricks alone usually will not.
- **A debug/echo endpoint reflects the upstream request line and headers.** Any endpoint that shows how the proxy rewrites/forwards your request (e.g. a `debug=...` POST echoing the internal HAProxy-routed `GET /devices/... HTTP/1.1` to `Host: internal.router`) → use it to learn the framing the back-end expects, then probe CL.TE / TE.CL against it.
- **An internal-only path returns a soft auth wall or edge 403/401 while a proxy sits in front.** `/admin`, `/admin_panel`, `/internal`, `/metrics`, `/actuator`, `/debug` returning a 200 "authorization modal" or a 401/403 that is enforced at the proxy layer while a separate back-end serves the content → smuggle past the first-request edge filter. Prefer this over endless proxy-header-trust / path-normalization fuzzing.
- **The objective/tags mention** "smuggling", "desync", "HRS", "proxy", "load balancer", or "CDN" → dispatch early, not as an afterthought.

## Use-case scenarios

- **CDN / WAF in front of an origin.** Cloudflare, Akamai, Fastly, CloudFront, Azure Front Door, Imperva. These accept HTTP/2 from clients, downgrade to HTTP/1.1 on the back link, and cache by URL — ideal for HTTP/2 downgrade desync and front-end cache poisoning.
- **Reverse proxy in front of an app server.** Nginx, HAProxy, Varnish, Apache `mod_proxy`, Traefik, Envoy fronting Node/Express, gunicorn/uvicorn, Go, .NET, Tomcat/Jetty/Undertow. The classic CL.TE / TE.CL / TE.TE matrix lives here — each proxy/app pairing mishandles `Transfer-Encoding` obfuscation differently. Outdated or experimental chains (e.g. mitmproxy + HAProxy) are prime targets because their framing handling is lenient or inconsistent.
- **Load balancers and API gateways.** AWS ALB/NLB, GCP HTTPS LB, F5 BIG-IP, NetScaler, Kong, AWS API Gateway. Each has its own `TE`/`CL` quirks; serverless gateways frequently drop request bodies (CL.0).
- **Service meshes / sidecars.** Istio (Envoy), Linkerd, Consul Connect — the mTLS-sidecar-to-app-port translation re-parses HTTP and introduces inconsistencies; h2c between sidecar and app is common.
- **Reaching an internal-only back-end.** A private vhost or internal service (`internal.router`, an internal API/admin host) you cannot hit directly because the proxy gates it → smuggle a request the back-end processes with the proxy's trust.
- **Defeating edge-only access control.** `/admin`, `/internal`, `/metrics`, `/actuator/*` blocked at the proxy but served by the app → a smuggled second request slips past the first-request-only filter and reaches the back-end unfiltered. Use this once proxy-trust headers (`X-Forwarded-*`), method override, and path-normalization variants have plateaued.
- **Bypassing a WAF that inspects only the first request on a connection.** Smuggle the malicious request as the "second" one so it never passes through the WAF's view.
- **SSRF pivot / host-whitelist bypass.** Smuggle a `Host: internal.service` line to reach internal vhosts the front-end would otherwise reject.

## Concrete tells (request → response)

- **Proxy-chain disclosure in headers.**
  ```
  > GET /devices/wifi_chipset/status HTTP/1.1
  < HTTP/1.1 200 OK
  < Server: Apache/2.4.67 (Debian)
  < X-Upstream-Proxy: mitmproxy (6.0.2)
  < Via: haproxy (2.0.5)
  < Host (forwarded): internal.router
  ```
  Two named proxies + an internal Host = framing-disagreement surface.

- **Timing oracle (TE.CL imbalance).** On a keep-alive connection:
  ```http
  POST / HTTP/1.1
  Host: target
  Transfer-Encoding: chunked
  Content-Length: 4

  1
  A
  X
  ```
  → If the connection then hangs for tens of seconds (back-end waiting for bytes the front-end already consumed; Nginx default 60 s, others ~30 s) while a fresh connection is instant → desync. Reverse the headers (CL big / TE) to test CL.TE.

- **Differential / confirmation oracle.** On one connection, send a CL.TE probe whose smuggled prefix is `GPOST / HTTP/1.1`, immediately followed by a normal `POST / HTTP/1.1`:
  ```http
  POST / HTTP/1.1
  Host: target
  Content-Length: 6
  Transfer-Encoding: chunked

  0

  G
  ```
  → If the second (normal) request returns **405 Method Not Allowed** (from the smuggled `GPOST`), or a follow-up returns a 4xx/redirect for a path you never sent → confirmed parser disagreement. The effect must vanish when you remove the `0\r\n\r\n` terminator — that toggle proves causality.

- **HTTP/2 downgrade with duplicate CL.** Over h2, send two `content-length` headers (`0` then `50`) with a smuggled `GET /admin HTTP/1.1` in the body. → If `/admin` content or its distinct status appears in a follow-up → downgrade desync confirmed. An inline `\r\n` injected into an h2 header value that surfaces as a new HTTP/1.1 header on the origin is the same tell.

- **CL.0 against a body-dropping back-end.** `POST` with a real `Content-Length` whose body is `GET /admin HTTP/1.1...`; if the back-end ignores POST bodies, the next request it reads is your smuggled `GET`. → A follow-up returning the `/admin` page → CL.0.

- **h2c upgrade.** `GET / HTTP/1.1` + `Connection: Upgrade, HTTP2-Settings` + `Upgrade: h2c` + `HTTP2-Settings: ...` → a **101 Switching Protocols** the proxy forwards → tunnel raw HTTP/2 past the edge.

- **TE.TE obfuscation sweep.** Vary one byte at a time: `Transfer-Encoding : chunked` (space before colon), `Transfer-Encoding:\tchunked` (tab), leading-space header, `Transfer-Encoding: xchunked`, `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`. → Exactly one obfuscation that flips behaviour identifies which parser ignores `TE`.

- **Smuggled internal request returns internal-only content.** After learning the forwarded shape (`Host: internal.router`, `GET /devices/...`), a smuggled prefix targeting that host/path returns back-end content you could not reach directly → smuggling is live and is the path to the objective.

## When NOT to use it / easily confused with

- **Single-server target with no front-end.** One server, no CDN/proxy/cache headers, one consistent `Server:` fingerprint, no connection reuse to a distinct origin → no parser seam → smuggling cannot exist. A lone Werkzeug/Flask dev server is not a target.
- **An internal host reachable by a simple Host header is routing, not smuggling.** If just sending `Host: internal.router` to the front-end returns the internal content, that is virtual-host/SSRF-style access — try it first. Reach for smuggling only when the front-end *gates* that host and only a framing desync gets a request through with the proxy's trust.
- **A soft 200 "authorization modal" is not automatically smuggling.** It may also be solved by default credentials, auth bypass, or BFLA. Smuggling is the right route specifically when the gate lives at the proxy and a separate back-end serves the resource — i.e. when proxy-trust-header / path-normalization fuzzing keeps preserving the denial marker.
- **A 502/504 is not automatically a desync.** Back-end overload, idle-timeout resets, and DNS/TLS/network jitter all mimic the timing oracle. Confirm on a warm connection and rule these out.
- **Differential responses from rate limiting or first-request WAF inspection** look like desync but are per-IP/per-request artifacts, not a parser disagreement.
- **Round-robin / AnyIP routing** makes results irreproducible; a "hit" that doesn't replay on a single sticky front-end IP is noise.
- **Parameter pollution / IDOR are different classes.** A duplicated `id` or `debug=` parameter handled inconsistently is parameter-pollution or IDOR. Smuggling is specifically about the front-end and back-end disagreeing on *where one HTTP request ends* (CL vs. TE), not the parameter layer.
- **Header *injection* into a single server's own response** is CRLF / response-splitting against ONE parser, not smuggling. Smuggling needs TWO parsers disagreeing about message *framing*.
- **SSRF, cache-deception, and open-redirect by themselves** are relevant only as the *impact* once a desync is confirmed. With no front/back parser split, route to the dedicated SSRF/cache/redirect skill.
- **An HTTP/2-only end-to-end path** (no downgrade to HTTP/1.1 anywhere) sharply limits classic CL/TE smuggling; if you cannot establish that the edge downgrades to HTTP/1.1 on the origin link, lower this skill's priority.
