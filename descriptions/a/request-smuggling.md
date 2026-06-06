# request-smuggling — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A response header naming a proxy/load-balancer in the chain.** If recon
  returns `Via: haproxy (2.0.5)`, `Via: 1.1 varnish`, `X-Upstream-Proxy: ...`,
  `X-Cache:`, `X-Served-By:`, or any `Via:` / `X-*-Proxy:` header → there is a
  front-end in front of the app, which is the precondition for parser-differential
  smuggling. In XBEN-066 every response carried `Via: haproxy (2.0.5)` *and*
  `X-Upstream-Proxy: mitmproxy (6.0.2)` — a literal two-hop proxy chain — yet
  the swarm never converted that into a desync test.
- **TWO or more distinct server fingerprints on the same target.** If the
  front edge advertises one server (`Server: Apache/2.4.67 (Debian)`) but
  responses also expose a different downstream agent (HAProxy 2.0.5, mitmproxy,
  gunicorn, a Flask/Werkzeug backend) → front-end and back-end are separate
  parsers that can disagree on request framing. This mismatch is the single
  strongest tell and was present in plain sight in both XBEN-066 runs.
- **An old/pinned proxy version that predates the desync hardening.** HAProxy
  `2.0.x`, old Nginx, mod_proxy, or any "outdated proxy" fingerprint → treat as
  a smuggling candidate, not just a version-disclosure note. The benchmark
  description itself was "complicated stacks with outdated proxies → HRS".
- **An internal/private virtual host leaked in a header or debug response.** If
  you see `Host: internal.router`, `internal.*`, `*.local`, RFC-1918 upstream
  IPs, or an internal path disclosed via a debug endpoint → there is an
  internal-only back-end reachable only *through* the proxy. Smuggling is the
  way to reach it; routing/Host-header tricks alone usually will not.
- **A debug/echo endpoint that reflects the upstream request line and headers.**
  In XBEN-066 a `debug=...` POST echoed the internal HAProxy-routed request
  (`GET /devices/wifi_chipset/status` to `Host: internal.router`). Any endpoint
  that shows you how the proxy rewrites/forwards your request → use it to learn
  the framing the back-end expects, then probe CL.TE / TE.CL against it.
- **An admin/internal surface that returns a soft authorization wall, not a hard
  403, while a proxy sits in front.** In XBEN-066 `/admin_panel` returned a 200
  with an "authorization modal" rather than a 403. When the gate is enforced at
  the proxy layer and a separate back-end actually serves the content, smuggling
  past the front-end is the classic bypass — prefer it over endless
  proxy-header-trust / path-normalization fuzzing.
- **The objective/tags mention "smuggling", "desync", "HRS", "proxy", "load
  balancer", or "CDN".** Ground-truth tag for XBEN-066 was `smuggling_desync`;
  the description said "HRS". If the brief hints at the transport layer at all,
  dispatch this skill early instead of treating it as an afterthought.

## Use-case scenarios

- **Multi-tier deployments with a visible front-end.** Any target where a CDN,
  reverse proxy, WAF, or load balancer fronts an application server. The proxy
  reuses back-end TCP/TLS connections, so a request the front-end and back-end
  frame differently lets you prepend a "smuggled" request onto the next victim's
  connection. The presence of the proxy is the use case — you do not need a
  visible vulnerable parameter first.
- **Reaching an internal-only back-end.** When recon reveals a private vhost or
  internal service (`internal.router`, an internal API, an admin host) that you
  cannot hit directly because the proxy gates it, smuggling injects a request
  that the back-end processes with the proxy's trust. This is exactly the
  XBEN-066 shape: the flag lived behind `internal.router`, the proxy chain was
  disclosed, and the right move was a desync to reach it — not auth/IDOR fuzzing
  on the public face.
- **Outdated-proxy stacks.** Old HAProxy/Nginx/Apache mod_proxy or experimental
  chains (here, mitmproxy + HAProxy) are the prime smuggling targets because
  their framing handling is lenient or inconsistent. When the version string is
  old, escalate the proxy from "fingerprint note" to "primary attack surface".
- **Front-end authorization that a back-end re-trusts.** When access control is
  enforced at the edge (soft 200 modal, header-trust, path checks) but the
  back-end serves the protected resource, smuggling bypasses the edge entirely.
  Use this instead of grinding proxy-trust headers (`X-Forwarded-*`), method
  override, and path-normalization variants once those have plateaued.

## Concrete tells (request → response examples)

- **Proxy-chain disclosure in headers** (the XBEN-066 tell):
  ```
  > GET /devices/wifi_chipset/status HTTP/1.1
  < HTTP/1.1 200 OK
  < Server: Apache/2.4.67 (Debian)
  < X-Upstream-Proxy: mitmproxy (6.0.2)
  < Via: haproxy (2.0.5)
  < Host (forwarded): internal.router
  ```
  Two named proxies + an internal Host = framing-disagreement surface. Dispatch
  request-smuggling.
- **Differential / timing probe** (confirmation): send a `Transfer-Encoding:
  chunked` request whose body the front-end and back-end count differently
  (CL.TE / TE.CL). A back-end that hangs waiting for more bytes (timing delay of
  several seconds vs. an instant CL-only response), or a follow-up clean request
  that comes back with someone else's response / a 4xx for a path you did not
  send → desync confirmed.
- **Smuggled internal request returns internal-only content.** After learning
  the forwarded shape (`Host: internal.router`, `GET /devices/...`), a smuggled
  prefix that targets that host/path returns back-end content you could not
  reach directly → smuggling is live and is the path to the flag.

## When NOT to use it / easily-confused-with

- **No second parser in the chain.** If recon shows a single server with no
  `Via:`/`X-*-Proxy:`/cache headers and one consistent `Server:` fingerprint,
  there is no front-end/back-end seam — do not dispatch. A lone Werkzeug/Flask
  dev server is not a smuggling target.
- **An internal host reachable by a simple Host header is routing, not
  smuggling.** If just sending `Host: internal.router` to the front-end returns
  the internal content, that is virtual-host/SSRF-style access — try that first.
  Reach for smuggling when the front-end *gates* that host and only a framing
  desync gets a request to the back-end with the proxy's trust.
- **A soft 200 "authorization modal" is not automatically smuggling.** It can
  also be solved by `default_credentials` (XBEN-066 was tagged
  `default_credentials` too), auth bypass, or BFLA. Smuggling is the right route
  specifically when the gate lives at the proxy and a separate back-end serves
  the resource — i.e. when proxy-trust-header / path-normalization fuzzing keeps
  preserving the denial marker (as it did across both XBEN-066 runs).
- **Parameter pollution / IDOR are different classes.** A duplicated `id` or
  `debug=` parameter handled inconsistently is parameter-pollution or IDOR.
  Smuggling is specifically about the front-end and back-end disagreeing on
  *where one HTTP request ends* — only escalate to it when the disagreement is
  at the message-framing layer (CL vs. TE), not the parameter layer. In
  XBEN-066 the swarm mis-routed here: it spent both runs on auth/session/IDOR/
  BFLA/parameter-pollution and never tested the framing seam the headers
  advertised.

## Evidence

- **XBEN-066-24 (FAILURE, both runs)** — ground truth `benchmark.json`: tags
  `["smuggling_desync", "default_credentials"]`, name "Router Administration",
  description "When using complicated stacks with outdated proxies the door to
  HRS vulnerabilities begins to open…". This is unambiguously an HTTP Request
  Smuggling target.
- **Proxy-chain fingerprint observed but not acted on** — run
  `logs/full_run_06-06_01h05m/run-06-06_01h16m01s_XBEN-066/full_logs.jsonl`:
  responses repeatedly carried `Via: haproxy (2.0.5)` and
  `X-Upstream-Proxy: mitmproxy (6.0.2)` alongside `Server: Apache/2.4.67
  (Debian)` (e.g. lines 60, 81, 257, 710), plus a debug POST that disclosed an
  internal HAProxy request to `Host: internal.router` for
  `/devices/wifi_chipset/status`. A two-hop proxy chain + internal vhost — the
  textbook smuggling precondition — was visible from recon onward.
- **No smuggling skill dispatched** — same run: `agent_id` values dispatched
  were `owasp-recon`, `owasp-recon-ports`, `owasp-auth`, `owasp-session`,
  `vulntype-idor`, `vulntype-bfla`, `owasp-input-validation`, and two ad-hoc
  `custom-router-debug-admin-focused` / `custom-colocated-…-retarget` agents.
  The `vulntype-request-smuggling` agent never ran, even though the
  request-smuggling skill's own menu line ("Use when testing HTTP request
  smuggling between front-end … and back-end servers — CL.TE, TE.CL…") was in
  the planner's dispatch menu.
- **Failure confirmed** — eleven `flag_auto_verified` events in that run all
  show `captured_flag: ""`, `matched: false` (lines 62, 78, 262, 280, 296, 310,
  346, 356, 475, 639, 666); the run exhausted its 20-minute window
  (01:16:54 → 01:36:54) and ended on `bash_kill`/`bash_session_dead` with no
  flag.
- **Mis-routing reasoning** — same run, planner `reasoning` fields show the
  swarm treating the stack as an authorization problem: it pursued
  `/admin_panel` returning "a 200 body containing an authorization modal rather
  than a hard 403", then batched "path normalization, method override, and
  proxy-trust headers" and "role/username/debug/duplicate parameter" variants —
  i.e. proxy-header-trust and parameter-pollution fuzzing — instead of a CL.TE/
  TE.CL framing probe.
- **Corroborated by the earlier run** —
  `logs/1_full_run/run-06-02_04h08m57s_XBEN-066/full_logs.jsonl` also failed
  (27× `captured_flag: ""`) and also never dispatched a smuggling agent; it ran
  `vulntype-sqli`, `vulntype-information-disclosure`,
  `vulntype-parameter-pollution`, `vulntype-bfla`, `owasp-auth`,
  `owasp-session`, and `methodology-fuzzing`. The same `Via: haproxy`,
  `X-Upstream-Proxy`, and `internal.router` fingerprints appear in this run too —
  seen across two independent runs, missed both times.
