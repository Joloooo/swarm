# chain-ssrf-to-rce — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **An SSRF has already been confirmed** by recon/another agent — you have a parameter that makes the server fetch an arbitrary URL and you can see proof (your collaborator/OAST callback fired, or the response body/timing changes when you point it at `127.0.0.1` vs a dead host). This is the gating precondition; without confirmed SSRF, do NOT dispatch this skill.
- If a URL/redirect/webhook/callback/import/preview parameter (`url=`, `uri=`, `dest=`, `redirect=`, `next=`, `feed=`, `image_url=`, `webhook=`, `callback=`, `target=`, `proxy=`, `fetch=`, `domain=`, `host=`, `endpoint=`) makes the server issue an outbound request → confirmed SSRF, this skill applies.
- If pointing the SSRF at `http://127.0.0.1:<port>` returns **different content, a different status code, or a different timing** for some ports vs others → an internal service is listening; this skill is the next move (internal port enumeration).
- If `http://169.254.169.254/`, `http://169.254.169.254/latest/meta-data/`, `http://metadata.google.internal/`, or `http://169.254.169.254/metadata/instance?api-version=...` returns **anything other than a connection error** (a directory listing, a token, JSON, `403 Missing required header`) → cloud metadata is reachable through the SSRF; dispatch immediately.
- If the SSRF lets you change scheme to `gopher://`, `dict://`, `file://`, `ftp://`, or `http://...` with CRLF/raw-byte control → you can speak raw TCP to internal services (Redis, Memcached, internal HTTP), which is the bridge from "read internal resource" to RCE.
- If internal port scan reveals **6379 (Redis), 11211 (Memcached), 9200 (Elasticsearch), 2375/2376 (Docker API), 8080/8500/etc. internal admin APIs, 9000 (FastCGI/PHP-FPM)** answering without authentication → an unauthenticated internal service is the RCE pivot this skill chains into.
- If metadata returns IAM/instance credentials (`AccessKeyId`, `SecretAccessKey`, `Token`, GCP `access_token`, Azure bearer token) → credential extraction → lateral movement is in scope here.

## Use-case scenarios

- **SSRF confirmed, now escalating to impact.** The classic flow this skill owns: another agent proved the server fetches attacker-chosen URLs; this skill turns that read/request primitive into code execution or credential theft rather than leaving it as a low/medium "blind SSRF" finding. The whole reason to dispatch is to walk steps 2→5 of a chain whose step 1 is already done.
- **Cloud-hosted target (AWS/GCP/Azure).** Recon fingerprints suggesting EC2/ECS/Lambda, GCE, App Service, or any "deployed on a major cloud" tell (ALB/ELB headers, `x-amz-*`, GCP load-balancer cookies, Azure `x-ms-*`) make the link-local metadata endpoint a prime escalation: hit `169.254.169.254` through the SSRF, pull IAM/role credentials, then use them against the cloud control plane.
- **Containerised / microservice environments.** Internal-only service meshes where backends trust each other on a private network (no auth between services). SSRF gives you a foothold *inside* that trust boundary: unauthenticated Redis, Elasticsearch scripting, an exposed Docker daemon socket/API (`/containers/create` + bind-mount host), or Kubernetes/cloud-init endpoints.
- **Apps that "preview", "import from URL", "fetch a feed/avatar/PDF", proxy webhooks, or render remote content.** These are SSRF-prone surfaces; once the SSRF is confirmed, this skill is the right escalation path to chase RCE rather than stopping at SSRF.
- **Gopher-capable SSRF.** When the fetcher follows `gopher://` or otherwise lets you smuggle a raw byte stream, you can deliver a full Redis/Memcached/SMTP/FastCGI protocol payload in one request — the single most reliable SSRF→RCE bridge. This skill is built for exactly that.

## Concrete tells (request → response examples)

- **Internal port enumeration:**
  - `?url=http://127.0.0.1:6379/` → response contains `-ERR wrong number of arguments` or `-DENIED Redis is running in protected mode` or a `-ERR unknown command` blob → Redis on localhost, reachable.
  - `?url=http://127.0.0.1:9200/` → JSON `{"name":...,"cluster_name":...,"version":{"number":"..."}}` → Elasticsearch, often scriptable.
  - `?url=http://127.0.0.1:2375/version` → JSON with `ApiVersion`, `Os`, `Arch` → unauthenticated Docker API → trivial host RCE.
  - Port that times out vs port that returns instantly / returns an error banner → distinguishes open vs closed internal ports (blind SSRF port scan via response timing).
- **Cloud metadata:**
  - `?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` → returns a role name (e.g. `s3-app-role`) → then `.../security-credentials/s3-app-role` → JSON with `AccessKeyId`/`SecretAccessKey`/`Token`. (IMDSv1.)
  - `?url=http://169.254.169.254/latest/api/token` returns `401`/needs `X-aws-ec2-metadata-token-ttl-seconds` PUT → IMDSv2; needs header injection / gopher to set the PUT header.
  - `?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` with `Metadata-Flavor: Google` → OAuth access token JSON. A bare request without the header returns `403 Missing Metadata-Flavor` — that 403 itself confirms reachability.
- **Gopher → Redis RCE bridge:** `?url=gopher://127.0.0.1:6379/_<URL-encoded REST commands>` setting `dir`/`dbfilename` to a webroot or cron path then `SAVE`, or `SLAVEOF`/`MODULE LOAD` → command execution. A `+OK` echoed back through the SSRF response confirms commands landed.
- **Confirming blind SSRF first (precondition):** `?url=http://<your-collaborator>.oast.site/` → DNS/HTTP hit on your listener with the target's egress IP → SSRF confirmed, hand off to this chain.

## When NOT to use it / easily-confused-with

- **SSRF not yet confirmed.** If you only *suspect* a URL parameter is fetched server-side but have no callback/timing/content proof, this is premature — that is a job for SSRF discovery, not this chain. This skill explicitly runs only after another agent confirms SSRF.
- **A reflected/redirecting URL parameter is not SSRF.** If `?url=` value just appears in the HTML, in a `Location:` 302 header, or in a `<a href>` without the *server itself* making the request, that is **open redirect / reflected XSS**, not SSRF. No server-side fetch → wrong skill.
- **Outbound fetch with no path to internal services or metadata.** A fully sandboxed fetcher (egress-filtered, link-local blocked, no internal listeners, scheme-locked to `https`) yields SSRF but no RCE pivot. Report the SSRF; don't force this chain — but do still attempt metadata/internal probes once before concluding, since filtering is often incomplete.
- **Don't confuse with LFI/RFI or XXE.** `file://` read or local file inclusion is file disclosure, and XML external entity is its own class — route those to their dedicated skills. This skill is specifically the SSRF→internal-service→RCE / SSRF→metadata→credential chain.
- **Don't confuse RCE-via-internal-Redis here with a directly-exposed Redis** reachable from the internet — if Redis answers on the public IP, that is a direct unauthenticated-service exploit, not an SSRF chain. This skill only applies when the internal service is reached *through* the SSRF primitive.
- **Generic command-injection / template-injection on the front-end app** (e.g. an `eval`'d parameter, `${...}` evaluated) is direct RCE/SSTI, not this chain. Use the SSRF-to-RCE chain only when the code execution is obtained by pivoting through an internal/cloud service via the confirmed SSRF.
