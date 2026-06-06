# subdomain-takeover

Reclaim a trusted hostname whose DNS still points at a third-party resource the target no longer owns. Once the missing provider resource is re-registered, you serve your own content from the trusted name. Best run during recon / asset-mapping on any engagement that owns more than one hostname, especially after enumerating a `*.example.com` scope into a CNAME/A/NS graph.

## Dispatch when:

- A subdomain resolves via **CNAME to a third-party provider domain**: `*.github.io`, `*.s3.amazonaws.com`, `*.s3-website-*.amazonaws.com`, `*.cloudfront.net`, `*.azurewebsites.net`, `*.blob.core.windows.net`, `*.trafficmanager.net`, `*.azureedge.net`, `*.fastly.net`, `*.herokudns.com`, `*.herokuapp.com`, `*.vercel.app`, `*.netlify.app`, `*.myshopify.com`, `*.zendesk.com`, `*.statuspage.io`, `*.surge.sh`, `*.readthedocs.io`, `*.pantheonsite.io`, `*.wpengine.com`.
- The CNAME chain resolves but the HTTP body returns a provider **"unclaimed / not found" banner**: "There isn't a GitHub Pages site here.", "NoSuchBucket", "Fastly error: unknown domain", "No such app", "There's nothing here, yet.", "Sorry, this shop is currently unavailable", "Do you want to register *.wordpress.com?", Surge "Project not found", "Heroku | No such app".
- A host has a **CNAME but the terminal target is NXDOMAIN** — the alias points at a name that no longer exists (dangling record, classic setup).
- `dig` shows a record but the web server returns a **404/403 that names the provider, not the app**: CloudFront "The request could not be satisfied", default Azure App Service 404, S3 `AccessDenied`/`NoSuchBucket` XML.
- An **NS delegation points a child zone at nameservers on a domain that fails to resolve or is registrable** (e.g. `sub.example.com.` NS `ns1.expired-dns-vendor.com` and `expired-dns-vendor.com` is available) — highest-impact signal, dispatch immediately. Also investigate when a subdomain returns **SERVFAIL / REFUSED at one delegated nameserver but not others**, or the delegation is lame.
- **MX records point to a SaaS mail/forwarding provider on a decommissioned or expired domain** — mail-surface takeover candidate.
- **Stale verification artifacts** sit in DNS without a live matching binding: `_github-pages-challenge-*` TXT, `asuid.*` TXT (Azure), dangling `_acme-challenge`, `_dnsauth` — a previous external binding may now be orphaned.
- A **wildcard CNAME** (`*.example.com CNAME something.provider.tld`) points at a provider — any arbitrary label may be claimable.
- CT-log / passive-DNS enumeration surfaces a subdomain **referenced in certificates or old asset lists but no longer serving the app** (decommissioned `support.`, `docs.`, `blog.`, `status.`, `careers.`, `mail.`, `cdn.`, `assets.`, `legacy.`, `staging.` hosts).

## Common takeover surfaces:

- **Decommissioned SaaS integrations.** Zendesk support, a Heroku side app, a Shopify store, GitHub Pages docs — migrated away but the CNAME left in place. The provider released the name; re-register it.
- **Cloud-storage static sites.** S3 / GCS / Azure Blob static hosting where the bucket/container name must equal the hostname. If the bucket was deleted but `assets.example.com → assets.example.com.s3-website-us-east-1.amazonaws.com` remains, that bucket name is free to claim.
- **CDN alternate-domain mappings.** CloudFront / Fastly / Azure CDN distributions that listed the victim subdomain as an alternate/alias. Several CDNs historically allowed adding an alternate domain without proving ownership; an orphaned mapping is claimable on your own distribution.
- **NS-delegation takeover.** A child zone delegated to a managed-DNS vendor whose domain expired or whose account was closed. Register the vendor domain (or claim the account) → become authoritative for every host under that label, i.e. full control of the whole subzone, not just one name.
- **Trust-chain pivots.** When a takeover-eligible subdomain is also an **OAuth `redirect_uri`, a CORS-allowlisted origin, a CSP `script-src`/`connect-src` source, or a parent-domain cookie scope**, the takeover escalates to session theft, script injection, or account takeover — flag as critical.

## Recognition tells (request → response):

- **GitHub Pages:** `dig +short docs.example.com` → `example.github.io`; `curl -s https://docs.example.com/` body contains "There isn't a GitHub Pages site here." + 404 — the org/repo with that custom domain is gone.
- **AWS S3 static site:** `dig +short assets.example.com` → `assets.example.com.s3-website-us-east-1.amazonaws.com`; `curl -s http://assets.example.com/` → `<Code>NoSuchBucket</Code>` / "The specified bucket does not exist". Bucket name is claimable.
- **Heroku:** `dig +short app.example.com` → `xxxx.herokudns.com`; `curl -s https://app.example.com/` → "No such app" or "There's nothing here, yet." App name is free.
- **Fastly:** `curl -s https://cdn.example.com/` → "Fastly error: unknown domain: cdn.example.com". Hostname is bound to no active Fastly service.
- **Azure (App Service / Blob / TrafficManager):** `dig +short legacy.example.com` → `legacy.example.com.azurewebsites.net` (or `*.trafficmanager.net` / `*.blob.core.windows.net`) where the CNAME's terminal target is NXDOMAIN — the Azure resource was deleted, name is reclaimable.
- **Shopify:** `curl -sL https://shop.example.com/` → "Sorry, this shop is currently unavailable". The myshopify store behind this custom domain is gone.
- **NS delegation:** `dig NS sub.example.com` → `ns1.somevendor.net ns2.somevendor.net`; `whois somevendor.net` shows expired/available (or `dig somevendor.net` is NXDOMAIN). Register it → authoritative for everything under `sub.example.com`.
- **Dangling CNAME generally:** `dig sub.example.com` returns a CNAME but querying the terminal name returns NXDOMAIN (status: NXDOMAIN in the dig header) — whoever registers/claims that target controls the subdomain.

## When NOT to use / easily confused with:

- **A provider banner on an owned, live resource is not a takeover.** A default provider page (Azure default 404, generic CDN landing) on a hostname the target genuinely owns and could reactivate is not claimable. Confirm the resource is actually unclaimed and re-registrable — a fingerprint match is a candidate, never a finding.
- **Modern providers enforce TXT/ownership verification.** "Unknown domain" pages on GitHub Pages, Netlify, Vercel, and current Azure flows are often not claimable because the provider requires a `_*-challenge` TXT or `asuid` record you cannot set. If the claim path stops at "verify ownership", it is a false positive — do not report.
- **A plain 404 / soft-404 from the target's own infrastructure** (catch-all vhost, app-level 404, WAF block page) is normal app behaviour — route to content discovery, not here.
- **A subdomain pointing at the target's own IP / load balancer** is in-scope app surface. Only third-party / unowned terminal targets qualify.
- **Not DNS rebinding or resolver cache poisoning** — this skill reclaims an unowned external resource the DNS still points at, not manipulating resolution paths.
- **Not open-redirect / SSRF** — a subdomain that redirects you elsewhere, or a parameter that fetches a URL, is a different class. Takeover specifically means the DNS record dangles at a provider where you can register the missing resource.
- **An expired TLS cert or HSTS warning on a live host** is a hygiene finding, not a takeover, unless the underlying resource is also unclaimed.
