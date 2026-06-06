# subdomain-takeover — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- If a subdomain resolves via **CNAME to a third-party provider domain** (`*.github.io`, `*.s3.amazonaws.com`, `*.s3-website-*.amazonaws.com`, `*.cloudfront.net`, `*.azurewebsites.net`, `*.blob.core.windows.net`, `*.trafficmanager.net`, `*.azureedge.net`, `*.fastly.net`, `*.herokudns.com`, `*.herokuapp.com`, `*.vercel.app`, `*.netlify.app`, `*.myshopify.com`, `*.zendesk.com`, `*.statuspage.io`, `*.surge.sh`, `*.readthedocs.io`, `*.pantheonsite.io`, `*.wpengine.com`) → this skill applies.
- If the CNAME chain resolves but the HTTP body returns a **provider's "unclaimed / not found" banner** ("There isn't a GitHub Pages site here.", "NoSuchBucket", "Fastly error: unknown domain", "No such app", "There's nothing here, yet.", "Sorry, this shop is currently unavailable", "Do you want to register *.wordpress.com?", "Project not found" on Surge, "Heroku | No such app") → strong takeover candidate, dispatch.
- If a host has a **CNAME but the terminal target is NXDOMAIN** (the alias points at a name that no longer exists) → dangling record, classic takeover setup.
- If `dig` shows a record but the web server returns a **404/403 that names the provider rather than the app** (CloudFront "The request could not be satisfied", default Azure App Service 404 page, S3 `AccessDenied`/`NoSuchBucket` XML) → fingerprint a provider takeover.
- If an **NS delegation points a child zone at nameservers on a domain that fails to resolve or is registrable** (e.g. `sub.example.com.` NS `ns1.expired-dns-vendor.com` and `expired-dns-vendor.com` is available to register) → highest-impact takeover signal, dispatch immediately.
- If a subdomain returns **SERVFAIL / REFUSED at one of its delegated nameservers but not others**, or the delegation is lame → investigate NS takeover.
- If **MX records point to a SaaS mail/forwarding provider on a decommissioned or expired domain** → mail-surface takeover candidate.
- If you find **stale verification artifacts in DNS** (`_github-pages-challenge-*` TXT, `asuid.*` TXT for Azure, `_acme-challenge` left dangling, `_dnsauth`) without a live matching binding → previous external binding may now be orphaned.
- If a **wildcard CNAME** (`*.example.com CNAME something.provider.tld`) points at a provider → any arbitrary label may be claimable.
- If CT-log / passive-DNS enumeration surfaces a subdomain that is **referenced in certificates or old asset lists but no longer serves the app** (decommissioned `support.`, `docs.`, `blog.`, `status.`, `careers.`, `mail.`, `cdn.`, `assets.`, `legacy.`, `staging.` hosts) → check for dangling pointers.

## Use-case scenarios

This is the right move during the **recon-to-asset-mapping phase of any black-box engagement that owns more than one hostname**, and specifically whenever DNS enumeration reveals subdomains delegated to or aliased onto infrastructure the target does not directly control.

- **Broad-scope enumeration.** When the engagement scope is `*.example.com` or an apex with many subdomains, the very first pass should build a CNAME/A/NS graph. Marketing, docs, support, status, and old campaign subdomains are the usual victims because they were spun up on a SaaS, then abandoned when the contract lapsed — the SaaS resource was deleted but the DNS pointer was never removed.
- **Decommissioned SaaS integrations.** A company that once used Zendesk for support, Heroku for a side app, Shopify for a store, or GitHub Pages for docs, and then migrated away, frequently leaves the CNAME in place. The provider released the name; you can re-register it.
- **Cloud-storage static sites.** S3 / GCS / Azure Blob static-website hosting where bucket/container names must equal the hostname. If the bucket was deleted but the CNAME `assets.example.com → assets.example.com.s3-website-us-east-1.amazonaws.com` remains, the bucket name is now free to claim.
- **CDN alternate-domain mappings.** CloudFront / Fastly / Azure CDN distributions that listed the victim subdomain as an alternate/alias name. Historically several CDNs let you add an alternate domain without proving ownership; an orphaned mapping is claimable on your own distribution.
- **NS-delegation takeover.** The most overlooked and highest-impact case. A child zone delegated to a managed-DNS vendor whose domain expired, or a vendor account that was closed, lets you register the vendor domain (or claim the account) and become authoritative for every host under that label — full control of the whole subzone, not just one name.
- **Trust-chain pivots.** Reach for this skill not only for phishing-on-trusted-origin, but when a takeover-eligible subdomain is also referenced as an **OAuth `redirect_uri`, a CORS allowlisted origin, a CSP `script-src`/`connect-src` source, or a parent-domain cookie scope** — there the takeover escalates to session theft, script injection, or account takeover, which is worth flagging as critical.

## Concrete tells (request → response examples)

- **GitHub Pages**
  `dig +short docs.example.com` → `example.github.io`
  `curl -s https://docs.example.com/` → body contains `There isn't a GitHub Pages site here.` and `404` — the org/repo with that custom domain is gone. Candidate.

- **AWS S3 static site**
  `dig +short assets.example.com` → `assets.example.com.s3-website-us-east-1.amazonaws.com`
  `curl -s http://assets.example.com/` → `<Code>NoSuchBucket</Code>` / `The specified bucket does not exist`. The bucket name is claimable.

- **Heroku**
  `dig +short app.example.com` → `xxxx.herokudns.com`
  `curl -s https://app.example.com/` → `No such app` or `There's nothing here, yet.` The Heroku app name is free.

- **Fastly**
  `curl -s https://cdn.example.com/` → `Fastly error: unknown domain: cdn.example.com`. The hostname is not bound to any active Fastly service.

- **Azure (App Service / Blob / TrafficManager)**
  `dig +short legacy.example.com` → `legacy.example.com.azurewebsites.net` (or `*.trafficmanager.net` / `*.blob.core.windows.net`) where the CNAME's terminal target is **NXDOMAIN** → the Azure resource was deleted; the name is reclaimable.

- **Shopify**
  `curl -sL https://shop.example.com/` → `Sorry, this shop is currently unavailable`. The myshopify store backing this custom domain is gone.

- **NS delegation**
  `dig NS sub.example.com` → `ns1.somevendor.net ns2.somevendor.net`; then `whois somevendor.net` shows the domain is **expired / available** (or `dig somevendor.net` is NXDOMAIN). Register it → become authoritative for everything under `sub.example.com`. Highest impact.

- **Dangling CNAME generally**
  `dig sub.example.com` returns a CNAME, but querying the terminal name returns `NXDOMAIN` (status: NXDOMAIN in the dig header) → the alias target does not exist; whoever can register/claim that target controls the subdomain.

## When NOT to use it / easily-confused-with

- **A provider banner on an owned, live resource is not a takeover.** A "default" provider page (Azure default 404, generic CDN landing) on a hostname that the target genuinely owns and could reactivate is not claimable — confirm the resource is actually *unclaimed and re-registrable* before calling it. A fingerprint match is a candidate, never a finding.
- **Modern providers enforce TXT/ownership verification.** "Unknown domain" pages on GitHub Pages, Netlify, Vercel, and current Azure flows are often *not* claimable because the provider requires a `_*-challenge` TXT or `asuid` record you cannot set. If the claim path stops at "verify ownership", it is a false positive — do not report.
- **A subdomain that simply 404s or shows a soft-404 from the target's own infrastructure** (catch-all vhost, app-level 404, WAF block page) is not a takeover — that is normal app behaviour, not a dangling third-party pointer. Route those to normal content discovery, not here.
- **A subdomain pointing at the target's own IP / their own load balancer** is in-scope app surface, not a takeover. Only third-party / unowned terminal targets qualify.
- **Don't confuse with DNS rebinding or DNS cache poisoning of the resolver** — this skill is about reclaiming an *unowned external resource the DNS still points at*, not about manipulating resolution paths.
- **Don't confuse with open-redirect / SSRF.** A subdomain that *redirects* you elsewhere, or a parameter that fetches a URL, is a different class. Subdomain takeover is specifically: the DNS record dangles at a provider where you can register the missing resource and then serve your own content from the trusted name.
- **An expired TLS cert or HSTS warning on a live host** is a hygiene finding, not a takeover, unless the underlying resource is also unclaimed.

B:subdomain-takeover done
