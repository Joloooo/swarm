# Virtual-host discovery playbook — Open WHEN: one IP/host may serve several apps and you need to find the hidden vhosts behind the `Host:` header

A web server (Apache, Nginx, IIS, …) can host many sites on one IP and
chooses which to serve from the request's `Host:` header. A plain
request only ever reaches the **default** vhost. Hidden vhosts — admin
panels, staging copies, internal apps, the "real" app on a CTF box —
answer only when you send their name in `Host:`. A vhost can exist with
**no public DNS record**, so DNS subdomain enumeration misses it
entirely; only `Host:`-header probing finds it.

## Why it is distinct from subdomain enumeration

- Subdomain enumeration asks DNS "what names resolve?" — it finds names
  with public records, then you connect to whatever IP each resolves to.
- Vhost discovery asks one server "what names do you answer for?" — it
  finds names served on an IP you already hold, including names that
  have no DNS record at all. Run both; they overlap but neither is a
  superset of the other.

## Brute-force with gobuster vhost

```
gobuster vhost -u http://<target> -w <wordlist> --append-domain
```

- `--append-domain` makes gobuster append the base domain to each
  wordlist entry (`admin` -> `admin.example.com`). Omit it when the
  wordlist already contains full FQDNs.
- Pull a vhost / subdomain wordlist with `get_wordlist` (the same lists
  used for subdomain enumeration work here). A focused, high-signal list
  beats a giant blind one — most vhosts have guessable names (`admin`,
  `dev`, `staging`, `internal`, `api`, `test`, `portal`, `intranet`).
- gobuster's vhost mode auto-filters the catch-all baseline in recent
  versions; still sanity-check hits by hand (see the oracle below).

## Manual probe with curl

```
# default response — capture title, status, and body size as a baseline
curl -s -i http://<target-ip>/ | head

# probe a guessed vhost
curl -s -i -H "Host: admin.example.com" http://<target-ip>/ | head

# compare body sizes quickly
curl -s -H "Host: admin.example.com" http://<target-ip>/ | wc -c
```

Swap in known or guessed names and diff each response against the
default. Manual probing is the right tool when you have a *short* list
of high-signal candidates (SAN entries, names seen in HTML); use
gobuster when you need to grind a wordlist.

## The difference oracle — is this a real vhost?

You have hit a *different* vhost (not the default) when, compared to the
default response, any of these change:

- HTML `<title>`, brand text, or `<meta>` description
- Body size / `Content-Length`
- Status code (e.g. default 200 vs this 403, 301, or 302)
- A custom or differently-worded error page
- A redirect chain that lands on a different domain

A **catch-all** server returns the *same* page for every made-up
`Host:` (including obvious garbage like `Host: thisdoesnotexist.invalid`).
Establish the catch-all baseline first by sending one nonsense host; any
candidate that matches that baseline is noise, and only candidates that
**differ** from it are real vhosts. Without this baseline you will log
the catch-all page dozens of times as false positives.

## Seed the candidate list from artifacts you already hold

Higher-signal than a blind wordlist:

- **TLS-cert SAN entries** — `echo | openssl s_client -connect <ip>:443 -servername <name> 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"`. Every SAN is a name the server may serve.
- **Certificate Transparency** — crt.sh / Cert Spotter list every name ever issued a cert for the domain (see `passive-sources.md`); each is a vhost candidate.
- **Homepage HTML and JS** — absolute links, `fetch`/`axios` base URLs, CDN and asset hostnames, CORS `Access-Control-Allow-Origin` values.
- **`robots.txt`, `sitemap.xml`, redirects** — often name sibling hosts.
- **Subdomains from the passive pass** — feed every discovered subdomain back as a `Host:` candidate against the IP you hold.

## Origin-IP discovery behind a WAF (Cloudflare et al.)

When the public name resolves to a WAF/CDN, the origin server often
still answers on its real IP if you address it directly. Find that IP
and send the real hostname in `Host:`:

1. Collect **historical** IPs for the domain from DNS-history / passive
   DNS (SecurityTrails, DNSDB, ViewDNS, RiskIQ — see `passive-sources.md`).
   The origin's old IP is frequently still live and no longer behind the
   WAF.
2. Spray the current hostname as a `Host:` header against each candidate
   IP:

   ```
   curl -s -i -H "Host: example.com" http://<historical-ip>/ | head
   ```

3. A response that matches the real site (same title / app, not a WAF
   error or default page) means you reached the **origin directly** and
   bypassed the WAF. That is a high-value finding — file it (origin IP +
   evidence) and hand it off; specialists can now test the app without
   the WAF in front of it.

The same idea works across a whole network block: enumerate the IPs in
an ASN/prefix the org owns (see `passive-sources.md`) and spray the
hostname against each.

## After a hit

Treat each confirmed vhost as a **new application to map**: file it as a
surface (hostname + IP + what it serves + how you reached it) and re-run
recon scoped to it (`fetch_page`, directory enumeration, fingerprint).
A new vhost is the start of a fresh mapping pass, not the end of the
current one.
