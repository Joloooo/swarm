# Passive surface mapping — third-party datasets

Reference material for FQDN engagements. NOT loaded into the recon
worker's system prompt by default — pulled on demand via
`load_reference("recon", "passive-sources.md")` when the target is a
real domain.

Passive sources never touch the target — they query third-party
datasets that already crawled it. Cheap, often reveal subdomains and
hosts that gobuster will miss. Run these in parallel with
`fetch_page`, not after `nmap`.

## Subdomain & host discovery (passive)

- **Certificate Transparency logs** — every public TLS cert is logged.
  Query `crt.sh?q=%25.target.tld` (URL-encoded `%`) for every subject
  and SAN ever issued for the domain. Cert Spotter and Censys
  Certificates do the same with cleaner pivots on issuer, serial, or
  SAN. CertStream gives a real-time feed if you need to watch new
  issuance.
- **Passive DNS** — SecurityTrails, RiskIQ PassiveTotal, and DNSDB
  store historical resolutions. Use them to find dead subdomains that
  still resolve to take-overable CNAMEs, or to map a target's full IP
  history.
- **Passive subdomain tools** — `subfinder -d target.tld` and
  `amass enum -passive -d target.tld` aggregate dozens of sources
  (CT, PassiveDNS, search engines) in one shot.
  `theHarvester -d target.tld -b all` also pulls hosts from public
  sources.

## Infrastructure & tech-stack pivots

- **Shodan / Censys / Netlas / FOFA / ZoomEye / BinaryEdge** —
  internet-wide scanners. Pivot on any artifact: `Shodan:
  ssl.cert.subject.cn:"target.tld"`, `Censys:
  services.tls.certificates.leaf_data.subject.common_name:"target.tld"`,
  or favicon hash (`http.favicon.hash:<mmh3>`) to find sibling hosts
  hosted on the same infrastructure but under different domains.
- **ASN / BGP walking** — once you have one IP, look up its ASN on
  Hurricane Electric BGP Toolkit (`bgp.he.net`), RIPEstat, BGPView,
  or `bgp.tools`. Every prefix announced by that ASN is in scope if
  the org owns the AS.
- **BuiltWith** — tech-stack lookup without touching the target.
  Often reveals the CMS, analytics, CDN, and hosting provider before
  you even fetch the page.
- **Robtex / SpiderFoot** — automated correlation of DNS, WHOIS, ASN,
  and reverse-IP data; SpiderFoot orchestrates 200+ modules in one
  run.

## Archived content

- **Wayback Machine** (`web.archive.org`), **archive.today**, and
  **URLScan.io** hold old versions of the site that often expose
  endpoints, parameters, and debug pages the live site has since
  hidden.

## Pivoting discipline

- Treat every artifact as a pivot: subject CNs, issuer, serial,
  favicon mmh3 hash, JA3/JA4 TLS fingerprint, HTML title, `Server:`
  header, name-server pattern, registrar account, ASN. Feed each one
  back into Shodan/Censys/crt.sh to widen the surface.
- Prefer durable pivots (cert reuse, favicon hash, registrar
  account) over ephemeral ones (a single resolving IP). Infrastructure
  rotates; build artifacts don't.
- Archive everything you find: URL + timestamp + screenshot. Targets
  change between scans, and the planner needs a stable reference for
  follow-up agents.
